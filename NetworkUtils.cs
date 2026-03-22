using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using MyNet.Models;

namespace MyNet.Helpers
{
    /// <summary>
    /// Static utilities for network math, IP iteration, and adapter enumeration.
    /// </summary>
    public static class NetworkUtils
    {
        // ----------------------------------------------------------------
        //  Adapter discovery
        // ----------------------------------------------------------------

        /// <summary>
        /// Enumerates all active unicast IPv4 adapters that have a gateway.
        /// Returns one AdapterInfo per adapter (skipping loopback / tunnel).
        /// </summary>
        public static List<AdapterInfo> GetAdapters()
        {
            var result = new List<AdapterInfo>();

            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                // Filter: must be up, not loopback, not tunnel
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

                var ipProps = nic.GetIPProperties();

                // Must have at least one IPv4 gateway
                var gateways = ipProps.GatewayAddresses
                    .Select(g => g.Address)
                    .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                    .ToList();

                if (gateways.Count == 0) continue;

                // Must have at least one unicast IPv4 address
                var unicast = ipProps.UnicastAddresses
                    .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork)
                    .ToList();

                if (unicast.Count == 0) continue;

                var firstUnicast = unicast[0];
                var localIp   = firstUnicast.Address.ToString();
                var subnetMask = firstUnicast.IPv4Mask.ToString();
                var gatewayIp = gateways[0].ToString();
                var mac       = FormatMac(nic.GetPhysicalAddress().GetAddressBytes());

                result.Add(new AdapterInfo
                {
                    Name         = nic.Id,
                    FriendlyName = nic.Name,
                    IpAddress    = localIp,
                    MacAddress   = mac,
                    SubnetMask   = subnetMask,
                    GatewayIp    = gatewayIp,
                });
            }

            return result;
        }

        // ----------------------------------------------------------------
        //  IP / subnet helpers
        // ----------------------------------------------------------------

        /// <summary>
        /// Given a host IP and subnet mask, returns all host addresses in the subnet
        /// (excluding network address and broadcast).
        /// For /24 that's 254 addresses; for /16 it would be 65 534 (cap at 1024 for safety).
        /// </summary>
        public static IEnumerable<IPAddress> GetSubnetHosts(string ipStr, string maskStr)
        {
            if (!IPAddress.TryParse(ipStr, out var ip)) yield break;
            if (!IPAddress.TryParse(maskStr, out var mask)) yield break;

            var ipBytes   = ip.GetAddressBytes();
            var maskBytes = mask.GetAddressBytes();

            // Network address = ip & mask
            byte[] network = new byte[4];
            for (int i = 0; i < 4; i++) network[i] = (byte)(ipBytes[i] & maskBytes[i]);

            // Broadcast = ip | (~mask)
            byte[] broadcast = new byte[4];
            for (int i = 0; i < 4; i++) broadcast[i] = (byte)(network[i] | (~maskBytes[i] & 0xFF));

            long start = BytesToLong(network) + 1;
            long end   = BytesToLong(broadcast) - 1;
            long count = end - start + 1;

            // Safety cap: do not iterate more than 1024 hosts automatically
            if (count > 1024) count = 1024;

            for (long addr = start; addr <= start + count - 1; addr++)
            {
                yield return new IPAddress(LongToBytes(addr));
            }
        }

        // ----------------------------------------------------------------
        //  MAC formatting
        // ----------------------------------------------------------------
        public static string FormatMac(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0) return "00:00:00:00:00:00";
            return string.Join(":", bytes.Select(b => b.ToString("X2")));
        }

        public static byte[] ParseMac(string mac)
        {
            var parts = mac.Split(':', '-');
            return parts.Select(p => Convert.ToByte(p, 16)).ToArray();
        }

        public static bool IsValidMac(string mac)
        {
            var parts = mac.Split(':', '-');
            if (parts.Length != 6) return false;
            return parts.All(p => p.Length == 2 && p.All(c => Uri.IsHexDigit(c)));
        }

        // ----------------------------------------------------------------
        //  Arithmetic helpers
        // ----------------------------------------------------------------
        private static long BytesToLong(byte[] b)
            => ((long)b[0] << 24) | ((long)b[1] << 16) | ((long)b[2] << 8) | b[3];

        private static byte[] LongToBytes(long v)
            => new byte[]
            {
                (byte)((v >> 24) & 0xFF),
                (byte)((v >> 16) & 0xFF),
                (byte)((v >>  8) & 0xFF),
                (byte)(v         & 0xFF)
            };

        // ----------------------------------------------------------------
        //  Nomad Protocol Helpers
        // ----------------------------------------------------------------
        
        /// <summary>
        /// Generates a random valid unicast MAC address string (no delimiters).
        /// Ensures the second hex digit is even (unicast).
        /// </summary>
        public static string GetRandomMac()
        {
            var r = new Random();
            var bytes = new byte[6];
            r.NextBytes(bytes);
            
            // Ensure unicast (LSB of first byte must be 0)
            bytes[0] = (byte)(bytes[0] & 0xFE);
            // Ensure bit 1 is set (locally administered)
            bytes[0] = (byte)(bytes[0] | 0x02);

            return string.Concat(bytes.Select(b => b.ToString("X2")));
        }

        public static async Task RestartAdapterAsync(string adapterId)
        {
            // We use netsh as it is the most reliable way to power-cycle a NIC on Windows
            // without needing COM/WMI complex interop.
            var psiDisable = new System.Diagnostics.ProcessStartInfo("netsh", $"interface set interface name=\"{adapterId}\" admin=disable") { CreateNoWindow = true, UseShellExecute = false };
            var psiEnable = new System.Diagnostics.ProcessStartInfo("netsh", $"interface set interface name=\"{adapterId}\" admin=enable") { CreateNoWindow = true, UseShellExecute = false };

            await Task.Run(() => {
                System.Diagnostics.Process.Start(psiDisable)?.WaitForExit();
                System.Threading.Thread.Sleep(1500); // Wait for the OS to finalize the disable
                System.Diagnostics.Process.Start(psiEnable)?.WaitForExit();
            });
        }
        // ----------------------------------------------------------------
        //  Diagnostics
        // ----------------------------------------------------------------
        public static async Task<bool> PingAsync(string ip)
        {
            try
            {
                using var pinger = new Ping();
                var reply = await pinger.SendPingAsync(ip, 2000); // 2 second timeout
                return reply.Status == IPStatus.Success;
            }
            catch
            {
                return false;
            }
        }

        // ----------------------------------------------------------------
        //  Hostname resolution (async, best-effort)
        // ----------------------------------------------------------------
        public static async Task<string> ResolveHostnameAsync(string ip)
        {
            try
            {
                var entry = await Dns.GetHostEntryAsync(ip);
                return entry.HostName;
            }
            catch
            {
                return ip; // Fall back to raw IP if DNS fails
            }
        }
    }
}
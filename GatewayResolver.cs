using PacketDotNet;
using SharpPcap;
using MyNet.Helpers;
using MyNet.Models;

namespace MyNet.Core
{
    /// <summary>
    /// Resolves the MAC address of the default gateway by sending an
    /// ARP request to the gateway IP and capturing the reply.
    ///
    /// Why we need this:
    ///   The gateway's MAC address is required to craft valid spoofed ARP replies.
    ///   Windows' ARP cache (arp -a) usually has it, but we read it directly
    ///   from the NIC using a live ARP exchange to stay self-contained.
    /// </summary>
    public static class GatewayResolver
    {
        /// <summary>
        /// Sends an ARP request to the gateway and waits up to
        /// <paramref name="timeoutMs"/> milliseconds for a reply.
        /// Returns the gateway MAC as "AA:BB:CC:DD:EE:FF" or null on timeout.
        /// </summary>
        public static async Task<string?> ResolveGatewayMacAsync(
            AdapterInfo adapter,
            int timeoutMs = 3000)
        {
            if (string.IsNullOrWhiteSpace(adapter.GatewayIp)) return null;

            // Find the Npcap device
            ILiveDevice? dev = null;
            foreach (var d in CaptureDeviceList.Instance)
            {
                if (d.Name.Contains(adapter.Name, StringComparison.OrdinalIgnoreCase))
                { dev = d; break; }
            }
            if (dev == null) return null;

            try { dev.Open(DeviceModes.Promiscuous, 100); } catch { /* Already open */ }
            dev.Filter = "arp";

            string? foundMac  = null;
            var     tcs        = new TaskCompletionSource<string?>();

            void Handler(object s, PacketCapture e)
            {
                try
                {
                    var raw = e.GetPacket();
                    var eth = EthernetPacket.ParsePacket(raw.LinkLayerType, raw.Data) as EthernetPacket;
                    var arp = eth?.Extract<ArpPacket>();
                    if (arp == null) return;
                    if (arp.Operation != ArpOperation.Response) return;

                    var senderIp = arp.SenderProtocolAddress.ToString();
                    if (senderIp != adapter.GatewayIp) return;

                    var mac = NetworkUtils.FormatMac(arp.SenderHardwareAddress.GetAddressBytes());
                    tcs.TrySetResult(mac);
                }
                catch { /* ignore parse errors */ }
            }

            dev.OnPacketArrival += Handler;
            dev.StartCapture();

            // Send the ARP request
            var request = ArpPacketBuilder.BuildArpRequest(
                adapter.MacAddress, adapter.IpAddress, adapter.GatewayIp);
            dev.SendPacket(request);

            // Wait for reply or timeout
            var timeout = Task.Delay(timeoutMs);
            var winner  = await Task.WhenAny(tcs.Task, timeout);
            foundMac    = winner == tcs.Task ? tcs.Task.Result : null;

            dev.OnPacketArrival -= Handler;

            return foundMac;
        }
    }
}
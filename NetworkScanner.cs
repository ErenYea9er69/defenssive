using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet;
using SharpPcap;
using MyNet.Helpers;
using MyNet.Models;

namespace MyNet.Core
{
    /// <summary>
    /// Scans the local subnet using ARP requests and collects responses.
    ///
    /// How it works:
    ///   1. Open the NIC with SharpPcap in promiscuous mode.
    ///   2. Start a background thread that captures incoming ARP Reply packets.
    ///   3. Send an ARP Request to every host address in the subnet.
    ///   4. Wait a short time for replies; collect (IP → MAC) mappings.
    ///   5. For each discovered device, resolve hostname asynchronously.
    /// </summary>
    public class NetworkScanner : IDisposable
    {
        // ----------------------------------------------------------------
        //  Fields
        // ----------------------------------------------------------------
        private readonly AdapterInfo _adapter;
        private ILiveDevice? _device;
        private CancellationTokenSource? _cts;

        // Thread-safe dict: IP string → MAC string
        private readonly ConcurrentDictionary<string, string> _discovered = new();

        public event Action<NetworkDevice>? DeviceFound;
        public event Action<string>? ScanStatusChanged;
        public event Action? ScanCompleted;

        // ----------------------------------------------------------------
        //  Constructor
        // ----------------------------------------------------------------
        public NetworkScanner(AdapterInfo adapter) => _adapter = adapter;

        // ----------------------------------------------------------------
        //  Public API
        // ----------------------------------------------------------------

        /// <summary>
        /// Starts an asynchronous ARP scan of the subnet.
        /// Discovered devices are reported via <see cref="DeviceFound"/>.
        /// </summary>
        public async Task ScanAsync(CancellationToken externalCt = default)
        {
            _cts?.Cancel();
            _cts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
            var ct = _cts.Token;

            _discovered.Clear();

            ScanStatusChanged?.Invoke("Opening network adapter…");

            // Open the capture device
            var devices = CaptureDeviceList.Instance;
            _device = FindDevice(devices, _adapter);
            if (_device == null)
            {
                ScanStatusChanged?.Invoke("ERROR: Could not find capture device. Is Npcap installed?");
                return;
            }

            try { _device.Open(DeviceModes.Promiscuous, 100 /* read timeout ms */); } catch { /* Already open */ }
            // Only capture ARP frames (EtherType 0x0806)
            _device.Filter = "arp";

            // Start capture thread
            _device.OnPacketArrival += OnPacketArrival;
            _device.StartCapture();

            ScanStatusChanged?.Invoke($"Scanning {_adapter.IpAddress} / {_adapter.SubnetMask} …");

            // Enumerate all hosts in subnet and ARP-request each one
            var hosts = NetworkUtils.GetSubnetHosts(_adapter.IpAddress, _adapter.SubnetMask).ToList();
            int total = hosts.Count;
            int sent  = 0;

            // Strategy: Send 3 probes for each host with a short delay between batches
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                if (ct.IsCancellationRequested) break;
                
                sent = 0;
                foreach (var host in hosts)
                {
                    if (ct.IsCancellationRequested) break;

                    var requestBytes = ArpPacketBuilder.BuildArpRequest(
                        _adapter.MacAddress,
                        _adapter.IpAddress,
                        host.ToString());

                    _device.SendPacket(requestBytes);
                    sent++;

                    if (attempt == 1 && sent % 20 == 0)
                        ScanStatusChanged?.Invoke($"Scanning… {sent}/{total} probes sent (Attempt {attempt}/3)");

                    // Pace the probes: 2 ms between each to avoid flooding
                    await Task.Delay(2, ct).ConfigureAwait(false);
                }
                
                if (attempt < 3)
                {
                    // Wait a bit between global retry rounds
                    ScanStatusChanged?.Invoke($"Attempt {attempt} complete. Waiting before retry…");
                    await Task.Delay(500, ct).ConfigureAwait(false);
                }
            }

            // Wait up to 3 s for the last replies to arrive
            ScanStatusChanged?.Invoke("Waiting for final replies…");
            await Task.Delay(3000, ct).ConfigureAwait(false);

            _device.OnPacketArrival -= OnPacketArrival;

            ScanStatusChanged?.Invoke($"Scan complete. {_discovered.Count} device(s) found.");
            ScanCompleted?.Invoke();
        }

        // ----------------------------------------------------------------
        //  Packet handler
        // ----------------------------------------------------------------
        private void OnPacketArrival(object sender, PacketCapture e)
        {
            try
            {
                var raw   = e.GetPacket();
                var eth   = EthernetPacket.ParsePacket(raw.LinkLayerType, raw.Data) as EthernetPacket;
                if (eth == null) return;

                var arp = eth.Extract<ArpPacket>();
                if (arp == null || arp.Operation != ArpOperation.Response) return;

                var ip  = arp.SenderProtocolAddress.ToString();
                var mac = NetworkUtils.FormatMac(arp.SenderHardwareAddress.GetAddressBytes());

                // Skip our own machine
                if (ip == _adapter.IpAddress) return;

                if (_discovered.TryAdd(ip, mac))
                {
                    // Build the device and notify the UI thread
                    var dev = new NetworkDevice
                    {
                        IpAddress  = ip,
                        MacAddress = mac,
                        Vendor     = MacVendorLookup.Lookup(mac),
                        Status     = "Online"
                    };

                    // Fire device found (UI will marshal to main thread)
                        // Shadow Identify: Start deep fingerprinting in the background
                        _ = FingerprintEngine.IdentifyDeviceAsync(dev);

                        DeviceFound?.Invoke(dev);

                    // Resolve hostname in background
                    _ = Task.Run(async () =>
                    {
                        var hostname = await NetworkUtils.ResolveHostnameAsync(ip);
                        dev.Hostname = hostname;
                    });
                }
            }
            catch { /* Swallow parse errors */ }
        }

        // ----------------------------------------------------------------
        //  Helper: match SharpPcap device to our AdapterInfo
        // ----------------------------------------------------------------
        private static ILiveDevice? FindDevice(CaptureDeviceList devices, AdapterInfo adapter)
        {
            foreach (var dev in devices)
            {
                // Match by GUID in the device name
                if (dev.Name.Contains(adapter.Name, StringComparison.OrdinalIgnoreCase))
                    return dev;
            }
            // Fallback: match by friendly name substring
            foreach (var dev in devices)
            {
                if (dev.Description?.Contains(adapter.FriendlyName, StringComparison.OrdinalIgnoreCase) == true)
                    return dev;
            }
            return null;
        }

        // ----------------------------------------------------------------
        //  IDisposable
        // ----------------------------------------------------------------
        public void Dispose()
        {
            _cts?.Cancel();

        }
    }
}
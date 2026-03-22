using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;
using MyNet.Models;
using MyNet.Helpers;

namespace MyNet.Core
{
    /// <summary>
    /// Performs real-time traffic analysis on intercepted MITM traffic.
    /// Detects TLS SNI (Websites) and tracks PPS (Screen Pulse).
    /// </summary>
    public class IdentitySniffer : IDisposable
    {
        private ILiveDevice? _captureDevice;
        private readonly ConcurrentDictionary<string, NetworkDevice> _monitoredDevices = new();
        private readonly ConcurrentDictionary<string, int> _packetCounts = new();
        private CancellationTokenSource? _pulseCts;

        public void Start(AdapterInfo adapter, System.Collections.Generic.IEnumerable<NetworkDevice> devices)
        {
            foreach (var d in devices) _monitoredDevices[d.IpAddress] = d;

            var deviceList = CaptureDeviceList.Instance;
            _captureDevice = deviceList.FirstOrDefault(d => d.Name.Contains(adapter.Name));
            
            if (_captureDevice == null) return;

            _captureDevice.Open(DeviceModes.Promiscuous, 10);
            // Filter: Only TCP traffic (for SNI) or any IP traffic from monitored IPs
            string filter = "ip";
            _captureDevice.Filter = filter;
            _captureDevice.OnPacketArrival += OnPacketArrival;
            _captureDevice.StartCapture();

            _pulseCts = new CancellationTokenSource();
            _ = Task.Run(() => PulseLoopAsync(_pulseCts.Token));
        }

        private void OnPacketArrival(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket == null) return;

            string srcIp = ipPacket.SourceAddress.ToString();
            
            // 1. Track PPS for Pulse
            if (_monitoredDevices.ContainsKey(srcIp))
            {
                _packetCounts.AddOrUpdate(srcIp, 1, (k, v) => v + 1);
            }

            // 2. Sniff TLS SNI (Port 443)
            var tcpPacket = packet.Extract<TcpPacket>();
            if (tcpPacket != null && tcpPacket.DestinationPort == 443 && tcpPacket.PayloadData?.Length > 40)
            {
                if (_monitoredDevices.TryGetValue(srcIp, out var device))
                {
                    string? domain = TryParseSni(tcpPacket.PayloadData);
                    if (!string.IsNullOrEmpty(domain))
                    {
                        device.ActiveDomain = domain;
                    }
                }
            }
        }

        private async Task PulseLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(1000, ct);
                    foreach (var kvp in _monitoredDevices)
                    {
                        if (_packetCounts.TryRemove(kvp.Key, out int count))
                        {
                            kvp.Value.PacketsPerSecond = count;
                            // Heuristic: > 5 PPS for a mobile device often indicates screen activity / active app
                            kvp.Value.IsScreenOn = count > 5;
                        }
                        else
                        {
                            kvp.Value.PacketsPerSecond = 0;
                            kvp.Value.IsScreenOn = false;
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }

        private string? TryParseSni(byte[] data)
        {
            try
            {
                // TLS Handshake (0x16), Client Hello (0x01)
                if (data[0] != 0x16 || data[5] != 0x01) return null;

                // Simple hunt for SNI extension (0x00 0x00)
                // This is a lightweight 'hardcoded' parser
                for (int i = 40; i < data.Length - 10; i++)
                {
                    if (data[i] == 0x00 && data[i + 1] == 0x00 && data[i + 2] == 0x00) // Extension: server_name
                    {
                        int nameListLen = (data[i + 7] << 8) | data[i + 8];
                        if (nameListLen + i + 9 <= data.Length)
                        {
                            int type = data[i + 9];
                            if (type == 0x00) // Name Type: host_name
                            {
                                int nameLen = (data[i + 10] << 8) | data[i + 11];
                                if (i + 12 + nameLen <= data.Length)
                                {
                                    return Encoding.ASCII.GetString(data, i + 12, nameLen);
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        public void Dispose()
        {
            _pulseCts?.Cancel();
            if (_captureDevice != null)
            {
                _captureDevice.StopCapture();
                _captureDevice.Close();
                _captureDevice = null;
            }
        }
    }
}

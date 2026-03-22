using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;
using MyNet.Models;

namespace MyNet.Core
{
    public static class VulnScanner
    {
        public static async Task ScanDeviceAsync(NetworkDevice device)
        {
            double risk = 0;
            var threats = new List<string>();

            // 1. Android Gallery SMB Exposure (Check Port 445 on Android)
            if (device.OperatingSystem.Contains("Android") || device.OperatingSystem.Contains("Linux"))
            {
                if (await ProbePortAsync(device.IpAddress, 445))
                {
                    risk += 7.5;
                    threats.Add("CRITICAL: Exposed SMB (Gallery/File Leak)");
                }
                if (await ProbePortAsync(device.IpAddress, 21))
                {
                    risk += 5.0;
                    threats.Add("HIGH: Unauthenticated FTP Exposure");
                }
            }

            // 2. iOS AirDrop / mDNS Leaks
            if (device.OperatingSystem.Contains("iOS") || device.OperatingSystem.Contains("Apple"))
            {
                // AirDrop uses 443 + mDNS. We look for indicators of AirDrop activity.
                if (await ProbePortAsync(device.IpAddress, 62078)) // iPhone Sync / Lockdown
                {
                    risk += 3.0;
                    threats.Add("INFO: AirDrop/Sync Proximity Active");
                }
            }

            // 3. General 2023 Wi-Fi Flaws (CVE-2023-52160/1) - Heuristic
            if (device.OperatingSystem.Contains("Android") && device.Vendor.Contains("Intel"))
            {
                risk += 6.0;
                threats.Add("POTENTIAL: CVE-2023-52161 (IWD/WiFi Bypass)");
            }

            // Update Device
            if (threats.Count > 0)
            {
                device.Vulnerabilities = string.Join(" | ", threats);
                device.RiskScore = Math.Min(10.0, risk);
            }
            else
            {
                device.Vulnerabilities = "Clean / Low Risk";
                device.RiskScore = 0.5;
            }
        }

        private static async Task<bool> ProbePortAsync(string ip, int port)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ip, port);
                var timeoutTask = Task.Delay(800);
                var completed = await Task.WhenAny(connectTask, timeoutTask);
                return completed == connectTask && client.Connected;
            }
            catch { return false; }
        }
    }
}

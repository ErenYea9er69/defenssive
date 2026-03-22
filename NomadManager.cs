using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Win32;
using MyNet.Models;
using MyNet.Helpers;

namespace MyNet.Core
{
    /// <summary>
    /// Orchestrates the 'Nomad Protocol' for bypassing router-level restrictions.
    /// Manages Registry-based MAC spoofing and Netsh-based DNS injection.
    /// </summary>
    public static class NomadManager
    {
        private const string NetworkClassGuid = "{4D36E972-E325-11CE-BFC1-08002BE10318}";

        public static async Task<bool> RotateIdentityAsync(AdapterInfo adapter, Action<string> log)
        {
            try
            {
                log($"[NOMAD] Initializing identity shift for {adapter.FriendlyName}...");
                
                // 1. Generate new MAC
                string newMac = NetworkUtils.GetRandomMac();
                log($"[NOMAD] Generated new Hardware ID: {newMac}");

                // 2. Find Registry Key for this adapter
                string registryPath = FindAdapterRegistryPath(adapter.Name);
                if (string.IsNullOrEmpty(registryPath))
                {
                    log("[NOMAD] ERROR: Could not locate adapter in Windows Registry.");
                    return false;
                }

                // 3. Write new MAC to Registry
                using (var key = Registry.LocalMachine.OpenSubKey(registryPath, true))
                {
                    if (key == null)
                    {
                        log("[NOMAD] ERROR: Registry access denied. Run as Administrator.");
                        return false;
                    }
                    key.SetValue("NetworkAddress", newMac);
                }
                log("[NOMAD] Registry updated with new Hardware ID.");

                // 4. Restart Adapter to apply changes
                log("[NOMAD] Restarting adapter to apply new identity. Connection will drop...");
                byte[] macBytes = NetworkUtils.ParseMac(string.Join(":", Enumerable.Range(0, 6).Select(i => newMac.Substring(i * 2, 2))));
                await NetworkUtils.RestartAdapterAsync(adapter.FriendlyName);
                
                log("[NOMAD] Identity shifted successfully. You are now a new device to the router.");
                return true;
            }
            catch (Exception ex)
            {
                log($"[NOMAD] CRITICAL FAILURE: {ex.Message}");
                return false;
            }
        }

        public static async Task LockdownDnsAsync(AdapterInfo adapter, Action<string> log)
        {
            try
            {
                log($"[NOMAD] Locking down DNS to Cloudflare (1.1.1.1) for {adapter.FriendlyName}...");
                
                var psiPrimary = new System.Diagnostics.ProcessStartInfo("netsh", $"interface ip set dns name=\"{adapter.FriendlyName}\" static 1.1.1.1") { CreateNoWindow = true, UseShellExecute = false };
                var psiSecondary = new System.Diagnostics.ProcessStartInfo("netsh", $"interface ip add dns name=\"{adapter.FriendlyName}\" 8.8.8.8 index=2") { CreateNoWindow = true, UseShellExecute = false };

                await Task.Run(() => {
                    System.Diagnostics.Process.Start(psiPrimary)?.WaitForExit();
                    System.Diagnostics.Process.Start(psiSecondary)?.WaitForExit();
                });

                log("[NOMAD] DNS Lockdown complete. Router-level DNS filters are now bypassed.");
            }
            catch (Exception ex)
            {
                log($"[NOMAD] DNS Lockdown Failed: {ex.Message}");
            }
        }

        private static string FindAdapterRegistryPath(string adapterGuid)
        {
            string basePath = $@"SYSTEM\CurrentControlSet\Control\Class\{NetworkClassGuid}";
            using (var baseKey = Registry.LocalMachine.OpenSubKey(basePath))
            {
                if (baseKey == null) return null;

                foreach (string subKeyName in baseKey.GetSubKeyNames())
                {
                    if (subKeyName.Length != 4) continue; // Skip non-adapter keys

                    using (var subKey = baseKey.OpenSubKey(subKeyName))
                    {
                        if (subKey == null) continue;
                        
                        var instanceId = subKey.GetValue("NetCfgInstanceId") as string;
                        if (string.Equals(instanceId, adapterGuid, StringComparison.OrdinalIgnoreCase))
                        {
                            return $@"{basePath}\{subKeyName}";
                        }
                    }
                }
            }
            return null;
        }
    }
}

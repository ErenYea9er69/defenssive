using Microsoft.Win32;
using System;
using System.IO;
using System.Windows;

namespace MyNet.Core
{
    public static class PersistenceHelper
    {
        private const string AppName = "MyNetPentestHub";

        public static void EnsurePersistence()
        {
            try
            {
                string exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
                if (string.IsNullOrEmpty(exePath)) return;

                // Add to CurrentUser Run key
                using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (key != null)
                    {
                        key.SetValue(AppName, exePath);
                        Console.WriteLine("[PERSISTENCE] Registry 'Run' key updated.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[PERSISTENCE] Failed to set persistence: " + ex.Message);
            }
        }
    }
}

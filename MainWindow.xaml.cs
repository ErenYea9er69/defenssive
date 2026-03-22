using System.Windows;
using System.Windows.Media;
using Brush = System.Windows.Media.Brush;
using System.Windows.Media.Animation;
using MyNet.Models;
using WinForms = System.Windows.Forms;

namespace MyNet.UI
{
    public partial class MainWindow : Window
    {
        private MainViewModel Vm => (MainViewModel)DataContext;
        private WinForms.NotifyIcon? _notifyIcon;
        private bool _isExplicitClose;

        public MainWindow()
        {
            InitializeComponent();
            Loaded  += OnLoaded;
            Closing += OnClosing;
        }

        // ----------------------------------------------------------------
        //  Window events
        // ----------------------------------------------------------------
        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            // Watch IsScanning to animate the status indicator
            Vm.PropertyChanged += (s, ev) =>
            {
                if (ev.PropertyName == nameof(Vm.IsScanning))
                    UpdateScanIndicator(Vm.IsScanning);
            };

            // Auto-scroll log to bottom
            Vm.LogLines.CollectionChanged += (s, e) =>
            {
                if (LogList.Items.Count > 0)
                    LogList.ScrollIntoView(LogList.Items[^1]);
            };

            // Setup System Tray Icon
            _notifyIcon = new WinForms.NotifyIcon
            {
                Icon = System.Drawing.Icon.ExtractAssociatedIcon(System.Reflection.Assembly.GetExecutingAssembly().Location),
                Visible = true,
                Text = "MyNet"
            };

            _notifyIcon.DoubleClick += (s, ev) =>
            {
                this.Show();
                this.WindowState = WindowState.Normal;
                this.Activate();
            };

            var contextMenu = new WinForms.ContextMenuStrip();
            var openItem = contextMenu.Items.Add("Open MyNet");
            openItem.Click += (s, ev) =>
            {
                this.Show();
                this.WindowState = WindowState.Normal;
                this.Activate();
            };

            var exitItem = contextMenu.Items.Add("Exit");
            exitItem.Click += (s, ev) =>
            {
                _isExplicitClose = true;
                this.Close();
            };

            _notifyIcon.ContextMenuStrip = contextMenu;

            UpdateScanIndicator(false);
        }

        private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
        {
            if (!_isExplicitClose)
            {
                e.Cancel = true;
                this.Hide();
                return;
            }

            // Real close
            _notifyIcon?.Dispose();

            // Restore all ARP caches before exiting
            try { Vm.RemoveAllControls(); } catch { /* best effort */ }
            Vm.Dispose();
        }

        // ----------------------------------------------------------------
        //  Toolbar buttons
        // ----------------------------------------------------------------
        private async void BtnScan_Click(object sender, RoutedEventArgs e)
        {
            await Vm.StartScanAsync();
        }

        private async void BtnScanVulns_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
            {
                await vm.ScanVulnsAsync();
            }
        }

        private async void BtnInject_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is NetworkDevice dev && DataContext is MainViewModel vm)
            {
                await vm.InjectPayloadAsync(dev);
            }
        }

        private void BtnStopScan_Click(object sender, RoutedEventArgs e)
        {
            Vm.StopScan();
        }

        private void BtnRestoreAll_Click(object sender, RoutedEventArgs e)
        {
            Vm.RemoveAllControls();
        }

        // ----------------------------------------------------------------
        //  Device selection
        // ----------------------------------------------------------------
        private void DeviceGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            var dev = Vm.SelectedDevice;
            if (dev == null)
            {
                ClearDevicePanel();
                return;
            }

            TxtSelectedIp.Text   = dev.IpAddress;
            TxtSelectedMac.Text  = dev.MacAddress;
            TxtSelectedHost.Text = dev.Hostname;
            TxtBytesSent.Text    = dev.BytesSentText;
            TxtBytesRecv.Text    = dev.BytesReceivedText;

            // Update block button label
            UpdateBlockButtonLabel(dev);

            // Sync sliders with existing limits
            SliderUpload.Value   = dev.UploadLimit;
            SliderDownload.Value = dev.DownloadLimit;

            // Subscribe to property changes to keep stats updated
            dev.PropertyChanged += OnSelectedDeviceChanged;
        }

        private void OnSelectedDeviceChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (sender is not NetworkDevice dev) return;
            Dispatcher.Invoke(() =>
            {
                if (e.PropertyName is nameof(NetworkDevice.BytesSent))
                    TxtBytesSent.Text = dev.BytesSentText;
                if (e.PropertyName is nameof(NetworkDevice.BytesReceived))
                    TxtBytesRecv.Text = dev.BytesReceivedText;
                if (e.PropertyName is nameof(NetworkDevice.IsBlocked))
                    UpdateBlockButtonLabel(dev);
                if (e.PropertyName is nameof(NetworkDevice.Hostname))
                    TxtSelectedHost.Text = dev.Hostname;
            });
        }

        // ----------------------------------------------------------------
        //  Block button
        // ----------------------------------------------------------------
        private async void BtnPhantomAlert_Click(object sender, RoutedEventArgs e)
        {
            if (Vm.SelectedDevice == null) return;

            string msg = "CRITICAL: Remote Terminal Session Initialized. Handshake ID: " + new Random().Next(1000, 9999);
            // In a real app we'd show an InputDialog, but for this 'hardcoded' version we'll use a scary default.
            
            await Vm.SendPhantomAlertAsync(Vm.SelectedDevice, msg);
        }

        private void CheckGhostMode_Changed(object sender, RoutedEventArgs e)
        {
            if (Vm == null || CheckGhostMode == null) return;
            Vm.ToggleGhostMode(CheckGhostMode.IsChecked == true);
        }

        private void BtnBlock_Click(object sender, RoutedEventArgs e)
        {
            if (Vm.SelectedDevice == null) return;
            Vm.ToggleBlock(Vm.SelectedDevice);
            UpdateBlockButtonLabel(Vm.SelectedDevice);
        }

        private void UpdateBlockButtonLabel(NetworkDevice dev)
        {
            if (dev.IsBlocked)
            {
                BtnBlock.Content = "✅ UNBLOCK INTERNET ACCESS";
                BtnBlock.Style   = FindResource("SuccessButton") as System.Windows.Style;
            }
            else
            {
                BtnBlock.Content = "🚫 BLOCK INTERNET ACCESS";
                BtnBlock.Style   = FindResource("DangerButton") as System.Windows.Style;
            }
        }

        // ----------------------------------------------------------------
        //  Bandwidth sliders
        // ----------------------------------------------------------------
        private void SliderUpload_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (TxtUploadVal == null) return;
            int val = (int)e.NewValue;
            TxtUploadVal.Text = val == 0 ? "Unlimited" : $"{val} kbps";
        }

        private void SliderDownload_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (TxtDownloadVal == null) return;
            int val = (int)e.NewValue;
            TxtDownloadVal.Text = val == 0 ? "Unlimited" : $"{val} kbps";
        }

        private void BtnApplyBandwidth_Click(object sender, RoutedEventArgs e)
        {
            // Bandwidth limiting is removed in this version in favor of Ghost Mode (Shadowing).
        }

        private void BtnRemoveLimits_Click(object sender, RoutedEventArgs e)
        {
            // Bandwidth limiting is removed in this version in favor of Ghost Mode (Shadowing).
        }

        private async void BtnDiagnostics_Click(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
            {
                await vm.RunDiagnosticsAsync();
            }
        }

        // ----------------------------------------------------------------
        //  Helpers
        // ----------------------------------------------------------------
        private void ClearDevicePanel()
        {
            TxtSelectedIp.Text   = "—";
            TxtSelectedMac.Text  = "—";
            TxtSelectedHost.Text = "—";
            TxtBytesSent.Text    = "0 B";
            TxtBytesRecv.Text    = "0 B";
        }

        private void UpdateScanIndicator(bool scanning)
        {
            if (scanning)
            {
                ScanIndicator.Fill     = (Brush)FindResource("BrushAccentGreen");
                TxtScanStatus.Text     = "SCANNING…";
                TxtScanStatus.Foreground = (Brush)FindResource("BrushAccentGreen");

                // Pulse animation
                var anim = new DoubleAnimation(0.3, 1.0, TimeSpan.FromMilliseconds(600))
                {
                    AutoReverse = true,
                    RepeatBehavior = RepeatBehavior.Forever
                };
                ScanIndicator.BeginAnimation(UIElement.OpacityProperty, anim);
            }
            else
            {
                ScanIndicator.BeginAnimation(UIElement.OpacityProperty, null);
                ScanIndicator.Opacity  = 1;
                ScanIndicator.Fill     = (Brush)FindResource("BrushTextSecondary");
                TxtScanStatus.Text     = "IDLE";
                TxtScanStatus.Foreground = (Brush)FindResource("BrushTextSecondary");
            }
        }
        private async void BtnRotateIdentity_Click(object sender, RoutedEventArgs e)
        {
            if (System.Windows.MessageBox.Show("Rotating your identity will temporarily drop your internet connection for 2-5 seconds. Continue?", 
                "Nomad Protocol", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes)
            {
                await Vm.RotateIdentityAsync();
            }
        }

        private async void BtnLockdownDns_Click(object sender, RoutedEventArgs e)
        {
            await Vm.LockdownDnsAsync();
        }
    }
}

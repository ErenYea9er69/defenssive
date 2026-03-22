using System.ComponentModel;
using System.Net;
using System.Runtime.CompilerServices;

namespace MyNet.Models
{
    /// <summary>
    /// Represents a device discovered on the local network.
    /// Implements INotifyPropertyChanged so the DataGrid updates in real time.
    /// </summary>
    public class NetworkDevice : INotifyPropertyChanged
    {
        // ----------------------------------------------------------------
        //  Backing fields
        // ----------------------------------------------------------------
        private string _ipAddress = string.Empty;
        private string _macAddress = "00:00:00:00:00:00";
        private string _hostname = "Unknown";
        private string _deviceName = "—";
        private string _vendor = "Unknown Vendor";
        private string _operatingSystem = "Calculating…";
        private string _services = "—";
        private string _scanDetails = "Ready";
        private string _vulnerabilities = "None Detected";
        private double _riskScore;
        private string _activeDomain = "—";
        private bool _isScreenOn;
        private int _packetsPerSecond;
        private bool _isBlocked;
        private int _uploadLimit;    // kbps, 0 = unlimited
        private int _downloadLimit;  // kbps, 0 = unlimited
        private long _bytesSent;
        private long _bytesReceived;
        private string _status = "Online";

        // Performance tracking for rate limiting
        private long _sentWindow;
        private long _receivedWindow;
        private DateTime _lastTick = DateTime.UtcNow;
        private double _bytesSentPerSecond;
        private double _bytesReceivedPerSecond;

        // ----------------------------------------------------------------
        //  Properties
        // ----------------------------------------------------------------
        public string IpAddress
        {
            get => _ipAddress;
            set { _ipAddress = value; OnPropertyChanged(); }
        }

        public string MacAddress
        {
            get => _macAddress;
            set { _macAddress = value; OnPropertyChanged(); }
        }

        public string Hostname
        {
            get => _hostname;
            set { _hostname = value; OnPropertyChanged(); }
        }
        
        public string DeviceName { get => _deviceName; set { _deviceName = value; OnPropertyChanged(); } }
        
        public string Vendor
        {
            get => _vendor;
            set { _vendor = value; OnPropertyChanged(); }
        }
        
        public string OperatingSystem { get => _operatingSystem; set { _operatingSystem = value; OnPropertyChanged(); } }

        public string Services { get => _services; set { _services = value; OnPropertyChanged(); } }

        public string ScanDetails { get => _scanDetails; set { _scanDetails = value; OnPropertyChanged(); } }

        public string Vulnerabilities { get => _vulnerabilities; set { _vulnerabilities = value; OnPropertyChanged(); } }

        public double RiskScore { get => _riskScore; set { _riskScore = value; OnPropertyChanged(); } }

        public string ActiveDomain { get => _activeDomain; set { _activeDomain = value; OnPropertyChanged(); } }

        public bool IsScreenOn { get => _isScreenOn; set { _isScreenOn = value; OnPropertyChanged(); OnPropertyChanged(nameof(StatusText)); } }

        public int PacketsPerSecond { get => _packetsPerSecond; set { _packetsPerSecond = value; OnPropertyChanged(); } }

        public bool IsBlocked
        {
            get => _isBlocked;
            set
            {
                _isBlocked = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusText));
            }
        }

        /// <summary>Upload limit in kbps. 0 means unlimited.</summary>
        public int UploadLimit
        {
            get => _uploadLimit;
            set { _uploadLimit = value; OnPropertyChanged(); OnPropertyChanged(nameof(UploadLimitText)); }
        }

        /// <summary>Download limit in kbps. 0 means unlimited.</summary>
        public int DownloadLimit
        {
            get => _downloadLimit;
            set { _downloadLimit = value; OnPropertyChanged(); OnPropertyChanged(nameof(DownloadLimitText)); }
        }

        public long BytesSent
        {
            get => _bytesSent;
            set 
            { 
                var delta = value - _bytesSent;
                _bytesSent = value; 
                _sentWindow += delta;
                UpdateThroughput();
                OnPropertyChanged(); 
                OnPropertyChanged(nameof(BytesSentText)); 
            }
        }

        public long BytesReceived
        {
            get => _bytesReceived;
            set 
            { 
                var delta = value - _bytesReceived;
                _bytesReceived = value; 
                _receivedWindow += delta;
                UpdateThroughput();
                OnPropertyChanged(); 
                OnPropertyChanged(nameof(BytesReceivedText)); 
            }
        }

        public double BytesSentPerSecond => _bytesSentPerSecond; // in kbps
        public double BytesReceivedPerSecond => _bytesReceivedPerSecond; // in kbps

        private void UpdateThroughput()
        {
            var now = DateTime.UtcNow;
            var elapsed = (now - _lastTick).TotalSeconds;
            if (elapsed >= 0.5) // Update every 500ms
            {
                // Convert bytes to kilobits: (bytes * 8) / 1024
                _bytesSentPerSecond = (_sentWindow * 8.0) / 1024.0 / elapsed;
                _bytesReceivedPerSecond = (_receivedWindow * 8.0) / 1024.0 / elapsed;
                
                _sentWindow = 0;
                _receivedWindow = 0;
                _lastTick = now;
                
                OnPropertyChanged(nameof(BytesSentPerSecond));
                OnPropertyChanged(nameof(BytesReceivedPerSecond));
            }
        }

        public string Status
        {
            get => _status;
            set { _status = value; OnPropertyChanged(); OnPropertyChanged(nameof(StatusText)); }
        }

        // ----------------------------------------------------------------
        //  Computed / display helpers
        // ----------------------------------------------------------------
        public string UploadLimitText   => UploadLimit   == 0 ? "Unlimited" : $"{UploadLimit} kbps";
        public string DownloadLimitText => DownloadLimit == 0 ? "Unlimited" : $"{DownloadLimit} kbps";
        public string BytesSentText     => FormatBytes(BytesSent);
        public string BytesReceivedText => FormatBytes(BytesReceived);

        public string StatusText
        {
            get
            {
                if (IsBlocked) return "BLOCKED";
                return Status;
            }
        }

        // ----------------------------------------------------------------
        //  INotifyPropertyChanged
        // ----------------------------------------------------------------
        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string? name = null)
        {
            if (System.Windows.Application.Current?.Dispatcher.CheckAccess() == true)
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
            else
                System.Windows.Application.Current?.Dispatcher.Invoke(() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name)));
        }

        // ----------------------------------------------------------------
        //  Helpers
        // ----------------------------------------------------------------
        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024)       return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes / (1024.0 * 1024):F1} MB";
        }

        public override string ToString() => $"{IpAddress} ({MacAddress})";
    }
}
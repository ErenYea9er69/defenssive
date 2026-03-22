using System.Windows;
using MessageBox = System.Windows.MessageBox;

namespace MyNet
{
    public partial class App : System.Windows.Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Global unhandled exception handler
            DispatcherUnhandledException += (s, ex) =>
            {
                MessageBox.Show(
                    $"Unhandled error:\n{ex.Exception.Message}",
                    "MyNet — Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                ex.Handled = true;
            };
        }
    }
}

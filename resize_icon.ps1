Add-Type -AssemblyName System.Drawing
$srcPath = "C:\Users\bmh\.gemini\antigravity\brain\4f4bf3e2-9300-446a-b898-8a434eb72971\straw_hat_network_logo_1774113449226.png"
$outPath = "C:\Users\bmh\Desktop\selfishnet\icon.ico"

$srcImg = [System.Drawing.Image]::FromFile($srcPath)
$bmp = New-Object System.Drawing.Bitmap($srcImg, 128, 128)
$srcImg.Dispose()

$hIcon = $bmp.GetHicon()
$icon = [System.Drawing.Icon]::FromHandle($hIcon)
$fs = [System.IO.FileStream]::new($outPath, [System.IO.FileMode]::Create)
$icon.Save($fs)
$fs.Close()
$icon.Dispose()
$bmp.Dispose()

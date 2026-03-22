$pngPath = $args[0]
$outPath = $args[1]
$png = [System.IO.File]::ReadAllBytes($pngPath)
$fs = [System.IO.FileStream]::new($outPath, [System.IO.FileMode]::Create)
$bw = [System.IO.BinaryWriter]::new($fs)
$bw.Write([short]0); $bw.Write([short]1); $bw.Write([short]1)
$bw.Write([byte]0); $bw.Write([byte]0); $bw.Write([byte]0); $bw.Write([byte]0)
$bw.Write([short]1); $bw.Write([short]32)
$bw.Write([int]$png.Length); $bw.Write([int]22)
$bw.Write($png)
$bw.Close(); $fs.Close()

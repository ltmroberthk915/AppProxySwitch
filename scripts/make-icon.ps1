# Generate resources\AppProxySwitch.ico using classic BITMAP-format entries
# (32bpp BGRA + zero AND-mask) instead of PNG-compressed entries, for maximum
# Explorer/shell compatibility on every Windows build.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$out = Join-Path $PSScriptRoot '..\resources\AppProxySwitch.ico'
$sizes = @(256, 48, 32, 16)

function New-Bitmap([int]$s) {
    $bmp = New-Object System.Drawing.Bitmap($s, $s, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)

    # Bright rounded-square background (deep blue).
    $bg = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 30, 58, 138))
    $r = [Math]::Max(2, [int]($s * 0.20))
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $r * 2
    $path.AddArc(0, 0, $d, $d, 180, 90)
    $path.AddArc($s - $d, 0, $d, $d, 270, 90)
    $path.AddArc($s - $d, $s - $d, $d, $d, 0, 90)
    $path.AddArc(0, $s - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    $g.FillPath($bg, $path)

    # Two arrows: white down (traffic in), mint up (proxied out).
    $w = [Math]::Max(2, [int]($s * 0.10))
    $penW = New-Object System.Drawing.Pen([System.Drawing.Color]::White, $w)
    $penG = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 52, 211, 153), $w)
    foreach ($p in @($penW, $penG)) {
        $p.StartCap = 'Round'; $p.EndCap = 'ArrowAnchor'
        $p.Alignment = [System.Drawing.Drawing2D.PenAlignment]::Center
    }
    $g.DrawLine($penW, [double]($s * 0.33), [double]($s * 0.30), [double]($s * 0.33), [double]($s * 0.70))
    $g.DrawLine($penG, [double]($s * 0.67), [double]($s * 0.70), [double]($s * 0.67), [double]($s * 0.30))
    $g.Dispose()
    return ,$bmp
}

# Returns the raw BGRA pixels of a bitmap, bottom-up as required by BMP.
function Get-Pixels($bmp) {
    $rect = New-Object System.Drawing.Rectangle(0, 0, $bmp.Width, $bmp.Height)
    $data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
                           [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $bytes = New-Object byte[] ($data.Stride * $data.Height)
    [System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $bytes, 0, $bytes.Length)
    $bmp.UnlockBits($data)
    # Strip any row padding (Stride may exceed w*4) and ensure BGRA ordering
    # (Format32bppArgb in memory is BGRA on little-endian, which is what ICO wants).
    $w = $bmp.Width; $h = $bmp.Height
    $outBytes = New-Object byte[] ($w * 4 * $h)
    for ($y = 0; $y -lt $h; ++$y) {
        [Array]::Copy($bytes, $y * $data.Stride, $outBytes, ($h - 1 - $y) * $w * 4, $w * 4)
    }
    return ,$outBytes
}

$entries = @()
foreach ($s in $sizes) {
    $bmp = New-Bitmap $s
    $px = Get-Pixels $bmp
    $bmp.Dispose()
    $andStride = (([int](($s + 31) / 32)) * 4)   # 1bpp rows padded to 32 bits
    $andSize = $andStride * $s
    # BITMAPINFOHEADER for an ICO image: height counts XOR + AND rows.
    $hdr = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($hdr)
    $bw.Write([UInt32]40)             # biSize
    $bw.Write([Int32]$s)              # biWidth
    $bw.Write([Int32]($s * 2))        # biHeight (XOR + AND)
    $bw.Write([UInt16]1)              # biPlanes
    $bw.Write([UInt16]32)             # biBitCount
    $bw.Write([UInt32]0)              # biCompression
    $bw.Write([UInt32]($s * 4 * $s + $andSize))  # biSizeImage (XOR + AND)
    $bw.Write([Int32]0); $bw.Write([Int32]0)   # ppm
    $bw.Write([UInt32]0); $bw.Write([UInt32]0) # palette
    $bw.Flush()
    # AND mask: all zero (alpha channel does the work).
    $and = New-Object byte[] ($andSize)
    $entries += ,@($hdr.ToArray(), $px, $and)
}

# Assemble the ICO container.
$ms = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($ms)
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; ++$i) {
    $s = $sizes[$i]
    $len = $entries[$i][0].Length + $entries[$i][1].Length + $entries[$i][2].Length
    $dim = if ($s -ge 256) { 0 } else { $s }
    $bw.Write([Byte]$dim); $bw.Write([Byte]$dim); $bw.Write([Byte]0); $bw.Write([Byte]0)
    $bw.Write([UInt16]1); $bw.Write([UInt16]32)
    $bw.Write([UInt32]$len); $bw.Write([UInt32]$offset)
    $offset += $len
}
foreach ($e in $entries) {
    $bw.Write($e[0]); $bw.Write($e[1]); $bw.Write($e[2])
}
$bw.Flush()
[System.IO.File]::WriteAllBytes((Join-Path (Split-Path -Parent $out) 'AppProxySwitch.ico'), $ms.ToArray())
Write-Host "Icon written: resources\AppProxySwitch.ico ($($ms.Length) bytes, BMP format)"

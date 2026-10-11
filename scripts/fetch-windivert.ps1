# Fetch the official WinDivert release with SHA-256 verification.
#
# Only ever downloads from the official basil00/WinDivert GitHub release page.
# Version and hash are pinned. To upgrade WinDivert:
#   1. Verify the new release at https://github.com/basil00/WinDivert/releases
#   2. Run: powershell -File scripts\fetch-windivert.ps1 -ReplaceHash <sha256>
#      (or run with -PrintHash after downloading manually and update below)
#   3. Update $Version / $Sha256 in this file and LICENSES\NOTICE.md.
[CmdletBinding()]
param(
    [switch]$PrintHash,
    [string]$ReplaceHash = ''   # explicitly override the pinned hash (supply chain change!)
)

$ErrorActionPreference = 'Stop'

# ---- pinned release metadata -------------------------------------------------
$Version  = '2.2.2'
$ZipName  = "WinDivert-$Version-A.zip"
$Sha256   = '63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15'
$Url      = "https://github.com/basil00/WinDivert/releases/download/v$Version/$ZipName"
# ------------------------------------------------------------------------------

if ($ReplaceHash -ne '') { $Sha256 = $ReplaceHash.ToLowerInvariant() }

$root     = Split-Path -Parent $PSScriptRoot   # repo root
$destDir  = Join-Path $root 'third_party\windivert'
$zipPath  = Join-Path $destDir $ZipName

New-Item -ItemType Directory -Force -Path $destDir | Out-Null

if (-not (Test-Path $zipPath)) {
    Write-Host "Downloading $Url"
    # Use TLS 1.2 and the .NET downloader so we get a proper error on failure.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-WebRequest -Uri $Url -OutFile $zipPath -UseBasicParsing
    } catch {
        throw "Download failed: $($_.Exception.Message). If GitHub is unreachable, download $ZipName manually from $Url into $destDir and re-run."
    }
}

$actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($PrintHash) { Write-Host "SHA256($ZipName) = $actual" }
if ($actual -ne $Sha256) {
    throw "SHA-256 mismatch!`nExpected: $Sha256`nActual:   $actual`nRefusing to use this file. Delete it and investigate."
}
Write-Host "SHA-256 verified: $actual"

# ---- extract & normalize layout ----------------------------------------------
function Remove-ExtractionDirectory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = (Resolve-Path -LiteralPath $Path).ProviderPath
    $allowed = [IO.Path]::GetFullPath((Join-Path $destDir '_extract'))
    if (-not [string]::Equals($resolved, $allowed, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to remove an unexpected extraction directory.'
    }
    if ((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Refusing to remove an extraction directory link.'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

$tmp = Join-Path $destDir '_extract'
Remove-ExtractionDirectory $tmp
Expand-Archive -Path $zipPath -DestinationPath $tmp -Force

$src = Get-ChildItem -Path $tmp -Recurse -Filter 'WinDivert64.sys' |
       Where-Object { $_.Directory.Name -match '^(x64|amd64)$' } |
       Select-Object -First 1
if (-not $src) { throw 'Could not find x64/WinDivert64.sys inside the archive (unexpected layout).' }
$binDir = $src.Directory.FullName   # e.g. ...\WinDivert-2.2.2-A\x64

New-Item -ItemType Directory -Force -Path (Join-Path $destDir 'include') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $destDir 'bin\x64')  | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $destDir 'lib\x64')  | Out-Null

$pkgRoot = Split-Path -Parent $binDir
Copy-Item (Join-Path $pkgRoot 'include\windivert.h') (Join-Path $destDir 'include\windivert.h') -Force
Copy-Item (Join-Path $binDir 'WinDivert.dll')    (Join-Path $destDir 'bin\x64\WinDivert.dll')    -Force
Copy-Item (Join-Path $binDir 'WinDivert64.sys')  (Join-Path $destDir 'bin\x64\WinDivert64.sys')  -Force
Copy-Item (Join-Path $binDir 'WinDivert.lib')    (Join-Path $destDir 'lib\x64\WinDivert.lib')    -Force

$licSrc = Get-ChildItem -Path $pkgRoot -Filter 'LICENSE' | Select-Object -First 1
if ($licSrc) {
    New-Item -ItemType Directory -Force -Path (Join-Path $root 'LICENSES') | Out-Null
    Copy-Item $licSrc.FullName (Join-Path $root 'LICENSES\WinDivert-LICENSE.txt') -Force
    Write-Host 'Copied WinDivert LICENSE to LICENSES\WinDivert-LICENSE.txt'
}

Set-Content -Path (Join-Path $destDir 'VERSION.txt') -Value "WinDivert $Version (official release, SHA-256 verified: $actual)"
Remove-ExtractionDirectory $tmp
Write-Host "WinDivert $Version ready under third_party\windivert"

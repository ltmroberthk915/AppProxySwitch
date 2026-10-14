# Assemble the distributable folder + zip. Usage: powershell -ExecutionPolicy Bypass -File package-release.ps1
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

$buildOut = Join-Path $root 'build\release\Release'
$exe = Join-Path $buildOut 'AppProxySwitch.exe'
if (-not (Test-Path $exe)) {
    throw "Release build not found ($exe). Run build-release.ps1 first."
}

$version = (Get-Item $exe).VersionInfo.ProductVersion
if (-not $version) { $version = '1.0.0' }
$distRoot = Join-Path $root 'dist'
$dist = Join-Path $distRoot "AppProxySwitch-$version-win-x64"
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Force -Path $dist | Out-Null

# --- main program -------------------------------------------------------------
Copy-Item $exe $dist

# --- WinDivert runtime (official, unmodified) ----------------------------------
$wd = Join-Path $root 'third_party\windivert\bin\x64'
Copy-Item (Join-Path $wd 'WinDivert.dll')   $dist
Copy-Item (Join-Path $wd 'WinDivert64.sys') $dist

# --- docs & config --------------------------------------------------------------
Copy-Item (Join-Path $root 'config.example.json') $dist
New-Item -ItemType Directory -Force -Path (Join-Path $dist 'scripts') | Out-Null
Copy-Item (Join-Path $root 'scripts\diagnose-business-route.ps1') (Join-Path $dist 'scripts')
Copy-Item (Join-Path $root 'scripts\diagnose-kernel-controller.ps1') (Join-Path $dist 'scripts')
Copy-Item (Join-Path $root 'scripts\aps-route-evidence.ps1') (Join-Path $dist 'scripts')
Copy-Item (Join-Path $root 'scripts\enable-codex-domain-policy.ps1') (Join-Path $dist 'scripts')
foreach ($doc in @('README.md', 'README.en.md')) {
    $p = Join-Path $root $doc
    if (Test-Path $p) { Copy-Item $p $dist }
}
# Ship only this version's release notes, not private operational handovers.
$releaseVersion = ([Version]$version).ToString(3)
$releaseNotes = Get-ChildItem -LiteralPath (Join-Path $root 'docs') -File |
    Where-Object { $_.Name -like ("RELEASE-$releaseVersion-*.md") }
if ($releaseNotes) {
    $notesDir = Join-Path $dist 'docs'
    New-Item -ItemType Directory -Force -Path $notesDir | Out-Null
    $releaseNotes | Copy-Item -Destination $notesDir
}
# Any top-level *.txt (e.g. the quick-start guide) ships too. (Matched by
# wildcard: this script is ASCII so PowerShell 5.1 reads it correctly.)
Get-ChildItem -Path $root -File -Filter '*.txt' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ne 'CMakeLists.txt' } |
    Copy-Item -Destination $dist -Force
Copy-Item (Join-Path $root 'LICENSE') $dist
New-Item -ItemType Directory -Force -Path (Join-Path $dist 'LICENSES') | Out-Null
Copy-Item (Join-Path $root 'LICENSES\WinDivert-LICENSE.txt') (Join-Path $dist 'LICENSES') -Force
Copy-Item (Join-Path $root 'LICENSES\NOTICE.md') (Join-Path $dist 'LICENSES') -Force

# --- zip -------------------------------------------------------------------------
$zip = Join-Path $distRoot "AppProxySwitch-$version-win-x64.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path (Join-Path $dist '*') -DestinationPath $zip

Write-Host "Packaged: $zip"
Get-ChildItem $dist | ForEach-Object { Write-Host ("  " + $_.Name) }

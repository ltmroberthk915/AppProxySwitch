# Build the Inno Setup installer. Requires the distributable folder first
# (package-release.ps1) and Inno Setup 6 anywhere discoverable.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

# Version is read from the built exe (same source as package-release.ps1).
$buildExe = Join-Path $root 'build\release\Release\AppProxySwitch.exe'
if (-not (Test-Path $buildExe)) { throw "Release build missing. Run build-release.ps1 first." }
$version = (Get-Item $buildExe).VersionInfo.ProductVersion
if (-not $version) { $version = '1.1.0' }

$dist = Join-Path $root "dist\AppProxySwitch-$version-win-x64"
if (-not (Test-Path (Join-Path $dist 'AppProxySwitch.exe'))) {
    throw "Distributable missing. Run package-release.ps1 first."
}

$iscc = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
if (-not $iscc) {
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe'))
    foreach ($c in $candidates) {
        if (Test-Path $c) { $iscc = $c; break }
    }
}
if (-not $iscc) { throw 'Inno Setup 6 not found (winget install JRSoftware.InnoSetup).' }
Write-Host "Using ISCC: $iscc"

& $iscc (Join-Path $root 'installer\installer.iss')
if ($LASTEXITCODE -ne 0) { throw "ISCC failed ($LASTEXITCODE)." }
$setupName = 'AppProxySwitch-Setup-' + $version.Substring(0, $version.LastIndexOf('.')) + '-x64.exe'
Write-Host "`nInstaller: dist\$setupName"

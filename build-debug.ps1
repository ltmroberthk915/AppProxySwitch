# Build Debug x64. Usage: powershell -ExecutionPolicy Bypass -File build-debug.ps1
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

# Locate CMake: PATH -> tools\ (portable) -> VS-bundled
function Find-CMake {
    $cmd = Get-Command cmake -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $portable = Get-ChildItem -Path (Join-Path $root 'tools') -Filter 'cmake.exe' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'bin\\cmake\.exe$' } | Select-Object -First 1
    if ($portable) { return $portable.FullName }
    $vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products '*' `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($vs) {
        $bundled = Get-ChildItem -Path (Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe') -ErrorAction SilentlyContinue
        if ($bundled) { return $bundled.FullName }
    }
    throw 'CMake not found. Install VS2022 Build Tools with the C++ workload, or place a portable CMake under tools\.'
}

$cmake = Find-CMake
Write-Host "Using CMake: $cmake"

if (-not (Test-Path (Join-Path $root 'third_party\windivert\include\windivert.h'))) {
    Write-Host 'WinDivert missing, fetching...'
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'scripts\fetch-windivert.ps1')
}

& $cmake --preset debug
if ($LASTEXITCODE -ne 0) { throw "Configure failed ($LASTEXITCODE)." }
& $cmake --build --preset debug --config Debug
if ($LASTEXITCODE -ne 0) { throw "Build failed ($LASTEXITCODE)." }
Write-Host "`nDebug build OK -> build\debug\Debug\AppProxySwitch.exe"

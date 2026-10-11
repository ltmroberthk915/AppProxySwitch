# Run ctest with label filtering. Usage:
#   powershell -File scripts\run-tests.ps1              # unit + integration
#   powershell -File scripts\run-tests.ps1 -Labels windivert
#   powershell -File scripts\run-tests.ps1 -Labels "unit|integration|windivert"
param(
    [string]$Labels = 'unit|integration',
    [string]$Config = 'Debug'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$testDir = Join-Path $root "build\debug"
if ($Config -eq 'Release') { $testDir = Join-Path $root "build\release" }
if (-not (Test-Path (Join-Path $testDir 'CTestTestfile.cmake'))) {
    throw "No CTest files under $testDir - build first (build-debug.ps1 / build-release.ps1)."
}
# Locate ctest: PATH -> portable tools\ -> VS-bundled CMake.
$ctest = (Get-Command ctest -ErrorAction SilentlyContinue).Source
if (-not $ctest) {
    $portable = Get-ChildItem -Path (Join-Path $root 'tools') -Filter 'ctest.exe' -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'bin\\ctest\.exe$' } | Select-Object -First 1
    if ($portable) { $ctest = $portable.FullName }
}
if (-not $ctest) {
    $vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products '*' -property installationPath 2>$null
    if ($vs) {
        $bundled = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe'
        if (Test-Path $bundled) { $ctest = $bundled }
    }
}
if (-not $ctest) { throw 'ctest not found (install CMake or keep tools\ portable copy).' }
Write-Host "ctest dir=$testDir config=$Config labels=$Labels"
& $ctest --test-dir $testDir -C $Config -L $Labels --output-on-failure
exit $LASTEXITCODE

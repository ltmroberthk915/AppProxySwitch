[CmdletBinding()]
param(
    [string]$Program = (Join-Path $env:LOCALAPPDATA 'Programs\AppProxySwitch\AppProxySwitch.exe'),
    [string]$ConfigPath
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Program -PathType Leaf)) { throw 'APS executable not found.' }
$version = [Version](Get-Item -LiteralPath $Program).VersionInfo.ProductVersion
if ($version -lt [Version]'1.3.2.0') { throw 'Install APS 1.3.2 or newer before applying this policy.' }
$arguments = @('--tls-domain-allow', 'chatgpt.com', '--tls-domain-allow', '*.chatgpt.com',
               '--tls-domain-allow', 'openai.com', '--tls-domain-allow', '*.openai.com')
if ($ConfigPath) { $arguments += @('--config', $ConfigPath) }
# Windows argument quoting only; no shell invocation or constructed commands.
$quoted = @($arguments | ForEach-Object {
    if ($_.Contains('"') -or $_.EndsWith('\')) { throw 'Unsupported argument path.' }
    '"' + $_ + '"'
})
$process = Start-Process -FilePath $Program -ArgumentList $quoted -WindowStyle Hidden -PassThru
if (-not $process.WaitForExit(8000)) { throw 'APS policy command did not exit; no process was stopped.' }
$process.Refresh()
$exitCode = $process.ExitCode
$process.Dispose()
if ($exitCode -eq 3) { throw 'Exit the APS GUI normally, apply this policy, then start APS again. No settings were changed.' }
if ($exitCode -ne 0) { throw ('APS refused the policy update (exit ' + $exitCode + '). No engine was started.') }
'Codex TLS domain policy enabled for new APS proxy connections. Existing routing and node preferences are preserved.'

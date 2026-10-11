$ErrorActionPreference = 'Stop'
$apsDiagnosticScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\diagnose-business-route.ps1'
$global:apsDiagnosticMode = 'global'
$global:apsDiagnosticCalls = @()
$global:apsCurlCalls = @()
function Assert-Aps([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Get-Command {
    [CmdletBinding()]param([string]$Name)
    Assert-Aps ($Name -eq 'curl.exe') 'Unexpected command'
    return [pscustomobject]@{ Source = {
        $global:apsCurlCalls += ,@($args)
        $global:LASTEXITCODE = 28
        '000|0.001|0.000|0.000|5.000'
    } }
}
function Invoke-WebRequest {
    [CmdletBinding()]param([switch]$UseBasicParsing, [string]$Uri, $Headers, $WebSession, [int]$TimeoutSec, [int]$MaximumRedirection)
    Assert-Aps ($Uri.StartsWith('http://127.0.0.1:39876/')) 'Non-local controller request'
    Assert-Aps ($TimeoutSec -eq 3 -and $MaximumRedirection -eq 0) 'Controller bounds or redirect policy changed'
    Assert-Aps ($WebSession.Proxy.IsBypassed([Uri]$Uri)) 'Controller uses system proxy'
    $global:apsDiagnosticCalls += $Uri
    $apsPayload = switch ([Uri]$Uri | Select-Object -ExpandProperty AbsolutePath) {
        '/configs' { @{ mode = $global:apsDiagnosticMode; secret = 'private-controller-value'; tun = @{ enable = $true } } }
        '/proxies' { @{ proxies = @{ GLOBAL = @{ now = 'PRIVATE-GROUP'; type = 'Selector' }; 'PRIVATE-GROUP' = @{ now = 'PRIVATE-NODE'; type = 'Selector' }; 'PRIVATE-NODE' = @{ type = 'Shadowsocks' } } } }
        '/connections' { @{ connections = @(
            @{ metadata = @{ processPath = 'C:\Private\AppProxySwitch.exe'; host = 'chatgpt.com'; sourcePort = '56722' }; rule = 'DomainSuffix'; rulePayload = 'PRIVATE-RULE'; chains = @('PRIVATE-NODE','PRIVATE-GROUP') },
            @{ metadata = @{ processPath = 'C:\Private\AppProxySwitch.exe'; host = 'ab.chatgpt.com'; sourcePort = '56723' }; rule = 'Match'; chains = @('DIRECT') },
            @{ metadata = @{ processPath = 'C:\Private\Other.exe'; host = 'chatgpt.com' }; chains = @('SECRET-OTHER') },
            @{ metadata = @{ processPath = 'C:\Private\AppProxySwitch.exe'; host = 'private.invalid' }; chains = @('SECRET-OTHER') }
        ) } }
        default { throw 'Unexpected controller endpoint' }
    }
    return [pscustomobject]@{ Content = ($apsPayload | ConvertTo-Json -Depth 10 -Compress) }
}
foreach ($apsTestMode in @('global','rule','direct')) {
    $global:apsDiagnosticMode = $apsTestMode
    $apsText = (& $apsDiagnosticScript -Port 7897 -ControllerPort 39876) -join "`n"
    $apsData = $apsText | ConvertFrom-Json
    Assert-Aps ($apsData.controller.mode -eq $apsTestMode) 'Mode missing'
    Assert-Aps ($apsData.https.Count -eq 2 -and $apsData.https[0].curl_exit -eq 28 -and -not $apsData.https[0].tls_completed) 'SOCKS response incorrectly implies TLS success'
    Assert-Aps ($apsData.aps_openai_chains.Count -eq 2) 'Connection scope incorrect'
    Assert-Aps ($apsData.aps_openai_chains[1].chains[0] -eq 'DIRECT') 'DIRECT evidence lost'
    Assert-Aps ($apsText -notmatch 'PRIVATE-|private-controller-value|SECRET-OTHER|C:\\Private') 'Private metadata leaked'
    Assert-Aps ($apsData.controller.global_selection_verified -eq ($apsTestMode -eq 'global')) 'GLOBAL used outside global mode'
}
foreach ($apsArgs in $global:apsCurlCalls) {
    Assert-Aps ($apsArgs[0] -eq '-q') 'curl config not disabled'
    Assert-Aps ($apsArgs -contains 'socks5h://127.0.0.1:7897') 'Proxy mismatch'
    Assert-Aps ($apsArgs -contains 'invalid-bypass.aps.invalid') 'Environment bypass not overridden'
    Assert-Aps ($apsArgs -contains 'NUL' -and $apsArgs -contains '--max-time') 'Probe bounds/content discard missing'
    Assert-Aps (-not ($apsArgs -contains '--insecure') -and -not ($apsArgs -contains '--location')) 'TLS or redirect safety changed'
}
$global:apsCurlCalls = @()
$apsNoHttps = & $apsDiagnosticScript -Port 7897 -SkipHttps | ConvertFrom-Json
Assert-Aps ($global:apsCurlCalls.Count -eq 0 -and $apsNoHttps.https.Count -eq 0) 'SkipHttps sends requests'
'Business diagnostic: mocked controller and curl checks passed; no network requests.'

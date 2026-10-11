# Windows PowerShell 5.1. Read-only controller GETs and bounded unauthenticated
# HTTPS probes through the chosen SOCKS port. No restart/settings/DNS changes.
[CmdletBinding()]
param(
    [ValidateRange(1,65535)][int]$Port = 7897,
    [ValidateRange(0,65535)][int]$ControllerPort = 0,
    [switch]$AskControllerSecret,
    [switch]$SkipHttps
)
$ErrorActionPreference = 'Stop'
$apsHeaders = @{}
$apsLocalSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
# An empty proxy object explicitly bypasses the machine's system proxy.
$apsLocalSession.Proxy = New-Object Net.WebProxy
if ($AskControllerSecret) {
    $apsSecure = Read-Host 'Local controller secret' -AsSecureString
    $apsBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($apsSecure)
    try { $apsHeaders.Authorization = 'Bearer ' + [Runtime.InteropServices.Marshal]::PtrToStringBSTR($apsBstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($apsBstr) }
}
function Read-ApsController([string]$Path) {
    try {
        # No redirects: never forward a controller credential off localhost.
        $apsResponse = Invoke-WebRequest -UseBasicParsing -Uri ('http://127.0.0.1:' + $ControllerPort + $Path) -Headers $apsHeaders -WebSession $apsLocalSession -TimeoutSec 3 -MaximumRedirection 0
        return ($apsResponse.Content | ConvertFrom-Json)
    } catch { return $null } # Never export response body/headers/credentials.
}
$apsResult = [ordered]@{
    captured_at = [DateTimeOffset]::Now.ToString('o')
    socks_port = $Port
    boundary = 'Controller GET only; fresh HTTPS through SOCKS; no auth/cookies; no settings or processes changed.'
    controller = [ordered]@{ mode = $null; selected_leaf_type = $null; global_selection_verified = $false }
    https = @()
    aps_openai_chains = @()
    interpretation = 'SOCKS accepted/node delay is not TLS or application success. HTTP 401/403/404 proves an HTTP response, not authenticated Codex success. Rule mode sees the APS relay process.'
}
if ($ControllerPort) {
    $apsConfigs = Read-ApsController '/configs'
    if ($apsConfigs -and $apsConfigs.mode) { $apsResult.controller.mode = [string]$apsConfigs.mode }
    $apsProxies = Read-ApsController '/proxies'
    if ($apsConfigs.mode -eq 'global' -and $apsProxies.proxies) {
        $apsCurrent = 'GLOBAL'; $apsVisited = @{}
        for ($apsDepth = 0; $apsDepth -lt 32; $apsDepth++) {
            if ($apsVisited.ContainsKey($apsCurrent)) { break }
            $apsVisited[$apsCurrent] = $true
            $apsProperty = $apsProxies.proxies.PSObject.Properties[$apsCurrent]
            if (-not $apsProperty) { break }
            $apsProxy = $apsProperty.Value
            if (-not $apsProxy.now) {
                $apsResult.controller.selected_leaf_type = [string]$apsProxy.type
                $apsResult.controller.global_selection_verified = $true
                break
            }
            $apsCurrent = [string]$apsProxy.now
        }
    }
}
if (-not $SkipHttps) {
    $apsCurl = Get-Command curl.exe -ErrorAction SilentlyContinue
    foreach ($apsHost in @('chatgpt.com','codex-cloud-backend.chatgpt.com')) {
        $apsProbe = [ordered]@{ target = $apsHost; curl_exit = $null; http_code = $null; tls_completed = $false; timings = $null }
        if ($apsCurl) {
            # -q disables .curlrc; explicit noproxy overrides environment bypass.
            # Discard body and stderr so neither content nor raw addresses leak.
            $apsMetrics = & $apsCurl.Source -q --silent --proxy ('socks5h://127.0.0.1:' + $Port) --noproxy 'invalid-bypass.aps.invalid' --connect-timeout 5 --max-time 12 --output NUL --write-out '%{http_code}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}' ('https://' + $apsHost + '/') 2>$null
            $apsProbe.curl_exit = $LASTEXITCODE
            if ($apsMetrics -match '^([0-9]{3})\|([0-9.]+)\|([0-9.]+)\|([0-9.]+)\|([0-9.]+)$') {
                $apsProbe.http_code = $Matches[1]
                $apsTlsSeconds = [double]::Parse($Matches[3], [Globalization.CultureInfo]::InvariantCulture)
                $apsProbe.tls_completed = $apsTlsSeconds -gt 0
                $apsProbe.timings = [ordered]@{ connect = $Matches[2]; tls = $Matches[3]; first_byte = $Matches[4]; total = $Matches[5] }
            }
        }
        $apsResult.https += $apsProbe
    }
}
if ($ControllerPort) {
    $apsConnections = Read-ApsController '/connections'
    foreach ($apsConnection in $apsConnections.connections) {
        $apsMeta = $apsConnection.metadata
        if ([IO.Path]::GetFileName([string]$apsMeta.processPath) -ine 'AppProxySwitch.exe') { continue }
        if ([string]$apsMeta.host -notmatch '^(?:[a-zA-Z0-9-]+\.)*chatgpt\.com$') { continue }
        # Preserve the meaningful route evidence while hiding provider/node names.
        $apsSafeChains = @($apsConnection.chains | ForEach-Object {
            if ($_ -in @('DIRECT','REJECT','REJECT-DROP','GLOBAL')) { [string]$_ } else { '<proxy-or-group>' }
        })
        $apsResult.aps_openai_chains += [ordered]@{
            source_port = [string]$apsMeta.sourcePort
            target = [string]$apsMeta.host
            rule_type = [string]$apsConnection.rule
            chains = $apsSafeChains
        }
    }
}
$apsHeaders.Clear()
$apsResult | ConvertTo-Json -Depth 8

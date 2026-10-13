# Metadata-only helpers shared by read-only controller diagnostics.
function Get-ApsSourceKey([string]$Address, [string]$Port) {
    $apsAddress = $null
    [int]$apsPort = 0
    if (-not [int]::TryParse($Port, [ref]$apsPort) -or $apsPort -lt 1 -or $apsPort -gt 65535 -or
        -not [Net.IPAddress]::TryParse($Address, [ref]$apsAddress)) { return '' }
    if ($apsAddress.IsIPv4MappedToIPv6) { $apsAddress = $apsAddress.MapToIPv4() }
    return $apsAddress.ToString() + ':' + $apsPort
}

function Get-ApsRelaySourceKeys([int[]]$ProxyPorts) {
    $apsPids = @(Get-Process -Name AppProxySwitch -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Id)
    if (-not $apsPids.Count -or -not $ProxyPorts.Count) { return @() }
    try {
        return @(Get-NetTCPConnection -State Established -ErrorAction Stop |
            Where-Object {
                $_.OwningProcess -in $apsPids -and $_.RemotePort -in $ProxyPorts -and
                $_.RemoteAddress -in @('127.0.0.1','::1','::ffff:127.0.0.1')
            } | ForEach-Object { Get-ApsSourceKey $_.LocalAddress $_.LocalPort } |
            Where-Object { $_ } | Select-Object -Unique)
    } catch { return @() } # Unavailable attribution is not route success.
}

function Select-ApsBusinessRoutes($Connections, [string[]]$RelaySourceKeys) {
    foreach ($apsConnection in $Connections) {
        $apsMeta = $apsConnection.metadata
        if ([string]$apsMeta.host -notmatch '^(?:[a-zA-Z0-9-]+\.)*(?:chatgpt|openai)\.com$') { continue }
        $apsKey = Get-ApsSourceKey ([string]$apsMeta.sourceIP) ([string]$apsMeta.sourcePort)
        $apsAttribution = ''
        if ($apsKey -and $apsKey -in $RelaySourceKeys) { $apsAttribution = 'socket-tuple' }
        elseif ([IO.Path]::GetFileName([string]$apsMeta.processPath) -ieq 'AppProxySwitch.exe') {
            $apsAttribution = 'controller-process'
        }
        if (-not $apsAttribution) { continue }
        [pscustomobject]@{
            source_port = [string]$apsMeta.sourcePort
            target = [string]$apsMeta.host
            rule_type = [string]$apsConnection.rule
            chains = @($apsConnection.chains)
            attribution = $apsAttribution
        }
    }
}

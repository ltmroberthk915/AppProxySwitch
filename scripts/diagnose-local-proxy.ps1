# Standalone Windows PowerShell 5.1 diagnostic for a REMOTE computer.
# Run ON the affected computer, e.g. -Port <port shown in its client>.
# Only loopback SOCKS method negotiation; no CONNECT, credentials, external
# requests, configuration changes, elevation, or process start/stop.
# JSON goes to stdout; this script does not write files.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$Port,
    [ValidateRange(50, 10000)]
    [int]$TimeoutMs = 3000,
    [ValidateRange(1, 5)]
    [int]$Attempts = 3
)

$ErrorActionPreference = 'Stop'

function Test-LoopbackSocks {
    param([string]$Address, [int]$Attempt, [switch]$OfferPassword)
    $result = [ordered]@{
        address = $Address
        port = $Port
        attempt = $Attempt
        offered_methods = '00 (no authentication)'
        tcp_connected = $false
        connect_ms = $null
        elapsed_ms = 0
        reply_hex = ''
        status = 'ERROR'
        error = ''
    }
    if ($OfferPassword) { $result.offered_methods = '00,02 (no auth, username/password)' }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $client = $null
    $waitHandle = $null
    try {
        $ip = [Net.IPAddress]::Parse($Address)
        if (-not [Net.IPAddress]::IsLoopback($ip)) { throw 'Only loopback is allowed.' }
        $client = New-Object Net.Sockets.TcpClient($ip.AddressFamily)
        $pending = $client.BeginConnect($ip, $Port, $null, $null)
        $waitHandle = $pending.AsyncWaitHandle
        if (-not $waitHandle.WaitOne($TimeoutMs)) {
            $result.status = 'TCP_TIMEOUT'
        } else {
            $client.EndConnect($pending)
            $result.tcp_connected = $true
            $result.connect_ms = $watch.ElapsedMilliseconds
            $stream = $client.GetStream()
            $remaining = $TimeoutMs - [int]$watch.ElapsedMilliseconds
            if ($remaining -le 0) { throw [TimeoutException]::new('Probe deadline reached.') }
            $stream.WriteTimeout = $remaining
            [byte[]]$greeting = @(5, 1, 0)
            if ($OfferPassword) { $greeting = [byte[]]@(5, 2, 0, 2) }
            $stream.Write($greeting, 0, $greeting.Length)
            [byte[]]$reply = @(0, 0)
            $received = 0
            while ($received -lt 2) {
                $remaining = $TimeoutMs - [int]$watch.ElapsedMilliseconds
                if ($remaining -le 0) { throw [TimeoutException]::new('Probe deadline reached.') }
                $stream.ReadTimeout = $remaining
                $count = $stream.Read($reply, $received, 2 - $received)
                if ($count -eq 0) { break }
                $received += $count
                $result.reply_hex = (($reply[0..($received - 1)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
            }
            if ($received -ne 2) { $result.status = 'CLOSED_BEFORE_REPLY' }
            elseif ($reply[0] -ne 5) { $result.status = 'NOT_SOCKS5' }
            elseif ($reply[1] -eq 0) { $result.status = 'SOCKS5_NO_AUTH_OK' }
            elseif ($reply[1] -eq 255) { $result.status = 'NO_ACCEPTABLE_AUTH_METHOD' }
            elseif ($reply[1] -eq 2 -and $OfferPassword) { $result.status = 'SOCKS5_PASSWORD_REQUIRED' }
            else { $result.status = 'UNEXPECTED_AUTH_METHOD' }
        }
    } catch {
        $problem = $_.Exception.GetBaseException()
        if ($problem -is [Net.Sockets.SocketException]) {
            $result.error = $problem.SocketErrorCode.ToString()
        } else {
            $result.error = $problem.GetType().Name + ': ' + $problem.Message
        }
        if ($result.tcp_connected) { $result.status = 'HANDSHAKE_ERROR' }
        else { $result.status = 'TCP_ERROR' }
    } finally {
        if ($null -ne $client) { $client.Dispose() }
        if ($null -ne $waitHandle) { $waitHandle.Close() }
        $watch.Stop()
        $result.elapsed_ms = $watch.ElapsedMilliseconds
    }
    [pscustomobject]$result
}

$processes = @(Get-Process)
$names = @{}
foreach ($process in $processes) { $names[[int]$process.Id] = $process.ProcessName }
# These hints only select metadata for this reported Clash/Verge incident;
# they are not discovery rules, and no process command lines are collected.
$related = @($processes | Where-Object { $_.ProcessName -match 'clash|mihomo|verge|AppProxySwitch' })
$relatedIds = @($related | ForEach-Object { $_.Id })
$listenerError = ''
$listeners = @()
try {
    $listeners = @(Get-NetTCPConnection -State Listen | Where-Object {
        $_.LocalPort -eq $Port -or $relatedIds -contains $_.OwningProcess
    } | Sort-Object LocalPort, LocalAddress, OwningProcess | ForEach-Object {
        [pscustomobject]@{
            address = $_.LocalAddress
            port = $_.LocalPort
            pid = $_.OwningProcess
            process = $names[[int]$_.OwningProcess]
        }
    })
} catch { $listenerError = $_.Exception.Message }

$probes = @(
    foreach ($address in @('127.0.0.1', '::1')) {
        for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
            $probe = Test-LoopbackSocks -Address $address -Attempt $attempt
            $probe
            if ($probe.status -eq 'NO_ACCEPTABLE_AUTH_METHOD') {
                # Offer the password method to identify the requirement ONLY.
                # Do not submit a username/password or a destination address.
                Test-LoopbackSocks -Address $address -Attempt $attempt -OfferPassword
            }
        }
    }
)

[ordered]@{
    diagnostic = 'APS loopback SOCKS check v1'
    time = (Get-Date).ToString('o')
    powershell_version = $PSVersionTable.PSVersion.ToString()
    port = $Port
    timeout_ms_per_probe = $TimeoutMs
    process_metadata = @($related | ForEach-Object {
        $version = $null
        try { $version = $_.MainModule.FileVersionInfo.FileVersion } catch { }
        [pscustomobject]@{ pid = $_.Id; process = $_.ProcessName; file_version = $version }
    })
    listener_query_error = $listenerError
    listeners_before_probes = $listeners
    probes = $probes
    scope = 'Loopback handshake only. No internet connectivity test. No settings changed.'
} | ConvertTo-Json -Depth 6

# Read-only local controller diagnostic. Never measures delays, selects a node,
# updates subscriptions, writes configuration, or contacts the APS control pipe.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2147483647)]
    [int]$CorePid,
    [ValidateRange(100, 10000)]
    [int]$TimeoutMs = 2000
)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ApsControllerDiagnostic {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);
}
'@

function Read-Controller {
    param([string]$PipeName, [string]$Resource)
    if ($Resource -notin @('/version', '/configs', '/proxies')) { throw 'Read endpoint rejected.' }
    $stream = [IO.Pipes.NamedPipeClientStream]::new('.', $PipeName,
        [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous,
        [Security.Principal.TokenImpersonationLevel]::Identification)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $stream.Connect($TimeoutMs)
        [uint32]$owner = 0
        if (-not [ApsControllerDiagnostic]::GetNamedPipeServerProcessId(
            $stream.SafePipeHandle.DangerousGetHandle(), [ref]$owner) -or $owner -ne $CorePid) {
            throw 'Controller owner mismatch; no request sent.'
        }
        $request = [Text.Encoding]::ASCII.GetBytes("GET $Resource HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n")
        $write = $stream.WriteAsync($request, 0, $request.Length)
        if (-not $write.Wait([Math]::Max(1, $TimeoutMs - [int]$watch.ElapsedMilliseconds))) {
            throw 'Controller write timeout.'
        }
        $write.GetAwaiter().GetResult()
        $result = [IO.MemoryStream]::new()
        try {
            $buffer = [byte[]]::new(4096)
            while ($watch.ElapsedMilliseconds -lt $TimeoutMs) {
                $read = $stream.ReadAsync($buffer, 0, $buffer.Length)
                if (-not $read.Wait([Math]::Max(1, $TimeoutMs - [int]$watch.ElapsedMilliseconds))) {
                    throw 'Controller read timeout.'
                }
                $count = $read.GetAwaiter().GetResult()
                if (-not $count) { break }
                $result.Write($buffer, 0, $count)
                if ($result.Length -gt 8MB) { throw 'Controller response exceeds limit.' }
            }
            $response = [Text.Encoding]::UTF8.GetString($result.ToArray())
            if ($response -notmatch '^HTTP/1\.[01] 200 ') { throw 'Controller did not return HTTP 200.' }
            $split = $response.IndexOf("`r`n`r`n")
            if ($split -lt 0) { throw 'Controller response incomplete.' }
            $body = $response.Substring($split + 4)
            if ($response.Substring(0, $split) -match '(?im)^Transfer-Encoding:\s*chunked') {
                $decoded = [Text.StringBuilder]::new()
                $position = 0
                while ($position -lt $body.Length) {
                    $end = $body.IndexOf("`r`n", $position)
                    if ($end -lt 0) { throw 'Chunk header incomplete.' }
                    $size = [Convert]::ToInt32(($body.Substring($position, $end - $position) -split ';')[0], 16)
                    if (-not $size) { break }
                    $position = $end + 2
                    # The controller's chunk sizes count UTF-8 bytes.
                    $remaining = [Text.Encoding]::UTF8.GetBytes($body.Substring($position))
                    if ($remaining.Length -lt $size + 2) { throw 'Chunk data incomplete.' }
                    $chunk = [Text.Encoding]::UTF8.GetString($remaining, 0, $size)
                    [void]$decoded.Append($chunk)
                    $position += $chunk.Length + 2
                }
                $body = $decoded.ToString()
            }
            return $body | ConvertFrom-Json
        } finally { $result.Dispose() }
    } finally { $stream.Dispose(); $watch.Stop() }
}

$core = Get-Process -Id $CorePid
if ($core.ProcessName -notmatch 'clash|mihomo|vortex') { throw 'Target is not a recognized proxy core.' }
$stem = $core.ProcessName.ToLowerInvariant()
$candidates = @([IO.Directory]::GetFiles('\\.\pipe\') | Where-Object {
    $short = $_.Substring(9).ToLowerInvariant()
    $short -eq $stem -or $short.StartsWith($stem + '-')
})
foreach ($candidate in $candidates) {
    $short = $candidate.Substring(9)
    try {
        $version = Read-Controller $short '/version'
        if (-not $version.version) { throw 'Version identity missing.' }
        $config = Read-Controller $short '/configs'
        $proxies = Read-Controller $short '/proxies'
        [pscustomobject]@{
            pid = $CorePid
            process = $core.ProcessName
            pipe = $candidate
            version = $version.version
            mode = $config.mode
            mixed_port = $config.'mixed-port'
            selectors = @($proxies.proxies.PSObject.Properties | Where-Object {
                $_.Value.type -eq 'Selector'
            } | ForEach-Object {
                [pscustomobject]@{ name = $_.Name; selected = $_.Value.now; members = @($_.Value.all).Count }
            })
            scope = 'GET /version, /configs and /proxies only; no changes or delay tests.'
        } | ConvertTo-Json -Depth 5
    } catch {
        # Do not expose raw controller replies, credentials, or subscription URLs.
        [pscustomobject]@{ pid = $CorePid; pipe = $candidate; error = $_.Exception.GetType().Name } | ConvertTo-Json
    }
}

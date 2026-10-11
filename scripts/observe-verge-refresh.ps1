# Passive, bounded observation of one user-initiated refresh. Does not invoke
# Verge, change its files/settings, or send network requests. URLs are redacted.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$DataDirectory,
    [Parameter(Mandatory=$true)][int]$ClientProcessId,
    [Parameter(Mandatory=$true)][int]$CoreProcessId,
    [ValidateRange(20,900)][int]$DurationSeconds = 300
)
$ErrorActionPreference = 'Stop'
$rootDirectory = (Get-Item -LiteralPath $DataDirectory).FullName
$logFile = Join-Path $rootDirectory 'logs\latest.log'
$logPosition = (Get-Item -LiteralPath $logFile).Length
$deadline = [DateTime]::UtcNow.AddSeconds($DurationSeconds)
$fileState = @{}
$seenConnections = @{}
$lastProcessCheck = [DateTime]::MinValue
$processState = ''
function Safe-LogText([string]$value) {
    $value = [regex]::Replace($value, '[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"''<>]+', '<url-redacted>')
    $value = [regex]::Replace($value, '(?i)(secret|password|authorization|token)(\s*[:=]\s*)[^\s,;]+', '$1$2<redacted>')
    return $value
}
function Observe-Files([bool]$initial) {
    $files = @(Get-ChildItem -LiteralPath $rootDirectory -File | Where-Object { $_.Extension -eq '.yaml' })
    $profilesDirectory = Join-Path $rootDirectory 'profiles'
    if (Test-Path -LiteralPath $profilesDirectory) { $files += @(Get-ChildItem -LiteralPath $profilesDirectory -File | Where-Object { $_.Extension -in @('.yaml','.js') }) }
    foreach ($file in $files) {
        $key = $file.FullName.Substring($rootDirectory.Length + 1)
        $fingerprint = "$($file.Length):$($file.LastWriteTimeUtc.Ticks)"
        if (-not $initial -and $fileState[$key] -ne $fingerprint) {
            Write-Output ("FILE_CHANGE {0:o} {1} bytes={2}" -f [DateTimeOffset]::Now,$key,$file.Length)
        }
        $fileState[$key] = $fingerprint
    }
}
Observe-Files $true
Write-Output ("READY {0:o} machine={1} user={2} clientPID={3} corePID={4} duration={5}s (passive metadata/log tail only)" -f [DateTimeOffset]::Now,[Environment]::MachineName,[Environment]::UserName,$ClientProcessId,$CoreProcessId,$DurationSeconds)
while ([DateTime]::UtcNow -lt $deadline) {
    if (Test-Path -LiteralPath $logFile) {
        $stream = [IO.File]::Open($logFile,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try {
            if ($stream.Length -lt $logPosition) { $logPosition = 0; Write-Output 'LOG_ROTATED' }
            if ($stream.Length -gt $logPosition) {
                [void]$stream.Seek($logPosition,[IO.SeekOrigin]::Begin)
                $reader = New-Object IO.StreamReader($stream,[Text.Encoding]::UTF8,$true,4096,$true)
                try { $newText = $reader.ReadToEnd(); $logPosition = $stream.Position } finally { $reader.Dispose() }
                foreach ($line in ($newText -split '\r?\n')) {
                    if ($line -match '订阅|更新|下载|配置|校验|[Pp]rofile|[Uu]pdate|[Rr]eload|[Dd]ownload|[Ee]rror|[Ff]ail|[Vv]alidat|IPC|[Rr]estart') {
                        Write-Output ('LOG ' + (Safe-LogText $line))
                    }
                }
            }
        } finally { $stream.Dispose() }
    }
    Observe-Files $false
    if (([DateTime]::UtcNow - $lastProcessCheck).TotalSeconds -ge 2) {
        $lastProcessCheck = [DateTime]::UtcNow
        $processes = @(Get-Process -Name 'clash-verge','verge-mihomo' -ErrorAction SilentlyContinue)
        $currentState = ($processes | Sort-Object Id | ForEach-Object { "$($_.ProcessName):$($_.Id)" }) -join ','
        if ($currentState -ne $processState) { Write-Output ("PROCESSES {0:o} {1}" -f [DateTimeOffset]::Now,$currentState); $processState = $currentState }
        $observedIds = @($ClientProcessId,$CoreProcessId) + @($processes | ForEach-Object { $_.Id })
        foreach ($row in (& netstat.exe -ano -p tcp)) {
            $fields = $row.Trim() -split '\s+'
            if ($fields.Count -lt 5 -or $fields[0] -ne 'TCP' -or [int]$fields[4] -notin $observedIds) { continue }
            $connectionKey = $row.Trim()
            if ($seenConnections.ContainsKey($connectionKey)) { continue }
            $seenConnections[$connectionKey] = $true
            $remote = if ($fields[2] -match '^(127\.|\[::1\])' -or $fields[2] -eq '0.0.0.0:0') { $fields[2] } else { '<remote>:' + ($fields[2] -split ':')[-1] }
            Write-Output ("TCP {0:o} pid={1} local={2} peer={3} state={4}" -f [DateTimeOffset]::Now,$fields[4],$fields[1],$remote,$fields[3])
        }
    }
    Start-Sleep -Milliseconds 250
}
Write-Output ("OBSERVATION_FINISHED {0:o}; no app/network settings changed by observer" -f [DateTimeOffset]::Now)

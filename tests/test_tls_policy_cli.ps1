param([Parameter(Mandatory = $true)][string]$Executable)
$ErrorActionPreference = 'Stop'
$apsPolicyTestRoot = Join-Path ([IO.Path]::GetTempPath()) ('aps-policy-test-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $apsPolicyTestRoot)
$apsPolicyConfig = Join-Path $apsPolicyTestRoot 'config.json'
function Assert-Policy([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Get-PolicyHash {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($apsPolicyConfig))) }
    finally { $sha.Dispose() }
}
function Run-Policy([string[]]$Arguments, [int]$ExpectedExit) {
    $quoted = @($Arguments | ForEach-Object { '"' + $_ + '"' })
    $process = Start-Process -FilePath $Executable -ArgumentList $quoted -WindowStyle Hidden -PassThru
    Assert-Policy ($process.WaitForExit(8000)) 'Policy CLI did not exit; no live process was stopped.'
    $process.Refresh()
    Assert-Policy ($process.ExitCode -eq $ExpectedExit) ('Unexpected CLI exit: ' + $process.ExitCode)
    $process.Dispose()
}
try {
    $fixture = @{
        version = 1
        proxy = @{ host = '127.0.0.1'; port = 7891; username = 'fixture'; password_enc = 'preserve-this-encrypted-value' }
        relay = @{ listen = '127.0.0.1'; port = 12753 }
        routing = @{ auto_outlet_id = 'fixture-outlet'; dns_cleanup_global = $false }
        outlets = @(@{ id = 'fixture-outlet'; name = 'test'; host = '127.0.0.1'; port = 30001; enabled = $true })
        rules = @(@{ id = 'fixture-rule'; name = 'test'; path = 'C:\Test\fixture.exe'; outlet = 'fixture-outlet'; action = 'proxy'; enabled = $true })
        node_monitor = @{ regions = @('SG'); node_classes = @('IEPL'); region = 'SG'; node_class = 'IEPL' }
    } | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($apsPolicyConfig, $fixture, [Text.UTF8Encoding]::new($false))
    Run-Policy @('--config', $apsPolicyConfig, '--tls-domain-allow', 'example.invalid', '--tls-domain-allow', '*.example.invalid') 0
    $config = Get-Content -LiteralPath $apsPolicyConfig -Raw | ConvertFrom-Json
    Assert-Policy (($config.routing.tls_domain_allowlist -join ',') -eq 'example.invalid,*.example.invalid') 'Domain list was not saved.'
    Run-Policy @('--config', $apsPolicyConfig, '--tls-domain-allow', 'EXAMPLE.INVALID', '--tls-domain-allow', 'other.invalid') 0
    $config = Get-Content -LiteralPath $apsPolicyConfig -Raw | ConvertFrom-Json
    Assert-Policy (($config.routing.tls_domain_allowlist -join ',') -eq 'example.invalid,*.example.invalid,other.invalid') 'Append or case-insensitive deduplication failed.'
    Assert-Policy ($config.proxy.password_enc -eq 'preserve-this-encrypted-value') 'Encrypted credential changed.'
    Assert-Policy ($config.routing.auto_outlet_id -eq 'fixture-outlet' -and $config.rules[0].outlet -eq 'fixture-outlet') 'Routing changed.'
    Assert-Policy ($config.node_monitor.regions[0] -eq 'SG' -and $config.node_monitor.node_classes[0] -eq 'IEPL') 'Node preferences changed.'
    $before = Get-PolicyHash
    foreach ($invalid in @('*', '*.com', 'https://example.invalid', '127.0.0.1')) {
        Run-Policy @('--config', $apsPolicyConfig, '--tls-domain-allow', $invalid) 2
        Assert-Policy ((Get-PolicyHash) -eq $before) 'Rejected policy changed config.'
    }
    Run-Policy @('--config', $apsPolicyConfig, '--tls-domain-allow', 'example.invalid', '--engine') 2
    Run-Policy @('--tls-domain-allow', 'example.invalid', '--config') 2
    Run-Policy @('--config', $apsPolicyConfig, '--clear-tls-domain-allowlist', '--tls-domain-allow', 'example.invalid') 2
    Assert-Policy ((Get-PolicyHash) -eq $before) 'Ambiguous CLI changed config.'
    $missing = Join-Path $apsPolicyTestRoot 'missing.json'
    Run-Policy @('--config', $missing, '--tls-domain-allow', 'example.invalid') 2
    Assert-Policy (-not (Test-Path -LiteralPath $missing)) 'Missing config was created.'
    Run-Policy @('--config', $apsPolicyConfig, '--clear-tls-domain-allowlist') 0
    $config = Get-Content -LiteralPath $apsPolicyConfig -Raw | ConvertFrom-Json
    Assert-Policy (@($config.routing.tls_domain_allowlist).Count -eq 0) 'Policy clear failed.'
    'TLS policy CLI: valid update, clear, preservation, rejection and isolated paths passed.'
} finally {
    # Only remove explicitly created fixture files; never recurse into Temp.
    foreach ($name in @('config.json', 'config.json.bak', 'config.json.tmp')) {
        $file = Join-Path $apsPolicyTestRoot $name
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
    }
    Remove-Item -LiteralPath $apsPolicyTestRoot
}

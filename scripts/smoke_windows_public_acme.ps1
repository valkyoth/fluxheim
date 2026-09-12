[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^public-acme-[0-9a-f]{16}$')]
    [string]$RunId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')]
    [string]$PublicName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Za-z.!#$%&''*+/=?^_`{|}~-]+@[0-9A-Za-z.-]+$')]
    [string]$ContactEmail,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://[0-9A-Za-z./_-]+$')]
    [string]$TermsOfServiceUrl,

    [ValidateRange(1, 65535)]
    [int]$HttpPort = 80,

    [ValidateRange(1, 65535)]
    [int]$HttpsPort = 443,

    [ValidateRange(60, 900)]
    [int]$WaitTimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64') {
    throw 'public ACME smoke requires native X64 Windows'
}
if ($HttpPort -eq $HttpsPort) {
    throw 'HTTP and HTTPS smoke ports must differ'
}
if (-not $PublicName.Contains('.') -or $PublicName.Contains('..')) {
    throw 'public ACME name must be a dotted DNS hostname'
}

$publicName = $PublicName.ToLowerInvariant()
$runRoot = Join-Path 'C:\FluxheimBuild\runs' $RunId
$archivePath = Join-Path $runRoot 'fluxheim-full.zip'
$bundleRoot = Join-Path $runRoot 'bundle'
$siteRoot = Join-Path $runRoot 'site'
$runtimeRoot = Join-Path $runRoot 'runtime'
$acmeRoot = Join-Path $runRoot 'acme'
$configPath = Join-Path $runRoot 'fluxheim.toml'
$readyPath = Join-Path $runRoot 'ready'
$stopPath = Join-Path $runRoot 'stop'
$issuedCertificatePath = Join-Path $runRoot 'issued-fullchain.pem'
$stdoutPath = Join-Path $runRoot 'fluxheim.stdout.log'
$stderrPath = Join-Path $runRoot 'fluxheim.stderr.log'
$renewalLogPath = Join-Path $runRoot 'acme-renew.log'
$process = $null
$succeeded = $false

function ConvertTo-TomlPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    return $Path.Replace('\', '/')
}

function Wait-ForTcpPort {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Process.HasExited) {
            throw "$Name exited before readiness with code $($Process.ExitCode)"
        }
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $client.Connect('127.0.0.1', $Port)
            return
        } catch [Net.Sockets.SocketException] {
            Start-Sleep -Milliseconds 200
        } finally {
            $client.Dispose()
        }
    }
    throw "timed out waiting for $Name on 127.0.0.1:$Port"
}

function Stop-SmokeProcess {
    if ($null -ne $script:process) {
        if (-not $script:process.HasExited) {
            Stop-Process -Id $script:process.Id -Force -ErrorAction SilentlyContinue
            $script:process.WaitForExit(10000) | Out-Null
        }
        $script:process.Dispose()
        $script:process = $null
    }
}

function Write-AcmeConfig {
    param([Parameter(Mandatory = $true)][bool]$EnableTlsListener)

    $siteToml = ConvertTo-TomlPath $siteRoot
    $runtimeToml = ConvertTo-TomlPath $runtimeRoot
    $acmeToml = ConvertTo-TomlPath $acmeRoot
    $tlsListener = if ($EnableTlsListener) {
        "tls_listen = [`"0.0.0.0:$HttpsPort`"]"
    } else {
        ''
    }
    $config = @"
[server]
listen = ["0.0.0.0:$HttpPort"]
$tlsListener
default_vhost = "$publicName"
trusted_proxies = []

[server.process]
pid_file = "$runtimeToml/fluxheim.pid"
upgrade_sock = "$runtimeToml/fluxheim-upgrade.sock"
certificate_reload_sock = "$runtimeToml/fluxheim-cert-reload.sock"
max_retries = 1
graceful_shutdown_timeout_seconds = 5

[logging]
level = "warn"
format = "text"

[logging.access]
enabled = false
request_id = false

[tls]
enabled = true
backend = "rustls"

[tls.acme]
enabled = true
storage = "$acmeToml"
contact_email = "$ContactEmail"
default_issuer = "letsencrypt-staging"
challenge = "http-01"
automation = "external"

[tls.acme.renewal]
enabled = true
renew_before_secs = 2592000
check_interval_secs = 3600
retry_initial_secs = 300
retry_max_secs = 86400
reload_after_renewal = false
zero_downtime_reload = false

[[tls.acme.issuers]]
name = "letsencrypt-staging"
directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
terms_of_service_agreed = true
terms_of_service_url = "$TermsOfServiceUrl"

[[vhosts]]
name = "$publicName"
hosts = ["$publicName"]

[vhosts.tls]
enabled = true

[vhosts.tls.acme]
enabled = true
issuer = "letsencrypt-staging"
domains = ["$publicName"]

[vhosts.web]
root = "$siteToml"
index_files = ["index.html"]
deny_dotfiles = true
"@
    Set-Content -LiteralPath $configPath -Value $config -Encoding utf8
}

function Start-Fluxheim {
    param(
        [Parameter(Mandatory = $true)][string]$Binary,
        [Parameter(Mandatory = $true)][bool]$ExpectTls
    )

    Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    $script:process = Start-Process -FilePath $Binary `
        -ArgumentList '--config', $configPath `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath -PassThru -WindowStyle Hidden
    Wait-ForTcpPort -Port $HttpPort -Process $script:process -Name 'Fluxheim HTTP'
    if ($ExpectTls) {
        Wait-ForTcpPort -Port $HttpsPort -Process $script:process -Name 'Fluxheim HTTPS'
    }
}

if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    throw "Windows full profile archive is missing: $archivePath"
}
New-Item -ItemType Directory -Force `
    -Path $bundleRoot, $siteRoot, $runtimeRoot, $acmeRoot | Out-Null

try {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $bundleRoot -Force
    $fluxheimCandidates = @(Get-ChildItem -LiteralPath $bundleRoot `
        -Filter 'fluxheim.exe' -File -Recurse)
    if ($fluxheimCandidates.Count -ne 1) {
        throw "expected one packaged fluxheim.exe, found $($fluxheimCandidates.Count)"
    }
    $fluxheimBinary = $fluxheimCandidates[0].FullName
    if ($fluxheimBinary -notmatch '-full-x86_64-windows[\\/]fluxheim[.]exe$') {
        throw "archive is not the Windows x86_64 full profile: $fluxheimBinary"
    }

    [IO.File]::WriteAllText(
        (Join-Path $siteRoot 'index.html'),
        'fluxheim-windows-public-acme-ok',
        [Text.Encoding]::ASCII
    )
    Write-AcmeConfig -EnableTlsListener $false
    & $fluxheimBinary --config $configPath --validate-config
    if ($LASTEXITCODE -ne 0) {
        throw 'packaged Windows full profile rejected the ACME smoke config'
    }
    Start-Fluxheim -Binary $fluxheimBinary -ExpectTls $false

    $renewalOutput = @(& $fluxheimBinary --config $configPath acme-renew 2>&1)
    $renewalOutput | Set-Content -LiteralPath $renewalLogPath -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw 'Let''s Encrypt staging issuance failed'
    }
    if (-not (($renewalOutput | Out-String).Contains('certificate=installed'))) {
        throw 'ACME renewal output did not confirm certificate installation'
    }

    Stop-SmokeProcess
    $certificateCandidates = @(Get-ChildItem -LiteralPath $acmeRoot `
        -Filter 'fullchain.pem' -File -Recurse)
    $privateKeyCandidates = @(Get-ChildItem -LiteralPath $acmeRoot `
        -Filter 'privkey.pem' -File -Recurse)
    if ($certificateCandidates.Count -ne 1 -or $privateKeyCandidates.Count -ne 1) {
        throw 'ACME staging issuance did not install exactly one certificate/key pair'
    }
    Copy-Item -LiteralPath $certificateCandidates[0].FullName `
        -Destination $issuedCertificatePath

    Write-AcmeConfig -EnableTlsListener $true
    & $fluxheimBinary --config $configPath --validate-config
    if ($LASTEXITCODE -ne 0) {
        throw 'packaged Windows full profile rejected its issued ACME certificate'
    }
    Start-Fluxheim -Binary $fluxheimBinary -ExpectTls $true

    Set-Content -LiteralPath $readyPath -Value 'ready' -Encoding ascii
    Write-Output "READY $publicName $HttpPort $HttpsPort"
    $deadline = [DateTime]::UtcNow.AddSeconds($WaitTimeoutSeconds)
    while (-not (Test-Path -LiteralPath $stopPath -PathType Leaf)) {
        if ($process.HasExited) {
            throw "Fluxheim exited during public ACME smoke with code $($process.ExitCode)"
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            throw 'public ACME smoke controller did not request shutdown before timeout'
        }
        Start-Sleep -Milliseconds 250
    }
    $succeeded = $true
    Write-Output 'Windows public ACME staging harness: ok'
} finally {
    Stop-SmokeProcess
    if (-not $succeeded) {
        if (Test-Path -LiteralPath $renewalLogPath -PathType Leaf) {
            Get-Content -LiteralPath $renewalLogPath -ErrorAction SilentlyContinue |
                ForEach-Object { [Console]::Error.WriteLine($_) }
        }
        if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
            Get-Content -LiteralPath $stderrPath -ErrorAction SilentlyContinue |
                ForEach-Object { [Console]::Error.WriteLine($_) }
        }
        [Console]::Error.WriteLine("Windows public ACME smoke artifacts kept in $runRoot")
    }
}

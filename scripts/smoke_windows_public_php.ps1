[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^public-php-[0-9a-f]{16}$')]
    [string]$RunId,

    [ValidateRange(1, 65535)]
    [int]$HttpPort = 80,

    [ValidateRange(1, 65535)]
    [int]$HttpsPort = 443,

    [ValidateRange(30, 900)]
    [int]$WaitTimeoutSeconds = 300,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')]
    [string]$PublicName
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$expectedArchitecture = 'X64'
$actualArchitecture =
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($actualArchitecture -ne $expectedArchitecture) {
    throw "public PHP smoke requires native $expectedArchitecture Windows"
}
if ($HttpPort -eq $HttpsPort) {
    throw 'HTTP and HTTPS smoke ports must differ'
}
if (-not $PublicName.Contains('.') -or $PublicName.Contains('..')) {
    throw 'public smoke name must be a dotted DNS hostname'
}

$runRoot = Join-Path 'C:\FluxheimBuild\runs' $RunId
$archivePath = Join-Path $runRoot 'fluxheim-php.zip'
$bundleRoot = Join-Path $runRoot 'bundle'
$phpArchivePath = Join-Path $runRoot 'php.zip'
$phpRoot = Join-Path $runRoot 'php'
$siteRoot = Join-Path $runRoot 'site'
$runtimeRoot = Join-Path $runRoot 'runtime'
$tlsRoot = Join-Path $runRoot 'tls'
$configPath = Join-Path $runRoot 'fluxheim.toml'
$certificateAuthorityPath = Join-Path $runRoot 'ca.pem'
$certificatePath = Join-Path $tlsRoot 'certificate.pem'
$privateKeyPath = Join-Path $tlsRoot 'private-key.pem'
$readyPath = Join-Path $runRoot 'ready'
$stopPath = Join-Path $runRoot 'stop'
$fluxheimStdoutPath = Join-Path $runRoot 'fluxheim.stdout.log'
$fluxheimStderrPath = Join-Path $runRoot 'fluxheim.stderr.log'
$phpStdoutPath = Join-Path $runRoot 'php-cgi.stdout.log'
$phpStderrPath = Join-Path $runRoot 'php-cgi.stderr.log'

$phpUrl =
    'https://downloads.php.net/~windows/releases/php-8.4.25-nts-Win32-vs17-x64.zip'
$phpSha256 = '43a8f67ed2e5223fafb21293c85976361808855405278cef2cf3037c3ae2529c'
$publicName = $PublicName.ToLowerInvariant()
$phpProcess = $null
$fluxheimProcess = $null
$succeeded = $false

function ConvertTo-TomlPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    return $Path.Replace('\', '/')
}

function ConvertTo-Pem {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    $encoded = [Convert]::ToBase64String(
        $Bytes,
        [Base64FormattingOptions]::InsertLineBreaks
    )
    return "-----BEGIN $Label-----`r`n$encoded`r`n-----END $Label-----`r`n"
}

function New-PublicSmokeCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$CertificateAuthorityPath,
        [Parameter(Mandatory = $true)][string]$CertificatePath,
        [Parameter(Mandatory = $true)][string]$PrivateKeyPath
    )

    $caKey = [Security.Cryptography.RSA]::Create(2048)
    $serverKey = [Security.Cryptography.RSA]::Create(2048)
    $caCertificate = $null
    $serverCertificate = $null
    try {
        $caRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=Fluxheim Windows public smoke CA',
            $caKey,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        [void]$caRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
                $true, $false, 0, $true
            )
        )
        $caUsage = [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign `
            -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
        [void]$caRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                $caUsage, $true
            )
        )
        $caCertificate = $caRequest.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-5),
            [DateTimeOffset]::UtcNow.AddDays(1)
        )

        $serverRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=$publicName",
            $serverKey,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        [void]$serverRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
                $false, $false, 0, $true
            )
        )
        $serverUsage = [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature `
            -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
        [void]$serverRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                $serverUsage, $true
            )
        )
        $serverAuthentication = [Security.Cryptography.OidCollection]::new()
        [void]$serverAuthentication.Add(
            [Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1')
        )
        [void]$serverRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
                $serverAuthentication, $true
            )
        )
        $san = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        [void]$san.AddDnsName($publicName)
        [void]$serverRequest.CertificateExtensions.Add($san.Build())

        $serial = [byte[]]::new(16)
        [Security.Cryptography.RandomNumberGenerator]::Fill($serial)
        $serial[0] = $serial[0] -band 0x7f
        $serial[0] = $serial[0] -bor 0x01
        $serverCertificate = $serverRequest.Create(
            $caCertificate,
            [DateTimeOffset]::UtcNow.AddMinutes(-5),
            [DateTimeOffset]::UtcNow.AddHours(6),
            $serial
        )

        [IO.File]::WriteAllText(
            $CertificateAuthorityPath,
            (ConvertTo-Pem -Label 'CERTIFICATE' -Bytes $caCertificate.RawData),
            [Text.Encoding]::ASCII
        )
        [IO.File]::WriteAllText(
            $CertificatePath,
            (ConvertTo-Pem -Label 'CERTIFICATE' -Bytes $serverCertificate.RawData),
            [Text.Encoding]::ASCII
        )
        [IO.File]::WriteAllText(
            $PrivateKeyPath,
            (ConvertTo-Pem -Label 'PRIVATE KEY' -Bytes $serverKey.ExportPkcs8PrivateKey()),
            [Text.Encoding]::ASCII
        )
    } finally {
        if ($null -ne $serverCertificate) { $serverCertificate.Dispose() }
        if ($null -ne $caCertificate) { $caCertificate.Dispose() }
        $serverKey.Dispose()
        $caKey.Dispose()
    }
}

function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
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

if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    throw "Windows PHP profile archive is missing: $archivePath"
}
New-Item -ItemType Directory -Force `
    -Path $bundleRoot, $phpRoot, $siteRoot, $runtimeRoot, $tlsRoot | Out-Null

try {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $bundleRoot -Force
    $fluxheimCandidates = @(Get-ChildItem -LiteralPath $bundleRoot `
        -Filter 'fluxheim.exe' -File -Recurse)
    if ($fluxheimCandidates.Count -ne 1) {
        throw "expected one packaged fluxheim.exe, found $($fluxheimCandidates.Count)"
    }
    $fluxheimBinary = $fluxheimCandidates[0].FullName
    if ($fluxheimBinary -notmatch '-php-x86_64-windows[\\/]fluxheim[.]exe$') {
        throw "archive is not the Windows x86_64 PHP profile: $fluxheimBinary"
    }

    Invoke-WebRequest -Uri $phpUrl -OutFile $phpArchivePath
    $actualPhpHash =
        (Get-FileHash -LiteralPath $phpArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualPhpHash -ne $phpSha256) {
        throw "official PHP archive checksum mismatch: $actualPhpHash"
    }
    Expand-Archive -LiteralPath $phpArchivePath -DestinationPath $phpRoot -Force
    $phpCgi = Join-Path $phpRoot 'php-cgi.exe'
    if (-not (Test-Path -LiteralPath $phpCgi -PathType Leaf)) {
        throw 'official PHP archive omitted php-cgi.exe'
    }

    Set-Content -LiteralPath (Join-Path $siteRoot 'index.php') -Encoding ascii -Value @'
<?php
header('Content-Type: text/plain');
$body = file_get_contents('php://input');
echo 'fluxheim-windows-public-php-ok';
echo '|scheme=' . ($_SERVER['REQUEST_SCHEME'] ?? 'missing');
echo '|https=' . ($_SERVER['HTTPS'] ?? 'missing');
echo '|method=' . ($_SERVER['REQUEST_METHOD'] ?? 'missing');
echo '|body=' . $body;
'@
    New-PublicSmokeCertificate `
        -CertificateAuthorityPath $certificateAuthorityPath `
        -CertificatePath $certificatePath `
        -PrivateKeyPath $privateKeyPath

    $fastCgiPort = Get-FreeTcpPort
    $siteToml = ConvertTo-TomlPath $siteRoot
    $runtimeToml = ConvertTo-TomlPath $runtimeRoot
    $certificateToml = ConvertTo-TomlPath $certificatePath
    $privateKeyToml = ConvertTo-TomlPath $privateKeyPath
    $config = @"
[server]
listen = ["0.0.0.0:$HttpPort"]
tls_listen = ["0.0.0.0:$HttpsPort"]
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

[[tls.certificates]]
cert_path = "$certificateToml"
key_path = "$privateKeyToml"

[[vhosts]]
name = "$publicName"
hosts = ["$publicName"]

[vhosts.tls]
enabled = true

[vhosts.tls.certificate]
cert_path = "$certificateToml"
key_path = "$privateKeyToml"

[vhosts.php]
enabled = true
runtime = "php-fpm"
root = "$siteToml"
index = "index.php"
allowed_extensions = ["php"]
try_files = "strict"
path_info = "disabled"
request_timeout_secs = 30
max_request_body_bytes = "1MiB"
max_response_bytes = "1MiB"

[vhosts.php.fpm]
mode = "external"
tcp = "127.0.0.1:$fastCgiPort"
allow_private_tcp_upstreams = true

[vhosts.web]
root = "$siteToml"
index_files = ["index.php"]
deny_dotfiles = true

[vhosts.web.directory_listing]
enabled = false
"@
    Set-Content -LiteralPath $configPath -Value $config -Encoding utf8

    & $fluxheimBinary --config $configPath --validate-config
    if ($LASTEXITCODE -ne 0) {
        throw 'packaged Windows PHP profile rejected the public smoke config'
    }

    $previousMaxRequests = $env:PHP_FCGI_MAX_REQUESTS
    $env:PHP_FCGI_MAX_REQUESTS = '100'
    try {
        $phpProcess = Start-Process -FilePath $phpCgi `
            -ArgumentList '-b', "127.0.0.1:$fastCgiPort", '-n' `
            -RedirectStandardOutput $phpStdoutPath `
            -RedirectStandardError $phpStderrPath -PassThru -WindowStyle Hidden
    } finally {
        $env:PHP_FCGI_MAX_REQUESTS = $previousMaxRequests
    }
    Wait-ForTcpPort -Port $fastCgiPort -Process $phpProcess -Name 'PHP FastCGI'

    $fluxheimProcess = Start-Process -FilePath $fluxheimBinary `
        -ArgumentList '--config', $configPath `
        -RedirectStandardOutput $fluxheimStdoutPath `
        -RedirectStandardError $fluxheimStderrPath -PassThru -WindowStyle Hidden
    Wait-ForTcpPort -Port $HttpPort -Process $fluxheimProcess -Name 'Fluxheim HTTP'
    Wait-ForTcpPort -Port $HttpsPort -Process $fluxheimProcess -Name 'Fluxheim HTTPS'

    Set-Content -LiteralPath $readyPath -Value 'ready' -Encoding ascii
    Write-Output "READY $publicName $HttpPort $HttpsPort"

    $deadline = [DateTime]::UtcNow.AddSeconds($WaitTimeoutSeconds)
    while (-not (Test-Path -LiteralPath $stopPath -PathType Leaf)) {
        if ($fluxheimProcess.HasExited) {
            throw "Fluxheim exited during public smoke with code $($fluxheimProcess.ExitCode)"
        }
        if ($phpProcess.HasExited) {
            throw "PHP FastCGI exited during public smoke with code $($phpProcess.ExitCode)"
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            throw 'public PHP smoke controller did not request shutdown before timeout'
        }
        Start-Sleep -Milliseconds 250
    }
    $succeeded = $true
    Write-Output 'Windows public PHP harness: ok'
} finally {
    foreach ($process in @($fluxheimProcess, $phpProcess)) {
        if ($null -ne $process) {
            if (-not $process.HasExited) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                $process.WaitForExit(10000) | Out-Null
            }
            $process.Dispose()
        }
    }
    if (-not $succeeded) {
        if (Test-Path -LiteralPath $fluxheimStderrPath -PathType Leaf) {
            Get-Content -LiteralPath $fluxheimStderrPath -ErrorAction SilentlyContinue |
                Write-Error
        }
        Write-Error "Windows public PHP smoke artifacts kept in $runRoot"
    }
}

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root

$features = 'profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp'
& cargo.exe build --locked --no-default-features --features $features --bin fluxheim
if ($LASTEXITCODE -ne 0) {
    throw 'native Windows smoke binary build failed'
}

& cargo.exe test --locked -p fluxheim-acme --lib --features acme-client
if ($LASTEXITCODE -ne 0) {
    throw 'native Windows ACME storage and lifecycle regressions failed'
}

& cargo.exe test --locked -p fluxheim-config --lib `
    'rejects_managed_php_fpm_without_unix_process_support' -- --nocapture
if ($LASTEXITCODE -ne 0) {
    throw 'native Windows managed PHP-FPM config rejection regression failed'
}

& cargo.exe test --locked -p fluxheim-php-fpm --lib `
    'managed_php_fpm_process_start_fails_closed_without_unix_support' -- --nocapture
if ($LASTEXITCODE -ne 0) {
    throw 'native Windows managed PHP-FPM runtime rejection regression failed'
}

& cargo.exe test --locked -p fluxheim-server --lib --features php-fpm `
    'native_route_proxy_php_route_executes_fastcgi_responder' -- --nocapture
if ($LASTEXITCODE -ne 0) {
    throw 'native Windows external TCP FastCGI regression failed'
}

& cargo.exe test --locked -p fluxheim-server --lib `
    'native_http1_cache::lease_tests::storage_bin_' -- --nocapture
if ($LASTEXITCODE -ne 0) {
    throw 'native Windows storage-bin lease regressions failed'
}

& cargo.exe test --locked -p fluxheim-cache --lib `
    'storage_bin_fs::tests::absolute_storage_bin_root_skips_bare_windows_prefix' -- --nocapture
if ($LASTEXITCODE -ne 0) {
    throw 'native Windows storage-bin absolute-root regression failed'
}

& cargo.exe test --locked -p fluxheim-server --lib `
    'absolute_native_cache_root_skips_bare_windows_prefix' -- --nocapture
if ($LASTEXITCODE -ne 0) {
    throw 'native Windows filesystem-cache absolute-root regression failed'
}

$binary = (Resolve-Path -LiteralPath (Join-Path $root 'target\debug\fluxheim.exe')).Path
if (-not $binary.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) {
    throw "native Windows smoke requires a Windows executable: $binary"
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

function New-WindowsSmokeCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$CertificatePath,
        [Parameter(Mandatory = $true)][string]$PrivateKeyPath
    )

    $rsa = [Security.Cryptography.RSA]::Create(2048)
    try {
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=static.test',
            $rsa,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $san = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $san.AddDnsName('static.test')
        $san.AddDnsName('localhost')
        $san.AddIpAddress([Net.IPAddress]::Loopback)
        $request.CertificateExtensions.Add($san.Build())
        $certificate = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-5),
            [DateTimeOffset]::UtcNow.AddDays(1)
        )
        try {
            [IO.File]::WriteAllText(
                $CertificatePath,
                (ConvertTo-Pem -Label 'CERTIFICATE' -Bytes $certificate.RawData),
                [Text.Encoding]::ASCII
            )
            [IO.File]::WriteAllText(
                $PrivateKeyPath,
                (ConvertTo-Pem -Label 'PRIVATE KEY' -Bytes $rsa.ExportPkcs8PrivateKey()),
                [Text.Encoding]::ASCII
            )
        } finally {
            $certificate.Dispose()
        }
    } finally {
        $rsa.Dispose()
    }
}

function New-WindowsSmokeUpstreamCertificate {
    param([Parameter(Mandatory = $true)][string]$CertificateAuthorityPath)

    $caKey = [Security.Cryptography.RSA]::Create(2048)
    $originKey = [Security.Cryptography.RSA]::Create(2048)
    $caCertificate = $null
    $issuedCertificate = $null
    $certificateWithKey = $null
    $pkcs12 = $null
    try {
        $caRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=Fluxheim Windows upstream smoke CA',
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
            [DateTimeOffset]::UtcNow.AddDays(2)
        )

        [IO.File]::WriteAllText(
            $CertificateAuthorityPath,
            (ConvertTo-Pem -Label 'CERTIFICATE' -Bytes $caCertificate.RawData),
            [Text.Encoding]::ASCII
        )

        $originRequest = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=origin.windows.test',
            $originKey,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        [void]$originRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
                $false, $false, 0, $true
            )
        )
        $originUsage = [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature `
            -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
        [void]$originRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                $originUsage, $true
            )
        )
        $serverAuthentication = [Security.Cryptography.OidCollection]::new()
        [void]$serverAuthentication.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
        [void]$originRequest.CertificateExtensions.Add(
            [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
                $serverAuthentication, $true
            )
        )
        $originSan =
            [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        [void]$originSan.AddDnsName('origin.windows.test')
        [void]$originRequest.CertificateExtensions.Add($originSan.Build())

        $serial = [byte[]]::new(16)
        [Security.Cryptography.RandomNumberGenerator]::Fill($serial)
        $serial[0] = $serial[0] -band 0x7f
        $serial[0] = $serial[0] -bor 0x01
        $issuedCertificate = $originRequest.Create(
            $caCertificate,
            [DateTimeOffset]::UtcNow.AddMinutes(-5),
            [DateTimeOffset]::UtcNow.AddDays(1),
            $serial
        )
        $certificateWithKey =
            [Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey(
            $issuedCertificate,
            $originKey
        )
        if (-not $certificateWithKey.HasPrivateKey) {
            throw 'Windows upstream smoke certificate has no private key'
        }
        $pkcs12 = $certificateWithKey.Export(
            [Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12,
            [string]::Empty
        )
        $detachedCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $pkcs12,
            [string]::Empty,
            [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
        )
        if (-not $detachedCertificate.HasPrivateKey) {
            $detachedCertificate.Dispose()
            throw 'Windows upstream smoke certificate import lost its private key'
        }
        return $detachedCertificate
    } finally {
        if ($null -ne $pkcs12) {
            [Array]::Clear($pkcs12, 0, $pkcs12.Length)
        }
        if ($null -ne $certificateWithKey) {
            $certificateWithKey.Dispose()
        }
        if ($null -ne $issuedCertificate) {
            $issuedCertificate.Dispose()
        }
        if ($null -ne $caCertificate) {
            $caCertificate.Dispose()
        }
        $originKey.Dispose()
        $caKey.Dispose()
    }
}

function Invoke-FluxheimRequest {
    param(
        [Parameter(Mandatory = $true)][Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][Uri]$Uri,
        [string]$HostHeader,
        [string]$BearerToken
    )

    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $Uri)
    if (-not [string]::IsNullOrEmpty($HostHeader)) {
        $request.Headers.Host = $HostHeader
    }
    if (-not [string]::IsNullOrEmpty($BearerToken)) {
        $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new(
            'Bearer',
            $BearerToken
        )
    }
    try {
        return $Client.SendAsync($request).GetAwaiter().GetResult()
    } finally {
        $request.Dispose()
    }
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class FluxheimWindowsSmokeOrigin : IDisposable
{
    private readonly TcpListener listener;
    private readonly string label;
    private readonly X509Certificate2 certificate;
    private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
    private Task acceptLoop;
    private string lastError;

    public string LastError
    {
        get { return Volatile.Read(ref this.lastError); }
    }

    public FluxheimWindowsSmokeOrigin(int port, string label)
        : this(port, label, null)
    {
    }

    public FluxheimWindowsSmokeOrigin(int port, string label, X509Certificate2 certificate)
    {
        this.listener = new TcpListener(IPAddress.Loopback, port);
        this.label = label;
        this.certificate = certificate;
    }

    public void Start()
    {
        this.listener.Start();
        this.acceptLoop = Task.Run(() => this.AcceptLoopAsync());
    }

    private async Task AcceptLoopAsync()
    {
        while (!this.cancellation.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await this.listener.AcceptTcpClientAsync().ConfigureAwait(false);
            }
            catch (Exception) when (this.cancellation.IsCancellationRequested)
            {
                return;
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    await this.ServeAsync(client).ConfigureAwait(false);
                }
                catch (Exception error)
                {
                    StringBuilder diagnostic = new StringBuilder();
                    for (Exception current = error; current != null; current = current.InnerException)
                    {
                        if (diagnostic.Length != 0)
                        {
                            diagnostic.Append(" -> ");
                        }
                        diagnostic.Append(current.GetType().FullName);
                        diagnostic.Append(" (0x");
                        diagnostic.Append(current.HResult.ToString("X8"));
                        diagnostic.Append(')');
                        Win32Exception win32 = current as Win32Exception;
                        if (win32 != null)
                        {
                            diagnostic.Append(" native=0x");
                            diagnostic.Append(win32.NativeErrorCode.ToString("X8"));
                        }
                    }
                    Interlocked.Exchange(ref this.lastError, diagnostic.ToString());
                }
            });
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        using (client)
        using (NetworkStream networkStream = client.GetStream())
        {
            Stream stream = networkStream;
            SslStream tlsStream = null;
            if (this.certificate != null)
            {
                tlsStream = new SslStream(networkStream, false);
                SslServerAuthenticationOptions options = new SslServerAuthenticationOptions
                {
                    ServerCertificate = this.certificate,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    ApplicationProtocols = new List<SslApplicationProtocol>
                    {
                        SslApplicationProtocol.Http11,
                    },
                };
                await tlsStream.AuthenticateAsServerAsync(options, CancellationToken.None)
                    .ConfigureAwait(false);
                stream = tlsStream;
            }

            byte[] request = new byte[16384];
            int used = 0;
            try
            {
                while (used < request.Length)
                {
                    int read = await stream.ReadAsync(request, used, request.Length - used)
                        .ConfigureAwait(false);
                    if (read == 0)
                    {
                        return;
                    }
                    used += read;
                    if (used >= 4 && request[used - 4] == 13 && request[used - 3] == 10 &&
                        request[used - 2] == 13 && request[used - 1] == 10)
                    {
                        break;
                    }
                }

                string firstLine = Encoding.ASCII.GetString(request, 0, used).Split('\n')[0].Trim();
                string[] fields = firstLine.Split(' ');
                string target = fields.Length >= 2 ? fields[1] : "/";
                byte[] body = Encoding.ASCII.GetBytes(this.label + " path=" + target + "\n");
                string headers = "HTTP/1.1 200 OK\r\n" +
                    "Content-Type: text/plain; charset=ascii\r\n" +
                    "Cache-Control: public, max-age=120\r\n" +
                    "Content-Length: " + body.Length + "\r\n" +
                    "X-Origin: " + this.label + "\r\n" +
                    "Connection: close\r\n\r\n";
                byte[] encodedHeaders = Encoding.ASCII.GetBytes(headers);
                await stream.WriteAsync(encodedHeaders, 0, encodedHeaders.Length).ConfigureAwait(false);
                await stream.WriteAsync(body, 0, body.Length).ConfigureAwait(false);
            }
            finally
            {
                if (tlsStream != null)
                {
                    tlsStream.Dispose();
                }
            }
        }
    }

    public void Dispose()
    {
        this.cancellation.Cancel();
        this.listener.Stop();
        if (this.acceptLoop != null)
        {
            try
            {
                this.acceptLoop.GetAwaiter().GetResult();
            }
            catch (Exception) when (this.cancellation.IsCancellationRequested)
            {
            }
        }
        this.cancellation.Dispose();
    }
}
'@

$runId = [Guid]::NewGuid().ToString('N')
$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
if (-not [IO.Path]::IsPathFullyQualified($temporaryRoot)) {
    throw "Windows temporary directory is not fully qualified: $temporaryRoot"
}
$testRoot = Join-Path $temporaryRoot "fluxheim-windows-smoke-$runId"
$publicRoot = Join-Path $testRoot 'public'
$cacheRoot = Join-Path $testRoot 'cache'
$runtimeRoot = Join-Path $testRoot 'run'
$snapshotRoot = Join-Path $testRoot 'snapshots'
$tlsRoot = Join-Path $testRoot 'tls'
$certificatePath = Join-Path $tlsRoot 'certificate.pem'
$privateKeyPath = Join-Path $tlsRoot 'private-key.pem'
$upstreamCaPath = Join-Path $tlsRoot 'upstream-ca.pem'
$configPath = Join-Path $testRoot 'fluxheim.toml'
$stdoutPath = Join-Path $testRoot 'fluxheim.stdout.log'
$stderrPath = Join-Path $testRoot 'fluxheim.stderr.log'
$restartStdoutPath = Join-Path $testRoot 'fluxheim-restart.stdout.log'
$restartStderrPath = Join-Path $testRoot 'fluxheim-restart.stderr.log'
$consoleHelperPath = Join-Path $root 'scripts\windows_console_signal_helper.ps1'
$powershellPath = (Get-Process -Id $PID).Path
$process = $null
$gracefulHarness = $null
$gracefulProcessId = $null
$originOne = $null
$originTwo = $null
$originTls = $null
$originTlsCertificate = $null
$previousAdminToken = $env:FLUXHEIM_WINDOWS_SMOKE_ADMIN_TOKEN
$succeeded = $false

New-Item -ItemType Directory -Force `
    -Path $publicRoot, $cacheRoot, $runtimeRoot, $snapshotRoot, $tlsRoot | Out-Null
Set-Content -LiteralPath (Join-Path $publicRoot 'index.html') `
    -Value '<!doctype html><title>Fluxheim Windows smoke</title><h1>windows-static-ok</h1>' `
    -Encoding ascii
Set-Content -LiteralPath (Join-Path $publicRoot 'asset.webp') `
    -Value 'windows-cache-ok' -Encoding ascii
New-WindowsSmokeCertificate `
    -CertificatePath $certificatePath `
    -PrivateKeyPath $privateKeyPath
$originTlsCertificate = New-WindowsSmokeUpstreamCertificate `
    -CertificateAuthorityPath $upstreamCaPath

$port = Get-FreeTcpPort
$tlsPort = Get-FreeTcpPort
$adminPort = Get-FreeTcpPort
$metricsPort = Get-FreeTcpPort
$originOnePort = Get-FreeTcpPort
$originTwoPort = Get-FreeTcpPort
$originTlsPort = Get-FreeTcpPort
$publicToml = ConvertTo-TomlPath $publicRoot
$cacheToml = ConvertTo-TomlPath $cacheRoot
$runtimeToml = ConvertTo-TomlPath $runtimeRoot
$snapshotToml = ConvertTo-TomlPath $snapshotRoot
$certificateToml = ConvertTo-TomlPath $certificatePath
$privateKeyToml = ConvertTo-TomlPath $privateKeyPath
$upstreamCaToml = ConvertTo-TomlPath $upstreamCaPath
$config = @"
[server]
listen = ["127.0.0.1:$port"]
tls_listen = ["127.0.0.1:$tlsPort"]
default_vhost = "static.test"
trusted_proxies = []

[server.process]
pid_file = "$runtimeToml/fluxheim.pid"
upgrade_sock = "$runtimeToml/fluxheim-upgrade.sock"
certificate_reload_sock = "$runtimeToml/fluxheim-cert-reload.sock"
graceful_shutdown_timeout_seconds = 5
max_retries = 1

[admin]
enabled = true
listen = "127.0.0.1:$adminPort"
require_loopback = true
token_env = "FLUXHEIM_WINDOWS_SMOKE_ADMIN_TOKEN"
snapshot_store = "$snapshotToml"

[admin.health]
unauthenticated = true

[metrics]
enabled = true
listen = "127.0.0.1:$metricsPort"
require_loopback = true

[logging]
level = "warn"
format = "text"

[logging.access]
enabled = false
request_id = false

[headers.response]
enabled = true
x_content_type_options = "nosniff"
x_frame_options = "DENY"
referrer_policy = "no-referrer"
unset = ["server", "x-powered-by"]

[tls]
enabled = true
backend = "rustls"

[[tls.certificates]]
cert_path = "$certificateToml"
key_path = "$privateKeyToml"

[cache]
enabled = false

[[vhosts]]
name = "static.test"
hosts = ["static.test"]

[vhosts.tls]
enabled = true

[vhosts.tls.certificate]
cert_path = "$certificateToml"
key_path = "$privateKeyToml"

[vhosts.cache]
enabled = true
local_static = true
status_header = "x-cache-status"
status_reason_header = "x-cache-reason"
image_extensions = ["webp"]
content_types = ["image/webp"]
max_object_bytes = "1MiB"

[vhosts.cache.memory]
enabled = true
max_size_bytes = "16MiB"

[vhosts.web]
root = "$publicToml"
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=60"

[[vhosts]]
name = "proxy.test"
hosts = ["proxy.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:$originOnePort"]
upstream_tls = false

[[vhosts]]
name = "disk-cache.test"
hosts = ["disk-cache.test"]

[vhosts.cache]
enabled = true
status_header = "x-cache-status"
status_reason_header = "x-cache-reason"
image_extensions = ["webp"]
content_types = ["text/plain"]
max_object_bytes = "1MiB"

[vhosts.cache.memory]
enabled = false

[vhosts.cache.disk]
enabled = true
backend = "storage-bin"
path = "$cacheToml"
max_size_bytes = "8MiB"

[vhosts.cache.disk.storage_bin]
bin_size_bytes = "1MiB"
preallocate = false
max_open_bins = 4

[vhosts.proxy]
upstreams = ["127.0.0.1:$originOnePort"]
upstream_tls = false

[[vhosts]]
name = "load-balancer.test"
hosts = ["load-balancer.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:$originOnePort", "127.0.0.1:$originTwoPort"]
upstream_aliases = ["origin-one", "origin-two"]
upstream_tls = false

[vhosts.proxy.load_balance]
selection = "round-robin"
max_iterations = 64
all_down_status = 503

[[vhosts]]
name = "upstream-tls.test"
hosts = ["upstream-tls.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:$originTlsPort"]
upstream_tls = true
upstream_sni = "origin.windows.test"
upstream_verify_cert = true
upstream_verify_hostname = true
upstream_ca_path = "$upstreamCaToml"
upstream_http_version = "http1"

[[vhosts]]
name = "upstream-tls-invalid.test"
hosts = ["upstream-tls-invalid.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:$originTlsPort"]
upstream_tls = true
upstream_sni = "wrong-origin.windows.test"
upstream_verify_cert = true
upstream_verify_hostname = true
upstream_ca_path = "$upstreamCaToml"
upstream_http_version = "http1"
"@
Set-Content -LiteralPath $configPath -Value $config -Encoding utf8

try {
    $originOne = [FluxheimWindowsSmokeOrigin]::new($originOnePort, 'origin-one')
    $originTwo = [FluxheimWindowsSmokeOrigin]::new($originTwoPort, 'origin-two')
    $originTls = [FluxheimWindowsSmokeOrigin]::new(
        $originTlsPort,
        'verified-upstream-tls',
        $originTlsCertificate
    )
    $originOne.Start()
    $originTwo.Start()
    $originTls.Start()

    $env:FLUXHEIM_WINDOWS_SMOKE_ADMIN_TOKEN = 'windows-admin-smoke-token'
    & $binary --config $configPath --validate-config
    if ($LASTEXITCODE -ne 0) {
        throw 'native Windows smoke configuration validation failed'
    }

    $process = Start-Process -FilePath $binary `
        -ArgumentList @('--config', $configPath) `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -PassThru

    $handler = [Net.Http.HttpClientHandler]::new()
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(2)
    try {
        $baseUri = [Uri]"http://127.0.0.1:$port/"
        $response = $null
        for ($attempt = 0; $attempt -lt 100; $attempt++) {
            if ($process.HasExited) {
                throw "Fluxheim exited before readiness with code $($process.ExitCode)"
            }
            try {
                $response = Invoke-FluxheimRequest -Client $client -Uri $baseUri `
                    -HostHeader 'static.test'
                if ([int]$response.StatusCode -eq 200) {
                    break
                }
                $response.Dispose()
                $response = $null
            } catch {
                Start-Sleep -Milliseconds 100
            }
        }
        if ($null -eq $response) {
            throw "timed out waiting for native Windows Fluxheim at $baseUri"
        }
        try {
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if (-not $body.Contains('windows-static-ok')) {
                throw 'native Windows static response body mismatch'
            }
            if (-not $response.Headers.Contains('x-content-type-options')) {
                throw 'native Windows static response omitted x-content-type-options'
            }
        } finally {
            $response.Dispose()
        }

        $tlsHandler = [Net.Http.HttpClientHandler]::new()
        $tlsHandler.ServerCertificateCustomValidationCallback =
            [Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
        $tlsClient = [Net.Http.HttpClient]::new($tlsHandler)
        $tlsClient.Timeout = [TimeSpan]::FromSeconds(5)
        try {
            $tlsUri = [Uri]"https://127.0.0.1:$tlsPort/"
            $tlsResponse = Invoke-FluxheimRequest -Client $tlsClient -Uri $tlsUri `
                -HostHeader 'static.test'
            try {
                $tlsBody = $tlsResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                if ([int]$tlsResponse.StatusCode -ne 200 -or
                    -not $tlsBody.Contains('windows-static-ok')) {
                    throw 'native Windows TLS response mismatch'
                }
            } finally {
                $tlsResponse.Dispose()
            }
        } finally {
            $tlsClient.Dispose()
            $tlsHandler.Dispose()
        }

        $assetUri = [Uri]"http://127.0.0.1:$port/asset.webp"
        $first = Invoke-FluxheimRequest -Client $client -Uri $assetUri `
            -HostHeader 'static.test'
        try {
            $firstBody = $first.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $firstStatus = ($first.Headers.GetValues('x-cache-status') | Select-Object -First 1)
            if ([int]$first.StatusCode -ne 200 -or $firstBody.Trim() -ne 'windows-cache-ok') {
                throw 'native Windows first cache response mismatch'
            }
            if ($firstStatus -ne 'MISS') {
                throw "native Windows first cache response was $firstStatus, expected MISS"
            }
        } finally {
            $first.Dispose()
        }

        $second = Invoke-FluxheimRequest -Client $client -Uri $assetUri `
            -HostHeader 'static.test'
        try {
            $secondBody = $second.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $secondStatus = ($second.Headers.GetValues('x-cache-status') | Select-Object -First 1)
            if ([int]$second.StatusCode -ne 200 -or $secondBody.Trim() -ne 'windows-cache-ok') {
                throw 'native Windows second cache response mismatch'
            }
            if ($secondStatus -ne 'HIT') {
                throw "native Windows second cache response was $secondStatus, expected HIT"
            }
        } finally {
            $second.Dispose()
        }

        $diskCacheUri = [Uri]"http://127.0.0.1:$port/windows-disk-cache.webp"
        $diskFirst = Invoke-FluxheimRequest -Client $client -Uri $diskCacheUri `
            -HostHeader 'disk-cache.test'
        try {
            $diskFirstBody = $diskFirst.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $diskFirstStatus = ($diskFirst.Headers.GetValues('x-cache-status') |
                Select-Object -First 1)
            if ([int]$diskFirst.StatusCode -ne 200 -or
                -not $diskFirstBody.Contains('origin-one path=/windows-disk-cache.webp')) {
                throw 'native Windows first disk-cache response mismatch'
            }
            if ($diskFirstStatus -ne 'MISS') {
                throw "native Windows first disk-cache response was $diskFirstStatus, expected MISS"
            }
        } finally {
            $diskFirst.Dispose()
        }

        $diskSecond = Invoke-FluxheimRequest -Client $client -Uri $diskCacheUri `
            -HostHeader 'disk-cache.test'
        try {
            $diskSecondBody = $diskSecond.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $diskSecondStatus = ($diskSecond.Headers.GetValues('x-cache-status') |
                Select-Object -First 1)
            if ([int]$diskSecond.StatusCode -ne 200 -or
                $diskSecondBody -ne $diskFirstBody) {
                throw 'native Windows second disk-cache response mismatch'
            }
            if ($diskSecondStatus -ne 'HIT') {
                throw "native Windows second disk-cache response was $diskSecondStatus, expected HIT"
            }
        } finally {
            $diskSecond.Dispose()
        }

        $proxyUri = [Uri]"http://127.0.0.1:$port/windows-proxy"
        $proxyResponse = Invoke-FluxheimRequest -Client $client -Uri $proxyUri `
            -HostHeader 'proxy.test'
        try {
            $proxyBody = $proxyResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ([int]$proxyResponse.StatusCode -ne 200 -or
                -not $proxyBody.Contains('origin-one path=/windows-proxy')) {
                throw 'native Windows reverse-proxy response mismatch'
            }
        } finally {
            $proxyResponse.Dispose()
        }

        $loadBalancerOrigins = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
        for ($requestIndex = 0; $requestIndex -lt 8; $requestIndex++) {
            $loadBalancerUri = [Uri]"http://127.0.0.1:$port/windows-lb/$requestIndex"
            $loadBalancerResponse = Invoke-FluxheimRequest -Client $client `
                -Uri $loadBalancerUri -HostHeader 'load-balancer.test'
            try {
                if ([int]$loadBalancerResponse.StatusCode -ne 200) {
                    throw 'native Windows load-balancer response was not HTTP 200'
                }
                $loadBalancerBody = $loadBalancerResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                if ($loadBalancerBody.Contains('origin-one')) {
                    [void]$loadBalancerOrigins.Add('origin-one')
                }
                if ($loadBalancerBody.Contains('origin-two')) {
                    [void]$loadBalancerOrigins.Add('origin-two')
                }
            } finally {
                $loadBalancerResponse.Dispose()
            }
        }
        if ($loadBalancerOrigins.Count -ne 2) {
            throw "native Windows load balancer reached only: $($loadBalancerOrigins -join ', ')"
        }

        $upstreamTlsUri = [Uri]"http://127.0.0.1:$port/windows-upstream-tls"
        $upstreamTlsResponse = Invoke-FluxheimRequest -Client $client -Uri $upstreamTlsUri `
            -HostHeader 'upstream-tls.test'
        try {
            $upstreamTlsBody =
                $upstreamTlsResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ([int]$upstreamTlsResponse.StatusCode -ne 200 -or
                -not $upstreamTlsBody.Contains(
                    'verified-upstream-tls path=/windows-upstream-tls'
                )) {
                $upstreamTlsStatus = [int]$upstreamTlsResponse.StatusCode
                $upstreamTlsBodyLength = [Text.Encoding]::UTF8.GetByteCount($upstreamTlsBody)
                $upstreamTlsOriginError = $originTls.LastError
                throw "native Windows verified upstream TLS response mismatch: status=$upstreamTlsStatus body_bytes=$upstreamTlsBodyLength origin_error=$upstreamTlsOriginError"
            }
        } finally {
            $upstreamTlsResponse.Dispose()
        }

        $invalidUpstreamTlsResponse = Invoke-FluxheimRequest -Client $client `
            -Uri $upstreamTlsUri -HostHeader 'upstream-tls-invalid.test'
        try {
            $invalidUpstreamTlsBody =
                $invalidUpstreamTlsResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ([int]$invalidUpstreamTlsResponse.StatusCode -ne 502 -or
                $invalidUpstreamTlsBody.Contains('verified-upstream-tls')) {
                throw 'native Windows upstream TLS hostname mismatch did not fail closed'
            }
        } finally {
            $invalidUpstreamTlsResponse.Dispose()
        }

        $adminHealthUri = [Uri]"http://127.0.0.1:$adminPort/_fluxheim/health"
        $adminHealth = Invoke-FluxheimRequest -Client $client -Uri $adminHealthUri
        try {
            if ([int]$adminHealth.StatusCode -ne 200) {
                throw 'native Windows admin health endpoint was not HTTP 200'
            }
        } finally {
            $adminHealth.Dispose()
        }

        $adminStatusUri = [Uri]"http://127.0.0.1:$adminPort/_fluxheim/status"
        $adminStatus = Invoke-FluxheimRequest -Client $client -Uri $adminStatusUri `
            -BearerToken 'windows-admin-smoke-token'
        try {
            $adminBody = $adminStatus.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ([int]$adminStatus.StatusCode -ne 200 -or
                -not $adminBody.Contains('"status":"ok"')) {
                throw 'native Windows authenticated admin status response mismatch'
            }
        } finally {
            $adminStatus.Dispose()
        }

        $metricsUri = [Uri]"http://127.0.0.1:$metricsPort/metrics"
        $metricsResponse = Invoke-FluxheimRequest -Client $client -Uri $metricsUri
        try {
            $metricsBody = $metricsResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ([int]$metricsResponse.StatusCode -ne 200 -or
                -not $metricsBody.Contains('fluxheim_proxy_requests_total')) {
                throw 'native Windows metrics endpoint omitted Fluxheim proxy metrics'
            }
        } finally {
            $metricsResponse.Dispose()
        }
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }

    $storageBinManifest = Join-Path $cacheRoot '.fluxheim-storage-bin-v1'
    $storageBinIndex = Join-Path $cacheRoot '.fluxheim-storage-bin-index-v1'
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if ((Test-Path -LiteralPath $storageBinManifest -PathType Leaf) -and
            (Test-Path -LiteralPath $storageBinIndex -PathType Leaf) -and
            $null -ne (Get-ChildItem -LiteralPath (Join-Path $cacheRoot 'bins') `
                -Filter '*.fhbin' -File -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 1)) {
            break
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $storageBinManifest -PathType Leaf) -or
        -not (Test-Path -LiteralPath $storageBinIndex -PathType Leaf)) {
        throw 'native Windows disk cache did not persist its manifest and index'
    }
    if ($null -eq (Get-ChildItem -LiteralPath (Join-Path $cacheRoot 'bins') `
        -Filter '*.fhbin' -File -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1)) {
        throw 'native Windows disk cache did not persist a storage-bin file'
    }

    Stop-Process -Id $process.Id -Force
    if (-not $process.WaitForExit(5000)) {
        throw 'native Windows Fluxheim did not stop for disk-cache restart'
    }
    $process = $null
    $originOne.Dispose()
    $originOne = $null

    $process = Start-Process -FilePath $binary `
        -ArgumentList @('--config', $configPath) `
        -RedirectStandardOutput $restartStdoutPath `
        -RedirectStandardError $restartStderrPath `
        -PassThru

    $restartHandler = [Net.Http.HttpClientHandler]::new()
    $restartClient = [Net.Http.HttpClient]::new($restartHandler)
    $restartClient.Timeout = [TimeSpan]::FromSeconds(2)
    try {
        $restartResponse = $null
        for ($attempt = 0; $attempt -lt 100; $attempt++) {
            if ($process.HasExited) {
                throw "restarted Fluxheim exited before disk-cache readiness with code $($process.ExitCode)"
            }
            try {
                $candidate = Invoke-FluxheimRequest -Client $restartClient -Uri $diskCacheUri `
                    -HostHeader 'disk-cache.test'
                if ([int]$candidate.StatusCode -eq 200) {
                    $restartResponse = $candidate
                    break
                }
                $candidate.Dispose()
            } catch {
                Start-Sleep -Milliseconds 100
            }
        }
        if ($null -eq $restartResponse) {
            throw 'timed out waiting for restarted Fluxheim disk-cache response'
        }
        try {
            $restartBody = $restartResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $restartStatus = ($restartResponse.Headers.GetValues('x-cache-status') |
                Select-Object -First 1)
            if ($restartStatus -ne 'HIT' -or $restartBody -ne $diskFirstBody) {
                throw 'restarted Windows Fluxheim did not serve the persisted disk-cache HIT'
            }
            if (-not $restartResponse.Headers.Contains('Age')) {
                throw 'restarted Windows disk-cache HIT omitted the Age header'
            }
        } finally {
            $restartResponse.Dispose()
        }
    } finally {
        $restartClient.Dispose()
        $restartHandler.Dispose()
    }

    Stop-Process -Id $process.Id -Force
    if (-not $process.WaitForExit(5000)) {
        throw 'restarted Windows Fluxheim did not stop before graceful-shutdown test'
    }
    $process.Dispose()
    $process = $null

    $harnessStart = [Diagnostics.ProcessStartInfo]::new()
    $harnessStart.FileName = $powershellPath
    [void]$harnessStart.ArgumentList.Add('-NoLogo')
    [void]$harnessStart.ArgumentList.Add('-NoProfile')
    [void]$harnessStart.ArgumentList.Add('-NonInteractive')
    [void]$harnessStart.ArgumentList.Add('-File')
    [void]$harnessStart.ArgumentList.Add($consoleHelperPath)
    [void]$harnessStart.ArgumentList.Add($binary)
    [void]$harnessStart.ArgumentList.Add($configPath)
    $harnessStart.UseShellExecute = $false
    $harnessStart.CreateNoWindow = $true
    $harnessStart.RedirectStandardInput = $true
    $harnessStart.RedirectStandardOutput = $true
    $harnessStart.RedirectStandardError = $true
    $gracefulHarness = [Diagnostics.Process]::Start($harnessStart)
    $startedTask = $gracefulHarness.StandardOutput.ReadLineAsync()
    if (-not $startedTask.Wait(10000)) {
        throw 'Windows graceful-shutdown harness timed out while starting Fluxheim'
    }
    $started = $startedTask.Result
    if ($started -notmatch '^STARTED=([0-9]+)$') {
        $harnessError = $gracefulHarness.StandardError.ReadToEnd()
        throw "Windows graceful-shutdown harness did not start Fluxheim: $harnessError"
    }
    $gracefulProcessId = [int]$Matches[1]

    $gracefulHandler = [Net.Http.HttpClientHandler]::new()
    $gracefulClient = [Net.Http.HttpClient]::new($gracefulHandler)
    $gracefulClient.Timeout = [TimeSpan]::FromSeconds(2)
    try {
        $gracefulReady = $false
        for ($attempt = 0; $attempt -lt 100; $attempt++) {
            if ($gracefulHarness.HasExited) {
                throw "Windows graceful-shutdown harness exited before readiness with code $($gracefulHarness.ExitCode)"
            }
            try {
                $readyResponse = Invoke-FluxheimRequest -Client $gracefulClient `
                    -Uri ([Uri]"http://127.0.0.1:$port/") -HostHeader 'static.test'
                try {
                    if ([int]$readyResponse.StatusCode -eq 200) {
                        $gracefulReady = $true
                        break
                    }
                } finally {
                    $readyResponse.Dispose()
                }
            } catch {
                Start-Sleep -Milliseconds 100
            }
        }
        if (-not $gracefulReady) {
            throw 'timed out waiting for isolated Windows graceful-shutdown process'
        }
    } finally {
        $gracefulClient.Dispose()
        $gracefulHandler.Dispose()
    }

    $gracefulHarness.StandardInput.WriteLine('stop')
    $gracefulHarness.StandardInput.Flush()
    $gracefulHarness.StandardInput.Close()
    if (-not $gracefulHarness.WaitForExit(20000)) {
        throw 'Windows graceful-shutdown harness timed out'
    }
    $gracefulError = $gracefulHarness.StandardError.ReadToEnd()
    if ($gracefulHarness.ExitCode -ne 0) {
        throw "Windows CTRL_BREAK graceful shutdown failed: $gracefulError"
    }
    $gracefulHarness.Dispose()
    $gracefulHarness = $null
    $gracefulProcessId = $null

    $succeeded = $true
    Write-Host 'native Windows static/downstream+upstream-TLS/memory+disk-cache/proxy/load-balancer/admin/metrics/graceful-shutdown smoke: ok'
} catch {
    if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
        [Console]::Error.WriteLine((Get-Content -LiteralPath $stderrPath -Raw))
    }
    if (Test-Path -LiteralPath $restartStderrPath -PathType Leaf) {
        [Console]::Error.WriteLine((Get-Content -LiteralPath $restartStderrPath -Raw))
    }
    throw
} finally {
    if ($null -ne $process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        [void]$process.WaitForExit(5000)
    }
    if ($null -ne $gracefulHarness -and -not $gracefulHarness.HasExited) {
        Stop-Process -Id $gracefulHarness.Id -Force -ErrorAction SilentlyContinue
        [void]$gracefulHarness.WaitForExit(5000)
    }
    if ($null -ne $gracefulHarness) {
        $gracefulHarness.Dispose()
    }
    if ($null -ne $gracefulProcessId) {
        Stop-Process -Id $gracefulProcessId -Force -ErrorAction SilentlyContinue
    }
    if ($null -eq $previousAdminToken) {
        Remove-Item Env:FLUXHEIM_WINDOWS_SMOKE_ADMIN_TOKEN -ErrorAction SilentlyContinue
    } else {
        $env:FLUXHEIM_WINDOWS_SMOKE_ADMIN_TOKEN = $previousAdminToken
    }
    if ($null -ne $originOne) {
        $originOne.Dispose()
    }
    if ($null -ne $originTwo) {
        $originTwo.Dispose()
    }
    if ($null -ne $originTls) {
        $originTls.Dispose()
    }
    if ($null -ne $originTlsCertificate) {
        $originTlsCertificate.Dispose()
    }
    if ($succeeded -and $env:FLUXHEIM_SMOKE_KEEP_LOGS -ne '1') {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    } else {
        Write-Host "native Windows smoke artifacts kept in $testRoot"
    }
}

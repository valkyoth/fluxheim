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
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class FluxheimWindowsSmokeOrigin : IDisposable
{
    private readonly TcpListener listener;
    private readonly string label;
    private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
    private Task acceptLoop;

    public FluxheimWindowsSmokeOrigin(int port, string label)
    {
        this.listener = new TcpListener(IPAddress.Loopback, port);
        this.label = label;
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

            _ = Task.Run(() => this.ServeAsync(client));
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        using (client)
        using (NetworkStream stream = client.GetStream())
        {
            byte[] request = new byte[16384];
            int used = 0;
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
                "Content-Length: " + body.Length + "\r\n" +
                "X-Origin: " + this.label + "\r\n" +
                "Connection: close\r\n\r\n";
            byte[] encodedHeaders = Encoding.ASCII.GetBytes(headers);
            await stream.WriteAsync(encodedHeaders, 0, encodedHeaders.Length).ConfigureAwait(false);
            await stream.WriteAsync(body, 0, body.Length).ConfigureAwait(false);
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
$runtimeRoot = Join-Path $testRoot 'run'
$snapshotRoot = Join-Path $testRoot 'snapshots'
$tlsRoot = Join-Path $testRoot 'tls'
$certificatePath = Join-Path $tlsRoot 'certificate.pem'
$privateKeyPath = Join-Path $tlsRoot 'private-key.pem'
$configPath = Join-Path $testRoot 'fluxheim.toml'
$stdoutPath = Join-Path $testRoot 'fluxheim.stdout.log'
$stderrPath = Join-Path $testRoot 'fluxheim.stderr.log'
$process = $null
$originOne = $null
$originTwo = $null
$previousAdminToken = $env:FLUXHEIM_WINDOWS_SMOKE_ADMIN_TOKEN
$succeeded = $false

New-Item -ItemType Directory -Force `
    -Path $publicRoot, $runtimeRoot, $snapshotRoot, $tlsRoot | Out-Null
Set-Content -LiteralPath (Join-Path $publicRoot 'index.html') `
    -Value '<!doctype html><title>Fluxheim Windows smoke</title><h1>windows-static-ok</h1>' `
    -Encoding ascii
Set-Content -LiteralPath (Join-Path $publicRoot 'asset.webp') `
    -Value 'windows-cache-ok' -Encoding ascii
New-WindowsSmokeCertificate `
    -CertificatePath $certificatePath `
    -PrivateKeyPath $privateKeyPath

$port = Get-FreeTcpPort
$tlsPort = Get-FreeTcpPort
$adminPort = Get-FreeTcpPort
$metricsPort = Get-FreeTcpPort
$originOnePort = Get-FreeTcpPort
$originTwoPort = Get-FreeTcpPort
$publicToml = ConvertTo-TomlPath $publicRoot
$runtimeToml = ConvertTo-TomlPath $runtimeRoot
$snapshotToml = ConvertTo-TomlPath $snapshotRoot
$certificateToml = ConvertTo-TomlPath $certificatePath
$privateKeyToml = ConvertTo-TomlPath $privateKeyPath
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
"@
Set-Content -LiteralPath $configPath -Value $config -Encoding utf8

try {
    $originOne = [FluxheimWindowsSmokeOrigin]::new($originOnePort, 'origin-one')
    $originTwo = [FluxheimWindowsSmokeOrigin]::new($originTwoPort, 'origin-two')
    $originOne.Start()
    $originTwo.Start()

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
        $tlsClient.Timeout = [TimeSpan]::FromSeconds(2)
        try {
            $tlsUri = [Uri]"https://localhost:$tlsPort/"
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

    $succeeded = $true
    Write-Host 'native Windows static/TLS/cache/proxy/load-balancer/admin/metrics smoke: ok'
} catch {
    if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
        Get-Content -LiteralPath $stderrPath | Write-Error
    }
    throw
} finally {
    if ($null -ne $process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        [void]$process.WaitForExit(5000)
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
    if ($succeeded -and $env:FLUXHEIM_SMOKE_KEEP_LOGS -ne '1') {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    } else {
        Write-Host "native Windows smoke artifacts kept in $testRoot"
    }
}

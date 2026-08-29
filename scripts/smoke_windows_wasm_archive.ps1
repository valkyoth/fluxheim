[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$')]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidateSet('x86_64', 'aarch64')]
    [string]$Architecture
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root

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

function Invoke-WasmSmokeRequest {
    param(
        [Parameter(Mandatory = $true)][Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][Uri]$Uri
    )

    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $Uri)
    $request.Headers.Host = 'wasm.test'
    try {
        return $Client.SendAsync($request).GetAwaiter().GetResult()
    } finally {
        $request.Dispose()
    }
}

Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class FluxheimWindowsWasmSmokeOrigin : IDisposable
{
    private readonly TcpListener listener;
    private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
    private Task acceptLoop;

    public FluxheimWindowsWasmSmokeOrigin(int port)
    {
        this.listener = new TcpListener(IPAddress.Loopback, port);
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
            _ = Task.Run(() => FluxheimWindowsWasmSmokeOrigin.ServeAsync(client));
        }
    }

    private static async Task ServeAsync(TcpClient client)
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

            byte[] body = Encoding.ASCII.GetBytes("windows-wasm-origin-ok\n");
            string headers = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/plain; charset=ascii\r\n" +
                "Content-Length: " + body.Length + "\r\n" +
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

$targetLabel = if ($Architecture -eq 'x86_64') {
    'x86_64-windows'
} else {
    'aarch64-windows'
}
$archiveName = "fluxheim-$Version-wasm-$targetLabel.zip"
$archivePath = Join-Path (Join-Path $root 'dist') $archiveName
if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    throw "Windows Wasm archive is missing: $archiveName"
}

$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
if (-not [IO.Path]::IsPathFullyQualified($temporaryRoot)) {
    throw "Windows temporary directory is not fully qualified: $temporaryRoot"
}
$testRoot = Join-Path $temporaryRoot "fluxheim-windows-wasm-smoke-$([Guid]::NewGuid().ToString('N'))"
$extractRoot = Join-Path $testRoot 'archive'
$pluginRoot = Join-Path $testRoot 'plugins'
$runtimeRoot = Join-Path $testRoot 'run'
$configPath = Join-Path $testRoot 'fluxheim.toml'
$stdoutPath = Join-Path $testRoot 'fluxheim.stdout.log'
$stderrPath = Join-Path $testRoot 'fluxheim.stderr.log'
$process = $null
$origin = $null
$succeeded = $false

New-Item -ItemType Directory -Force -Path $extractRoot, $pluginRoot, $runtimeRoot | Out-Null
Expand-Archive -LiteralPath $archivePath -DestinationPath $extractRoot
$bundleRoot = Join-Path $extractRoot "fluxheim-$Version-wasm-$targetLabel"
$binary = Join-Path $bundleRoot 'fluxheim.exe'
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw "Windows Wasm archive omitted fluxheim.exe: $archiveName"
}

& cargo.exe run --locked -p fluxheim-wasm --example build_policy_examples --quiet
if ($LASTEXITCODE -ne 0) {
    throw 'building Windows Wasm policy examples failed'
}
$sourcePlugin = Join-Path $root 'target\wasm-policy-examples\irules-access-policy.wasm'
$pluginPath = Join-Path $pluginRoot 'irules-access-policy.wasm'
Copy-Item -LiteralPath $sourcePlugin -Destination $pluginPath
$pluginHash = (Get-FileHash -LiteralPath $pluginPath -Algorithm SHA256).Hash.ToLowerInvariant()

$fluxheimPort = Get-FreeTcpPort
$originPort = Get-FreeTcpPort
$pluginRootToml = ConvertTo-TomlPath $pluginRoot
$pluginToml = ConvertTo-TomlPath $pluginPath
$runtimeToml = ConvertTo-TomlPath $runtimeRoot
$config = @"
[server]
listen = ["127.0.0.1:$fluxheimPort"]
default_vhost = "wasm.test"
trusted_proxies = []

[server.process]
pid_file = "$runtimeToml/fluxheim.pid"
upgrade_sock = "$runtimeToml/fluxheim-upgrade.sock"
certificate_reload_sock = "$runtimeToml/fluxheim-cert-reload.sock"

[logging]
level = "warn"
format = "text"

[logging.access]
enabled = false
request_id = false

[tls]
enabled = false
backend = "rustls"

[cache]
enabled = false

[wasm]
enabled = true
plugin_roots = ["$pluginRootToml"]
max_total_concurrent_executions = 8
max_total_cache_concurrent_executions = 4

[[wasm.plugins]]
name = "irules"
path = "$pluginToml"
sha256 = "$pluginHash"
phases = ["access-decision"]
fail_mode = "fail-closed"

[[wasm.attachments]]
plugin = "irules"
vhost = "wasm.test"
route = "admin"
priority = 100
phases = ["access-decision"]

[[vhosts]]
name = "wasm.test"
hosts = ["wasm.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:$originPort"]
upstream_tls = false

[[vhosts.routes]]
name = "admin"
path_prefix = "/admin/"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$originPort"]
upstream_tls = false
"@
Set-Content -LiteralPath $configPath -Value $config -Encoding utf8

try {
    $origin = [FluxheimWindowsWasmSmokeOrigin]::new($originPort)
    $origin.Start()

    & $binary --config $configPath --validate-config
    if ($LASTEXITCODE -ne 0) {
        throw 'archived Windows Wasm configuration validation failed'
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
        $publicUri = [Uri]"http://127.0.0.1:$fluxheimPort/public"
        $publicResponse = $null
        for ($attempt = 0; $attempt -lt 100; $attempt++) {
            if ($process.HasExited) {
                throw "archived Windows Wasm Fluxheim exited with code $($process.ExitCode)"
            }
            try {
                $publicResponse = Invoke-WasmSmokeRequest -Client $client -Uri $publicUri
                if ([int]$publicResponse.StatusCode -eq 200) {
                    break
                }
                $publicResponse.Dispose()
                $publicResponse = $null
            } catch {
                Start-Sleep -Milliseconds 100
            }
        }
        if ($null -eq $publicResponse) {
            throw 'timed out waiting for archived Windows Wasm Fluxheim'
        }
        try {
            $publicBody = $publicResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if (-not $publicBody.Contains('windows-wasm-origin-ok')) {
                throw 'archived Windows Wasm allow-path response mismatch'
            }
        } finally {
            $publicResponse.Dispose()
        }

        $deniedUri = [Uri]"http://127.0.0.1:$fluxheimPort/admin/panel"
        $deniedResponse = Invoke-WasmSmokeRequest -Client $client -Uri $deniedUri
        try {
            $deniedBody = $deniedResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ([int]$deniedResponse.StatusCode -ne 403 -or
                $deniedBody.Trim() -ne 'wasm access denied') {
                throw 'archived Windows Wasm deny-path response mismatch'
            }
        } finally {
            $deniedResponse.Dispose()
        }
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }

    $succeeded = $true
    Write-Host 'archived Windows Wasm policy allow/deny smoke: ok'
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
    if ($null -ne $origin) {
        $origin.Dispose()
    }
    if ($succeeded -and $env:FLUXHEIM_SMOKE_KEEP_LOGS -ne '1') {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    } else {
        Write-Host "archived Windows Wasm smoke artifacts kept in $testRoot"
    }
}

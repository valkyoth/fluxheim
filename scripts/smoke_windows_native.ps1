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

function Invoke-FluxheimRequest {
    param(
        [Parameter(Mandatory = $true)][Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][Uri]$Uri
    )

    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $Uri)
    $request.Headers.Host = 'static.test'
    try {
        return $Client.SendAsync($request).GetAwaiter().GetResult()
    } finally {
        $request.Dispose()
    }
}

$runId = [Guid]::NewGuid().ToString('N')
$testRoot = Join-Path $root "target\fluxheim-windows-smoke\$runId"
$publicRoot = Join-Path $testRoot 'public'
$runtimeRoot = Join-Path $testRoot 'run'
$configPath = Join-Path $testRoot 'fluxheim.toml'
$stdoutPath = Join-Path $testRoot 'fluxheim.stdout.log'
$stderrPath = Join-Path $testRoot 'fluxheim.stderr.log'
$process = $null
$succeeded = $false

New-Item -ItemType Directory -Force -Path $publicRoot, $runtimeRoot | Out-Null
Set-Content -LiteralPath (Join-Path $publicRoot 'index.html') `
    -Value '<!doctype html><title>Fluxheim Windows smoke</title><h1>windows-static-ok</h1>' `
    -Encoding ascii
Set-Content -LiteralPath (Join-Path $publicRoot 'asset.webp') `
    -Value 'windows-cache-ok' -Encoding ascii

$port = Get-FreeTcpPort
$publicToml = ConvertTo-TomlPath $publicRoot
$runtimeToml = ConvertTo-TomlPath $runtimeRoot
$config = @"
[server]
listen = ["127.0.0.1:$port"]
default_vhost = "static.test"
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

[headers.response]
enabled = true
x_content_type_options = "nosniff"
x_frame_options = "DENY"
referrer_policy = "no-referrer"
unset = ["server", "x-powered-by"]

[tls]
enabled = false
backend = "rustls"

[cache]
enabled = false

[[vhosts]]
name = "static.test"
hosts = ["static.test"]

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
"@
Set-Content -LiteralPath $configPath -Value $config -Encoding utf8

try {
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
                $response = Invoke-FluxheimRequest -Client $client -Uri $baseUri
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

        $assetUri = [Uri]"http://127.0.0.1:$port/asset.webp"
        $first = Invoke-FluxheimRequest -Client $client -Uri $assetUri
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

        $second = Invoke-FluxheimRequest -Client $client -Uri $assetUri
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
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }

    $succeeded = $true
    Write-Host 'native Windows static and memory-cache smoke: ok'
} catch {
    if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
        Get-Content -LiteralPath $stderrPath | Write-Error
    }
    throw
} finally {
    if ($null -ne $process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        $process.WaitForExit(5000)
    }
    if ($succeeded -and $env:FLUXHEIM_SMOKE_KEEP_LOGS -ne '1') {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    } else {
        Write-Host "native Windows smoke artifacts kept in $testRoot"
    }
}

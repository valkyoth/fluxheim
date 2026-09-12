[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^public-profiles-[0-9a-f]{16}$')]
    [string]$RunId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')]
    [string]$PublicName,

    [ValidateRange(1, 65535)]
    [int]$HttpPort = 80,

    [ValidateRange(1, 65535)]
    [int]$HttpsPort = 443,

    [ValidateRange(60, 1200)]
    [int]$WaitTimeoutSeconds = 600
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64') {
    throw 'public profile smoke requires native X64 Windows'
}
if ($HttpPort -eq $HttpsPort) {
    throw 'HTTP and HTTPS smoke ports must differ'
}
if (-not $PublicName.Contains('.') -or $PublicName.Contains('..')) {
    throw 'public profile smoke name must be a dotted DNS hostname'
}

$publicName = $PublicName.ToLowerInvariant()
$runRoot = Join-Path 'C:\FluxheimBuild\runs' $RunId
$tlsRoot = Join-Path $runRoot 'tls'
$siteRoot = Join-Path $runRoot 'site'
$cacheRoot = Join-Path $runRoot 'cache'
$originScriptPath = Join-Path $runRoot 'origin.py'
$certificatePath = Join-Path $tlsRoot 'certificate.pem'
$privateKeyPath = Join-Path $tlsRoot 'private-key.pem'
$process = $null
$origin = $null
$originOne = $null
$originTwo = $null
$succeeded = $false

function ConvertTo-TomlPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    return $Path.Replace('\', '/')
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

function Stop-OwnedProcess {
    param([Diagnostics.Process]$OwnedProcess)

    if ($null -eq $OwnedProcess) {
        return
    }
    if (-not $OwnedProcess.HasExited) {
        Stop-Process -Id $OwnedProcess.Id -Force -ErrorAction SilentlyContinue
        $OwnedProcess.WaitForExit(10000) | Out-Null
    }
    $OwnedProcess.Dispose()
}

function Wait-ForControl {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process
    )

    $path = Join-Path $runRoot $Name
    $deadline = [DateTime]::UtcNow.AddSeconds($WaitTimeoutSeconds)
    while (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        if ($Process.HasExited) {
            throw "Fluxheim exited while waiting for $Name with code $($Process.ExitCode)"
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "public profile smoke controller did not send $Name before timeout"
        }
        Start-Sleep -Milliseconds 200
    }
}

function Resolve-ProfileBinary {
    param([Parameter(Mandatory = $true)][string]$Profile)

    $archive = Join-Path $runRoot "fluxheim-$Profile.zip"
    $bundle = Join-Path $runRoot "bundle-$Profile"
    if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
        throw "Windows $Profile profile archive is missing: $archive"
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $bundle -Force
    $candidates = @(Get-ChildItem -LiteralPath $bundle -Filter 'fluxheim.exe' -File -Recurse)
    if ($candidates.Count -ne 1) {
        throw "expected one packaged $Profile fluxheim.exe, found $($candidates.Count)"
    }
    if ($candidates[0].FullName -notmatch "-$Profile-x86_64-windows[\\/]fluxheim[.]exe`$") {
        throw "archive is not the Windows x86_64 $Profile profile"
    }
    return $candidates[0].FullName
}

function Start-Origin {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $stdout = Join-Path $runRoot "$Label.stdout.log"
    $stderr = Join-Path $runRoot "$Label.stderr.log"
    $originProcess = Start-Process -FilePath 'python.exe' `
        -ArgumentList '-u', $originScriptPath, "$Port", $Label `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -PassThru -WindowStyle Hidden
    Wait-ForTcpPort -Port $Port -Process $originProcess -Name $Label
    return $originProcess
}

function Start-Fluxheim {
    param(
        [Parameter(Mandatory = $true)][string]$Binary,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$Stage
    )

    & $Binary --config $ConfigPath --validate-config
    if ($LASTEXITCODE -ne 0) {
        throw "packaged Windows $Stage profile rejected its smoke config"
    }
    $stdout = Join-Path $runRoot "$Stage.stdout.log"
    $stderr = Join-Path $runRoot "$Stage.stderr.log"
    $fluxheimProcess = Start-Process -FilePath $Binary `
        -ArgumentList '--config', $ConfigPath `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -PassThru -WindowStyle Hidden
    Wait-ForTcpPort -Port $HttpPort -Process $fluxheimProcess -Name "$Stage HTTP"
    Wait-ForTcpPort -Port $HttpsPort -Process $fluxheimProcess -Name "$Stage HTTPS"
    return $fluxheimProcess
}

function Write-CommonConfig {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)][string]$VhostBody
    )

    $runtimeToml = ConvertTo-TomlPath $RuntimeRoot
    $certificateToml = ConvertTo-TomlPath $certificatePath
    $privateKeyToml = ConvertTo-TomlPath $privateKeyPath
    return @"
[server]
listen = ["0.0.0.0:$HttpPort"]
tls_listen = ["0.0.0.0:$HttpsPort"]
default_vhost = "$publicName"
trusted_proxies = []

[server.host_routing]
strict = true

[server.process]
pid_file = "$runtimeToml/fluxheim.pid"
upgrade_sock = "$runtimeToml/fluxheim-upgrade.sock"
certificate_reload_sock = "$runtimeToml/fluxheim-cert-reload.sock"
max_retries = 4
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

$VhostBody
"@
}

New-Item -ItemType Directory -Force -Path $runRoot, $tlsRoot, $siteRoot, $cacheRoot | Out-Null
if (-not (Test-Path -LiteralPath $certificatePath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $privateKeyPath -PathType Leaf)) {
    throw 'controller did not upload the public profile smoke certificate and key'
}

[IO.File]::WriteAllText(
    (Join-Path $siteRoot 'index.html'),
    'fluxheim-windows-public-full-ok',
    [Text.Encoding]::ASCII
)
[IO.File]::WriteAllText($originScriptPath, @'
import http.server
import sys
import threading

port = int(sys.argv[1])
label = sys.argv[2]
counter = 0
lock = threading.Lock()

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        global counter
        with lock:
            counter += 1
            current = counter
        body = f"{label}|path={self.path}|count={current}".encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=ascii")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("X-Origin", label)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
server.serve_forever()
'@, [Text.Encoding]::ASCII)

try {
    $proxyBinary = Resolve-ProfileBinary -Profile 'proxy'
    $loadBalancerBinary = Resolve-ProfileBinary -Profile 'load-balancer'
    $cacheBinary = Resolve-ProfileBinary -Profile 'cache'
    $fullBinary = Resolve-ProfileBinary -Profile 'full'

    $originPort = Get-FreeTcpPort
    $origin = Start-Origin -Port $originPort -Label 'origin-proxy'
    $proxyRuntime = Join-Path $runRoot 'runtime-proxy'
    New-Item -ItemType Directory -Force -Path $proxyRuntime | Out-Null
    $proxyConfigPath = Join-Path $runRoot 'proxy.toml'
    $proxyVhost = @"
[vhosts.proxy]
upstreams = ["127.0.0.1:$originPort"]
upstream_tls = false
connect_timeout_secs = 5
read_timeout_secs = 5
send_timeout_secs = 5
"@
    Set-Content -LiteralPath $proxyConfigPath `
        -Value (Write-CommonConfig -RuntimeRoot $proxyRuntime -VhostBody $proxyVhost) `
        -Encoding utf8
    $process = Start-Fluxheim -Binary $proxyBinary -ConfigPath $proxyConfigPath -Stage 'proxy'
    Write-Output 'READY proxy'
    Wait-ForControl -Name 'next-proxy' -Process $process
    Stop-OwnedProcess $process
    $process = $null
    Stop-OwnedProcess $origin
    $origin = $null
    Start-Sleep -Milliseconds 300

    $originOnePort = Get-FreeTcpPort
    $originTwoPort = Get-FreeTcpPort
    $originOne = Start-Origin -Port $originOnePort -Label 'origin-lb-one'
    $originTwo = Start-Origin -Port $originTwoPort -Label 'origin-lb-two'
    $loadBalancerRuntime = Join-Path $runRoot 'runtime-load-balancer'
    New-Item -ItemType Directory -Force -Path $loadBalancerRuntime | Out-Null
    $loadBalancerConfigPath = Join-Path $runRoot 'load-balancer.toml'
    $loadBalancerVhost = @"
[vhosts.proxy]
upstreams = ["127.0.0.1:$originOnePort", "127.0.0.1:$originTwoPort"]
upstream_aliases = ["origin-lb-one", "origin-lb-two"]
upstream_tls = false
connect_timeout_secs = 2
read_timeout_secs = 5
send_timeout_secs = 5

[vhosts.proxy.load_balance]
selection = "round-robin"
max_iterations = 16
all_down_status = 503
"@
    Set-Content -LiteralPath $loadBalancerConfigPath `
        -Value (Write-CommonConfig `
            -RuntimeRoot $loadBalancerRuntime -VhostBody $loadBalancerVhost) `
        -Encoding utf8
    $process = Start-Fluxheim -Binary $loadBalancerBinary `
        -ConfigPath $loadBalancerConfigPath -Stage 'load-balancer'
    Write-Output 'READY load-balancer'
    Wait-ForControl -Name 'stop-lb-origin-one' -Process $process
    Stop-OwnedProcess $originOne
    $originOne = $null
    Write-Output 'READY load-balancer-failover'
    Wait-ForControl -Name 'next-load-balancer' -Process $process
    Stop-OwnedProcess $process
    $process = $null
    Stop-OwnedProcess $originTwo
    $originTwo = $null
    Start-Sleep -Milliseconds 300

    $cacheOriginPort = Get-FreeTcpPort
    $origin = Start-Origin -Port $cacheOriginPort -Label 'origin-cache'
    $cacheRuntime = Join-Path $runRoot 'runtime-cache'
    New-Item -ItemType Directory -Force -Path $cacheRuntime | Out-Null
    $cacheConfigPath = Join-Path $runRoot 'cache.toml'
    $cacheToml = ConvertTo-TomlPath $cacheRoot
    $cacheVhost = @"
[vhosts.cache]
enabled = true
status_header = "x-cache-status"
status_reason_header = "x-cache-reason"
image_extensions = ["webp"]
content_types = ["text/plain"]
max_object_bytes = "1MiB"

[vhosts.cache.memory]
enabled = true
max_size_bytes = "8MiB"

[vhosts.cache.disk]
enabled = true
backend = "storage-bin"
path = "$cacheToml"
max_size_bytes = "16MiB"

[vhosts.cache.disk.storage_bin]
bin_size_bytes = "1MiB"
preallocate = false
max_open_bins = 4

[vhosts.proxy]
upstreams = ["127.0.0.1:$cacheOriginPort"]
upstream_tls = false
connect_timeout_secs = 2
read_timeout_secs = 5
send_timeout_secs = 5
"@
    Set-Content -LiteralPath $cacheConfigPath `
        -Value (Write-CommonConfig -RuntimeRoot $cacheRuntime -VhostBody $cacheVhost) `
        -Encoding utf8
    $process = Start-Fluxheim -Binary $cacheBinary -ConfigPath $cacheConfigPath -Stage 'cache'
    Write-Output 'READY cache'
    Wait-ForControl -Name 'restart-cache' -Process $process
    Start-Sleep -Milliseconds 500
    Stop-OwnedProcess $process
    $process = $null
    Stop-OwnedProcess $origin
    $origin = $null
    Start-Sleep -Milliseconds 300
    $process = Start-Fluxheim -Binary $cacheBinary `
        -ConfigPath $cacheConfigPath -Stage 'cache-restarted'
    Write-Output 'READY cache-restarted-origin-offline'
    Wait-ForControl -Name 'next-cache' -Process $process
    Stop-OwnedProcess $process
    $process = $null
    Start-Sleep -Milliseconds 300

    $fullRuntime = Join-Path $runRoot 'runtime-full'
    New-Item -ItemType Directory -Force -Path $fullRuntime | Out-Null
    $siteToml = ConvertTo-TomlPath $siteRoot
    $fullConfigPath = Join-Path $runRoot 'full.toml'
    $fullVhost = @"
[vhosts.web]
root = "$siteToml"
index_files = ["index.html"]
deny_dotfiles = true
"@
    Set-Content -LiteralPath $fullConfigPath `
        -Value (Write-CommonConfig -RuntimeRoot $fullRuntime -VhostBody $fullVhost) `
        -Encoding utf8
    $process = Start-Fluxheim -Binary $fullBinary -ConfigPath $fullConfigPath -Stage 'full'
    Write-Output 'READY full'
    Wait-ForControl -Name 'stop' -Process $process
    $succeeded = $true
    Write-Output 'Windows public packaged-profile harness: ok'
} finally {
    Stop-OwnedProcess $process
    Stop-OwnedProcess $origin
    Stop-OwnedProcess $originOne
    Stop-OwnedProcess $originTwo
    if (-not $succeeded) {
        Get-ChildItem -LiteralPath $runRoot -Filter '*.stderr.log' -File `
            -ErrorAction SilentlyContinue | ForEach-Object {
                [Console]::Error.WriteLine("--- $($_.Name) ---")
                Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue |
                    ForEach-Object { [Console]::Error.WriteLine($_) }
            }
        [Console]::Error.WriteLine("Windows public profile smoke artifacts kept in $runRoot")
    }
}

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scripts = @(
    'scripts/build_release_assets.ps1',
    'scripts/prepare_windows_release_builder.ps1',
    'scripts/run_windows_release_builder.ps1',
    'scripts/smoke_windows_native.ps1',
    'scripts/smoke_windows_wasm_archive.ps1',
    'scripts/windows_console_signal_helper.ps1'
)

foreach ($relative in $scripts) {
    $path = Join-Path $root $relative
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $path,
        [ref]$tokens,
        [ref]$errors
    )
    if ($errors.Count -gt 0) {
        $messages = $errors | ForEach-Object { $_.Message }
        throw "$relative has PowerShell parse errors: $($messages -join '; ')"
    }
}

$consoleHelperPath = Join-Path $root 'scripts/windows_console_signal_helper.cs'
if (-not (Test-Path -LiteralPath $consoleHelperPath -PathType Leaf)) {
    throw 'Windows console signal helper source is missing'
}
$consoleHelper = Get-Content -LiteralPath $consoleHelperPath -Raw
foreach ($required in @(
    'public static int Run',
    'CreateNewConsole',
    'AttachConsole',
    'GenerateConsoleCtrlEvent',
    'CtrlBreakEvent',
    'WaitForSingleObject'
)) {
    if (-not $consoleHelper.Contains($required)) {
        throw "Windows console signal helper is missing required behavior: $required"
    }
}

$consoleHarnessPath = Join-Path $root 'scripts/windows_console_signal_helper.ps1'
$consoleHarness = Get-Content -LiteralPath $consoleHarnessPath -Raw
foreach ($required in @(
    'windows_console_signal_helper.cs',
    '$result = [FluxheimWindowsConsoleSignalHelper]::Run($Binary, $Config)',
    'exit $result'
)) {
    if (-not $consoleHarness.Contains($required)) {
        throw "Windows console signal harness is missing required behavior: $required"
    }
}
if ($consoleHarness.Contains('ConsoleApplication')) {
    throw 'Windows console signal harness must remain compatible with PowerShell 7.1 and newer'
}

$smoke = Get-Content -LiteralPath (Join-Path $root 'scripts/smoke_windows_native.ps1') -Raw
foreach ($required in @(
    '--validate-config',
    '[IO.Path]::GetTempPath()',
    'windows-static-ok',
    'x-content-type-options',
    'x-cache-status',
    "expected MISS",
    "expected HIT",
    'backend = "storage-bin"',
    'cargo.exe test --locked -p fluxheim-acme --lib --features acme-client',
    'native Windows ACME storage and lifecycle regressions failed',
    'rejects_managed_php_fpm_without_unix_process_support',
    'native Windows managed PHP-FPM config rejection regression failed',
    'managed_php_fpm_process_start_fails_closed_without_unix_support',
    'native Windows managed PHP-FPM runtime rejection regression failed',
    'native_route_proxy_php_route_executes_fastcgi_responder',
    'native Windows external TCP FastCGI regression failed',
    'native_http1_cache::lease_tests::storage_bin_',
    'native Windows storage-bin lease regressions failed',
    'absolute_storage_bin_root_skips_bare_windows_prefix',
    'native Windows storage-bin absolute-root regression failed',
    'absolute_native_cache_root_skips_bare_windows_prefix',
    'native Windows filesystem-cache absolute-root regression failed',
    '.fluxheim-storage-bin-index-v1',
    'restarted Windows Fluxheim did not serve the persisted disk-cache HIT',
    "Headers.Contains('Age')",
    'windows_console_signal_helper.ps1',
    'StandardOutput.ReadLineAsync()',
    "StandardInput.WriteLine('stop')",
    'Windows CTRL_BREAK graceful shutdown failed',
    'New-WindowsSmokeCertificate',
    'New-WindowsSmokeUpstreamCertificate',
    '[Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey(',
    '[Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet',
    '[Array]::Clear($pkcs12, 0, $pkcs12.Length)',
    'public string LastError',
    'Interlocked.Exchange(ref this.lastError, diagnostic.ToString())',
    'origin_error=$upstreamTlsOriginError',
    'tls_listen',
    'https://127.0.0.1:',
    'DangerousAcceptAnyServerCertificateValidator',
    'upstream_sni = "origin.windows.test"',
    'upstream_verify_cert = true',
    'upstream_verify_hostname = true',
    'verified-upstream-tls path=/windows-upstream-tls',
    'upstream-tls-invalid.test',
    'upstream TLS hostname mismatch did not fail closed',
    'FluxheimWindowsSmokeOrigin',
    'origin-one path=/windows-proxy',
    'load-balancer.test',
    '/_fluxheim/health',
    '/_fluxheim/status',
    'fluxheim_proxy_requests_total'
)) {
    if (-not $smoke.Contains($required)) {
        throw "Windows native smoke is missing required behavior: $required"
    }
}
if ($smoke.Contains('$issuedCertificate.CopyWithPrivateKey(')) {
    throw 'Windows native smoke must invoke the RSA certificate extension explicitly'
}

$runtimeShutdown = Get-Content -LiteralPath (Join-Path $root 'src/runtime_shutdown.rs') -Raw
foreach ($required in @(
    'tokio::signal::windows::{ctrl_break, ctrl_c}',
    'let mut terminate = ctrl_break().ok()',
    'signal.recv().await'
)) {
    if (-not $runtimeShutdown.Contains($required)) {
        throw "Windows runtime shutdown handling is missing required behavior: $required"
    }
}

$cacheBackend = Get-Content -LiteralPath `
    (Join-Path $root 'crates/fluxheim-server/src/native_http1_cache_backend.rs') -Raw
foreach ($required in @(
    '.share_mode(0)',
    'ERROR_SHARING_VIOLATION',
    'native_storage_bin_already_owned_error(root)'
)) {
    if (-not $cacheBackend.Contains($required)) {
        throw "Windows storage-bin lease is missing required behavior: $required"
    }
}

foreach ($relative in @(
    'crates/fluxheim-cache/src/storage_bin_fs_windows.rs',
    'crates/fluxheim-server/src/native_http1_cache_disk_path_windows.rs'
)) {
    $cachePathBoundary = Get-Content -LiteralPath (Join-Path $root $relative) -Raw
    foreach ($required in @(
        'Component::Prefix(_) | Component::CurDir => continue',
        'Component::ParentDir => return Ok(true)'
    )) {
        if (-not $cachePathBoundary.Contains($required)) {
            throw "$relative is missing Windows absolute-path handling: $required"
        }
    }
}
if ($smoke.Contains('target\fluxheim-windows-smoke')) {
    throw 'Windows native smoke must not place trusted runtime inputs below the inherited checkout ACL'
}

$wasmSmoke = Get-Content -LiteralPath `
    (Join-Path $root 'scripts/smoke_windows_wasm_archive.ps1') -Raw
foreach ($required in @(
    'Expand-Archive',
    'irules-access-policy.wasm',
    'Get-FileHash',
    'FluxheimWindowsWasmSmokeOrigin.ServeAsync(client)',
    'windows-wasm-origin-ok',
    'wasm access denied',
    'archived Windows Wasm policy allow/deny smoke: ok'
)) {
    if (-not $wasmSmoke.Contains($required)) {
        throw "Windows Wasm archive smoke is missing required behavior: $required"
    }
}

$archiveSmoke = Get-Content -LiteralPath `
    (Join-Path $root 'scripts/smoke_windows_archive_profiles.ps1') -Raw
foreach ($required in @(
    "@('full', 'wasm', 'cache', 'proxy', 'load-balancer', 'php', 'config-tester')",
    '[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()',
    "@('fluxheim.exe', 'fluxheim-acme.exe')",
    "@('fluxheim-config-tester.exe')",
    '& $binaryPath --version',
    'all seven Windows profile archive executables: ok'
)) {
    if (-not $archiveSmoke.Contains($required)) {
        throw "Windows all-profile archive smoke is missing required behavior: $required"
    }
}

$buildScript = Get-Content -LiteralPath (Join-Path $root 'build.rs') -Raw
foreach ($required in @(
    'CARGO_CFG_TARGET_OS',
    'CARGO_CFG_TARGET_ENV',
    'cargo:rustc-link-arg-bins=/STACK:8388608'
)) {
    if (-not $buildScript.Contains($required)) {
        throw "Windows build script is missing required stack-reserve contract: $required"
    }
}

$builder = Get-Content -LiteralPath (Join-Path $root 'scripts/build_release_assets.ps1') -Raw
foreach ($required in @(
    'scripts/portable_release_plan.py',
    'scripts/create_release_archives.py',
    'x86_64-pc-windows-msvc',
    'aarch64-pc-windows-msvc'
)) {
    if (-not $builder.Contains($required)) {
        throw "Windows archive builder is missing required contract: $required"
    }
}

$preparation = Get-Content -LiteralPath (Join-Path $root 'scripts/prepare_windows_release_builder.ps1') -Raw
foreach ($required in @(
    'PasswordAuthentication no',
    'AuthenticationMethods publickey',
    'AllowedSourceCidr',
    'TagAllowedSignersFile',
    'icacls.exe',
    'sshd.exe',
    'Get-NetFirewallRule'
)) {
    if (-not $preparation.Contains($required)) {
        throw "Windows preparation script is missing required hardening: $required"
    }
}

$release = Get-Content -LiteralPath (Join-Path $root 'scripts/run_windows_release_builder.ps1') -Raw
foreach ($required in @(
    'tag -v',
    'cargo.exe test --workspace --locked',
    'smoke_windows_native.ps1',
    'smoke_windows_archive_profiles.ps1',
    'smoke_windows_wasm_archive.ps1',
    'Get-CimInstance -ClassName Win32_OperatingSystem',
    'windows_os_caption=',
    'windows_os_version=',
    'windows_os_build=',
    'archive_count=7',
    'reproducible=true',
    'test_scope=workspace-native-all-archives-and-wasm-smoke'
)) {
    if (-not $release.Contains($required)) {
        throw "Windows release runner is missing required evidence: $required"
    }
}
if ($release.Contains('checkout main') -or $release.Contains('|| git checkout')) {
    throw 'Windows release runner must not fall back from the requested tag'
}

$ci = Get-Content -LiteralPath (Join-Path $root '.github/workflows/ci.yml') -Raw
foreach ($required in @(
    'name: Windows x86_64 portable compile gate',
    'RUSTFLAGS: -Dwarnings',
    'name: Run Windows workspace tests',
    'run: cargo test --workspace --locked',
    'name: Build and test Windows portable archives',
    'scripts/build_release_assets.ps1 -Version $version -Architecture x86_64',
    'scripts/smoke_windows_archive_profiles.ps1 -Version $version -Architecture x86_64'
)) {
    if (-not $ci.Contains($required)) {
        throw "Windows CI is missing required native test policy: $required"
    }
}

$manifest = Get-Content -LiteralPath (Join-Path $root 'Cargo.toml') -Raw
if (-not $manifest.Contains('exclude = ["vendor/fluxheim-openssl-fips-support"]')) {
    throw 'Windows workspace tests must exclude the Unix/OpenSSL FIPS support shim'
}

Write-Host 'Windows release scripts: ok'

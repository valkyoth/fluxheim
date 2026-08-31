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
    '$storageBinIndexLines.Count -gt 1',
    'storage-bin index did not flush an entry',
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
    'win32.NativeErrorCode.ToString("X8")',
    'SslServerAuthenticationOptions options',
    'SslApplicationProtocol.Http11',
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
    "[ValidateSet('GET', 'POST')][string]`$Method = 'GET'",
    "`$request.Headers.Add('X-Fluxheim-Message', `$SnapshotMessage)",
    'windows native baseline',
    'windows native candidate',
    '/_fluxheim/snapshots',
    '/_fluxheim/rollback',
    'native Windows snapshot rollback did not persist the current pointer',
    '$snapshotIntegrityRng.GetBytes($snapshotIntegrityKey)',
    'snapshot_integrity_key_file = "$snapshotIntegrityKeyToml"',
    '--integrity-key-file $snapshotIntegrityKeyPath doctor',
    'native Windows snapshot integrity doctor failed',
    'fluxheim_proxy_requests_total'
)) {
    if (-not $smoke.Contains($required)) {
        throw "Windows native smoke is missing required behavior: $required"
    }
}
if ($smoke.Contains('$issuedCertificate.CopyWithPrivateKey(')) {
    throw 'Windows native smoke must invoke the RSA certificate extension explicitly'
}
if ($smoke.Contains('X509KeyStorageFlags]::PersistKeySet')) {
    throw 'Windows native smoke must not persist generated TLS private keys'
}
if ($smoke.Contains('X509KeyStorageFlags]::UserKeySet')) {
    throw 'Windows native smoke must not place generated TLS private keys in the user key store'
}

$windowsTrust = @(
    Get-Content -LiteralPath `
        (Join-Path $root 'crates/fluxheim-config/src/fs_trust_windows.rs') -Raw
    Get-Content -LiteralPath `
        (Join-Path $root 'crates/fluxheim-config/src/fs_trust_windows_acl.rs') -Raw
) -join "`n"
foreach ($required in @(
    'TrustPolicy::ConfidentialSecret',
    'AccessRights::GenericRead',
    'AccessRights::FileGenericRead',
    'AccessRights::Bit6',
    'FILE_FLAG_OPEN_REPARSE_POINT',
    'opened_file_has_insecure_confidential_permissions',
    'create_confidential_file',
    'open_or_create_confidential_file',
    'create_private_directory_all',
    'AceFlags::ObjectInherit | AceFlags::ContainerInherit',
    'WRITE_DAC',
    '.share_mode(0)',
    'harden_confidential_file',
    'GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES',
    'SecurityInformation::ProtectedDacl'
)) {
    if (-not $windowsTrust.Contains($required)) {
        throw "Windows filesystem trust is missing required behavior: $required"
    }
}

$windowsTrustTests = Get-Content -LiteralPath `
    (Join-Path $root 'crates/fluxheim-config/src/fs_trust_windows_tests.rs') -Raw
foreach ($required in @(
    'everyone_read_access_is_only_rejected_for_confidential_files',
    'confidential_hardening_removes_inherited_everyone_access',
    'confidential_creation_is_exclusive_until_the_protected_acl_is_installed',
    'inherit_only_everyone_write_access_blocks_child_creation',
    'private_directory_tree_uses_protected_acl_creation',
    'everyone_delete_child_access_on_directory_is_rejected',
    'real_directory_flush_succeeds'
)) {
    if (-not $windowsTrustTests.Contains($required)) {
        throw "Windows filesystem trust tests are missing required regression: $required"
    }
}

$windowsCapability = @(
    Get-Content -LiteralPath `
        (Join-Path $root 'crates/fluxheim-windows-security/src/lib.rs') -Raw
    Get-Content -LiteralPath `
        (Join-Path $root 'crates/fluxheim-windows-security/src/windows_security_tests.rs') -Raw
) -join "`n"
foreach ($required in @(
    'NtCreateFile',
    'RootDirectory: parent.as_raw_handle() as HANDLE',
    'OBJ_DONT_REPARSE',
    'FILE_OPEN_REPARSE_POINT',
    'FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE',
    'create_private_directory',
    'create_hard_link_regular_file',
    'rename_regular_file',
    'remove_regular_file',
    'absolute_create_rename_open_and_remove_stay_handle_relative',
    'rejects_directory_junction_component'
)) {
    if (-not $windowsCapability.Contains($required)) {
        throw "Windows handle-relative filesystem boundary is missing required behavior: $required"
    }
}

foreach ($relative in @(
    'crates/fluxheim-cache/src/storage_bin_fs_windows.rs',
    'crates/fluxheim-server/src/native_http1_cache_disk_path_windows.rs'
)) {
    $cachePath = Get-Content -LiteralPath (Join-Path $root $relative) -Raw
    foreach ($required in @(
        'fluxheim_windows_security::open_existing_regular_file',
        'fluxheim_windows_security::rename_regular_file',
        'fluxheim_windows_security::remove_regular_file'
    )) {
        if (-not $cachePath.Contains($required)) {
            throw "Windows cache path boundary is missing handle-relative operation: $relative $required"
        }
    }
}

$staticResponse = Get-Content -LiteralPath `
    (Join-Path $root 'crates/fluxheim-server/src/native_http1_static_web_response.rs') -Raw
if (-not $staticResponse.Contains('fluxheim_windows_security::open_regular_file_beneath')) {
    throw 'Windows static serving must use the handle-relative no-reparse filesystem boundary'
}

$runtimeShutdown = Get-Content -LiteralPath (Join-Path $root 'src/runtime_shutdown.rs') -Raw
foreach ($required in @(
    'tokio::signal::windows::{ctrl_break, ctrl_c}',
    'failed to register Windows CTRL_C shutdown handler',
    'failed to register Windows CTRL_BREAK shutdown handler',
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
        'Component::ParentDir => return Ok(true)',
        'existing_path_or_parent_has_insecure_write_permissions'
    )) {
        if (-not $cachePathBoundary.Contains($required)) {
            throw "$relative is missing Windows absolute-path handling: $required"
        }
    }
}

$diskCachePath = Get-Content -LiteralPath `
    (Join-Path $root 'crates/fluxheim-server/src/native_http1_cache_disk_path_windows.rs') -Raw
foreach ($required in @(
    'file.take(max_bytes.saturating_add(1))',
    'native disk cache object changed while reading and exceeds read limit'
)) {
    if (-not $diskCachePath.Contains($required)) {
        throw "Windows disk-cache read is missing required bound: $required"
    }
}

$phpSpool = Get-Content -LiteralPath `
    (Join-Path $root 'crates/fluxheim-php-fpm/src/request_body.rs') -Raw
foreach ($required in @(
    'FILE_FLAG_DELETE_ON_CLOSE',
    'FILE_ATTRIBUTE_TEMPORARY',
    'FILE_FLAG_OPEN_REPARSE_POINT',
    'WRITE_DAC',
    '.read(true)',
    '.write(true)',
    '.share_mode(0)',
    'harden_confidential_file',
    'opened_file_has_insecure_confidential_permissions'
)) {
    if (-not $phpSpool.Contains($required)) {
        throw "Windows PHP request spool is missing required behavior: $required"
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
    'KbdInteractiveAuthentication no',
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
$globalPasswordAuthentication = $preparation.IndexOf('PasswordAuthentication no')
$firstMatch = [regex]::Match($preparation, '(?m)^\s*Match\s+')
if ($globalPasswordAuthentication -lt 0 -or
    ($firstMatch.Success -and $globalPasswordAuthentication -gt $firstMatch.Index)) {
    throw 'Windows preparation must disable password authentication before the first Match block'
}
foreach ($required in @(
    'sshd.exe" -T -C',
    'passwordauthentication no',
    'kbdinteractiveauthentication no',
    'authenticationmethods publickey'
)) {
    if (-not $preparation.Contains($required)) {
        throw "Windows preparation script is missing effective sshd validation: $required"
    }
}
foreach ($required in @(
    '$trustedDirectory /inheritance:r',
    '$allowedSigners /inheritance:r',
    '$BuildUser`:R',
    'Administrators:F'
)) {
    if (-not $preparation.Contains($required)) {
        throw "Windows preparation trust anchor is missing required ACL policy: $required"
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
    'name: Cross-check Windows ARM64 portable profiles',
    'rustup target add aarch64-pc-windows-msvc',
    'cargo check --locked --target aarch64-pc-windows-msvc --no-default-features --features profile-full',
    'cargo check --locked --target aarch64-pc-windows-msvc --no-default-features --features profile-wasm',
    'cargo check --locked --target aarch64-pc-windows-msvc --no-default-features --features profile-cache-edge',
    'cargo check --locked --target aarch64-pc-windows-msvc --no-default-features --features profile-proxy-edge',
    'cargo check --locked --target aarch64-pc-windows-msvc --no-default-features --features profile-load-balancer-edge',
    'cargo check --locked --target aarch64-pc-windows-msvc --no-default-features --features profile-web-server',
    'cargo check --locked --target aarch64-pc-windows-msvc --no-default-features --features profile-development',
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

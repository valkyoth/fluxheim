[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scripts = @(
    'scripts/install_windows_release_builder_tools.ps1',
    'scripts/build_release_assets.ps1',
    'scripts/prepare_windows_release_builder.ps1',
    'scripts/run_windows_release_builder.ps1',
    'scripts/smoke_windows_native.ps1',
    'scripts/smoke_windows_public_acme.ps1',
    'scripts/smoke_windows_public_php.ps1',
    'scripts/smoke_windows_public_profiles.ps1',
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

$publicAcmeSmoke = Get-Content -LiteralPath `
    (Join-Path $root 'scripts/smoke_windows_public_acme.ps1') -Raw
foreach ($required in @(
    "[ValidatePattern('^public-acme-[0-9a-f]{16}`$')]",
    '[string]$PublicName',
    '[string]$ContactEmail',
    '[string]$TermsOfServiceUrl',
    "-notmatch '-full-x86_64-windows[\\/]fluxheim[.]exe`$'",
    'listen = ["0.0.0.0:$HttpPort"]',
    'tls_listen = [`"0.0.0.0:$HttpsPort`"]',
    'automation = "external"',
    'https://acme-staging-v02.api.letsencrypt.org/directory',
    'terms_of_service_agreed = true',
    'terms_of_service_url = "$TermsOfServiceUrl"',
    '& $fluxheimBinary --config $configPath acme-renew',
    "Contains('certificate=installed')",
    "-Filter 'fullchain.pem'",
    "-Filter 'privkey.pem'",
    "[IO.File]::WriteAllText(",
    "'fluxheim-windows-public-acme-ok'",
    'Windows public ACME staging harness: ok'
)) {
    if (-not $publicAcmeSmoke.Contains($required)) {
        throw "Windows public ACME smoke is missing required behavior: $required"
    }
}

$publicAcmeControllerPath = Join-Path $root 'scripts/smoke_windows_public_acme.sh'
if (-not (Test-Path -LiteralPath $publicAcmeControllerPath -PathType Leaf)) {
    throw 'Windows public ACME smoke Linux controller is missing'
}
$publicAcmeController = Get-Content -LiteralPath $publicAcmeControllerPath -Raw
foreach ($required in @(
    'StrictHostKeyChecking=yes',
    'fluxheim-*-full-x86_64-windows.zip',
    'smoke_windows_public_acme.ps1',
    '-TermsOfServiceUrl $TERMS_URL',
    '--resolve "$PUBLIC_NAME:$HTTP_PORT:$PUBLIC_IP"',
    'openssl s_client -connect "$PUBLIC_IP:$HTTPS_PORT" -servername "$PUBLIC_NAME"',
    'openssl x509 -in "$PRESENTED_LEAF" -noout -checkhost "$PUBLIC_NAME"',
    'ISSUED_FINGERPRINT=',
    'PRESENTED_FINGERPRINT=',
    'Windows public Let''s Encrypt staging ACME HTTP-01 smoke: ok'
)) {
    if (-not $publicAcmeController.Contains($required)) {
        throw "Windows public ACME smoke controller is missing required behavior: $required"
    }
}

$publicProfilesSmoke = Get-Content -LiteralPath `
    (Join-Path $root 'scripts/smoke_windows_public_profiles.ps1') -Raw
foreach ($required in @(
    "[ValidatePattern('^public-profiles-[0-9a-f]{16}`$')]",
    "Resolve-ProfileBinary -Profile 'proxy'",
    "Resolve-ProfileBinary -Profile 'load-balancer'",
    "Resolve-ProfileBinary -Profile 'cache'",
    "Resolve-ProfileBinary -Profile 'full'",
    '-notmatch "-$Profile-x86_64-windows[\\/]fluxheim[.]exe`$"',
    'listen = ["0.0.0.0:$HttpPort"]',
    'tls_listen = ["0.0.0.0:$HttpsPort"]',
    'strict = true',
    'upstreams = ["127.0.0.1:$originPort"]',
    'selection = "round-robin"',
    'Stop-OwnedProcess $originOne',
    'READY load-balancer-failover',
    '[vhosts.cache.memory]',
    'backend = "storage-bin"',
    'Stop-OwnedProcess $origin',
    'READY cache-restarted-origin-offline',
    "'fluxheim-windows-public-full-ok'",
    'Windows public packaged-profile harness: ok'
)) {
    if (-not $publicProfilesSmoke.Contains($required)) {
        throw "Windows public profile smoke is missing required behavior: $required"
    }
}

$publicProfilesControllerPath = Join-Path $root 'scripts/smoke_windows_public_profiles.sh'
if (-not (Test-Path -LiteralPath $publicProfilesControllerPath -PathType Leaf)) {
    throw 'Windows public profile smoke Linux controller is missing'
}
$publicProfilesController = Get-Content -LiteralPath $publicProfilesControllerPath -Raw
foreach ($required in @(
    'StrictHostKeyChecking=yes',
    'fluxheim-*-$profile-x86_64-windows.zip',
    'smoke_windows_public_profiles.ps1',
    '--cacert "$CA_CERT"',
    '--resolve "$PUBLIC_NAME:$HTTPS_PORT:$PUBLIC_ADDRESS"',
    'strict Windows host routing returned $UNKNOWN_STATUS, expected 421',
    'public Windows load balancer did not reach both origins',
    'load-balancer failover reached an unexpected origin',
    'first public Windows cache status was $CACHE_STATUS, expected MISS',
    'second public Windows cache request was not an identical HIT',
    'restarted Windows cache did not serve the persistent HIT with origin offline',
    'packaged Windows full profile static response mismatch',
    'Windows public packaged proxy/load-balancer/cache/full profile smoke: ok'
)) {
    if (-not $publicProfilesController.Contains($required)) {
        throw "Windows public profile smoke controller is missing required behavior: $required"
    }
}

$publicPhpSmoke = Get-Content -LiteralPath `
    (Join-Path $root 'scripts/smoke_windows_public_php.ps1') -Raw
foreach ($required in @(
    "[ValidatePattern('^public-php-[0-9a-f]{16}`$')]",
    '[string]$PublicName',
    'php-8.4.25-nts-Win32-vs17-x64.zip',
    '43a8f67ed2e5223fafb21293c85976361808855405278cef2cf3037c3ae2529c',
    "Get-FileHash -LiteralPath `$phpArchivePath -Algorithm SHA256",
    "-notmatch '-php-x86_64-windows[\\/]fluxheim[.]exe`$'",
    'listen = ["0.0.0.0:$HttpPort"]',
    'tls_listen = ["0.0.0.0:$HttpsPort"]',
    'runtime = "php-fpm"',
    'mode = "external"',
    'tcp = "127.0.0.1:$fastCgiPort"',
    'allow_private_tcp_upstreams = true',
    "`$phpProcess = Start-Process -FilePath `$phpCgi",
    "`$fluxheimProcess = Start-Process -FilePath `$fluxheimBinary",
    "`$body = file_get_contents('php://input');",
    'fluxheim-windows-public-php-ok',
    'Windows public PHP harness: ok'
)) {
    if (-not $publicPhpSmoke.Contains($required)) {
        throw "Windows public PHP smoke is missing required behavior: $required"
    }
}

$publicPhpControllerPath = Join-Path $root 'scripts/smoke_windows_public_php.sh'
if (-not (Test-Path -LiteralPath $publicPhpControllerPath -PathType Leaf)) {
    throw 'Windows public PHP smoke Linux controller is missing'
}
$publicPhpController = Get-Content -LiteralPath $publicPhpControllerPath -Raw
foreach ($required in @(
    'StrictHostKeyChecking=yes',
    'fluxheim-*-php-x86_64-windows.zip',
    'smoke_windows_public_php.ps1',
    '-PublicName $PUBLIC_NAME',
    '--resolve "$PUBLIC_NAME:$HTTP_PORT:$PUBLIC_ADDRESS"',
    '--resolve "$PUBLIC_NAME:$HTTPS_PORT:$PUBLIC_ADDRESS"',
    '--cacert "$CA_FILE"',
    "--data-binary 'windows-fastcgi-post'",
    'scheme=http|https=off|method=GET',
    'scheme=https|https=on|method=POST',
    'Windows public HTTP/HTTPS real-PHP FastCGI smoke: ok'
)) {
    if (-not $publicPhpController.Contains($required)) {
        throw "Windows public PHP smoke controller is missing required behavior: $required"
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
    '-CertificatePath $originTlsCertificatePath',
    '-PrivateKeyPath $originTlsPrivateKeyPath',
    '$originKey.ExportPkcs8PrivateKey()',
    '$originTlsConfigPath',
    '$originTlsProcess = Start-Process',
    'native Windows Rustls origin configuration validation failed',
    'timed out waiting for native Windows Rustls origin',
    'native Windows Rustls origin response body mismatch',
    'Test-Path -LiteralPath $originTlsStderrPath -PathType Leaf',
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
foreach ($forbidden in @(
    'X509ContentType]::Pkcs12',
    'X509KeyStorageFlags]::UserKeySet',
    'SslServerAuthenticationOptions',
    'SslStream'
)) {
    if ($smoke.Contains($forbidden)) {
        throw "Windows native smoke must not depend on SSH-token-incompatible Schannel key persistence: $forbidden"
    }
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
    'opened_file_has_insecure_confidential_permissions',
    'fluxheim_windows_security::open_existing_regular_file_with_ancestors',
    'fluxheim_windows_security::create_new_regular_file_with_ancestors',
    'create_confidential_file',
    'open_or_create_confidential_file',
    'create_private_directory_all',
    'AceFlags::ObjectInherit | AceFlags::ContainerInherit',
    'harden_confidential_file',
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
    'confidential_reopen_allows_readable_integrity_safe_parent',
    'retained_path_type_check_distinguishes_files_directories_and_missing_targets',
    'inherit_only_everyone_write_access_blocks_child_creation',
    'rejected_integrity_creation_removes_the_new_child',
    'private_directory_tree_uses_protected_acl_creation',
    'everyone_delete_child_access_on_directory_is_rejected',
    'real_directory_flush_succeeds'
)) {
    if (-not $windowsTrustTests.Contains($required)) {
        throw "Windows filesystem trust tests are missing required regression: $required"
    }
}

$snapshotOperationsTests = Get-Content -LiteralPath `
    (Join-Path $root 'crates/fluxheim-snapshot/src/operations_tests.rs') -Raw
foreach ($required in @(
    '#[cfg(windows)]',
    'fluxheim_config::fs_trust::create_confidential_file(path)',
    'file.write_all(contents)',
    'file.sync_all()'
)) {
    if (-not $snapshotOperationsTests.Contains($required)) {
        throw "Windows snapshot test fixture is missing explicit confidential ACL hardening: $required"
    }
}

$windowsCapability = @(
    Get-Content -LiteralPath `
        (Join-Path $root 'crates/fluxheim-windows-security/src/lib.rs') -Raw
    Get-Content -LiteralPath `
        (Join-Path $root 'crates/fluxheim-windows-security/src/file_mutation.rs') -Raw
    Get-Content -LiteralPath `
        (Join-Path $root 'crates/fluxheim-windows-security/src/path_handles.rs') -Raw
    Get-Content -LiteralPath `
        (Join-Path $root 'crates/fluxheim-windows-security/src/relative_open.rs') -Raw
    Get-Content -LiteralPath `
        (Join-Path $root 'crates/fluxheim-windows-security/src/windows_security_tests.rs') -Raw
) -join "`n"
foreach ($required in @(
    'NtCreateFile',
    'RootDirectory: parent.as_raw_handle() as HANDLE',
    'OBJ_DONT_REPARSE',
    'FILE_OPEN_REPARSE_POINT',
    'FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE',
    'create_new_exclusive_regular_file_with_ancestors',
    'GENERIC_READ | GENERIC_WRITE | DELETE_ACCESS | READ_CONTROL | WRITE_DAC',
    'newly_created_regular_file_handle_supports_rejection_cleanup',
    'create_private_directory',
    'create_relative_private_directory',
    'private_directory_creation_rejects_a_junction_parent',
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
$windowsDirectoryMutation = Get-Content -LiteralPath `
    (Join-Path $root 'crates/fluxheim-windows-security/src/file_mutation.rs') -Raw
foreach ($required in @(
    'open_absolute_parent(path)?',
    'create_relative_private_directory(&parent, &name, descriptor.as_ptr().cast())?'
)) {
    if (-not $windowsDirectoryMutation.Contains($required)) {
        throw "Windows private-directory creation is missing retained-parent behavior: $required"
    }
}
if ($windowsDirectoryMutation.Contains('CreateDirectoryW')) {
    throw 'Windows private-directory creation must not re-resolve an absolute path'
}

foreach ($relative in @(
    'crates/fluxheim-cache/src/storage_bin_fs_windows.rs',
    'crates/fluxheim-server/src/native_http1_cache_disk_path_windows.rs'
)) {
    $cachePath = Get-Content -LiteralPath (Join-Path $root $relative) -Raw
    foreach ($required in @(
        'fluxheim_config::fs_trust::open_regular_file',
        'fluxheim_config::fs_trust::create_regular_file',
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
        'inspect_absolute_path',
        'Component::ParentDir',
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

$wasmFileBoundary = Get-Content -LiteralPath `
    (Join-Path $root 'crates/fluxheim-wasm/src/file.rs') -Raw
foreach ($required in @(
    'WASM_PLUGIN_FILE_ATTRIBUTE_REPARSE_POINT',
    'metadata.file_attributes()',
    'create_directory_junction',
    '.args(["/D", "/C", "mklink", "/J"])'
)) {
    if (-not $wasmFileBoundary.Contains($required)) {
        throw "Windows Wasm plugin path boundary is missing reparse-point coverage: $required"
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
    "[ValidateSet('x86_64')]"
)) {
    if (-not $builder.Contains($required)) {
        throw "Windows archive builder is missing required contract: $required"
    }
}

$releaseRunner = Get-Content -LiteralPath `
    (Join-Path $root 'scripts/run_windows_release_builder.ps1') -Raw
foreach ($required in @(
    "`$tempRoot = Join-Path `$runRoot 'temp'",
    '$env:TEMP = $tempRoot',
    '$env:TMP = $tempRoot',
    '$env:TEMP = $previousTemp',
    '$env:TMP = $previousTmp'
)) {
    if (-not $releaseRunner.Contains($required)) {
        throw "Windows release runner is missing isolated temporary storage: $required"
    }
}

$preparation = Get-Content -LiteralPath (Join-Path $root 'scripts/prepare_windows_release_builder.ps1') -Raw
$toolInstaller = Get-Content -LiteralPath `
    (Join-Path $root 'scripts/install_windows_release_builder_tools.ps1') -Raw
foreach ($required in @(
    "Install-WinGetPackage -Id 'Microsoft.PowerShell'",
    "Install-WinGetPackage -Id 'Git.Git'",
    "Install-WinGetPackage -Id 'Python.Python.3.13'",
    "Install-WinGetPackage -Id 'Kitware.CMake'",
    "Install-WinGetPackage -Id 'Microsoft.VisualStudio.2022.BuildTools'",
    'Microsoft.VisualStudio.Workload.VCTools',
    "`$rustupVersion = '1.29.1'",
    "`$rustupSha256 = '6f4bef66261261fcb43131be8720bab817d403a09edec7455c371974b90bdb7e'",
    '[Security.Cryptography.RandomNumberGenerator]::Create()',
    '$random.GetBytes($passwordBytes)',
    "[Security.Principal.SecurityIdentifier]::new('S-1-5-32-585')",
    'Get-LocalGroup -SID $openSshUsersSid',
    '$openSshMemberSids = @($openSshMembers | ForEach-Object { $_.SID.Value })',
    'Add-LocalGroupMember -Group $openSshUsers.Name -Member $localUser',
    'release build account must not be a local administrator'
)) {
    if (-not $toolInstaller.Contains($required)) {
        throw "Windows tool installer is missing required behavior: $required"
    }
}
foreach ($forbidden in @(
    "SetEnvironmentVariable('RUSTUP_HOME', `$rustupHome, 'Machine')",
    "SetEnvironmentVariable('CARGO_HOME', `$cargoHome, 'Machine')",
    'SetEnvironmentVariable(''Path'', "$machinePath;$cargoBin", ''Machine'')'
)) {
    if ($toolInstaller.Contains($forbidden)) {
        throw "Windows tool installer publishes build-account-writable Rust tools machine-wide: $forbidden"
    }
}
foreach ($required in @(
    "SetEnvironmentVariable('RUSTUP_HOME', `$null, 'Machine')",
    "SetEnvironmentVariable('CARGO_HOME', `$null, 'Machine')",
    'Remove-Item Env:RUSTUP_HOME -ErrorAction SilentlyContinue',
    'Remove-Item Env:CARGO_HOME -ErrorAction SilentlyContinue',
    '$openSshMemberSids = @($openSshMembers | ForEach-Object { $_.SID.Value })',
    "`$env:Path = `$pathEntries -join ';'",
    "Join-Path `$cargoBin 'rustup.exe'",
    "Join-Path `$cargoBin 'cargo.exe'"
)) {
    if (-not $toolInstaller.Contains($required)) {
        throw "Windows tool installer is missing process-scoped Rust environment hardening: $required"
    }
}
if ($toolInstaller.Contains("`$env:Path = `$cargoBin + ';'")) {
    throw 'Windows tool installer must not resolve build-account Rust tools from an elevated PATH'
}
$sshdPolicyHelper = Get-Content -LiteralPath `
    (Join-Path $root 'scripts/windows_release_sshd_config.ps1') -Raw
$preparationContract = $preparation + "`n" + $sshdPolicyHelper
foreach ($required in @(
    'PasswordAuthentication no',
    'AuthenticationMethods publickey',
    'AllowUsers $buildUserSsh',
    'AuthorizedKeysFile __PROGRAMDATA__/ssh/fluxheim-release/authorized_keys',
    'AllowedSourceCidr',
    'TagAllowedSignersFile',
    "[Security.Principal.SecurityIdentifier]::new('S-1-5-32-585')",
    'Get-LocalGroup -SID $openSshUsersSid',
    '$openSshMemberSids = @($openSshMembers | ForEach-Object { $_.SID.Value })',
    'Add-LocalGroupMember -Group $openSshUsers.Name -Member $localUser',
    'icacls.exe',
    'sshd.exe',
    'Get-NetFirewallRule'
)) {
    if (-not $preparationContract.Contains($required)) {
        throw "Windows preparation script is missing required hardening: $required"
    }
}
if (-not $preparation.Contains('Set-FluxheimReleaseBuilderSshdPolicy')) {
    throw 'Windows preparation must render its SSH policy through the tested configuration helper'
}
foreach ($required in @(
    'sshd.exe" -T -C',
    '$effectiveValidationUser = $env:USERNAME.ToLowerInvariant()',
    "`$authorizedKeysPolicy = 'AuthorizedKeysFile __PROGRAMDATA__/ssh/fluxheim-release/authorized_keys'",
    "`$firstMatch = [regex]::Match(`$config, '(?im)^\s*Match\s+')",
    'OpenSSH authorized-keys policy is not in global scope',
    'passwordauthentication no',
    'authenticationmethods publickey',
    'allowusers $BuildUser'
)) {
    if (-not $preparationContract.Contains($required)) {
        throw "Windows preparation script is missing effective sshd validation: $required"
    }
}

. (Join-Path $root 'scripts/windows_release_sshd_config.ps1')
$representativeSshdConfig = @"
PasswordAuthentication yes
Match Group administrators
    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
"@
$renderedSshdConfig = Set-FluxheimReleaseBuilderSshdPolicy `
    -Config $representativeSshdConfig -BuildUser 'Fluxheim-Build'
$renderedFirstMatch = [regex]::Match($renderedSshdConfig, '(?im)^\s*Match\s+')
$renderedPasswordPolicy = $renderedSshdConfig.IndexOf('PasswordAuthentication no')
if ($renderedPasswordPolicy -lt 0 -or
    -not $renderedFirstMatch.Success -or
    $renderedPasswordPolicy -gt $renderedFirstMatch.Index -or
    -not $renderedSshdConfig.Contains('AllowUsers fluxheim-build') -or
    -not $renderedSshdConfig.Contains(
        'AuthorizedKeysFile __PROGRAMDATA__/ssh/fluxheim-release/authorized_keys') -or
    $renderedSshdConfig.Contains('KbdInteractiveAuthentication')) {
    throw 'rendered Windows sshd policy is not global, account-scoped, and Windows-compatible'
}
foreach ($required in @(
    "`$sshTrustRoot = Join-Path `$env:ProgramData 'ssh\fluxheim-release'",
    '$sshTrustRoot /inheritance:r',
    '$trustedDirectory /inheritance:r',
    '$WorkspaceRoot /inheritance:r',
    '$BuildUser`:RX',
    '$runsDirectory',
    '$outputDirectory',
    '$BuildUser`:(OI)(CI)M',
    '$allowedSigners /inheritance:r',
    '$BuildUser`:R',
    'Administrators:F',
    "/setowner 'Administrators'"
)) {
    if (-not $preparation.Contains($required)) {
        throw "Windows preparation trust anchor is missing required ACL policy: $required"
    }
}
if ($preparation.Contains('$BuildUser`:(OI)(CI)F') -or
    $preparation.Contains('$WorkspaceRoot /inheritance:r /grant:r "$BuildUser`:(OI)(CI)M"')) {
    throw 'Windows preparation must not grant the build account control of SSH trust or workspace children'
}

$release = Get-Content -LiteralPath (Join-Path $root 'scripts/run_windows_release_builder.ps1') -Raw
$tagPolicy = Get-Content -LiteralPath `
    (Join-Path $root 'scripts/windows_release_tag_policy.ps1') -Raw
$releaseContract = $release + "`n" + $tagPolicy
foreach ($required in @(
    'Assert-FluxheimReleaseBuilderTrustAnchorsReadOnly',
    'Windows release builds must run as the dedicated non-administrator account',
    "`$env:RUSTUP_HOME = Join-Path `$rustRoot 'rustup'",
    "`$env:CARGO_HOME = Join-Path `$rustRoot 'cargo'",
    "`$env:Path = `$pathEntries -join ';'",
    'FileFlagOpenReparsePoint',
    'FileAttributeReparsePoint',
    'GetFileAttributesW',
    'IsReparsePoint',
    '[System.IO.Directory]::GetParent',
    'release trust path must not contain a reparse point',
    '$fileAddSubdirectory',
    '$fileDeleteChild',
    '$fileWriteData',
    '$fileAppendData',
    '$writeDac',
    '$writeOwner',
    'write allowed_signers',
    'overwrite allowed_signers content',
    'append allowed_signers content',
    'delete allowed_signers',
    'replace allowed_signers through its parent',
    'write authorized_keys',
    'overwrite authorized_keys content',
    'append authorized_keys content',
    'delete authorized_keys',
    'replace authorized_keys through its parent',
    'delete the release workspace',
    'delete the SSH trust directory',
    'delete ancestor',
    'delete ancestor children',
    'change ancestor ACL',
    'take ancestor ownership',
    'change the release workspace ACL',
    'change the trusted directory ACL',
    'change the allowed_signers ACL',
    'change the authorized_keys ACL',
    'change the SSH trust directory ACL',
    'git.exe cat-file tag',
    'BEGIN SSH SIGNATURE',
    'END SSH SIGNATURE',
    "gpg.format=ssh",
    'gpg.minTrustLevel=fully',
    'verify-tag',
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
    if (-not $releaseContract.Contains($required)) {
        throw "Windows release runner is missing required evidence: $required"
    }
}
if ($release.Contains('($genericWrite -bor $deleteAccess)')) {
    throw 'Windows release trust-anchor write and delete rights must be probed separately'
}
if ($release.Contains("Operation = 'create ancestor files'") -or
    $release.Contains("Operation = 'create ancestor directories'")) {
    throw 'Windows release checks must not reject harmless sibling creation in generic ancestors'
}
if ($release.Contains('checkout main') -or $release.Contains('|| git checkout')) {
    throw 'Windows release runner must not fall back from the requested tag'
}
. (Join-Path $root 'scripts/windows_release_tag_policy.ps1')
$sshTagFixture = "object`n-----BEGIN SSH SIGNATURE-----`nbody`n-----END SSH SIGNATURE-----"
$pgpTagFixture = "object`n-----BEGIN PGP SIGNATURE-----`nbody`n-----END PGP SIGNATURE-----"
$x509TagFixture = "object`n-----BEGIN SIGNED MESSAGE-----`nbody`n-----END SIGNED MESSAGE-----"
$duplicateSshTagFixture = $sshTagFixture + "`n" + $sshTagFixture
if (-not (Test-FluxheimSshSignedTagObject -TagObject $sshTagFixture) -or
    (Test-FluxheimSshSignedTagObject -TagObject $pgpTagFixture) -or
    (Test-FluxheimSshSignedTagObject -TagObject $x509TagFixture) -or
    (Test-FluxheimSshSignedTagObject -TagObject $duplicateSshTagFixture)) {
    throw 'Windows release tag policy did not enforce exactly one SSH signature'
}

$consoleHelper = Get-Content -LiteralPath `
    (Join-Path $root 'scripts/windows_console_signal_helper.cs') -Raw
foreach ($required in @(
    "IndexOf('\0')",
    'WaitForSingleObject(child.Process, 0) != WaitTimeout',
    'Fluxheim exited before console signal attachment',
    'AttachConsole(child.ProcessId)'
)) {
    if (-not $consoleHelper.Contains($required)) {
        throw "Windows console signal helper is missing required race hardening: $required"
    }
}
if ($consoleHelper.IndexOf('WaitForSingleObject(child.Process, 0) != WaitTimeout') -gt
    $consoleHelper.IndexOf('AttachConsole(child.ProcessId)')) {
    throw 'Windows console signal helper must recheck the child immediately before AttachConsole'
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

$supportedWindowsContract = $builder + "`n" + $archiveSmoke + "`n" + $wasmSmoke +
    "`n" + $release + "`n" + $preparation + "`n" + $ci
foreach ($unsupported in @(
    'aarch64-pc-windows-msvc',
    'aarch64-windows',
    "Architecture aarch64",
    'Windows ARM64 portable profiles'
)) {
    if ($supportedWindowsContract.Contains($unsupported)) {
        throw "Windows release scripts still advertise deferred ARM64 support: $unsupported"
    }
}

$manifest = Get-Content -LiteralPath (Join-Path $root 'Cargo.toml') -Raw
if (-not $manifest.Contains('exclude = ["vendor/fluxheim-openssl-fips-support"]')) {
    throw 'Windows workspace tests must exclude the Unix/OpenSSL FIPS support shim'
}

Write-Host 'Windows release scripts: ok'

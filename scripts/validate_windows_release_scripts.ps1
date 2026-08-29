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
    'scripts/smoke_windows_wasm_archive.ps1'
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

$smoke = Get-Content -LiteralPath (Join-Path $root 'scripts/smoke_windows_native.ps1') -Raw
foreach ($required in @(
    '--validate-config',
    '[IO.Path]::GetTempPath()',
    'windows-static-ok',
    'x-content-type-options',
    'x-cache-status',
    "expected MISS",
    "expected HIT",
    'New-WindowsSmokeCertificate',
    'tls_listen',
    'https://127.0.0.1:',
    'DangerousAcceptAnyServerCertificateValidator',
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
if ($smoke.Contains('target\fluxheim-windows-smoke')) {
    throw 'Windows native smoke must not place trusted runtime inputs below the inherited checkout ACL'
}

$wasmSmoke = Get-Content -LiteralPath `
    (Join-Path $root 'scripts/smoke_windows_wasm_archive.ps1') -Raw
foreach ($required in @(
    'Expand-Archive',
    'irules-access-policy.wasm',
    'Get-FileHash',
    'windows-wasm-origin-ok',
    'wasm access denied',
    'archived Windows Wasm policy allow/deny smoke: ok'
)) {
    if (-not $wasmSmoke.Contains($required)) {
        throw "Windows Wasm archive smoke is missing required behavior: $required"
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
    'smoke_windows_wasm_archive.ps1',
    'archive_count=7',
    'reproducible=true',
    'test_scope=workspace-native-live-and-archived-wasm-smoke'
)) {
    if (-not $release.Contains($required)) {
        throw "Windows release runner is missing required evidence: $required"
    }
}
if ($release.Contains('checkout main') -or $release.Contains('|| git checkout')) {
    throw 'Windows release runner must not fall back from the requested tag'
}

Write-Host 'Windows release scripts: ok'

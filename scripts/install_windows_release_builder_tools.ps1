[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidatePattern('^[A-Za-z0-9_.-]+$')]
    [string]$BuildUser = 'fluxheim-build',

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+[.][0-9]+[.][0-9]+$')]
    [string]$RustVersion
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run this installer from an elevated Administrator session'
}
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64') {
    throw 'Fluxheim Windows release builders require native x86_64 Windows'
}

$winget = Get-Command winget.exe -ErrorAction SilentlyContinue
if ($null -eq $winget) {
    throw 'winget.exe is required; use the Windows Server 2025 Desktop Experience image'
}

function Install-WinGetPackage {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [string]$Scope,
        [string]$InstallerType,
        [string]$Override
    )

    $arguments = @(
        'install', '--id', $Id, '--exact', '--source', 'winget',
        '--accept-package-agreements', '--accept-source-agreements',
        '--disable-interactivity', '--silent'
    )
    if (-not [string]::IsNullOrWhiteSpace($Scope)) {
        $arguments += @('--scope', $Scope)
    }
    if (-not [string]::IsNullOrWhiteSpace($InstallerType)) {
        $arguments += @('--installer-type', $InstallerType)
    }
    if (-not [string]::IsNullOrWhiteSpace($Override)) {
        $arguments += @('--override', $Override)
    }

    if ($PSCmdlet.ShouldProcess($Id, 'Install or update release-builder package')) {
        & $winget.Source @arguments
        if ($LASTEXITCODE -notin 0, -1978335189) {
            throw "winget failed for $Id with exit code $LASTEXITCODE"
        }
    }
}

if ($null -eq (Get-LocalUser -Name $BuildUser -ErrorAction SilentlyContinue)) {
    $passwordBytes = [byte[]]::new(48)
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($passwordBytes)
    } finally {
        $random.Dispose()
    }
    $passwordText = [Convert]::ToBase64String($passwordBytes) + 'aA1!'
    $password = ConvertTo-SecureString $passwordText -AsPlainText -Force
    try {
        if ($PSCmdlet.ShouldProcess($BuildUser, 'Create non-administrator release account')) {
            New-LocalUser -Name $BuildUser -Password $password -PasswordNeverExpires `
                -UserMayNotChangePassword -AccountNeverExpires | Out-Null
        }
    } finally {
        $passwordText = $null
        $password = $null
        [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
    }
}

$localUser = Get-LocalUser -Name $BuildUser -ErrorAction Stop
$administrators = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
if ($administrators.Name -contains "$env:COMPUTERNAME\$BuildUser") {
    throw 'release build account must not be a local administrator'
}
$openSshUsersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-585')
$openSshUsers = Get-LocalGroup -SID $openSshUsersSid -ErrorAction Stop
$openSshMembers = Get-LocalGroupMember -Group $openSshUsers.Name -ErrorAction Stop
$openSshMemberSids = @($openSshMembers | ForEach-Object { $_.SID.Value })
if ($openSshMemberSids -notcontains $localUser.SID.Value) {
    if ($PSCmdlet.ShouldProcess($BuildUser, "Add to $($openSshUsers.Name)")) {
        Add-LocalGroupMember -Group $openSshUsers.Name -Member $localUser
    }
}

Install-WinGetPackage -Id 'Microsoft.PowerShell' -Scope 'machine' -InstallerType 'wix'
Install-WinGetPackage -Id 'Git.Git' -Scope 'machine'
Install-WinGetPackage -Id 'Python.Python.3.13' -Scope 'machine'
Install-WinGetPackage -Id 'Kitware.CMake' -Scope 'machine'
Install-WinGetPackage -Id 'Microsoft.VisualStudio.2022.BuildTools' -Override `
    '--wait --quiet --norestart --nocache --installPath C:\BuildTools --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended'

$programFiles = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ProgramFiles)
$rustRoot = Join-Path $programFiles 'FluxheimRustTrusted'
$rustupHome = Join-Path $rustRoot 'rustup'
$cargoHome = Join-Path $rustRoot 'cargo'
$cargoBin = Join-Path $cargoHome 'bin'
$rustTarget = 'x86_64-pc-windows-msvc'
$toolchainRoot = Join-Path $rustupHome "toolchains\$RustVersion-$rustTarget"
$toolchainBin = Join-Path $toolchainRoot 'bin'
$cargoWorkRoot = Join-Path $rustRoot 'cargo-work'
$provisioningPath = Join-Path $rustRoot 'provisioning.json'
$excludedCargoBins = @(
    $cargoBin.TrimEnd('\'),
    (Join-Path ([Environment]::GetFolderPath(
        [Environment+SpecialFolder]::CommonApplicationData)) `
        'FluxheimRust\cargo\bin').TrimEnd('\')
)
$rustupVersion = '1.29.1'
$rustupSha256 = '6f4bef66261261fcb43131be8720bab817d403a09edec7455c371974b90bdb7e'
$rustupUrl = "https://static.rust-lang.org/rustup/archive/$rustupVersion/x86_64-pc-windows-msvc/rustup-init.exe"
$rustupInstaller = Join-Path $env:TEMP "rustup-init-$rustupVersion.exe"

if ($PSCmdlet.ShouldProcess($rustupInstaller, 'Download pinned Rustup installer')) {
    Invoke-WebRequest -UseBasicParsing -Uri $rustupUrl -OutFile $rustupInstaller
    $actualHash = (Get-FileHash -LiteralPath $rustupInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $rustupSha256) {
        throw "Rustup installer checksum mismatch: $actualHash"
    }
}

if (Test-Path -LiteralPath $rustRoot) {
    throw "trusted Rust root already exists; provision a fresh disposable builder: $rustRoot"
}

if ($PSCmdlet.ShouldProcess($rustRoot, 'Install administrator-controlled Rust toolchain')) {
    New-Item -ItemType Directory -Path $rustRoot | Out-Null
    & icacls.exe $rustRoot /setowner 'Administrators' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to set initial trusted Rust root ownership' }
    & icacls.exe $rustRoot /inheritance:r /grant:r `
        'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to secure the initial trusted Rust root' }
    New-Item -ItemType Directory -Path $rustupHome, $cargoHome, $cargoWorkRoot | Out-Null
    $env:RUSTUP_HOME = $rustupHome
    $env:CARGO_HOME = $cargoHome
    & $rustupInstaller -y --no-modify-path --default-toolchain none
    if ($LASTEXITCODE -ne 0) {
        throw "rustup-init failed with exit code $LASTEXITCODE"
    }
    $rustup = Join-Path $cargoBin 'rustup.exe'
    & $rustup toolchain install $RustVersion --profile minimal
    if ($LASTEXITCODE -ne 0) {
        throw "Rust toolchain installation failed: $RustVersion"
    }
    Remove-Item Env:RUSTUP_HOME -ErrorAction SilentlyContinue
    Remove-Item Env:CARGO_HOME -ErrorAction SilentlyContinue

    foreach ($required in 'cargo.exe', 'rustc.exe', 'rustdoc.exe') {
        $requiredPath = Join-Path $toolchainBin $required
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "administrator-installed Rust toolchain is incomplete: $requiredPath"
        }
    }

    $builderId = [Guid]::NewGuid().ToString('N')
    $provisionedUtc = [DateTimeOffset]::UtcNow.ToString('O')
    $rustRootPrefix = $rustRoot.TrimEnd('\') + '\'
    $files = @(Get-ChildItem -LiteralPath $rustRoot -Recurse -File | ForEach-Object {
        [ordered]@{
            path = $_.FullName.Substring($rustRootPrefix.Length).Replace('\', '/')
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    })
    [ordered]@{
        schema = 1
        builder_mode = 'fresh-disposable'
        builder_id = $builderId
        provisioned_utc = $provisionedUtc
        rust_version = $RustVersion
        rust_target = $rustTarget
        files = $files
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $provisioningPath -Encoding utf8

    & icacls.exe $rustRoot /setowner 'Administrators' /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to set trusted Rust root ownership' }
    & icacls.exe $rustRoot /inheritance:r /grant:r `
        "$BuildUser`:(OI)(CI)RX" 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to make the trusted Rust toolchain read-only' }
    & icacls.exe $rustRoot /grant "$BuildUser`:RX" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to apply read-only access to every trusted Rust file' }

}

if ($PSCmdlet.ShouldProcess('machine environment', 'Remove build-account Rust tool paths')) {
    [Environment]::SetEnvironmentVariable('RUSTUP_HOME', $null, 'Machine')
    [Environment]::SetEnvironmentVariable('CARGO_HOME', $null, 'Machine')
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $machinePath = (($machinePath -split ';') | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and $_.TrimEnd('\') -notin $excludedCargoBins
    }) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $machinePath, 'Machine')
}

Remove-Item -LiteralPath $rustupInstaller -Force -ErrorAction SilentlyContinue

$pathEntries = @(
    [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';'
    [Environment]::GetEnvironmentVariable('Path', 'User') -split ';'
) | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_) -and $_.TrimEnd('\') -notin $excludedCargoBins
}
$env:Path = $pathEntries -join ';'
foreach ($required in 'pwsh.exe', 'git.exe', 'python.exe', 'cmake.exe') {
    if ($null -eq (Get-Command $required -ErrorAction SilentlyContinue)) {
        throw "required command is unavailable after installation: $required"
    }
}
foreach ($required in (Join-Path $toolchainBin 'rustc.exe'), (Join-Path $toolchainBin 'cargo.exe')) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "required trusted Rust executable is unavailable after installation: $required"
    }
}

Write-Host "Installed Fluxheim Windows release-builder tools for $BuildUser"

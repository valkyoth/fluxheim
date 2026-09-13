[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$')]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+[.][0-9]+[.][0-9]+$')]
    [string]$RustVersion,

    [Parameter(Mandatory = $true)]
    [ValidateSet('x86_64')]
    [string]$Architecture,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$ExpectedCommit,

    [ValidatePattern('^https://github[.]com/[0-9A-Za-z_.-]+/[0-9A-Za-z_.-]+[.]git$')]
    [string]$RepositoryUrl = 'https://github.com/valkyoth/fluxheim.git',

    [ValidatePattern('^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$')]
    [string]$WorkspaceRoot = 'C:\FluxheimBuild',

    [switch]$ValidateBuilderOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'windows_release_tag_policy.ps1')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Windows release builds must run as the dedicated non-administrator account'
}
$programFiles = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::ProgramFiles)
$trustedRustRoot = Join-Path $programFiles 'FluxheimRustTrusted'
$maximumBuilderAgeHours = 24

function Assert-FluxheimReleaseBuilderTrustAnchorsReadOnly {
    param([Parameter(Mandatory = $true)][string]$Root)

    if ($null -eq ('FluxheimReleaseAclProbe' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class FluxheimReleaseAclProbe {
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint InvalidFileAttributes = 0xFFFFFFFF;
    private const uint FileShareAll = 0x00000007;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string name, uint access, uint share, IntPtr securityAttributes,
        uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFileAttributesW(string path);

    public static int Probe(string path, uint access, bool directory) {
        uint flags = FileFlagOpenReparsePoint;
        if (directory) flags |= FileFlagBackupSemantics;
        using (SafeFileHandle handle = CreateFileW(
            path, access, FileShareAll, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero)) {
            return handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        }
    }

    public static bool IsReparsePoint(string path) {
        uint attributes = GetFileAttributesW(path);
        if (attributes == InvalidFileAttributes) {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        return (attributes & FileAttributeReparsePoint) != 0;
    }
}
'@
    }

    $accessDenied = 5
    $deleteAccess = 0x00010000
    $fileWriteData = 0x00000002
    $fileAppendData = 0x00000004
    $writeDac = 0x00040000
    $writeOwner = 0x00080000
    $genericWrite = 0x40000000
    $fileAddSubdirectory = 0x00000004
    $fileDeleteChild = 0x00000040
    $trusted = Join-Path $Root 'trusted'
    $allowedSignersPath = Join-Path $trusted 'allowed_signers'
    $sshTrustRoot = Join-Path $env:ProgramData 'ssh\fluxheim-release'
    $authorizedKeysPath = Join-Path $sshTrustRoot 'authorized_keys'

    foreach ($trustPath in @(
        $Root, $trusted, $allowedSignersPath, $sshTrustRoot, $authorizedKeysPath
    )) {
        $current = [System.IO.Path]::GetFullPath($trustPath)
        while ($null -ne $current) {
            if ([FluxheimReleaseAclProbe]::IsReparsePoint($current)) {
                throw "release trust path must not contain a reparse point: $current"
            }
            $parent = [System.IO.Directory]::GetParent($current)
            $current = if ($null -eq $parent) { $null } else { $parent.FullName }
        }
    }

    foreach ($trustPath in @(
        $Root, $trusted, $allowedSignersPath, $sshTrustRoot, $authorizedKeysPath
    )) {
        $current = [System.IO.Directory]::GetParent(
            [System.IO.Path]::GetFullPath($trustPath))
        while ($null -ne $current) {
            $rights = @(
                [pscustomobject]@{ Access = $deleteAccess; Operation = 'delete ancestor' },
                [pscustomobject]@{ Access = $fileDeleteChild; Operation = 'delete ancestor children' },
                [pscustomobject]@{ Access = $writeDac; Operation = 'change ancestor ACL' },
                [pscustomobject]@{ Access = $writeOwner; Operation = 'take ancestor ownership' }
            )
            foreach ($right in $rights) {
                $errorCode = [FluxheimReleaseAclProbe]::Probe(
                    $current.FullName, [uint32]$right.Access, $true)
                if ($errorCode -ne $accessDenied) {
                    throw "release build account can $($right.Operation): $($current.FullName) (Win32 error $errorCode)"
                }
            }
            $current = [System.IO.Directory]::GetParent($current.FullName)
        }
    }

    $probes = @(
        [pscustomobject]@{
            Path = $Root
            Access = $fileAddSubdirectory
            Directory = $true
            Operation = 'create a second trusted directory'
        },
        [pscustomobject]@{
            Path = $Root
            Access = $deleteAccess
            Directory = $true
            Operation = 'delete the release workspace'
        },
        [pscustomobject]@{
            Path = $Root
            Access = $fileDeleteChild
            Directory = $true
            Operation = 'replace a trusted directory through its parent'
        },
        [pscustomobject]@{
            Path = $Root
            Access = $writeDac
            Directory = $true
            Operation = 'change the release workspace ACL'
        },
        [pscustomobject]@{
            Path = $Root
            Access = $writeOwner
            Directory = $true
            Operation = 'take ownership of the release workspace'
        },
        [pscustomobject]@{
            Path = $trusted
            Access = $deleteAccess
            Directory = $true
            Operation = 'rename the trusted directory'
        },
        [pscustomobject]@{
            Path = $trusted
            Access = $writeDac
            Directory = $true
            Operation = 'change the trusted directory ACL'
        },
        [pscustomobject]@{
            Path = $trusted
            Access = $writeOwner
            Directory = $true
            Operation = 'take ownership of the trusted directory'
        },
        [pscustomobject]@{
            Path = $allowedSignersPath
            Access = $fileWriteData
            Directory = $false
            Operation = 'overwrite allowed_signers content'
        },
        [pscustomobject]@{
            Path = $allowedSignersPath
            Access = $fileAppendData
            Directory = $false
            Operation = 'append allowed_signers content'
        },
        [pscustomobject]@{
            Path = $allowedSignersPath
            Access = $genericWrite
            Directory = $false
            Operation = 'write allowed_signers'
        },
        [pscustomobject]@{
            Path = $allowedSignersPath
            Access = $deleteAccess
            Directory = $false
            Operation = 'delete allowed_signers'
        },
        [pscustomobject]@{
            Path = $allowedSignersPath
            Access = $writeDac
            Directory = $false
            Operation = 'change the allowed_signers ACL'
        },
        [pscustomobject]@{
            Path = $allowedSignersPath
            Access = $writeOwner
            Directory = $false
            Operation = 'take ownership of allowed_signers'
        },
        [pscustomobject]@{
            Path = $trusted
            Access = $fileDeleteChild
            Directory = $true
            Operation = 'replace allowed_signers through its parent'
        },
        [pscustomobject]@{
            Path = $authorizedKeysPath
            Access = $fileWriteData
            Directory = $false
            Operation = 'overwrite authorized_keys content'
        },
        [pscustomobject]@{
            Path = $authorizedKeysPath
            Access = $fileAppendData
            Directory = $false
            Operation = 'append authorized_keys content'
        },
        [pscustomobject]@{
            Path = $authorizedKeysPath
            Access = $genericWrite
            Directory = $false
            Operation = 'write authorized_keys'
        },
        [pscustomobject]@{
            Path = $authorizedKeysPath
            Access = $deleteAccess
            Directory = $false
            Operation = 'delete authorized_keys'
        },
        [pscustomobject]@{
            Path = $authorizedKeysPath
            Access = $writeDac
            Directory = $false
            Operation = 'change the authorized_keys ACL'
        },
        [pscustomobject]@{
            Path = $authorizedKeysPath
            Access = $writeOwner
            Directory = $false
            Operation = 'take ownership of authorized_keys'
        },
        [pscustomobject]@{
            Path = $sshTrustRoot
            Access = $fileDeleteChild
            Directory = $true
            Operation = 'replace authorized_keys through its parent'
        },
        [pscustomobject]@{
            Path = $sshTrustRoot
            Access = $deleteAccess
            Directory = $true
            Operation = 'delete the SSH trust directory'
        },
        [pscustomobject]@{
            Path = $sshTrustRoot
            Access = $writeDac
            Directory = $true
            Operation = 'change the SSH trust directory ACL'
        },
        [pscustomobject]@{
            Path = $sshTrustRoot
            Access = $writeOwner
            Directory = $true
            Operation = 'take ownership of the SSH trust directory'
        }
    )
    foreach ($probe in $probes) {
        $errorCode = [FluxheimReleaseAclProbe]::Probe(
            $probe.Path, [uint32]$probe.Access, [bool]$probe.Directory)
        if ($errorCode -ne $accessDenied) {
            throw "release build account can $($probe.Operation) (Win32 error $errorCode)"
        }
    }
}

function Assert-FluxheimTrustedRustToolchain {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$ExpectedRustVersion,
        [Parameter(Mandatory = $true)][int]$MaximumAgeHours
    )

    $provisioningPath = Join-Path $Root 'provisioning.json'
    if (-not (Test-Path -LiteralPath $provisioningPath -PathType Leaf)) {
        throw "trusted Rust provisioning manifest is missing: $provisioningPath"
    }
    $provisioning = Get-Content -LiteralPath $provisioningPath -Raw | ConvertFrom-Json
    if ([int]$provisioning.schema -ne 1 -or
        [string]$provisioning.builder_mode -ne 'fresh-disposable' -or
        [string]$provisioning.rust_version -ne $ExpectedRustVersion -or
        [string]$provisioning.rust_target -ne 'x86_64-pc-windows-msvc' -or
        [string]::IsNullOrWhiteSpace([string]$provisioning.builder_id)) {
        throw 'trusted Rust provisioning manifest does not match the requested release toolchain'
    }
    $provisionedUtc = [DateTimeOffset]::Parse([string]$provisioning.provisioned_utc)
    $builderAge = [DateTimeOffset]::UtcNow - $provisionedUtc
    if ($builderAge.TotalMinutes -lt -5 -or $builderAge.TotalHours -gt $MaximumAgeHours) {
        throw "official Windows releases require a builder provisioned within $MaximumAgeHours hours"
    }

    $toolchainRoot = Join-Path $Root "rustup\toolchains\$ExpectedRustVersion-x86_64-pc-windows-msvc"
    $toolchainBin = Join-Path $toolchainRoot 'bin'
    $cargoWorkRoot = Join-Path $Root 'cargo-work'
    $rustupProxyRoot = Join-Path $Root 'cargo\bin'
    $rustupProxyTarget = Join-Path $rustupProxyRoot 'rustup.exe'
    foreach ($path in $Root, $toolchainRoot, $toolchainBin, $cargoWorkRoot, $provisioningPath) {
        $current = [IO.Path]::GetFullPath($path)
        while ($null -ne $current) {
            if ([FluxheimReleaseAclProbe]::IsReparsePoint($current)) {
                throw "trusted Rust path must not contain a reparse point: $current"
            }
            $parent = [IO.Directory]::GetParent($current)
            $current = if ($null -eq $parent) { $null } else { $parent.FullName }
        }
    }

    $accessDenied = 5
    $genericWrite = 0x40000000
    $deleteAccess = 0x00010000
    $writeDac = 0x00040000
    $writeOwner = 0x00080000
    $fileAddFile = 0x00000002
    $fileAddSubdirectory = 0x00000004
    $fileDeleteChild = 0x00000040
    $current = [IO.Directory]::GetParent([IO.Path]::GetFullPath($Root))
    while ($null -ne $current) {
        $ancestorParent = [IO.Directory]::GetParent($current.FullName)
        $ancestorRights = @(
            [pscustomobject]@{ Access = $deleteAccess; Operation = 'delete a trusted Rust ancestor' },
            [pscustomobject]@{ Access = $fileDeleteChild; Operation = 'replace trusted Rust through an ancestor' },
            [pscustomobject]@{ Access = $writeDac; Operation = 'change a trusted Rust ancestor ACL' },
            [pscustomobject]@{ Access = $writeOwner; Operation = 'take ownership of a trusted Rust ancestor' }
        )
        # A standard Windows volume root permits Users to create directories. That
        # cannot replace the protected existing child while delete-child is denied.
        if ($null -ne $ancestorParent) {
            $ancestorRights += @(
                [pscustomobject]@{ Access = $fileAddFile; Operation = 'create files in a trusted Rust ancestor' },
                [pscustomobject]@{ Access = $fileAddSubdirectory; Operation = 'create directories in a trusted Rust ancestor' }
            )
        }
        foreach ($right in $ancestorRights) {
            $errorCode = [FluxheimReleaseAclProbe]::Probe(
                $current.FullName, [uint32]$right.Access, $true)
            if ($errorCode -ne $accessDenied) {
                throw "release build account can $($right.Operation): $($current.FullName) (Win32 error $errorCode)"
            }
        }
        $current = $ancestorParent
    }
    foreach ($probe in @(
        [pscustomobject]@{ Path = $Root; Access = $genericWrite; Directory = $true; Operation = 'write the trusted Rust root' },
        [pscustomobject]@{ Path = $Root; Access = $fileAddFile; Directory = $true; Operation = 'add files to the trusted Rust root' },
        [pscustomobject]@{ Path = $Root; Access = $deleteAccess; Directory = $true; Operation = 'delete the trusted Rust root' },
        [pscustomobject]@{ Path = $Root; Access = $fileDeleteChild; Directory = $true; Operation = 'replace trusted Rust files through their parent' },
        [pscustomobject]@{ Path = $Root; Access = $writeDac; Directory = $true; Operation = 'change the trusted Rust root ACL' },
        [pscustomobject]@{ Path = $Root; Access = $writeOwner; Directory = $true; Operation = 'take ownership of the trusted Rust root' },
        [pscustomobject]@{ Path = $provisioningPath; Access = $genericWrite; Directory = $false; Operation = 'write the Rust provisioning manifest' },
        [pscustomobject]@{ Path = $provisioningPath; Access = $deleteAccess; Directory = $false; Operation = 'delete the Rust provisioning manifest' },
        [pscustomobject]@{ Path = $provisioningPath; Access = $writeDac; Directory = $false; Operation = 'change the Rust provisioning manifest ACL' },
        [pscustomobject]@{ Path = $provisioningPath; Access = $writeOwner; Directory = $false; Operation = 'take ownership of the Rust provisioning manifest' }
    )) {
        $errorCode = [FluxheimReleaseAclProbe]::Probe(
            $probe.Path, [uint32]$probe.Access, [bool]$probe.Directory)
        if ($errorCode -ne $accessDenied) {
            throw "release build account can $($probe.Operation) (Win32 error $errorCode)"
        }
    }

    $expectedFiles = @{}
    foreach ($file in @($provisioning.files)) {
        $relative = [string]$file.path
        $expectedHash = [string]$file.sha256
        if ([string]::IsNullOrWhiteSpace($relative) -or
            $relative.Contains('..') -or
            [IO.Path]::IsPathRooted($relative) -or
            $expectedHash -notmatch '^[0-9a-f]{64}$' -or
            $expectedFiles.ContainsKey($relative)) {
            throw 'trusted Rust provisioning manifest contains an invalid file entry'
        }
        $expectedFiles[$relative] = $expectedHash
    }
    $actualFiles = @(Get-ChildItem -LiteralPath $Root -Recurse -File | Where-Object {
        $_.FullName -ne $provisioningPath
    })
    if ($actualFiles.Count -ne $expectedFiles.Count) {
        throw 'trusted Rust toolchain file inventory changed after provisioning'
    }
    $rootPrefix = $Root.TrimEnd('\') + '\'
    foreach ($file in $actualFiles) {
        if (-not $file.FullName.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "trusted Rust inventory escaped its root: $($file.FullName)"
        }
        if ([FluxheimReleaseAclProbe]::IsReparsePoint($file.FullName)) {
            $proxyTarget = [string]$file.Target
            $isPinnedRustupProxy =
                $file.LinkType -eq 'SymbolicLink' -and
                $file.DirectoryName -eq $rustupProxyRoot -and
                $proxyTarget -eq 'rustup.exe' -and
                $expectedFiles.ContainsKey('cargo/bin/rustup.exe') -and
                (Test-Path -LiteralPath $rustupProxyTarget -PathType Leaf) -and
                -not [FluxheimReleaseAclProbe]::IsReparsePoint($rustupProxyTarget)
            if (-not $isPinnedRustupProxy) {
                throw "trusted Rust file must not be an unrecognized reparse point: $($file.FullName)"
            }
        }
        $relative = $file.FullName.Substring($rootPrefix.Length).Replace('\', '/')
        if (-not $expectedFiles.ContainsKey($relative)) {
            throw "unprovisioned file exists in trusted Rust toolchain: $relative"
        }
        $actualHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedFiles[$relative]) {
            throw "trusted Rust toolchain file hash changed after provisioning: $relative"
        }
        foreach ($access in $genericWrite, $deleteAccess, $writeDac, $writeOwner) {
            $errorCode = [FluxheimReleaseAclProbe]::Probe(
                $file.FullName, [uint32]$access, $false)
            if ($errorCode -ne $accessDenied) {
                throw "release build account can modify trusted Rust file: $relative (Win32 error $errorCode)"
            }
        }
    }

    foreach ($directory in @(Get-ChildItem -LiteralPath $Root -Recurse -Directory)) {
        if ([FluxheimReleaseAclProbe]::IsReparsePoint($directory.FullName)) {
            throw "trusted Rust directory must not be a reparse point: $($directory.FullName)"
        }
        foreach ($access in $fileAddFile, $fileAddSubdirectory, $fileDeleteChild,
                $deleteAccess, $writeDac, $writeOwner) {
            $errorCode = [FluxheimReleaseAclProbe]::Probe(
                $directory.FullName, [uint32]$access, $true)
            if ($errorCode -ne $accessDenied) {
                throw "release build account can modify trusted Rust directory: $($directory.FullName) (Win32 error $errorCode)"
            }
        }
    }

    foreach ($name in 'cargo.exe', 'rustc.exe', 'rustdoc.exe') {
        $path = Join-Path $toolchainBin $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "trusted Rust executable is missing: $path"
        }
    }
    if (-not (Test-Path -LiteralPath $cargoWorkRoot -PathType Container)) {
        throw "trusted Cargo working directory is missing: $cargoWorkRoot"
    }

    [pscustomobject]@{
        BuilderId = [string]$provisioning.builder_id
        ProvisionedUtc = $provisionedUtc.ToString('O')
        ManifestSha256 = (Get-FileHash -LiteralPath $provisioningPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        ManifestPath = $provisioningPath
        ToolchainBin = $toolchainBin
        CargoWorkRoot = $cargoWorkRoot
    }
}

function Assert-NoUntrustedCargoConfiguration {
    param([Parameter(Mandatory = $true)][string]$Path)

    $current = [IO.Directory]::GetParent([IO.Path]::GetFullPath($Path))
    while ($null -ne $current) {
        foreach ($relative in '.cargo\config', '.cargo\config.toml') {
            $candidate = Join-Path $current.FullName $relative
            if (Test-Path -LiteralPath $candidate) {
                throw "untrusted ancestor Cargo configuration: $candidate"
            }
        }
        $current = $current.Parent
    }
}

function Invoke-TrustedCargo {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    if ($Arguments.Count -eq 0) { throw 'Cargo command is missing' }
    $command = $Arguments[0]
    $remaining = @($Arguments | Select-Object -Skip 1)
    Push-Location $trustedRust.CargoWorkRoot
    try {
        & $cargo $command --manifest-path (Join-Path $sourceRoot 'Cargo.toml') @remaining
    } finally {
        Pop-Location
    }
}

$expectedArchitecture = 'X64'
$actualArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($actualArchitecture -ne $expectedArchitecture) {
    throw "expected native $expectedArchitecture host, found $actualArchitecture"
}

$tag = "v$Version"
$targetLabel = 'x86_64-windows'
$allowedSigners = Join-Path $WorkspaceRoot 'trusted\allowed_signers'
if (-not (Test-Path -LiteralPath $allowedSigners -PathType Leaf)) {
    throw "trusted tag allowed-signers file is missing: $allowedSigners"
}
Assert-FluxheimReleaseBuilderTrustAnchorsReadOnly -Root $WorkspaceRoot
$trustedRust = Assert-FluxheimTrustedRustToolchain -Root $trustedRustRoot `
    -ExpectedRustVersion $RustVersion -MaximumAgeHours $maximumBuilderAgeHours

$runId = [Guid]::NewGuid().ToString('N')
$runRoot = Join-Path $WorkspaceRoot "runs\$runId"
$sourceRoot = Join-Path $runRoot 'source'
$tempRoot = Join-Path $runRoot 'temp'
$outputRoot = Join-Path $WorkspaceRoot "output\$Version\$Architecture"
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
New-Item -ItemType Directory -Force -Path $runRoot, $tempRoot | Out-Null
$systemRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$programData = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::CommonApplicationData)
$allowedEnvironment = @{
    SystemRoot = $systemRoot
    WINDIR = $systemRoot
    SystemDrive = [IO.Path]::GetPathRoot($systemRoot).TrimEnd('\')
    ProgramData = $programData
    ALLUSERSPROFILE = $programData
    COMSPEC = Join-Path $systemRoot 'System32\cmd.exe'
}
foreach ($name in @(
    'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432',
    'CommonProgramFiles', 'CommonProgramFiles(x86)', 'CommonProgramW6432',
    'PATHEXT', 'PSModulePath', 'OS', 'NUMBER_OF_PROCESSORS',
    'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER', 'PROCESSOR_LEVEL',
    'PROCESSOR_REVISION'
)) {
    $value = [Environment]::GetEnvironmentVariable($name, 'Machine')
    if ($null -ne $value) { $allowedEnvironment[$name] = $value }
}
foreach ($entry in @(Get-ChildItem Env:)) {
    Remove-Item -LiteralPath "Env:$($entry.Name)"
}
foreach ($entry in $allowedEnvironment.GetEnumerator()) {
    Set-Item -LiteralPath "Env:$($entry.Name)" -Value $entry.Value
}
$env:TEMP = $tempRoot
$env:TMP = $tempRoot
$env:CARGO_HOME = Join-Path $runRoot 'cargo-home'
New-Item -ItemType Directory -Path $env:CARGO_HOME | Out-Null
$env:RUSTC = Join-Path $trustedRust.ToolchainBin 'rustc.exe'
$env:RUSTDOC = Join-Path $trustedRust.ToolchainBin 'rustdoc.exe'
$cargo = Join-Path $trustedRust.ToolchainBin 'cargo.exe'
$env:Path = $trustedRust.ToolchainBin + ';' + $machinePath
$env:FLUXHEIM_TRUSTED_CARGO_CWD = $trustedRust.CargoWorkRoot
$env:GIT_CONFIG_GLOBAL = 'NUL'
$env:GIT_CONFIG_NOSYSTEM = '1'
Assert-NoUntrustedCargoConfiguration -Path $sourceRoot
Assert-NoUntrustedCargoConfiguration -Path $trustedRust.CargoWorkRoot

$requiredCommands = 'git.exe', 'python.exe', 'cmake.exe'
foreach ($command in $requiredCommands) {
    if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "required release command is unavailable from the machine toolchain: $command"
    }
}

$rustcVersionOutput = @(& $env:RUSTC -vV)
if ($LASTEXITCODE -ne 0) { throw 'trusted Rust compiler identity check failed' }
$rustcHost = ($rustcVersionOutput | Select-String '^host: ' | ForEach-Object { $_.Line.Substring(6) })
$rustcRelease = ($rustcVersionOutput | Select-String '^release: ' | ForEach-Object { $_.Line.Substring(9) })
$expectedHost = 'x86_64-pc-windows-msvc'
if ($rustcHost -ne $expectedHost) {
    throw "Rust host $rustcHost does not match release target $expectedHost"
}
if ($rustcRelease -ne $RustVersion) {
    throw "Rust compiler release $rustcRelease does not match requested $RustVersion"
}
Push-Location $trustedRust.CargoWorkRoot
try {
    & $cargo --version --verbose | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'trusted Cargo identity check failed' }
} finally {
    Pop-Location
}
if ($ValidateBuilderOnly) {
    Write-Output "Fluxheim Windows release builder policy: ok ($($trustedRust.BuilderId))"
    return
}

try {
    & git.exe clone --no-checkout --filter=blob:none $RepositoryUrl $sourceRoot
    if ($LASTEXITCODE -ne 0) { throw 'repository clone failed' }
    Set-Location $sourceRoot
    & git.exe fetch --force --depth=1 origin "refs/tags/$tag`:refs/tags/$tag"
    if ($LASTEXITCODE -ne 0) { throw "exact tag fetch failed: $tag" }

    $tagCommit = (& git.exe rev-parse "$tag^{commit}").Trim()
    if ($LASTEXITCODE -ne 0 -or $tagCommit -ne $ExpectedCommit.ToLowerInvariant()) {
        throw "tag commit $tagCommit does not match expected commit $ExpectedCommit"
    }
    $tagObject = (& git.exe cat-file tag $tag 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "release tag must be an annotated tag object: $tag" }
    if (-not (Test-FluxheimSshSignedTagObject -TagObject $tagObject)) {
        throw "release tag must contain exactly one SSH signature and no other signature format: $tag"
    }
    & git.exe -c 'gpg.format=ssh' -c 'gpg.minTrustLevel=fully' `
        -c "gpg.ssh.allowedSignersFile=$allowedSigners" verify-tag $tag 2>&1 |
        Set-Content -LiteralPath (Join-Path $runRoot 'tag-verification.txt') -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw "signed tag verification failed: $tag" }
    & git.exe checkout --detach $tag
    if ($LASTEXITCODE -ne 0) { throw "tag checkout failed: $tag" }
    $env:SOURCE_DATE_EPOCH = (& git.exe log -1 --format=%ct).Trim()
    if ($LASTEXITCODE -ne 0 -or $env:SOURCE_DATE_EPOCH -notmatch '^[0-9]+$') {
        throw 'could not determine the release source timestamp'
    }
    $windowsVersion = Get-ItemProperty -LiteralPath `
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $runtimeVersion = [Environment]::OSVersion.Version
    $osCaption = ([string]$windowsVersion.ProductName).Replace("`r", ' ').Replace("`n", ' ').Trim()
    $osVersion = "$($runtimeVersion.Major).$($runtimeVersion.Minor).$($runtimeVersion.Build)"
    $osBuild = ([string]$windowsVersion.CurrentBuildNumber).Trim()
    if ([string]::IsNullOrWhiteSpace($osCaption) -or
        [string]::IsNullOrWhiteSpace($osVersion) -or
        [string]::IsNullOrWhiteSpace($osBuild)) {
        throw 'native Windows operating-system identity is unavailable'
    }

    & python.exe scripts/validate_portable_release_plan.py
    if ($LASTEXITCODE -ne 0) { throw 'portable release-plan validation failed' }
    Invoke-TrustedCargo -Arguments @('test', '--workspace', '--locked')
    if ($LASTEXITCODE -ne 0) { throw 'native Windows workspace tests failed' }
    $nativeSmoke = Join-Path $sourceRoot 'scripts\smoke_windows_native.ps1'
    if (-not (Test-Path -LiteralPath $nativeSmoke -PathType Leaf)) {
        throw 'native Windows live smoke is required before release evidence can be produced'
    }
    & pwsh.exe -NoProfile -File $nativeSmoke
    if ($LASTEXITCODE -ne 0) { throw 'native Windows live smoke failed' }

    function Build-ReproducibleBinary {
        param([Parameter(Mandatory = $true)][string]$Destination)

        if (Test-Path -LiteralPath $Destination) {
            Remove-Item -LiteralPath $Destination -Recurse -Force
        }
        $previousCargoTargetDir = $env:CARGO_TARGET_DIR
        try {
            $env:CARGO_TARGET_DIR = $Destination
            Invoke-TrustedCargo -Arguments @('build', '--release', '--locked') | Out-Host
            if ($LASTEXITCODE -ne 0) { throw 'Windows reproducible release build failed' }
        } finally {
            if ($null -eq $previousCargoTargetDir) {
                Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
            } else {
                $env:CARGO_TARGET_DIR = $previousCargoTargetDir
            }
        }

        $binary = Join-Path $Destination 'release\fluxheim.exe'
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
            throw "Windows reproducible release binary is missing: $binary"
        }
        (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    function Build-ArchiveSet {
        param([Parameter(Mandatory = $true)][string]$Destination)

        if (Test-Path -LiteralPath (Join-Path $sourceRoot 'target')) {
            Remove-Item -LiteralPath (Join-Path $sourceRoot 'target') -Recurse -Force
        }
        if (Test-Path -LiteralPath (Join-Path $sourceRoot 'dist')) {
            Remove-Item -LiteralPath (Join-Path $sourceRoot 'dist') -Recurse -Force
        }
        & pwsh.exe -NoProfile -File scripts/build_release_assets.ps1 `
            -Version $Version -Architecture $Architecture
        if ($LASTEXITCODE -ne 0) { throw 'Windows archive build failed' }

        New-Item -ItemType Directory -Force -Path $Destination | Out-Null
        $archives = @(Get-ChildItem -LiteralPath (Join-Path $sourceRoot 'dist') `
            -Filter "fluxheim-$Version-*-$targetLabel.zip" -File)
        if ($archives.Count -ne 7) {
            throw "expected seven Windows ZIP archives, found $($archives.Count)"
        }
        foreach ($archive in $archives) {
            & python.exe -m zipfile -t $archive.FullName
            if ($LASTEXITCODE -ne 0) { throw "invalid ZIP archive: $($archive.Name)" }
            Copy-Item -LiteralPath $archive.FullName -Destination $Destination
        }
    }

    $firstReproBuild = Join-Path $runRoot 'reproducible-a'
    $secondReproBuild = Join-Path $runRoot 'reproducible-b'
    $firstReproHash = Build-ReproducibleBinary -Destination $firstReproBuild
    $secondReproHash = Build-ReproducibleBinary -Destination $secondReproBuild
    if ($firstReproHash -ne $secondReproHash) {
        throw 'Windows default release binary is not reproducible across two clean target directories'
    }

    $archiveBuild = Join-Path $runRoot 'archives'
    Build-ArchiveSet -Destination $archiveBuild
    $archiveSmoke = Join-Path $sourceRoot 'scripts\smoke_windows_archive_profiles.ps1'
    if (-not (Test-Path -LiteralPath $archiveSmoke -PathType Leaf)) {
        throw 'all-profile Windows archive smoke is required before release evidence can be produced'
    }
    & pwsh.exe -NoProfile -File $archiveSmoke -Version $Version -Architecture $Architecture
    if ($LASTEXITCODE -ne 0) { throw 'all-profile Windows archive smoke failed' }
    $wasmSmoke = Join-Path $sourceRoot 'scripts\smoke_windows_wasm_archive.ps1'
    if (-not (Test-Path -LiteralPath $wasmSmoke -PathType Leaf)) {
        throw 'archived Windows Wasm smoke is required before release evidence can be produced'
    }
    & pwsh.exe -NoProfile -File $wasmSmoke -Version $Version -Architecture $Architecture
    if ($LASTEXITCODE -ne 0) { throw 'archived Windows Wasm smoke failed' }

    $archiveHashes = @{}
    Get-ChildItem -LiteralPath $archiveBuild -Filter '*.zip' -File | ForEach-Object {
        $archiveHashes[$_.Name] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    if (Test-Path -LiteralPath $outputRoot) {
        Remove-Item -LiteralPath $outputRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
    Copy-Item -Path (Join-Path $archiveBuild '*.zip') -Destination $outputRoot
    Copy-Item -LiteralPath (Join-Path $runRoot 'tag-verification.txt') -Destination $outputRoot
    Copy-Item -LiteralPath $trustedRust.ManifestPath -Destination `
        (Join-Path $outputRoot "toolchain-provisioning-$targetLabel.json")

    $checksumLines = @($archiveHashes.GetEnumerator() | Sort-Object Name | ForEach-Object {
        "$($_.Value)  $($_.Name)"
    })
    $checksumFile = Join-Path $outputRoot "SHA256SUMS-$targetLabel.txt"
    Set-Content -LiteralPath $checksumFile -Value $checksumLines -Encoding ascii

    Set-Content -LiteralPath (Join-Path $outputRoot "REPRODUCIBLE-BUILD-SHA256-$targetLabel.txt") `
        -Value $firstReproHash -Encoding ascii

    @(
        "version=$Version"
        "tag=$tag"
        "commit=$tagCommit"
        "architecture=$Architecture"
        "rust_host=$rustcHost"
        "windows_os_caption=$osCaption"
        "windows_os_version=$osVersion"
        "windows_os_build=$osBuild"
        "builder_id=$($trustedRust.BuilderId)"
        "builder_provisioned_utc=$($trustedRust.ProvisionedUtc)"
        "toolchain_manifest_sha256=$($trustedRust.ManifestSha256)"
        'builder_mode=fresh-disposable'
        'toolchain_read_only=true'
        'cargo_home_scope=per-run'
        'cargo_config_scope=trusted-cwd'
        'environment_scope=allowlist'
        'test_scope=workspace-native-all-archives-and-wasm-smoke'
        'reproducibility_scope=default-release-binary'
        'archive_count=7'
        'reproducible=true'
    ) | Set-Content -LiteralPath (Join-Path $outputRoot "release-evidence-$targetLabel.txt") -Encoding ascii

    Write-Host "Windows release evidence written to $outputRoot"
} finally {
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
    Set-Location ($env:SystemDrive + '\')
    if (Test-Path -LiteralPath $runRoot) {
        Remove-Item -LiteralPath $runRoot -Recurse -Force
    }
}

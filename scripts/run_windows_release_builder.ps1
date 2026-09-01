[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$')]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9]+[.][0-9]+[.][0-9]+$')]
    [string]$RustVersion,

    [Parameter(Mandatory = $true)]
    [ValidateSet('x86_64', 'aarch64')]
    [string]$Architecture,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$ExpectedCommit,

    [ValidatePattern('^https://github[.]com/[0-9A-Za-z_.-]+/[0-9A-Za-z_.-]+[.]git$')]
    [string]$RepositoryUrl = 'https://github.com/valkyoth/fluxheim.git',

    [ValidatePattern('^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$')]
    [string]$WorkspaceRoot = 'C:\FluxheimBuild'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'windows_release_tag_policy.ps1')

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
    private const uint FileShareAll = 0x00000007;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string name, uint access, uint share, IntPtr securityAttributes,
        uint creation, uint flags, IntPtr template);

    public static int Probe(string path, uint access, bool directory) {
        uint flags = FileFlagOpenReparsePoint;
        if (directory) flags |= FileFlagBackupSemantics;
        using (SafeFileHandle handle = CreateFileW(
            path, access, FileShareAll, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero)) {
            return handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        }
    }
}
'@
    }

    $accessDenied = 5
    $deleteAccess = 0x00010000
    $genericWrite = 0x40000000
    $fileAddSubdirectory = 0x00000004
    $fileDeleteChild = 0x00000040
    $trusted = Join-Path $Root 'trusted'
    $allowedSignersPath = Join-Path $trusted 'allowed_signers'
    $authorizedKeysPath = Join-Path $env:ProgramData 'ssh\fluxheim-release\authorized_keys'

    $probes = @(
        [pscustomobject]@{
            Path = $Root
            Access = $fileAddSubdirectory
            Directory = $true
            Operation = 'create a second trusted directory'
        },
        [pscustomobject]@{
            Path = $Root
            Access = $fileDeleteChild
            Directory = $true
            Operation = 'replace a trusted directory through its parent'
        },
        [pscustomobject]@{
            Path = $trusted
            Access = $deleteAccess
            Directory = $true
            Operation = 'rename the trusted directory'
        },
        [pscustomobject]@{
            Path = $allowedSignersPath
            Access = ($genericWrite -bor $deleteAccess)
            Directory = $false
            Operation = 'replace allowed_signers'
        },
        [pscustomobject]@{
            Path = $authorizedKeysPath
            Access = ($genericWrite -bor $deleteAccess)
            Directory = $false
            Operation = 'replace authorized_keys'
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

$expectedArchitecture = if ($Architecture -eq 'x86_64') { 'X64' } else { 'Arm64' }
$actualArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($actualArchitecture -ne $expectedArchitecture) {
    throw "expected native $expectedArchitecture host, found $actualArchitecture"
}

$tag = "v$Version"
$targetLabel = if ($Architecture -eq 'x86_64') { 'x86_64-windows' } else { 'aarch64-windows' }
$allowedSigners = Join-Path $WorkspaceRoot 'trusted\allowed_signers'
if (-not (Test-Path -LiteralPath $allowedSigners -PathType Leaf)) {
    throw "trusted tag allowed-signers file is missing: $allowedSigners"
}
Assert-FluxheimReleaseBuilderTrustAnchorsReadOnly -Root $WorkspaceRoot

$requiredCommands = 'git.exe', 'rustup.exe', 'rustc.exe', 'cargo.exe', 'python.exe'
foreach ($command in $requiredCommands) {
    if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "required release command is unavailable: $command"
    }
}

$runId = [Guid]::NewGuid().ToString('N')
$runRoot = Join-Path $WorkspaceRoot "runs\$runId"
$sourceRoot = Join-Path $runRoot 'source'
$outputRoot = Join-Path $WorkspaceRoot "output\$Version\$Architecture"
New-Item -ItemType Directory -Force -Path $runRoot | Out-Null

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

    & rustup.exe toolchain install $RustVersion --profile minimal
    if ($LASTEXITCODE -ne 0) { throw "Rust toolchain installation failed: $RustVersion" }
    & rustup.exe override set $RustVersion
    if ($LASTEXITCODE -ne 0) { throw 'Rust toolchain override failed' }

    $host = (& rustc.exe -vV | Select-String '^host: ' | ForEach-Object { $_.Line.Substring(6) })
    $expectedHost = if ($Architecture -eq 'x86_64') {
        'x86_64-pc-windows-msvc'
    } else {
        'aarch64-pc-windows-msvc'
    }
    if ($host -ne $expectedHost) {
        throw "Rust host $host does not match release target $expectedHost"
    }

    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
    $osCaption = ([string]$operatingSystem.Caption).Replace("`r", ' ').Replace("`n", ' ').Trim()
    $osVersion = ([string]$operatingSystem.Version).Trim()
    $osBuild = ([string]$operatingSystem.BuildNumber).Trim()
    if ([string]::IsNullOrWhiteSpace($osCaption) -or
        [string]::IsNullOrWhiteSpace($osVersion) -or
        [string]::IsNullOrWhiteSpace($osBuild)) {
        throw 'native Windows operating-system identity is unavailable'
    }

    & python.exe scripts/validate_portable_release_plan.py
    if ($LASTEXITCODE -ne 0) { throw 'portable release-plan validation failed' }
    & cargo.exe test --workspace --locked
    if ($LASTEXITCODE -ne 0) { throw 'native Windows workspace tests failed' }
    $nativeSmoke = Join-Path $sourceRoot 'scripts\smoke_windows_native.ps1'
    if (-not (Test-Path -LiteralPath $nativeSmoke -PathType Leaf)) {
        throw 'native Windows live smoke is required before release evidence can be produced'
    }
    & pwsh.exe -NoProfile -File $nativeSmoke
    if ($LASTEXITCODE -ne 0) { throw 'native Windows live smoke failed' }

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

    $firstBuild = Join-Path $runRoot 'first'
    $secondBuild = Join-Path $runRoot 'second'
    Build-ArchiveSet -Destination $firstBuild
    Build-ArchiveSet -Destination $secondBuild
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

    $firstHashes = @{}
    Get-ChildItem -LiteralPath $firstBuild -Filter '*.zip' -File | ForEach-Object {
        $firstHashes[$_.Name] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $secondHashes = @{}
    Get-ChildItem -LiteralPath $secondBuild -Filter '*.zip' -File | ForEach-Object {
        $secondHashes[$_.Name] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    if ($firstHashes.Count -ne $secondHashes.Count) {
        throw 'reproducible Windows builds produced different archive counts'
    }
    foreach ($name in $firstHashes.Keys) {
        if (-not $secondHashes.ContainsKey($name) -or $firstHashes[$name] -ne $secondHashes[$name]) {
            throw "Windows archive is not reproducible: $name"
        }
    }

    if (Test-Path -LiteralPath $outputRoot) {
        Remove-Item -LiteralPath $outputRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
    Copy-Item -Path (Join-Path $secondBuild '*.zip') -Destination $outputRoot
    Copy-Item -LiteralPath (Join-Path $runRoot 'tag-verification.txt') -Destination $outputRoot

    $checksumLines = @($secondHashes.GetEnumerator() | Sort-Object Name | ForEach-Object {
        "$($_.Value)  $($_.Name)"
    })
    $checksumFile = Join-Path $outputRoot "SHA256SUMS-$targetLabel.txt"
    Set-Content -LiteralPath $checksumFile -Value $checksumLines -Encoding ascii

    $manifestBytes = [Text.Encoding]::UTF8.GetBytes(($checksumLines -join "`n") + "`n")
    $manifestHash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($manifestBytes)
    ).ToLowerInvariant()
    Set-Content -LiteralPath (Join-Path $outputRoot "REPRODUCIBLE-BUILD-SHA256-$targetLabel.txt") `
        -Value "$manifestHash  archive-set-manifest" -Encoding ascii

    @(
        "version=$Version"
        "tag=$tag"
        "commit=$tagCommit"
        "architecture=$Architecture"
        "rust_host=$host"
        "windows_os_caption=$osCaption"
        "windows_os_version=$osVersion"
        "windows_os_build=$osBuild"
        'test_scope=workspace-native-all-archives-and-wasm-smoke'
        'archive_count=7'
        'reproducible=true'
    ) | Set-Content -LiteralPath (Join-Path $outputRoot "release-evidence-$targetLabel.txt") -Encoding ascii

    Write-Host "Windows release evidence written to $outputRoot"
} finally {
    Set-Location ($env:SystemDrive + '\')
    if (Test-Path -LiteralPath $runRoot) {
        Remove-Item -LiteralPath $runRoot -Recurse -Force
    }
}

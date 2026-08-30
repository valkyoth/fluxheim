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
$targetLabel = if ($Architecture -eq 'x86_64') {
    'x86_64-windows'
} else {
    'aarch64-windows'
}
$expectedHostArchitecture = if ($Architecture -eq 'x86_64') { 'X64' } else { 'Arm64' }
$actualHostArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($actualHostArchitecture -ne $expectedHostArchitecture) {
    throw "native Windows archive smoke requires $expectedHostArchitecture, running on $actualHostArchitecture"
}
$profiles = @('full', 'wasm', 'cache', 'proxy', 'load-balancer', 'php', 'config-tester')
$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
if (-not [IO.Path]::IsPathFullyQualified($temporaryRoot)) {
    throw "Windows temporary directory is not fully qualified: $temporaryRoot"
}
$testRoot = Join-Path $temporaryRoot "fluxheim-windows-archive-smoke-$([Guid]::NewGuid().ToString('N'))"

try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    foreach ($profile in $profiles) {
        $bundleName = "fluxheim-$Version-$profile-$targetLabel"
        $archivePath = Join-Path (Join-Path $root 'dist') "$bundleName.zip"
        if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
            throw "Windows profile archive is missing: $archivePath"
        }

        $extractRoot = Join-Path $testRoot $profile
        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractRoot
        $bundleRoot = Join-Path $extractRoot $bundleName
        if (-not (Test-Path -LiteralPath $bundleRoot -PathType Container)) {
            throw "Windows profile archive omitted its bundle root: $bundleName"
        }

        $binaries = if ($profile -eq 'config-tester') {
            @('fluxheim-config-tester.exe')
        } else {
            @('fluxheim.exe', 'fluxheim-acme.exe')
        }
        foreach ($binaryName in $binaries) {
            $binaryPath = Join-Path $bundleRoot $binaryName
            if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
                throw "Windows profile archive $bundleName omitted $binaryName"
            }
            $versionOutput = @(& $binaryPath --version 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw "Windows profile archive $bundleName could not run $binaryName --version"
            }
            if (-not (($versionOutput -join "`n").StartsWith("fluxheim $Version"))) {
                throw "Windows profile archive $bundleName reported an unexpected version for $binaryName"
            }
        }
    }

    Write-Host 'all seven Windows profile archive executables: ok'
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

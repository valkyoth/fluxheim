[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Za-z][0-9A-Za-z._+-]*$')]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidateSet('x86_64', 'aarch64')]
    [string]$Architecture,

    [ValidateSet('all', 'full', 'wasm', 'cache', 'proxy', 'load-balancer', 'php', 'config-tester')]
    [string]$Profile = 'all',

    [switch]$Plan
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Version.Contains('..')) {
    throw 'release version must not contain a parent-directory component'
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root

$target = if ($Architecture -eq 'x86_64') {
    'x86_64-pc-windows-msvc'
} else {
    'aarch64-pc-windows-msvc'
}

$python = Get-Command python.exe -ErrorAction SilentlyContinue
if ($null -eq $python) {
    throw 'python.exe is required on PATH'
}

$planArguments = @(
    'scripts/portable_release_plan.py',
    $Version,
    '--kind', 'windows',
    '--target', $target,
    '--profile', $Profile
)
$releasePlan = @(& $python.Source @planArguments)
if ($LASTEXITCODE -ne 0) {
    throw 'portable Windows release planning failed'
}
if ($Plan) {
    $releasePlan
    exit 0
}

$expectedHostArchitecture = if ($Architecture -eq 'x86_64') { 'X64' } else { 'Arm64' }
$actualHostArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($actualHostArchitecture -ne $expectedHostArchitecture) {
    throw "native Windows release build requires $expectedHostArchitecture, running on $actualHostArchitecture"
}

$distRoot = Join-Path $root 'dist'
New-Item -ItemType Directory -Force -Path $distRoot | Out-Null

function Invoke-CargoBuild {
    param(
        [Parameter(Mandatory = $true)][string]$Features,
        [Parameter(Mandatory = $true)][string[]]$Binaries
    )

    $arguments = @(
        'build', '--release', '--locked', '--target', $target,
        '--no-default-features', '--features', $Features
    )
    foreach ($binary in $Binaries) {
        $arguments += @('--bin', $binary)
    }
    & cargo.exe @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed for $($Binaries -join ', ')"
    }
}

function Copy-CommonPayload {
    param([Parameter(Mandatory = $true)][string]$Destination)

    Copy-Item README.md, LICENSE, CHANGELOG.md -Destination $Destination
}

foreach ($row in $releasePlan) {
    $fields = $row -split '\|', 3
    if ($fields.Count -ne 3) {
        throw "invalid portable release plan row: $row"
    }
    $distName = $fields[0]
    $features = $fields[1]
    $binaries = @($fields[2] -split ',' | ForEach-Object { $_ -replace '[.]exe$', '' })
    if ($distName -notmatch '^[0-9A-Za-z][0-9A-Za-z._+-]*$') {
        throw "unsafe release bundle name: $distName"
    }

    Invoke-CargoBuild -Features $features -Binaries $binaries

    $destination = Join-Path $distRoot $distName
    if (Test-Path -LiteralPath $destination) {
        Remove-Item -LiteralPath $destination -Recurse -Force
    }
    New-Item -ItemType Directory -Path $destination | Out-Null

    foreach ($binary in $binaries) {
        $source = Join-Path $root "target/$target/release/$binary.exe"
        Copy-Item -LiteralPath $source -Destination $destination
    }
    Copy-CommonPayload -Destination $destination

    if ($distName -notmatch '-config-tester-') {
        Copy-Item docs, examples, packaging, release-notes -Destination $destination -Recurse
    }

    & $python.Source scripts/create_release_archives.py $distName
    if ($LASTEXITCODE -ne 0) {
        throw "archive creation failed for $distName"
    }
}

Write-Host "Windows release assets built for $target"

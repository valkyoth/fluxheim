[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('X64', 'Arm64')]
    [string]$ExpectedArchitecture,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]+$')]
    [string]$BuildUser,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$AuthorizedKeyFile,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f:./]+$')]
    [string]$AllowedSourceCidr,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$TagAllowedSignersFile,

    [ValidatePattern('^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$')]
    [string]$WorkspaceRoot = 'C:\FluxheimBuild'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'windows_release_sshd_config.ps1')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'run this preparation script from an elevated PowerShell session'
}

$actualArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($actualArchitecture -ne $ExpectedArchitecture) {
    throw "expected $ExpectedArchitecture Windows host, found $actualArchitecture"
}

$localUser = Get-LocalUser -Name $BuildUser -ErrorAction Stop
if (-not $localUser.Enabled) {
    throw "release build account is disabled: $BuildUser"
}
$administrators = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
if ($administrators.Name -contains "$env:COMPUTERNAME\$BuildUser") {
    throw 'release build account must not be a local administrator'
}

$authorizedKey = (Get-Content -LiteralPath $AuthorizedKeyFile -Raw).Trim()
if ($authorizedKey -notmatch '^ssh-(ed25519|rsa|ecdsa-[^ ]+) [A-Za-z0-9+/=]+(?: .*)?$' -or $authorizedKey.Contains("`n")) {
    throw 'authorized key file must contain exactly one OpenSSH public key'
}

$capability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
if ($null -eq $capability) {
    throw 'OpenSSH Server capability is unavailable on this Windows host'
}
if ($capability.State -ne 'Installed') {
    if ($PSCmdlet.ShouldProcess('OpenSSH.Server', 'Install Windows capability')) {
        Add-WindowsCapability -Online -Name $capability.Name | Out-Null
    }
}

$sshTrustRoot = Join-Path $env:ProgramData 'ssh\fluxheim-release'
$authorizedKeys = Join-Path $sshTrustRoot 'authorized_keys'

if ($PSCmdlet.ShouldProcess($sshTrustRoot, 'Install administrator-controlled release-builder SSH key')) {
    New-Item -ItemType Directory -Force -Path $sshTrustRoot | Out-Null
    & icacls.exe $sshTrustRoot /setowner 'Administrators' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to set release-builder SSH trust directory owner' }
    & icacls.exe $sshTrustRoot /inheritance:r /grant:r `
        "$BuildUser`:(OI)(CI)RX" 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to secure release-builder SSH trust directory' }
    if (Test-Path -LiteralPath $authorizedKeys -PathType Leaf) {
        & icacls.exe $authorizedKeys /setowner 'Administrators' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'failed to set existing authorized_keys owner' }
        & icacls.exe $authorizedKeys /inheritance:r /grant:r `
            "$BuildUser`:R" 'SYSTEM:F' 'Administrators:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'failed to secure existing authorized_keys' }
    }
    Set-Content -LiteralPath $authorizedKeys -Value $authorizedKey -Encoding ascii -NoNewline
    & icacls.exe $authorizedKeys /inheritance:r /grant:r `
        "$BuildUser`:R" 'SYSTEM:F' 'Administrators:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to secure authorized_keys' }
    & icacls.exe $authorizedKeys /setowner 'Administrators' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to set authorized_keys owner' }
}

$trustedDirectory = Join-Path $WorkspaceRoot 'trusted'
$runsDirectory = Join-Path $WorkspaceRoot 'runs'
$outputDirectory = Join-Path $WorkspaceRoot 'output'
$allowedSigners = Join-Path $trustedDirectory 'allowed_signers'
if ($PSCmdlet.ShouldProcess($WorkspaceRoot, 'Create private release workspace')) {
    New-Item -ItemType Directory -Force -Path $WorkspaceRoot | Out-Null
    & icacls.exe $WorkspaceRoot /setowner 'Administrators' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to set release workspace owner' }
    & icacls.exe $WorkspaceRoot /inheritance:r /grant:r `
        "$BuildUser`:RX" 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to secure release workspace' }
    New-Item -ItemType Directory -Force -Path `
        $trustedDirectory, $runsDirectory, $outputDirectory | Out-Null
    & icacls.exe $trustedDirectory /setowner 'Administrators' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to set trusted release directory owner' }
    & icacls.exe $trustedDirectory /inheritance:r /grant:r "$BuildUser`:(OI)(CI)RX" 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to secure trusted release directory' }
    if (Test-Path -LiteralPath $allowedSigners -PathType Leaf) {
        & icacls.exe $allowedSigners /setowner 'Administrators' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'failed to set existing trusted tag signer policy owner' }
        & icacls.exe $allowedSigners /inheritance:r /grant:r "$BuildUser`:R" 'SYSTEM:F' 'Administrators:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'failed to secure existing trusted tag signer policy' }
    }
    Copy-Item -LiteralPath $TagAllowedSignersFile -Destination $allowedSigners -Force
    & icacls.exe $allowedSigners /inheritance:r /grant:r "$BuildUser`:R" 'SYSTEM:F' 'Administrators:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to secure trusted tag signer policy' }
    & icacls.exe $allowedSigners /setowner 'Administrators' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to set trusted tag signer policy owner' }
    foreach ($mutableDirectory in $runsDirectory, $outputDirectory) {
        & icacls.exe $mutableDirectory /inheritance:r /grant:r `
            "$BuildUser`:(OI)(CI)M" 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "failed to secure mutable release directory: $mutableDirectory" }
    }
}

$sshdConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
$config = Get-Content -LiteralPath $sshdConfig -Raw
$config = Set-FluxheimReleaseBuilderSshdPolicy -Config $config -BuildUser $BuildUser
if ($PSCmdlet.ShouldProcess($sshdConfig, 'Restrict release-builder SSH authentication')) {
    Set-Content -LiteralPath $sshdConfig -Value $config -Encoding ascii
    & "$env:WINDIR\System32\OpenSSH\sshd.exe" -t
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH configuration validation failed' }
    $effectiveSshd = (& "$env:WINDIR\System32\OpenSSH\sshd.exe" -T -C "user=$BuildUser,host=localhost,addr=127.0.0.1") -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH effective configuration validation failed' }
    foreach ($required in @(
        'passwordauthentication no',
        'authenticationmethods publickey',
        "allowusers $BuildUser",
        'authorizedkeysfile __PROGRAMDATA__/ssh/fluxheim-release/authorized_keys'
    )) {
        if ($effectiveSshd -notmatch "(?m)^$([regex]::Escape($required))$") {
            throw "OpenSSH effective configuration does not enforce: $required"
        }
    }
}

if ($PSCmdlet.ShouldProcess('Fluxheim-Release-SSH-In-TCP', 'Restrict SSH firewall ingress')) {
    Get-NetFirewallRule -DisplayName 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue |
        Disable-NetFirewallRule | Out-Null
    Remove-NetFirewallRule -DisplayName 'Fluxheim-Release-SSH-In-TCP' -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName 'Fluxheim-Release-SSH-In-TCP' -Direction Inbound `
        -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress $AllowedSourceCidr | Out-Null
}

if ($PSCmdlet.ShouldProcess('sshd', 'Enable and restart OpenSSH Server')) {
    Set-Service -Name sshd -StartupType Automatic
    Restart-Service -Name sshd
}

$requiredCommands = 'pwsh.exe', 'git.exe', 'rustup.exe', 'rustc.exe', 'cargo.exe', 'python.exe', 'cmake.exe'
$missing = @($requiredCommands | Where-Object { $null -eq (Get-Command $_ -ErrorAction SilentlyContinue) })
if ($missing.Count -gt 0) {
    Write-Warning "Install these tools for the build account and add them to PATH: $($missing -join ', ')"
}

Write-Host "Prepared Fluxheim $ExpectedArchitecture release builder for $BuildUser"
Write-Host 'Also restrict TCP/22 to the Linux release host in the Azure NSG or external firewall.'
Get-ChildItem "$env:ProgramData\ssh\ssh_host_*_key.pub" |
    ForEach-Object { & ssh-keygen.exe -lf $_.FullName }

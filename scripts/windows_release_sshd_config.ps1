function Resolve-FluxheimReleaseSshdExecutable {
    param(
        [Parameter(Mandatory = $true)][string]$ImagePath,
        [Parameter(Mandatory = $true)][string]$WindowsDirectory,
        [Parameter(Mandatory = $true)][string]$ProgramFilesDirectory
    )

    # Accept only a standard service executable, never command-line arguments
    # or a PATH-resolved program. Do not switch OpenSSH distributions over SSH.
    $executable = $ImagePath.Trim()
    if ($executable -match '^"([^"\r\n]+)"$') {
        $executable = $Matches[1]
    } elseif ($executable -match '[\s"]') {
        throw 'OpenSSH service executable must be quoted when its path contains spaces'
    }
    $allowed = @(
        $WindowsDirectory.TrimEnd('\') + '\System32\OpenSSH\sshd.exe'
        $ProgramFilesDirectory.TrimEnd('\') + '\OpenSSH\sshd.exe'
        $ProgramFilesDirectory.TrimEnd('\') + '\OpenSSH-Win64\sshd.exe'
    )
    foreach ($candidate in $allowed) {
        if ([string]::Equals($candidate, $executable, [StringComparison]::OrdinalIgnoreCase)) {
            return $candidate
        }
    }
    throw 'OpenSSH service must use a supported Windows or Program Files installation without arguments'
}

function Set-FluxheimReleaseBuilderSshdPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Config,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9_.-]+$')]
        [string]$BuildUser
    )

    $beginMarker = '# BEGIN FLUXHEIM RELEASE BUILDER'
    $endMarker = '# END FLUXHEIM RELEASE BUILDER'
    $escapedBegin = [regex]::Escape($beginMarker)
    $escapedEnd = [regex]::Escape($endMarker)
    $withoutPreviousPolicy = [regex]::Replace(
        $Config,
        "(?ms)^$escapedBegin.*?^$escapedEnd\r?\n?",
        ''
    )
    $buildUserSsh = $BuildUser.ToLowerInvariant()
    $globalBlock = @"
$beginMarker
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers $buildUserSsh
AuthorizedKeysFile __PROGRAMDATA__/ssh/fluxheim-release/authorized_keys
$endMarker
"@

    # OpenSSH uses the first obtained value. Prepending keeps this policy
    # global even when the vendor configuration ends in a Match block.
    return $globalBlock + "`r`n" + $withoutPreviousPolicy.TrimStart()
}

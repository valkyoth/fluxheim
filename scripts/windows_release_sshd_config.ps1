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
$endMarker
"@

    # OpenSSH uses the first obtained value. Prepending keeps this policy
    # global even when the vendor configuration ends in a Match block.
    return $globalBlock + "`r`n" + $withoutPreviousPolicy.TrimStart()
}

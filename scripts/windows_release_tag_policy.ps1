function Test-FluxheimSshSignedTagObject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TagObject
    )

    $signatureHeaders = [regex]::Matches(
        $TagObject,
        '(?m)^-----BEGIN (?:SSH SIGNATURE|PGP SIGNATURE|PGP MESSAGE|SIGNED MESSAGE)-----\r?$'
    )
    $sshSignatureEnds = [regex]::Matches(
        $TagObject,
        '(?m)^-----END SSH SIGNATURE-----\r?$'
    ).Count
    return (
        $signatureHeaders.Count -eq 1 -and
        $signatureHeaders[0].Value -match 'BEGIN SSH SIGNATURE' -and
        $sshSignatureEnds -eq 1
    )
}

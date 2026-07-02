use super::*;
pub(super) fn validate_certificate_pem(contents: &[u8]) -> Result<(), AcmeCertificateInstallError> {
    validate_pem_bytes(
        contents,
        MAX_CERTIFICATE_CHAIN_BYTES,
        b"-----BEGIN CERTIFICATE-----",
        b"-----END CERTIFICATE-----",
        AcmeCertificateInstallError::InvalidCertificatePem,
    )
}

pub(super) fn validate_private_key_pem(contents: &[u8]) -> Result<(), AcmeCertificateInstallError> {
    if contents.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(AcmeCertificateInstallError::InvalidPrivateKeyPem(
            "file is too large",
        ));
    }
    if contents.is_empty() {
        return Err(AcmeCertificateInstallError::InvalidPrivateKeyPem(
            "file is empty",
        ));
    }
    if contents
        .iter()
        .any(|byte| *byte == b'\0' || (*byte < 0x09) || (*byte > 0x0d && *byte < 0x20))
    {
        return Err(AcmeCertificateInstallError::InvalidPrivateKeyPem(
            "file contains control bytes",
        ));
    }

    let supported_key_markers = [
        (
            b"-----BEGIN PRIVATE KEY-----".as_slice(),
            b"-----END PRIVATE KEY-----".as_slice(),
        ),
        (
            b"-----BEGIN EC PRIVATE KEY-----".as_slice(),
            b"-----END EC PRIVATE KEY-----".as_slice(),
        ),
        (
            b"-----BEGIN RSA PRIVATE KEY-----".as_slice(),
            b"-----END RSA PRIVATE KEY-----".as_slice(),
        ),
    ];

    if supported_key_markers
        .iter()
        .any(|(begin, end)| contains_subslice(contents, begin) && contains_subslice(contents, end))
    {
        Ok(())
    } else {
        Err(AcmeCertificateInstallError::InvalidPrivateKeyPem(
            "missing supported private-key PEM markers",
        ))
    }
}

fn validate_pem_bytes(
    contents: &[u8],
    max_bytes: usize,
    begin_marker: &[u8],
    end_marker: &[u8],
    error: fn(&'static str) -> AcmeCertificateInstallError,
) -> Result<(), AcmeCertificateInstallError> {
    if contents.is_empty() {
        return Err(error("file is empty"));
    }
    if contents.len() > max_bytes {
        return Err(error("file is too large"));
    }
    if contents
        .iter()
        .any(|byte| *byte == b'\0' || (*byte < 0x09) || (*byte > 0x0d && *byte < 0x20))
    {
        return Err(error("file contains control bytes"));
    }
    if !contains_subslice(contents, begin_marker) || !contains_subslice(contents, end_marker) {
        return Err(error("missing PEM markers"));
    }

    Ok(())
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

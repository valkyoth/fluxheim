use super::*;
use std::collections::HashSet;

use rcgen::PublicKeyData as _;
use x509_parser::extensions::GeneralName;

pub(super) fn validate_issued_material(
    chain_pem: &[u8],
    key_pem: &[u8],
    expected_domains: &[String],
) -> Result<(), AcmeCertificateInstallError> {
    validate_certificate_pem(chain_pem)?;
    validate_private_key_pem(key_pem)?;
    if expected_domains.is_empty() {
        return Err(AcmeCertificateInstallError::InvalidCertificatePem(
            "expected DNS names are empty",
        ));
    }

    let key_text = std::str::from_utf8(key_pem).map_err(|_| {
        AcmeCertificateInstallError::InvalidPrivateKeyPem("private key is not UTF-8 PEM")
    })?;
    let key = rcgen::KeyPair::from_pem(key_text).map_err(|_| {
        AcmeCertificateInstallError::InvalidPrivateKeyPem("private key cannot be parsed")
    })?;

    let mut certificates = x509_parser::pem::Pem::iter_from_buffer(chain_pem);
    let leaf_pem = certificates
        .next()
        .ok_or(AcmeCertificateInstallError::InvalidCertificatePem(
            "certificate chain is empty",
        ))?
        .map_err(|_| {
            AcmeCertificateInstallError::InvalidCertificatePem("leaf PEM cannot be parsed")
        })?;
    if leaf_pem.label != "CERTIFICATE" {
        return Err(AcmeCertificateInstallError::InvalidCertificatePem(
            "first PEM block is not a certificate",
        ));
    }
    let leaf = leaf_pem.parse_x509().map_err(|_| {
        AcmeCertificateInstallError::InvalidCertificatePem("leaf X.509 certificate is invalid")
    })?;

    if leaf.public_key().raw != key.subject_public_key_info() {
        return Err(AcmeCertificateInstallError::InvalidPrivateKeyPem(
            "certificate public key does not match private key",
        ));
    }
    if !leaf.validity().is_valid() {
        return Err(AcmeCertificateInstallError::InvalidCertificatePem(
            "leaf certificate is not currently valid",
        ));
    }
    if leaf.is_ca() {
        return Err(AcmeCertificateInstallError::InvalidCertificatePem(
            "leaf certificate is a CA certificate",
        ));
    }
    if let Some(usage) = leaf.extended_key_usage().map_err(|_| {
        AcmeCertificateInstallError::InvalidCertificatePem("leaf extended key usage is invalid")
    })? && !usage.value.server_auth
        && !usage.value.any
    {
        return Err(AcmeCertificateInstallError::InvalidCertificatePem(
            "leaf certificate is not valid for TLS server authentication",
        ));
    }

    let san = leaf
        .subject_alternative_name()
        .map_err(|_| {
            AcmeCertificateInstallError::InvalidCertificatePem(
                "leaf subjectAltName extension is invalid",
            )
        })?
        .ok_or(AcmeCertificateInstallError::InvalidCertificatePem(
            "leaf certificate has no subjectAltName extension",
        ))?;
    let issued_names = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(name) => Some(normalized_domain(name)),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let expected_names = expected_domains
        .iter()
        .map(|name| normalized_domain(name))
        .collect::<HashSet<_>>();
    if issued_names != expected_names {
        return Err(AcmeCertificateInstallError::InvalidCertificatePem(
            "leaf DNS subjectAltName values do not exactly match the requested identifiers",
        ));
    }

    for certificate in certificates {
        let certificate = certificate.map_err(|_| {
            AcmeCertificateInstallError::InvalidCertificatePem(
                "certificate chain contains malformed PEM",
            )
        })?;
        if certificate.label != "CERTIFICATE" || certificate.parse_x509().is_err() {
            return Err(AcmeCertificateInstallError::InvalidCertificatePem(
                "certificate chain contains an invalid X.509 certificate",
            ));
        }
    }

    Ok(())
}

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

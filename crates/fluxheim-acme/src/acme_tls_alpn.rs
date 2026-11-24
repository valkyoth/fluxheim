use sanitization::SecretVec;

#[cfg(test)]
#[test]
fn generated_certificate_contains_only_the_requested_san_and_critical_identifier() {
    let digest = [42; 32];
    let (cert_pem, _) = tls_alpn_01_certificate("Example.TEST", &digest).unwrap();
    let (_, pem) = x509_parser::pem::parse_x509_pem(&cert_pem).unwrap();
    let certificate = pem.parse_x509().unwrap();
    let san = certificate.subject_alternative_name().unwrap().unwrap();
    assert_eq!(
        san.value.general_names,
        [x509_parser::extensions::GeneralName::DNSName(
            "example.test"
        )]
    );
    let extensions: Vec<_> = certificate
        .extensions()
        .iter()
        .filter(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        .collect();
    assert_eq!(extensions.len(), 1);
    assert!(extensions[0].critical);
    assert_eq!(extensions[0].value, [&[4, 32][..], &digest].concat());
    assert_eq!(
        certificate.validity().not_after.timestamp()
            - certificate.validity().not_before.timestamp(),
        240
    );
    assert!(tls_alpn_01_certificate("example.test", &[0; 31]).is_err());
}

use fluxheim_config::normalize_host;

use super::AcmeRenewalError;

#[cfg(feature = "acme-client")]
pub fn tls_alpn_01_certificate(
    domain: &str,
    key_authorization_digest: &[u8],
) -> Result<(Vec<u8>, SecretVec), AcmeRenewalError> {
    if key_authorization_digest.len() != 32 {
        return Err(AcmeRenewalError::TlsAlpnCertificate {
            domain: domain.to_owned(),
            message: "key authorization digest must be 32 bytes".to_owned(),
        });
    }
    let Some(normalized_domain) = normalize_host(domain) else {
        return Err(AcmeRenewalError::TlsAlpnCertificate {
            domain: domain.to_owned(),
            message: "domain is not a valid DNS identifier".to_owned(),
        });
    };

    let mut params =
        rcgen::CertificateParams::new(vec![normalized_domain.clone()]).map_err(|error| {
            AcmeRenewalError::TlsAlpnCertificate {
                domain: normalized_domain.clone(),
                message: error.to_string(),
            }
        })?;
    let now = std::time::SystemTime::now();
    params.not_before = now
        .checked_sub(std::time::Duration::from_secs(60))
        .unwrap_or(now)
        .into();
    params.not_after = now
        .checked_add(std::time::Duration::from_secs(180))
        .ok_or_else(|| AcmeRenewalError::TlsAlpnCertificate {
            domain: normalized_domain.clone(),
            message: "challenge validity out of range".into(),
        })?
        .into();
    params
        .custom_extensions
        .push(rcgen::CustomExtension::new_acme_identifier(
            key_authorization_digest,
        ));
    let signing_key =
        rcgen::KeyPair::generate().map_err(|error| AcmeRenewalError::TlsAlpnCertificate {
            domain: normalized_domain.clone(),
            message: error.to_string(),
        })?;
    let certificate =
        params
            .self_signed(&signing_key)
            .map_err(|error| AcmeRenewalError::TlsAlpnCertificate {
                domain: normalized_domain,
                message: error.to_string(),
            })?;

    Ok((
        certificate.pem().into_bytes(),
        SecretVec::from_vec(signing_key.serialize_pem().into_bytes()),
    ))
}

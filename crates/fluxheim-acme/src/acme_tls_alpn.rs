use zeroize::Zeroizing;

use fluxheim_config::normalize_host;

use super::{AcmeRenewalError, AcmeTlsAlpn01ChallengeStore};

#[cfg(feature = "acme-client")]
pub(super) fn cleanup_tls_alpn_01_challenges(
    store: &AcmeTlsAlpn01ChallengeStore,
    domains: &[String],
) -> Result<(), AcmeRenewalError> {
    for domain in domains {
        store
            .remove_challenge_certificate(domain)
            .map_err(|error| AcmeRenewalError::Challenge {
                token: domain.clone(),
                error,
            })?;
    }
    Ok(())
}

#[cfg(feature = "acme-client")]
pub(super) fn tls_alpn_01_certificate(
    domain: &str,
    key_authorization_digest: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AcmeRenewalError> {
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
        Zeroizing::new(signing_key.serialize_pem().into_bytes()),
    ))
}

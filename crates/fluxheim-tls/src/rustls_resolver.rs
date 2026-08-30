use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;

use base64_ng::ct;
use fluxheim_config::{StaticCertificateConfig, normalize_host};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    pem::{Error as PemError, PemObject},
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, SigningKey};
use sanitization::SecretVec;
use thiserror::Error;

use crate::DownstreamCertificateSelector;
use crate::tls_input::{
    MAX_CERT_CHAIN_BYTES, MAX_CHAIN_CERTIFICATES, MAX_PRIVATE_KEY_BYTES, read_bounded_file,
    read_bounded_secret,
};

const MAX_TLS_ALPN_CHALLENGE_CERTIFICATES: usize = 1024;
const MAX_PRIVATE_KEY_DER_STAGING_BYTES: usize = 64 * 1024;

static PENDING_MANAGED_CERTIFICATE_RECORDER: OnceLock<fn()> = OnceLock::new();

pub fn set_pending_managed_certificate_recorder(recorder: fn()) {
    let _ = PENDING_MANAGED_CERTIFICATE_RECORDER.set(recorder);
}

#[derive(Debug, Error)]
pub enum RustlsDownstreamCertificateError {
    #[error("failed to open TLS certificate file {path}: {source}")]
    OpenCertificate {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse TLS certificate file {path}: {source}")]
    ParseCertificate {
        path: PathBuf,
        #[source]
        source: PemError,
    },
    #[error("TLS certificate file {path} does not contain a certificate chain")]
    EmptyCertificateChain { path: PathBuf },
    #[error("TLS certificate chain {path} contains {count} certificates; maximum is {maximum}")]
    TooManyCertificates {
        path: PathBuf,
        count: usize,
        maximum: usize,
    },
    #[error("failed to open TLS private-key file {path}: {source}")]
    OpenPrivateKey {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse TLS private-key file {path}: {reason}")]
    ParsePrivateKey { path: PathBuf, reason: String },
    #[error("TLS certificate/key pair is not usable; cert={cert_path} key={key_path}: {source}")]
    InvalidCertificateKey {
        cert_path: PathBuf,
        key_path: PathBuf,
        #[source]
        source: Box<rustls::Error>,
    },
    #[error(
        "failed to inspect managed certificate paths; cert={cert_path} key={key_path}: {source}"
    )]
    InspectManagedCertificate {
        cert_path: PathBuf,
        key_path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("TLS-ALPN challenge certificate SNI is invalid: {sni}")]
    InvalidTlsAlpnSni { sni: String },
    #[error("TLS-ALPN challenge certificate SNI is duplicated: {sni}")]
    DuplicateTlsAlpnSni { sni: String },
    #[error("TLS-ALPN challenge certificate count exceeds {maximum}")]
    TooManyTlsAlpnCertificates { maximum: usize },
}

#[derive(Debug, Default)]
pub struct RustlsTlsAlpnCertificateStore {
    certificates: arc_swap::ArcSwap<HashMap<String, Arc<CertifiedKey>>>,
}

impl RustlsTlsAlpnCertificateStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn replace(
        &self,
        certificates: impl IntoIterator<Item = (String, Arc<CertifiedKey>)>,
    ) -> Result<(), RustlsDownstreamCertificateError> {
        let mut replacement = HashMap::new();
        for (index, (sni, certificate)) in certificates.into_iter().enumerate() {
            if index >= MAX_TLS_ALPN_CHALLENGE_CERTIFICATES {
                return Err(
                    RustlsDownstreamCertificateError::TooManyTlsAlpnCertificates {
                        maximum: MAX_TLS_ALPN_CHALLENGE_CERTIFICATES,
                    },
                );
            }
            let normalized = normalize_host(&sni)
                .ok_or(RustlsDownstreamCertificateError::InvalidTlsAlpnSni { sni })?;
            if replacement
                .insert(normalized.clone(), certificate)
                .is_some()
            {
                return Err(RustlsDownstreamCertificateError::DuplicateTlsAlpnSni {
                    sni: normalized,
                });
            }
        }
        self.certificates.store(Arc::new(replacement));
        Ok(())
    }

    fn resolve(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let normalized = sni.and_then(normalize_host)?;
        self.certificates.load().get(&normalized).cloned()
    }
}

pub struct RustlsDownstreamCertificateResolver {
    selector: DownstreamCertificateSelector,
    certificates: arc_swap::ArcSwap<Vec<Option<Arc<CertifiedKey>>>>,
    tls_alpn_challenge: Option<RustlsTlsAlpnChallenge>,
}

struct RustlsTlsAlpnChallenge {
    protocol: Vec<u8>,
    certificates: Arc<RustlsTlsAlpnCertificateStore>,
}

impl std::fmt::Debug for RustlsDownstreamCertificateResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RustlsDownstreamCertificateResolver")
            .field("certificate_slots", &self.certificate_slot_count())
            .field(
                "tls_alpn_challenge",
                &self.tls_alpn_challenge.as_ref().map(|challenge| {
                    String::from_utf8_lossy(challenge.protocol.as_slice()).into_owned()
                }),
            )
            .finish_non_exhaustive()
    }
}

impl RustlsDownstreamCertificateResolver {
    pub fn new(
        selector: &DownstreamCertificateSelector,
    ) -> Result<Self, RustlsDownstreamCertificateError> {
        Self::with_optional_tls_alpn_challenge(selector, None, None)
    }

    pub fn with_tls_alpn_challenge(
        selector: &DownstreamCertificateSelector,
        protocol: Vec<u8>,
        certificates: Arc<RustlsTlsAlpnCertificateStore>,
    ) -> Result<Self, RustlsDownstreamCertificateError> {
        Self::with_optional_tls_alpn_challenge(selector, Some(protocol), Some(certificates))
    }

    fn with_optional_tls_alpn_challenge(
        selector: &DownstreamCertificateSelector,
        protocol: Option<Vec<u8>>,
        challenge_certificates: Option<Arc<RustlsTlsAlpnCertificateStore>>,
    ) -> Result<Self, RustlsDownstreamCertificateError> {
        let certificates = load_rustls_certified_keys(selector)?;
        let tls_alpn_challenge =
            protocol
                .zip(challenge_certificates)
                .map(|(protocol, certificates)| RustlsTlsAlpnChallenge {
                    protocol,
                    certificates,
                });

        Ok(Self {
            selector: selector.clone(),
            certificates: arc_swap::ArcSwap::from_pointee(certificates),
            tls_alpn_challenge,
        })
    }

    pub fn reload(&self) -> Result<(), RustlsDownstreamCertificateError> {
        let certificates = load_rustls_certified_keys(&self.selector)?;
        self.certificates.store(Arc::new(certificates));
        Ok(())
    }

    pub fn certificate_slot_count(&self) -> usize {
        self.certificates.load().len()
    }

    pub fn loaded_certificate_count(&self) -> usize {
        self.certificates
            .load()
            .iter()
            .filter(|certificate| certificate.is_some())
            .count()
    }

    fn resolve_static_certificate(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let index = self.selector.certificate_index_for_sni(sni);
        let certificates = self.certificates.load();
        certificates.get(index).and_then(Clone::clone).or_else(|| {
            certificates
                .get(self.selector.default_certificate_index())
                .and_then(Clone::clone)
        })
    }

    fn resolve_tls_alpn_challenge(
        &self,
        client_hello: &ClientHello<'_>,
    ) -> Option<Arc<CertifiedKey>> {
        let challenge = self.tls_alpn_challenge.as_ref()?;
        if !client_hello_requests_alpn_protocol(client_hello, challenge.protocol.as_slice()) {
            return None;
        }

        challenge.certificates.resolve(client_hello.server_name())
    }
}

impl ResolvesServerCert for RustlsDownstreamCertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_tls_alpn_challenge(&client_hello)
            .or_else(|| self.resolve_static_certificate(client_hello.server_name()))
    }
}

pub fn load_rustls_certified_key_from_paths(
    cert_path: &Path,
    key_path: &Path,
) -> Result<CertifiedKey, RustlsDownstreamCertificateError> {
    let certs = read_certificate_chain(cert_path)?;
    if certs.is_empty() {
        return Err(RustlsDownstreamCertificateError::EmptyCertificateChain {
            path: cert_path.to_path_buf(),
        });
    }
    let key = read_private_key(key_path)?;
    let signing_key = signing_key_from_secret(&key).map_err(|source| {
        RustlsDownstreamCertificateError::InvalidCertificateKey {
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            source: Box::new(source),
        }
    })?;
    let certified = CertifiedKey::new(certs, signing_key);
    certified.keys_match().map_err(|source| {
        RustlsDownstreamCertificateError::InvalidCertificateKey {
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            source: Box::new(source),
        }
    })?;
    Ok(certified)
}

fn load_rustls_certified_keys(
    selector: &DownstreamCertificateSelector,
) -> Result<Vec<Option<Arc<CertifiedKey>>>, RustlsDownstreamCertificateError> {
    let mut certificates = Vec::with_capacity(selector.certificates().len());
    for (index, certificate) in selector.certificates().iter().enumerate() {
        if selector.certificate_is_managed_acme(index) && certificate_paths_are_absent(certificate)?
        {
            log::warn!(
                "managed ACME certificate is pending issuance; cert={} key={}",
                certificate.cert_path.display(),
                certificate.key_path.display()
            );
            record_pending_managed_certificate();
            certificates.push(None);
            continue;
        }
        #[cfg(feature = "acme")]
        let _read_lock = if selector.certificate_is_managed_acme(index) {
            Some(
                fluxheim_acme::lock_managed_certificate_pair(
                    &certificate.cert_path,
                    &certificate.key_path,
                )
                .map_err(|source| {
                    RustlsDownstreamCertificateError::InspectManagedCertificate {
                        cert_path: certificate.cert_path.clone(),
                        key_path: certificate.key_path.clone(),
                        source,
                    }
                })?,
            )
        } else {
            None
        };
        if selector.certificate_is_managed_acme(index) && certificate_paths_are_absent(certificate)?
        {
            log::warn!(
                "managed ACME certificate is pending issuance; cert={} key={}",
                certificate.cert_path.display(),
                certificate.key_path.display()
            );
            record_pending_managed_certificate();
            certificates.push(None);
            continue;
        }
        certificates.push(Some(Arc::new(load_rustls_certified_key_from_paths(
            &certificate.cert_path,
            &certificate.key_path,
        )?)));
    }
    Ok(certificates)
}

fn record_pending_managed_certificate() {
    if let Some(recorder) = PENDING_MANAGED_CERTIFICATE_RECORDER.get() {
        recorder();
    }
}

fn read_certificate_chain(
    cert_path: &Path,
) -> Result<Vec<CertificateDer<'static>>, RustlsDownstreamCertificateError> {
    let bytes = read_bounded_file(cert_path, MAX_CERT_CHAIN_BYTES).map_err(|source| {
        RustlsDownstreamCertificateError::OpenCertificate {
            path: cert_path.to_path_buf(),
            source,
        }
    })?;
    let mut certificates = Vec::new();
    for certificate in CertificateDer::pem_slice_iter(&bytes) {
        let certificate =
            certificate.map_err(
                |source| RustlsDownstreamCertificateError::ParseCertificate {
                    path: cert_path.to_path_buf(),
                    source,
                },
            )?;
        if certificates.len() >= MAX_CHAIN_CERTIFICATES {
            return Err(RustlsDownstreamCertificateError::TooManyCertificates {
                path: cert_path.to_path_buf(),
                count: certificates.len() + 1,
                maximum: MAX_CHAIN_CERTIFICATES,
            });
        }
        certificates.push(certificate);
    }
    Ok(certificates)
}

fn read_private_key(
    key_path: &Path,
) -> Result<SanitizedPrivateKey, RustlsDownstreamCertificateError> {
    let pem = read_bounded_secret(key_path, MAX_PRIVATE_KEY_BYTES).map_err(|source| {
        RustlsDownstreamCertificateError::OpenPrivateKey {
            path: key_path.to_path_buf(),
            source,
        }
    })?;
    pem.with_secret(decode_private_key_pem).map_err(|reason| {
        RustlsDownstreamCertificateError::ParsePrivateKey {
            path: key_path.to_path_buf(),
            reason,
        }
    })
}

#[derive(Clone, Copy)]
enum PrivateKeyKind {
    Pkcs1,
    Sec1,
    Pkcs8,
}

struct SanitizedPrivateKey {
    kind: PrivateKeyKind,
    der: SecretVec,
}

fn decode_private_key_pem(pem: &[u8]) -> Result<SanitizedPrivateKey, String> {
    const SECTIONS: [(&[u8], &[u8], PrivateKeyKind); 3] = [
        (
            b"-----BEGIN RSA PRIVATE KEY-----",
            b"-----END RSA PRIVATE KEY-----",
            PrivateKeyKind::Pkcs1,
        ),
        (
            b"-----BEGIN EC PRIVATE KEY-----",
            b"-----END EC PRIVATE KEY-----",
            PrivateKeyKind::Sec1,
        ),
        (
            b"-----BEGIN PRIVATE KEY-----",
            b"-----END PRIVATE KEY-----",
            PrivateKeyKind::Pkcs8,
        ),
    ];
    for (begin, end, kind) in SECTIONS {
        let Some(begin_at) = find_bytes(pem, begin) else {
            continue;
        };
        let content_start = begin_at + begin.len();
        let Some(end_offset) = find_bytes(&pem[content_start..], end) else {
            return Err("private-key PEM end marker is missing".to_owned());
        };
        let encoded = &pem[content_start..content_start + end_offset];
        let mut compact = Vec::new();
        compact
            .try_reserve_exact(encoded.len())
            .map_err(|error| format!("failed to reserve private-key PEM payload: {error}"))?;
        compact.extend(
            encoded
                .iter()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace()),
        );
        let compact = SecretVec::from_vec(compact);
        let der = compact
            .with_secret(|encoded| {
                ct::STANDARD.decode_secret_staged::<MAX_PRIVATE_KEY_DER_STAGING_BYTES>(encoded)
            })
            .map_err(|error| format!("private-key PEM base64 is invalid: {}", error.kind()))?;
        if der.is_empty() {
            return Err("private-key PEM payload is empty".to_owned());
        }
        return Ok(SanitizedPrivateKey {
            kind,
            der: SecretVec::from_slice(der.expose_secret()),
        });
    }
    Err("TLS private-key file does not contain a supported private key".to_owned())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}

fn signing_key_from_secret(
    key: &SanitizedPrivateKey,
) -> Result<Arc<dyn SigningKey>, rustls::Error> {
    key.der.with_secret(|der| {
        let private_key = match key.kind {
            PrivateKeyKind::Pkcs1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)),
            PrivateKeyKind::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)),
            PrivateKeyKind::Pkcs8 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
        };
        #[cfg(feature = "tls-rustls-fips")]
        {
            rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key)
        }
        #[cfg(not(feature = "tls-rustls-fips"))]
        {
            rustls::crypto::ring::sign::any_supported_type(&private_key)
        }
    })
}

fn certificate_paths_are_absent(
    certificate: &StaticCertificateConfig,
) -> Result<bool, RustlsDownstreamCertificateError> {
    let cert_exists = certificate.cert_path.try_exists().map_err(|source| {
        RustlsDownstreamCertificateError::InspectManagedCertificate {
            cert_path: certificate.cert_path.clone(),
            key_path: certificate.key_path.clone(),
            source,
        }
    })?;
    let key_exists = certificate.key_path.try_exists().map_err(|source| {
        RustlsDownstreamCertificateError::InspectManagedCertificate {
            cert_path: certificate.cert_path.clone(),
            key_path: certificate.key_path.clone(),
            source,
        }
    })?;
    Ok(!cert_exists || !key_exists)
}

fn client_hello_requests_alpn_protocol(client_hello: &ClientHello<'_>, protocol: &[u8]) -> bool {
    client_hello
        .alpn()
        .is_some_and(|mut protocols| protocols.any(|candidate| candidate == protocol))
}

#[cfg(test)]
#[path = "rustls_resolver_tests.rs"]
mod tests;

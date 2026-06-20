use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;

use fluxheim_config::StaticCertificateConfig;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer,
    pem::{Error as PemError, PemObject},
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use thiserror::Error;

use crate::{DownstreamCertificateSelector, rustls_crypto_provider};

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
    #[error("failed to open TLS private-key file {path}: {source}")]
    OpenPrivateKey {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse TLS private-key file {path}: {source}")]
    ParsePrivateKey {
        path: PathBuf,
        #[source]
        source: PemError,
    },
    #[error("TLS private-key file {path} does not contain a supported private key")]
    MissingPrivateKey { path: PathBuf },
    #[error("TLS certificate/key pair is not usable; cert={cert_path} key={key_path}: {source}")]
    InvalidCertificateKey {
        cert_path: PathBuf,
        key_path: PathBuf,
        #[source]
        source: rustls::Error,
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
}

pub trait RustlsTlsAlpnCertificateLoader: std::fmt::Debug + Send + Sync {
    fn load_tls_alpn_certificate(
        &self,
        sni: Option<&str>,
    ) -> Result<Option<CertifiedKey>, RustlsDownstreamCertificateError>;
}

pub struct RustlsDownstreamCertificateResolver {
    selector: DownstreamCertificateSelector,
    certificates: arc_swap::ArcSwap<Vec<Option<Arc<CertifiedKey>>>>,
    tls_alpn_challenge: Option<RustlsTlsAlpnChallenge>,
}

struct RustlsTlsAlpnChallenge {
    protocol: Vec<u8>,
    loader: Arc<dyn RustlsTlsAlpnCertificateLoader>,
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
        loader: Arc<dyn RustlsTlsAlpnCertificateLoader>,
    ) -> Result<Self, RustlsDownstreamCertificateError> {
        Self::with_optional_tls_alpn_challenge(selector, Some(protocol), Some(loader))
    }

    fn with_optional_tls_alpn_challenge(
        selector: &DownstreamCertificateSelector,
        protocol: Option<Vec<u8>>,
        loader: Option<Arc<dyn RustlsTlsAlpnCertificateLoader>>,
    ) -> Result<Self, RustlsDownstreamCertificateError> {
        let certificates = load_rustls_certified_keys(selector)?;
        let tls_alpn_challenge = protocol
            .zip(loader)
            .map(|(protocol, loader)| RustlsTlsAlpnChallenge { protocol, loader });

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

        match challenge
            .loader
            .load_tls_alpn_certificate(client_hello.server_name())
        {
            Ok(Some(certificate)) => Some(Arc::new(certificate)),
            Ok(None) => None,
            Err(error) => {
                log::warn!("failed to load TLS-ALPN challenge certificate: {error}");
                None
            }
        }
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
    let provider = rustls_crypto_provider();
    CertifiedKey::from_der(certs, key, &provider).map_err(|source| {
        RustlsDownstreamCertificateError::InvalidCertificateKey {
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            source,
        }
    })
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
    let file = File::open(cert_path).map_err(|source| {
        RustlsDownstreamCertificateError::OpenCertificate {
            path: cert_path.to_path_buf(),
            source,
        }
    })?;
    let mut reader = BufReader::new(file);
    CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(
            |source| RustlsDownstreamCertificateError::ParseCertificate {
                path: cert_path.to_path_buf(),
                source,
            },
        )
}

fn read_private_key(
    key_path: &Path,
) -> Result<PrivateKeyDer<'static>, RustlsDownstreamCertificateError> {
    let file = File::open(key_path).map_err(|source| {
        RustlsDownstreamCertificateError::OpenPrivateKey {
            path: key_path.to_path_buf(),
            source,
        }
    })?;
    let mut reader = BufReader::new(file);
    PrivateKeyDer::from_pem_reader(&mut reader).map_err(|source| match source {
        PemError::NoItemsFound => RustlsDownstreamCertificateError::MissingPrivateKey {
            path: key_path.to_path_buf(),
        },
        source => RustlsDownstreamCertificateError::ParsePrivateKey {
            path: key_path.to_path_buf(),
            source,
        },
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
mod tests {
    use std::path::PathBuf;

    use fluxheim_config::{Config, StaticCertificateConfig, TlsConfig};

    use super::*;

    #[test]
    fn resolver_can_reload_certificate_files()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let certificate = StaticCertificateConfig {
            cert_path: PathBuf::from("../../tests/fixtures/tls/localhost-cert.pem"),
            key_path: PathBuf::from("../../tests/fixtures/tls/localhost-key.pem"),
        };
        let config = Config {
            tls: TlsConfig {
                enabled: true,
                certificates: vec![certificate],
                ..TlsConfig::default()
            },
            ..Config::default()
        };
        let selector = DownstreamCertificateSelector::from_config(&config)
            .ok_or("expected downstream certificate selector")?;
        let resolver = RustlsDownstreamCertificateResolver::new(&selector)?;

        resolver.reload()?;

        assert_eq!(resolver.certificate_slot_count(), 1);
        assert_eq!(resolver.loaded_certificate_count(), 1);
        Ok(())
    }

    #[test]
    fn managed_certificate_is_pending_when_either_file_is_missing()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let existing_cert = PathBuf::from("../../tests/fixtures/tls/localhost-cert.pem");
        let existing_key = PathBuf::from("../../tests/fixtures/tls/localhost-key.pem");

        assert!(certificate_paths_are_absent(&StaticCertificateConfig {
            cert_path: existing_cert,
            key_path: PathBuf::from("../../tests/fixtures/tls/missing-key.pem"),
        })?);
        assert!(certificate_paths_are_absent(&StaticCertificateConfig {
            cert_path: PathBuf::from("../../tests/fixtures/tls/missing-cert.pem"),
            key_path: existing_key,
        })?);
        Ok(())
    }
}

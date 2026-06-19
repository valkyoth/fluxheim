use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use fluxheim_config::{
    StaticCertificateConfig, TlsAlpnPolicy, TlsClientAuthMode, TlsConfig, TlsProtocolVersion,
};
use openssl::pkey::{PKey, Private};
use openssl::ssl::{AlpnError, SslAcceptor, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::{X509, X509Name};
use thiserror::Error;

use crate::{DownstreamCertificateSelector, openssl_cipher_lists, openssl_curve_list};

const ALPN_HTTP1: &[u8] = b"\x08http/1.1";
const ALPN_HTTP2: &[u8] = b"\x02h2";
const ALPN_HTTP2_HTTP1: &[u8] = b"\x02h2\x08http/1.1";

#[derive(Debug, Error)]
pub enum OpenSslDownstreamAcceptorError {
    #[error("failed to build OpenSSL downstream TLS acceptor: {0}")]
    BuildAcceptor(#[source] openssl::error::ErrorStack),
    #[error("failed to read TLS certificate chain {path}: {source}")]
    ReadCertificate {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse TLS certificate chain {path}: {source}")]
    ParseCertificate {
        path: PathBuf,
        #[source]
        source: openssl::error::ErrorStack,
    },
    #[error("TLS certificate chain {path} does not contain any certificates")]
    EmptyCertificate { path: PathBuf },
    #[error("failed to read TLS private key {path}: {source}")]
    ReadPrivateKey {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse TLS private key {path}: {source}")]
    ParsePrivateKey {
        path: PathBuf,
        #[source]
        source: openssl::error::ErrorStack,
    },
    #[error("failed to apply TLS certificate to OpenSSL acceptor: {0}")]
    ApplyCertificate(#[source] openssl::error::ErrorStack),
    #[error("failed to apply TLS private key to OpenSSL acceptor: {0}")]
    ApplyPrivateKey(#[source] openssl::error::ErrorStack),
    #[error("OpenSSL rejected downstream TLS curve policy: {0}")]
    ApplyCurves(#[source] openssl::error::ErrorStack),
    #[error("OpenSSL rejected downstream TLS 1.2 cipher policy: {0}")]
    ApplyTls12Ciphers(#[source] openssl::error::ErrorStack),
    #[error("OpenSSL rejected downstream TLS 1.3 cipher policy: {0}")]
    ApplyTls13Ciphers(#[source] openssl::error::ErrorStack),
    #[error("OpenSSL rejected downstream TLS protocol policy: {0}")]
    ApplyProtocol(#[source] openssl::error::ErrorStack),
    #[error("tls.client_auth.ca_path is required when client auth is enabled")]
    MissingClientAuthCa,
    #[error("tls.client_auth.ca_path must be valid UTF-8 for OpenSSL: {path}")]
    ClientAuthCaPathUtf8 { path: PathBuf },
    #[error("OpenSSL rejected TLS client-auth CA file {path}: {source}")]
    ApplyClientAuthCa {
        path: PathBuf,
        #[source]
        source: openssl::error::ErrorStack,
    },
    #[error("OpenSSL rejected TLS client-auth CA list {path}: {source}")]
    ApplyClientAuthCaList {
        path: PathBuf,
        #[source]
        source: openssl::error::ErrorStack,
    },
}

#[derive(Debug, Error)]
pub enum OpenSslDownstreamCertificateStoreError {
    #[error(transparent)]
    Certificate(#[from] OpenSslDownstreamAcceptorError),
    #[error(
        "failed to inspect managed certificate paths; cert={cert_path} key={key_path}: {source}"
    )]
    InspectManagedCertificate {
        cert_path: PathBuf,
        key_path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("downstream SNI certificate index {index} was not loaded")]
    MissingLoadedCertificate { index: usize },
}

pub struct OpenSslDownstreamCertificateStore {
    selector: DownstreamCertificateSelector,
    certificates: ArcSwap<Vec<Option<OpenSslDownstreamCertificate>>>,
    pending_managed_certificate_recorder: Option<fn()>,
}

impl OpenSslDownstreamCertificateStore {
    pub fn new(
        selector: &DownstreamCertificateSelector,
        pending_managed_certificate_recorder: Option<fn()>,
    ) -> Result<Self, OpenSslDownstreamCertificateStoreError> {
        let certificates =
            load_openssl_downstream_certificates(selector, pending_managed_certificate_recorder)?;
        Ok(Self {
            selector: selector.clone(),
            certificates: ArcSwap::from_pointee(certificates),
            pending_managed_certificate_recorder,
        })
    }

    pub fn reload(&self) -> Result<(), OpenSslDownstreamCertificateStoreError> {
        let certificates = load_openssl_downstream_certificates(
            &self.selector,
            self.pending_managed_certificate_recorder,
        )?;
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

    pub fn apply_certificate_for_sni(
        &self,
        sni: Option<&str>,
        ssl: &mut openssl::ssl::SslRef,
    ) -> Result<(), OpenSslDownstreamCertificateStoreError> {
        let index = self.selector.certificate_index_for_sni(sni);
        let certificates = self.certificates.load();
        let Some(certificate) = certificates
            .get(index)
            .and_then(Option::as_ref)
            .or_else(|| {
                certificates
                    .get(self.selector.default_certificate_index())
                    .and_then(Option::as_ref)
            })
        else {
            return Err(OpenSslDownstreamCertificateStoreError::MissingLoadedCertificate { index });
        };
        certificate.apply_to_ssl(ssl)?;
        Ok(())
    }
}

struct OpenSslDownstreamCertificate {
    chain: Vec<X509>,
    private_key: PKey<Private>,
}

impl OpenSslDownstreamCertificate {
    fn load(certificate: &StaticCertificateConfig) -> Result<Self, OpenSslDownstreamAcceptorError> {
        let chain = load_certificate_chain(certificate)?;
        let private_key = load_private_key(certificate)?;
        Ok(Self { chain, private_key })
    }

    fn apply_to_ssl(
        &self,
        ssl: &mut openssl::ssl::SslRef,
    ) -> Result<(), OpenSslDownstreamAcceptorError> {
        let Some((leaf, chain)) = self.chain.split_first() else {
            return Err(OpenSslDownstreamAcceptorError::EmptyCertificate {
                path: PathBuf::from("<in-memory>"),
            });
        };
        ssl.set_certificate(leaf)
            .map_err(OpenSslDownstreamAcceptorError::ApplyCertificate)?;
        ssl.set_private_key(&self.private_key)
            .map_err(OpenSslDownstreamAcceptorError::ApplyPrivateKey)?;
        for certificate in chain {
            ssl.add_chain_cert(certificate.clone())
                .map_err(OpenSslDownstreamAcceptorError::ApplyCertificate)?;
        }
        Ok(())
    }
}

pub fn build_openssl_downstream_acceptor(
    tls: &TlsConfig,
    certificate: &StaticCertificateConfig,
) -> Result<SslAcceptor, OpenSslDownstreamAcceptorError> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls_server())
        .map_err(OpenSslDownstreamAcceptorError::BuildAcceptor)?;
    apply_certificate(&mut builder, certificate)?;
    apply_tls_policy(&mut builder, tls)?;
    Ok(builder.build())
}

fn apply_certificate(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
    certificate: &StaticCertificateConfig,
) -> Result<(), OpenSslDownstreamAcceptorError> {
    let chain = load_certificate_chain(certificate)?;
    let private_key = load_private_key(certificate)?;
    let (leaf, intermediates) =
        chain
            .split_first()
            .ok_or_else(|| OpenSslDownstreamAcceptorError::EmptyCertificate {
                path: certificate.cert_path.clone(),
            })?;

    builder
        .set_certificate(leaf)
        .map_err(OpenSslDownstreamAcceptorError::ApplyCertificate)?;
    for certificate in intermediates {
        builder
            .add_extra_chain_cert(certificate.clone())
            .map_err(OpenSslDownstreamAcceptorError::ApplyCertificate)?;
    }
    builder
        .set_private_key(&private_key)
        .map_err(OpenSslDownstreamAcceptorError::ApplyPrivateKey)?;
    builder
        .check_private_key()
        .map_err(OpenSslDownstreamAcceptorError::ApplyPrivateKey)?;
    Ok(())
}

fn load_certificate_chain(
    certificate: &StaticCertificateConfig,
) -> Result<Vec<X509>, OpenSslDownstreamAcceptorError> {
    let bytes = fs::read(&certificate.cert_path).map_err(|source| {
        OpenSslDownstreamAcceptorError::ReadCertificate {
            path: certificate.cert_path.clone(),
            source,
        }
    })?;
    let chain = X509::stack_from_pem(&bytes).map_err(|source| {
        OpenSslDownstreamAcceptorError::ParseCertificate {
            path: certificate.cert_path.clone(),
            source,
        }
    })?;
    if chain.is_empty() {
        return Err(OpenSslDownstreamAcceptorError::EmptyCertificate {
            path: certificate.cert_path.clone(),
        });
    }
    Ok(chain)
}

fn load_private_key(
    certificate: &StaticCertificateConfig,
) -> Result<PKey<Private>, OpenSslDownstreamAcceptorError> {
    let bytes = fs::read(&certificate.key_path).map_err(|source| {
        OpenSslDownstreamAcceptorError::ReadPrivateKey {
            path: certificate.key_path.clone(),
            source,
        }
    })?;
    PKey::private_key_from_pem(&bytes).map_err(|source| {
        OpenSslDownstreamAcceptorError::ParsePrivateKey {
            path: certificate.key_path.clone(),
            source,
        }
    })
}

fn load_openssl_downstream_certificates(
    selector: &DownstreamCertificateSelector,
    pending_managed_certificate_recorder: Option<fn()>,
) -> Result<Vec<Option<OpenSslDownstreamCertificate>>, OpenSslDownstreamCertificateStoreError> {
    let mut certificates = Vec::with_capacity(selector.certificates().len());
    for (index, certificate) in selector.certificates().iter().enumerate() {
        if selector.certificate_is_managed_acme(index) && certificate_paths_are_absent(certificate)?
        {
            log::warn!(
                "managed ACME certificate is pending issuance; cert={} key={}",
                certificate.cert_path.display(),
                certificate.key_path.display()
            );
            if let Some(recorder) = pending_managed_certificate_recorder {
                recorder();
            }
            certificates.push(None);
            continue;
        }
        certificates.push(Some(OpenSslDownstreamCertificate::load(certificate)?));
    }
    Ok(certificates)
}

fn certificate_paths_are_absent(
    certificate: &StaticCertificateConfig,
) -> Result<bool, OpenSslDownstreamCertificateStoreError> {
    let cert_exists = path_exists(&certificate.cert_path).map_err(|source| {
        OpenSslDownstreamCertificateStoreError::InspectManagedCertificate {
            cert_path: certificate.cert_path.clone(),
            key_path: certificate.key_path.clone(),
            source,
        }
    })?;
    let key_exists = path_exists(&certificate.key_path).map_err(|source| {
        OpenSslDownstreamCertificateStoreError::InspectManagedCertificate {
            cert_path: certificate.cert_path.clone(),
            key_path: certificate.key_path.clone(),
            source,
        }
    })?;
    Ok(!cert_exists || !key_exists)
}

fn path_exists(path: &std::path::Path) -> Result<bool, std::io::Error> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn apply_tls_policy(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
    tls: &TlsConfig,
) -> Result<(), OpenSslDownstreamAcceptorError> {
    let alpn = openssl_alpn_wire(tls.effective_alpn());
    builder.set_alpn_select_callback(move |_ssl, client| {
        openssl::ssl::select_next_proto(alpn, client).ok_or(AlpnError::NOACK)
    });
    builder
        .set_groups_list(&openssl_curve_list(&tls.effective_curve_preferences()))
        .map_err(OpenSslDownstreamAcceptorError::ApplyCurves)?;
    let (tls12_ciphers, tls13_ciphers) = openssl_cipher_lists(&tls.effective_cipher_suites());
    if !tls12_ciphers.is_empty() {
        builder
            .set_cipher_list(&tls12_ciphers)
            .map_err(OpenSslDownstreamAcceptorError::ApplyTls12Ciphers)?;
    }
    if !tls13_ciphers.is_empty() {
        builder
            .set_ciphersuites(&tls13_ciphers)
            .map_err(OpenSslDownstreamAcceptorError::ApplyTls13Ciphers)?;
    }
    let min_version = match tls.effective_min_protocol() {
        TlsProtocolVersion::Tls12 => SslVersion::TLS1_2,
        TlsProtocolVersion::Tls13 => SslVersion::TLS1_3,
    };
    builder
        .set_min_proto_version(Some(min_version))
        .map_err(OpenSslDownstreamAcceptorError::ApplyProtocol)?;
    apply_client_auth(builder, tls)?;
    Ok(())
}

fn openssl_alpn_wire(policy: TlsAlpnPolicy) -> &'static [u8] {
    match policy {
        TlsAlpnPolicy::Http1 => ALPN_HTTP1,
        TlsAlpnPolicy::Http2 => ALPN_HTTP2,
        TlsAlpnPolicy::Http1AndHttp2 => ALPN_HTTP2_HTTP1,
    }
}

fn apply_client_auth(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
    tls: &TlsConfig,
) -> Result<(), OpenSslDownstreamAcceptorError> {
    if tls.client_auth.mode == TlsClientAuthMode::Off {
        return Ok(());
    }
    let ca_path = tls
        .client_auth
        .ca_path
        .as_deref()
        .ok_or(OpenSslDownstreamAcceptorError::MissingClientAuthCa)?;
    let ca_path_str =
        ca_path
            .to_str()
            .ok_or_else(|| OpenSslDownstreamAcceptorError::ClientAuthCaPathUtf8 {
                path: ca_path.to_path_buf(),
            })?;
    let verify = match tls.client_auth.mode {
        TlsClientAuthMode::Off => SslVerifyMode::NONE,
        TlsClientAuthMode::Optional => SslVerifyMode::PEER,
        TlsClientAuthMode::Required => SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
    };
    builder.set_verify(verify);
    builder.set_ca_file(ca_path_str).map_err(|source| {
        OpenSslDownstreamAcceptorError::ApplyClientAuthCa {
            path: ca_path.to_path_buf(),
            source,
        }
    })?;
    builder.set_client_ca_list(
        X509Name::load_client_ca_file(ca_path_str).map_err(|source| {
            OpenSslDownstreamAcceptorError::ApplyClientAuthCaList {
                path: ca_path.to_path_buf(),
                source,
            }
        })?,
    );
    Ok(())
}

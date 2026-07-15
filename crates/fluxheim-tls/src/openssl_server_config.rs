use std::fs;
use std::sync::Arc;

use arc_swap::ArcSwap;
use fluxheim_config::{StaticCertificateConfig, TlsAlpnPolicy, TlsConfig, TlsProtocolVersion};
use openssl::pkey::{PKey, Private};
use openssl::ssl::{AlpnError, NameType, SniError, SslAcceptor, SslContext, SslMethod, SslVersion};
use openssl::x509::X509;
#[path = "openssl_client_auth.rs"]
mod client_auth;
#[path = "openssl_server_error.rs"]
mod error;
#[path = "openssl_server_generation.rs"]
mod generation;

use crate::tls_input::{
    MAX_CERT_CHAIN_BYTES, MAX_CHAIN_CERTIFICATES, MAX_PRIVATE_KEY_BYTES, read_bounded_file,
    read_bounded_secret,
};
use crate::{DownstreamCertificateSelector, openssl_cipher_lists, openssl_curve_list};
use client_auth::OpenSslClientAuthPolicy;
pub use error::{OpenSslDownstreamAcceptorError, OpenSslDownstreamCertificateStoreError};
use generation::{OpenSslGenerationLease, OpenSslReloadGenerationState};

const ALPN_HTTP1: &[u8] = b"\x08http/1.1";
const ALPN_HTTP2: &[u8] = b"\x02h2";
const ALPN_HTTP2_HTTP1: &[u8] = b"\x02h2\x08http/1.1";
const MAX_PROJECTED_OPENSSL_SNI_POLICY_BYTES: usize = 128 * 1024 * 1024;
const OPENSSL_SESSION_CACHE_BUDGET: usize = 4096;
const OPENSSL_RELOAD_POLICY_GENERATIONS: usize = 2;

pub struct OpenSslDownstreamCertificateStore {
    selector: DownstreamCertificateSelector,
    tls: TlsConfig,
    generation: ArcSwap<OpenSslCertificateGeneration>,
    reload_generations: OpenSslReloadGenerationState,
    session_cache_entries_per_context: i32,
    pending_managed_certificate_recorder: Option<fn()>,
}

struct OpenSslCertificateGeneration {
    certificates: Vec<Option<OpenSslDownstreamCertificate>>,
    lease: Arc<OpenSslGenerationLease>,
}

impl OpenSslDownstreamCertificateStore {
    pub fn new(
        selector: &DownstreamCertificateSelector,
        tls: &TlsConfig,
        pending_managed_certificate_recorder: Option<fn()>,
    ) -> Result<Self, OpenSslDownstreamCertificateStoreError> {
        let client_auth = OpenSslClientAuthPolicy::load(tls)?;
        let session_cache_entries_per_context = validate_openssl_sni_context_budget(
            selector.certificates().len(),
            client_auth.input_bytes(),
        )?;
        let certificates = load_openssl_downstream_certificates(
            selector,
            tls,
            &client_auth,
            session_cache_entries_per_context,
            pending_managed_certificate_recorder,
        )?;
        let lease = Arc::new(OpenSslGenerationLease);
        let reload_generations = OpenSslReloadGenerationState::new(&lease)?;
        let generation = Arc::new(OpenSslCertificateGeneration {
            certificates,
            lease: lease.clone(),
        });
        Ok(Self {
            selector: selector.clone(),
            tls: tls.clone(),
            generation: ArcSwap::from(generation),
            reload_generations,
            session_cache_entries_per_context,
            pending_managed_certificate_recorder,
        })
    }

    pub fn reload(&self) -> Result<(), OpenSslDownstreamCertificateStoreError> {
        let mut reload = self
            .reload_generations
            .lock(OPENSSL_RELOAD_POLICY_GENERATIONS)?;
        let client_auth = OpenSslClientAuthPolicy::load(&self.tls)?;
        validate_openssl_sni_context_budget(
            self.selector.certificates().len(),
            client_auth.input_bytes(),
        )?;
        let certificates = load_openssl_downstream_certificates(
            &self.selector,
            &self.tls,
            &client_auth,
            self.session_cache_entries_per_context,
            self.pending_managed_certificate_recorder,
        )?;
        let lease = Arc::new(OpenSslGenerationLease);
        let generation = Arc::new(OpenSslCertificateGeneration {
            certificates,
            lease: lease.clone(),
        });
        reload.track(&lease);
        self.generation.store(generation);
        Ok(())
    }

    pub fn certificate_slot_count(&self) -> usize {
        self.generation.load().certificates.len()
    }

    pub fn loaded_certificate_count(&self) -> usize {
        self.generation
            .load()
            .certificates
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
        let generation = self.generation.load_full();
        let Some(certificate) = generation
            .certificates
            .get(index)
            .and_then(Option::as_ref)
            .or_else(|| {
                generation
                    .certificates
                    .get(self.selector.default_certificate_index())
                    .and_then(Option::as_ref)
            })
        else {
            return Err(OpenSslDownstreamCertificateStoreError::MissingLoadedCertificate { index });
        };
        certificate.apply_to_ssl(ssl)?;
        self.reload_generations
            .attach_to_ssl(ssl, generation.lease.clone());
        Ok(())
    }
}

struct OpenSslDownstreamCertificate {
    context: SslContext,
}

impl OpenSslDownstreamCertificate {
    fn load(
        certificate: &StaticCertificateConfig,
        tls: &TlsConfig,
        client_auth: &OpenSslClientAuthPolicy,
        session_cache_entries: i32,
    ) -> Result<Self, OpenSslDownstreamAcceptorError> {
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .map_err(OpenSslDownstreamAcceptorError::BuildAcceptor)?;
        apply_certificate(&mut builder, certificate)?;
        apply_tls_policy(&mut builder, tls, client_auth, session_cache_entries)?;
        Ok(Self {
            context: builder.build().into_context(),
        })
    }

    fn apply_to_ssl(
        &self,
        ssl: &mut openssl::ssl::SslRef,
    ) -> Result<(), OpenSslDownstreamAcceptorError> {
        ssl.set_ssl_context(&self.context)
            .map_err(OpenSslDownstreamAcceptorError::ApplyCertificateContext)
    }
}

pub fn build_openssl_downstream_acceptor(
    tls: &TlsConfig,
    certificate: &StaticCertificateConfig,
) -> Result<SslAcceptor, OpenSslDownstreamAcceptorError> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
        .map_err(OpenSslDownstreamAcceptorError::BuildAcceptor)?;
    apply_certificate(&mut builder, certificate)?;
    let client_auth = OpenSslClientAuthPolicy::load(tls)?;
    apply_tls_policy(
        &mut builder,
        tls,
        &client_auth,
        OPENSSL_SESSION_CACHE_BUDGET as i32,
    )?;
    Ok(builder.build())
}

pub fn build_openssl_downstream_acceptor_with_sni_store(
    tls: &TlsConfig,
    certificate: &StaticCertificateConfig,
    store: Arc<OpenSslDownstreamCertificateStore>,
) -> Result<SslAcceptor, OpenSslDownstreamAcceptorError> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
        .map_err(OpenSslDownstreamAcceptorError::BuildAcceptor)?;
    apply_certificate(&mut builder, certificate)?;
    let store_for_callback = store.clone();
    builder.set_servername_callback(move |ssl, _alert| {
        let sni = ssl.servername(NameType::HOST_NAME).map(str::to_owned);
        if let Err(error) = store_for_callback.apply_certificate_for_sni(sni.as_deref(), ssl) {
            log::error!(
                target: "fluxheim::tls",
                "failed to apply OpenSSL downstream SNI certificate: {error}"
            );
            return Err(SniError::ALERT_FATAL);
        }
        Ok(())
    });
    let client_auth = OpenSslClientAuthPolicy::load(tls)?;
    apply_tls_policy(
        &mut builder,
        tls,
        &client_auth,
        store.session_cache_entries_per_context,
    )?;
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
    let public_key = leaf
        .public_key()
        .map_err(OpenSslDownstreamAcceptorError::InspectCertificatePublicKey)?;
    if !private_key.public_eq(&public_key) {
        return Err(OpenSslDownstreamAcceptorError::CertificateKeyMismatch {
            cert_path: certificate.cert_path.clone(),
            key_path: certificate.key_path.clone(),
        });
    }

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
    let bytes =
        read_bounded_file(&certificate.cert_path, MAX_CERT_CHAIN_BYTES).map_err(|source| {
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
    if chain.len() > MAX_CHAIN_CERTIFICATES {
        return Err(OpenSslDownstreamAcceptorError::TooManyCertificates {
            path: certificate.cert_path.clone(),
            count: chain.len(),
            maximum: MAX_CHAIN_CERTIFICATES,
        });
    }
    Ok(chain)
}

fn load_private_key(
    certificate: &StaticCertificateConfig,
) -> Result<PKey<Private>, OpenSslDownstreamAcceptorError> {
    let bytes =
        read_bounded_secret(&certificate.key_path, MAX_PRIVATE_KEY_BYTES).map_err(|source| {
            OpenSslDownstreamAcceptorError::ReadPrivateKey {
                path: certificate.key_path.clone(),
                source,
            }
        })?;
    bytes
        .with_secret(PKey::private_key_from_pem)
        .map_err(|source| OpenSslDownstreamAcceptorError::ParsePrivateKey {
            path: certificate.key_path.clone(),
            source,
        })
}

fn load_openssl_downstream_certificates(
    selector: &DownstreamCertificateSelector,
    tls: &TlsConfig,
    client_auth: &OpenSslClientAuthPolicy,
    session_cache_entries: i32,
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
        #[cfg(feature = "acme")]
        let _read_lock = if selector.certificate_is_managed_acme(index) {
            Some(
                fluxheim_acme::lock_managed_certificate_pair(
                    &certificate.cert_path,
                    &certificate.key_path,
                )
                .map_err(|source| {
                    OpenSslDownstreamCertificateStoreError::InspectManagedCertificate {
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
            if let Some(recorder) = pending_managed_certificate_recorder {
                recorder();
            }
            certificates.push(None);
            continue;
        }
        certificates.push(Some(OpenSslDownstreamCertificate::load(
            certificate,
            tls,
            client_auth,
            session_cache_entries,
        )?));
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
    client_auth: &OpenSslClientAuthPolicy,
    session_cache_entries: i32,
) -> Result<(), OpenSslDownstreamAcceptorError> {
    builder.set_session_cache_size(session_cache_entries);
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
    let mut min_version = match tls.effective_min_protocol() {
        TlsProtocolVersion::Tls12 => SslVersion::TLS1_2,
        TlsProtocolVersion::Tls13 => SslVersion::TLS1_3,
    };
    let mut max_version = None;
    if tls12_ciphers.is_empty() {
        min_version = SslVersion::TLS1_3;
    }
    if tls13_ciphers.is_empty() {
        max_version = Some(SslVersion::TLS1_2);
    }
    builder
        .set_min_proto_version(Some(min_version))
        .map_err(OpenSslDownstreamAcceptorError::ApplyProtocol)?;
    builder
        .set_max_proto_version(max_version)
        .map_err(OpenSslDownstreamAcceptorError::ApplyProtocol)?;
    client_auth.apply(builder)?;
    Ok(())
}

fn validate_openssl_sni_context_budget(
    certificate_count: usize,
    policy_input_bytes: usize,
) -> Result<i32, OpenSslDownstreamCertificateStoreError> {
    let context_count = certificate_count
        .checked_add(1)
        .ok_or(OpenSslDownstreamCertificateStoreError::ContextBudgetOverflow)?;
    let projected_bytes = policy_input_bytes
        .checked_mul(context_count)
        .and_then(|bytes| bytes.checked_mul(OPENSSL_RELOAD_POLICY_GENERATIONS))
        .ok_or(OpenSslDownstreamCertificateStoreError::ContextBudgetOverflow)?;
    if projected_bytes > MAX_PROJECTED_OPENSSL_SNI_POLICY_BYTES {
        return Err(
            OpenSslDownstreamCertificateStoreError::ClientAuthPolicyBudgetExceeded {
                context_count,
                projected_bytes,
                maximum_bytes: MAX_PROJECTED_OPENSSL_SNI_POLICY_BYTES,
            },
        );
    }
    let entries = (OPENSSL_SESSION_CACHE_BUDGET / context_count).max(1);
    i32::try_from(entries)
        .map_err(|_| OpenSslDownstreamCertificateStoreError::ContextBudgetOverflow)
}

fn openssl_alpn_wire(policy: TlsAlpnPolicy) -> &'static [u8] {
    match policy {
        TlsAlpnPolicy::Http1 => ALPN_HTTP1,
        TlsAlpnPolicy::Http2 => ALPN_HTTP2,
        TlsAlpnPolicy::Http1AndHttp2 => ALPN_HTTP2_HTTP1,
    }
}

#[cfg(test)]
#[path = "openssl_server_generation_tests.rs"]
mod generation_tests;
#[cfg(test)]
#[path = "openssl_server_config_tests.rs"]
mod tests;

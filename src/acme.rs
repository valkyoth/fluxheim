use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::config::{AcmeChallenge, Config};

const HTTP_01_CHALLENGE_DIR: &str = "http-01";
const TLS_ALPN_01_CHALLENGE_DIR: &str = "tls-alpn-01";
const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";
const MAX_HTTP_01_TOKEN_BYTES: usize = 256;
const MAX_HTTP_01_KEY_AUTHORIZATION_BYTES: u64 = 4096;
const MAX_EAB_SECRET_BYTES: u64 = 4096;
const MAX_ACCOUNT_CREDENTIALS_BYTES: u64 = 32 * 1024;
const MAX_CERTIFICATE_CHAIN_BYTES: usize = 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 128 * 1024;

#[cfg(any(target_os = "linux", target_os = "android"))]
const UNIX_O_NOFOLLOW: i32 = 0o400000;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const UNIX_O_NOFOLLOW: i32 = 0x0100;

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit symlink-safe file opening before building Fluxheim"
);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcmeRenewalTarget {
    pub vhost_name: String,
    pub issuer: String,
    pub domains: Vec<String>,
    pub challenge: AcmeChallenge,
    pub certificate: AcmeCertificatePaths,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcmeCertificatePaths {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcmeAccountCredentialsPath {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CertificateObservation {
    pub vhost_name: String,
    pub not_after: SystemTime,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcmeRenewalItem {
    pub target: AcmeRenewalTarget,
    pub not_after: Option<SystemTime>,
    pub due_at: SystemTime,
    pub due_now: bool,
}

pub struct AcmeIssueRequest<'a> {
    pub target: &'a AcmeRenewalTarget,
    pub issuer_directory_url: &'a str,
    pub contact_email: Option<&'a str>,
    pub external_account_binding: Option<&'a AcmeExternalAccountBindingSecrets>,
}

impl fmt::Debug for AcmeIssueRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeIssueRequest")
            .field("target", self.target)
            .field("issuer_directory_url", &self.issuer_directory_url)
            .field("contact_email", &self.contact_email)
            .field(
                "external_account_binding",
                &self.external_account_binding.map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcmeHttp01Challenge {
    pub token: String,
    pub key_authorization: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AcmePreparedHttp01Order {
    pub challenges: Vec<AcmeHttp01Challenge>,
}

impl fmt::Debug for AcmePreparedHttp01Order {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmePreparedHttp01Order")
            .field("challenge_count", &self.challenges.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AcmeIssuedCertificate {
    pub fullchain_pem: Vec<u8>,
    pub private_key_pem: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for AcmeIssuedCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeIssuedCertificate")
            .field("fullchain_pem_bytes", &self.fullchain_pem.len())
            .field("private_key_pem", &"<redacted>")
            .finish()
    }
}

pub trait AcmeIssuerClient {
    type Error: fmt::Display;

    fn prepare_http_01_order(
        &mut self,
        request: AcmeIssueRequest<'_>,
    ) -> Result<AcmePreparedHttp01Order, Self::Error>;

    fn finalize_http_01_order(
        &mut self,
        order: &AcmePreparedHttp01Order,
        challenge_store: &AcmeHttp01ChallengeStore,
    ) -> Result<AcmeIssuedCertificate, Self::Error>;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcmeRenewalOutcome {
    pub vhost_name: String,
    pub issuer: String,
    pub certificate: AcmeCertificatePaths,
    pub published_challenges: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcmeRenewalFailure {
    pub vhost_name: String,
    pub issuer: String,
    pub domains: Vec<String>,
    pub error: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AcmeRenewalRun {
    pub attempted: usize,
    pub renewed: Vec<AcmeRenewalOutcome>,
    pub failed: Vec<AcmeRenewalFailure>,
}

pub fn acme_tls_alpn_protocol() -> &'static [u8] {
    ACME_TLS_ALPN_PROTOCOL
}

pub struct AcmeExternalAccountBindingSecrets {
    pub key_id: Zeroizing<String>,
    pub hmac_key: Zeroizing<String>,
}

impl fmt::Debug for AcmeExternalAccountBindingSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeExternalAccountBindingSecrets")
            .field("key_id", &"<redacted>")
            .field("hmac_key", &"<redacted>")
            .finish()
    }
}

#[path = "acme_account_store.rs"]
mod acme_account_store;
#[path = "acme_certificate_install.rs"]
mod acme_certificate_install;
#[path = "acme_certificate_paths.rs"]
mod acme_certificate_paths;
#[path = "acme_challenges.rs"]
mod acme_challenges;
#[path = "acme_eab.rs"]
mod acme_eab;
#[path = "acme_errors.rs"]
mod acme_errors;
#[cfg(feature = "acme-client")]
#[path = "acme_instant.rs"]
mod acme_instant;
#[path = "acme_names.rs"]
mod acme_names;
#[path = "acme_pem.rs"]
mod acme_pem;
#[path = "acme_queue.rs"]
mod acme_queue;
#[path = "acme_tls_alpn.rs"]
mod acme_tls_alpn;
pub use acme_account_store::{
    account_credentials_path, load_account_credentials, store_account_credentials,
};
pub use acme_certificate_install::install_managed_certificate;
use acme_certificate_install::{
    install_certificate_files, managed_certificate_owner, reject_existing_symlink_in_path,
};
use acme_certificate_paths::{MANAGED_FULLCHAIN_FILE, MANAGED_PRIVATE_KEY_FILE};
pub use acme_certificate_paths::{
    load_certificate_not_after, managed_certificate_paths, observe_target_certificate,
};
pub use acme_challenges::{
    AcmeHttp01ChallengeStore, AcmeTlsAlpn01ChallengeStore, http_01_token_from_path,
};
#[cfg(feature = "acme-client")]
use acme_challenges::{acme_client_error_message_with_http_01_context, cleanup_http_01_challenges};
#[cfg(all(feature = "acme-client", test))]
pub(crate) use acme_eab::decode_eab_hmac_key;
#[cfg(feature = "acme-client")]
use acme_eab::external_account_key_from_secrets;
use acme_eab::load_external_account_binding_from_config;
#[cfg(feature = "acme-client")]
pub use acme_errors::AcmeInstantClientError;
#[cfg(feature = "acme-client")]
use acme_errors::instant_client_error_to_renewal_error;
pub use acme_errors::{
    AcmeAccountStoreError, AcmeCertificateInstallError, AcmeRenewalError, AcmeSecretLoadError,
};
#[cfg(feature = "acme-client")]
pub use acme_instant::{
    execute_instant_acme_renewal, load_or_create_instant_acme_account,
    renew_all_instant_acme_targets, renew_due_instant_acme_targets,
    renew_selected_instant_acme_targets,
};
use acme_names::{
    managed_certificate_segment, normalized_domain, short_sha256_hex,
    valid_http_01_key_authorization, valid_http_01_token,
};
use acme_pem::{validate_certificate_pem, validate_private_key_pem};
pub use acme_queue::{next_retry_at, plan_renewal_queue, toml_offset_datetime_to_system_time};
#[cfg(feature = "acme-client")]
use acme_tls_alpn::{cleanup_tls_alpn_01_challenges, tls_alpn_01_certificate};

pub fn renewal_targets(config: &Config) -> Vec<AcmeRenewalTarget> {
    if !config.tls.enabled || !config.tls.acme.enabled || !config.tls.acme.renewal.enabled {
        return Vec::new();
    }

    let Some(storage) = &config.tls.acme.storage else {
        return Vec::new();
    };

    config
        .vhosts
        .iter()
        .filter(|vhost| vhost.tls.enabled && vhost.tls.acme.enabled)
        .map(|vhost| {
            let issuer = vhost
                .tls
                .acme
                .issuer
                .clone()
                .unwrap_or_else(|| config.tls.acme.default_issuer.clone());
            let domains = if vhost.tls.acme.domains.is_empty() {
                vhost
                    .hosts
                    .iter()
                    .filter(|host| !host.starts_with("*."))
                    .map(|host| normalized_domain(host))
                    .collect()
            } else {
                vhost
                    .tls
                    .acme
                    .domains
                    .iter()
                    .map(|domain| normalized_domain(domain))
                    .collect()
            };

            AcmeRenewalTarget {
                vhost_name: vhost.name.clone(),
                issuer,
                domains,
                challenge: config.tls.acme.challenge,
                certificate: managed_certificate_paths(storage, &vhost.name),
            }
        })
        .collect()
}

pub fn execute_renewal<Client: AcmeIssuerClient>(
    config: &Config,
    item: &AcmeRenewalItem,
    client: &mut Client,
) -> Result<AcmeRenewalOutcome, AcmeRenewalError> {
    if item.target.challenge != AcmeChallenge::Http01 {
        return Err(AcmeRenewalError::UnsupportedChallenge {
            challenge: item.target.challenge,
        });
    }

    let storage = config
        .tls
        .acme
        .storage
        .as_deref()
        .ok_or(AcmeRenewalError::MissingStorage)?;
    let issuer = config
        .tls
        .acme
        .issuers
        .iter()
        .find(|issuer| issuer.name == item.target.issuer)
        .ok_or_else(|| AcmeRenewalError::UnknownIssuer {
            issuer: item.target.issuer.clone(),
        })?;
    let eab = load_external_account_binding(config, &item.target.issuer)
        .map_err(AcmeRenewalError::ExternalAccountBinding)?;
    let request = AcmeIssueRequest {
        target: &item.target,
        issuer_directory_url: &issuer.directory_url,
        contact_email: config.tls.acme.contact_email.as_deref(),
        external_account_binding: eab.as_ref(),
    };
    let order =
        client
            .prepare_http_01_order(request)
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: error.to_string(),
            })?;
    let challenge_store = AcmeHttp01ChallengeStore::new(storage, &item.target.vhost_name);
    let mut published = Vec::with_capacity(order.challenges.len());

    let result = (|| {
        for challenge in &order.challenges {
            challenge_store
                .install_key_authorization(&challenge.token, &challenge.key_authorization)
                .map_err(|error| AcmeRenewalError::Challenge {
                    token: challenge.token.clone(),
                    error,
                })?;
            published.push(challenge.token.clone());
        }

        let issued = client
            .finalize_http_01_order(&order, &challenge_store)
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: acme_client_error_message_with_http_01_context(
                    error,
                    &item.target.domains,
                    &published,
                ),
            })?;
        let certificate = install_managed_certificate(
            storage,
            &item.target.vhost_name,
            &issued.fullchain_pem,
            &issued.private_key_pem,
        )
        .map_err(AcmeRenewalError::CertificateInstall)?;

        Ok(AcmeRenewalOutcome {
            vhost_name: item.target.vhost_name.clone(),
            issuer: item.target.issuer.clone(),
            certificate,
            published_challenges: published.len(),
        })
    })();

    let cleanup = cleanup_http_01_challenges(&challenge_store, &published);
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) | (Err(_), Err(cleanup_error)) => Err(cleanup_error),
    }
}

pub fn load_external_account_binding(
    config: &Config,
    issuer_name: &str,
) -> Result<Option<AcmeExternalAccountBindingSecrets>, AcmeSecretLoadError> {
    let Some(issuer) = config
        .tls
        .acme
        .issuers
        .iter()
        .find(|issuer| issuer.name == issuer_name)
    else {
        return Err(AcmeSecretLoadError::UnknownIssuer {
            issuer: issuer_name.to_owned(),
        });
    };

    let Some(eab) = &issuer.eab else {
        return Ok(None);
    };

    Ok(Some(load_external_account_binding_from_config(
        &issuer.name,
        eab,
    )?))
}

pub fn observe_configured_certificates(config: &Config) -> Vec<CertificateObservation> {
    renewal_targets(config)
        .into_iter()
        .filter_map(|target| observe_target_certificate(&target).ok().flatten())
        .collect()
}

fn write_challenge_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }

    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

fn sync_directory_io(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(test)]
#[path = "acme_tests.rs"]
mod tests;

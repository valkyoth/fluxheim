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

#[cfg(feature = "acme-client")]
pub async fn load_or_create_instant_acme_account(
    config: &Config,
    issuer_name: &str,
) -> Result<instant_acme::Account, AcmeInstantClientError> {
    let storage = config
        .tls
        .acme
        .storage
        .as_deref()
        .ok_or(AcmeInstantClientError::MissingStorage)?;
    let issuer = config
        .tls
        .acme
        .issuers
        .iter()
        .find(|issuer| issuer.name == issuer_name)
        .ok_or_else(|| AcmeInstantClientError::UnknownIssuer {
            issuer: issuer_name.to_owned(),
        })?;

    if let Some(credentials) = load_account_credentials(storage, issuer_name)
        .map_err(AcmeInstantClientError::AccountStore)?
    {
        return instant_acme::Account::builder()
            .map_err(|error| AcmeInstantClientError::Account {
                issuer: issuer_name.to_owned(),
                message: error.to_string(),
            })?
            .from_credentials(credentials)
            .await
            .map_err(|error| AcmeInstantClientError::Account {
                issuer: issuer_name.to_owned(),
                message: error.to_string(),
            });
    }

    let contact_storage;
    let contacts: &[&str] = if let Some(email) = config.tls.acme.contact_email.as_deref() {
        contact_storage = [format!("mailto:{email}")];
        &[&contact_storage[0]]
    } else {
        &[]
    };
    let account_request = instant_acme::NewAccount {
        contact: contacts,
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let eab = load_external_account_binding(config, issuer_name)
        .map_err(AcmeInstantClientError::ExternalAccountBinding)?;
    let eab_key = match eab.as_ref() {
        Some(secrets) => Some(external_account_key_from_secrets(issuer_name, secrets)?),
        None => None,
    };
    let (account, credentials) = instant_acme::Account::builder()
        .map_err(|error| AcmeInstantClientError::Account {
            issuer: issuer_name.to_owned(),
            message: error.to_string(),
        })?
        .create(
            &account_request,
            issuer.directory_url.clone(),
            eab_key.as_ref(),
        )
        .await
        .map_err(|error| AcmeInstantClientError::Account {
            issuer: issuer_name.to_owned(),
            message: error.to_string(),
        })?;
    store_account_credentials(storage, issuer_name, &credentials)
        .map_err(AcmeInstantClientError::AccountStore)?;

    Ok(account)
}

#[cfg(feature = "acme-client")]
pub async fn execute_instant_acme_renewal(
    config: &Config,
    item: &AcmeRenewalItem,
) -> Result<AcmeRenewalOutcome, AcmeRenewalError> {
    match item.target.challenge {
        AcmeChallenge::Http01 => execute_instant_http_01_renewal(config, item).await,
        AcmeChallenge::TlsAlpn01 => execute_instant_tls_alpn_01_renewal(config, item).await,
    }
}

#[cfg(feature = "acme-client")]
async fn execute_instant_http_01_renewal(
    config: &Config,
    item: &AcmeRenewalItem,
) -> Result<AcmeRenewalOutcome, AcmeRenewalError> {
    let storage = config
        .tls
        .acme
        .storage
        .as_deref()
        .ok_or(AcmeRenewalError::MissingStorage)?;
    let account = load_or_create_instant_acme_account(config, &item.target.issuer)
        .await
        .map_err(instant_client_error_to_renewal_error)?;
    let challenge_store = AcmeHttp01ChallengeStore::new(storage, &item.target.vhost_name);
    let mut published = Vec::with_capacity(item.target.domains.len());

    let result = async {
        let identifiers: Vec<instant_acme::Identifier> = item
            .target
            .domains
            .iter()
            .map(|domain| instant_acme::Identifier::Dns(domain.clone()))
            .collect();
        let mut order = account
            .new_order(&instant_acme::NewOrder::new(&identifiers))
            .await
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: error.to_string(),
            })?;

        {
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization =
                    authorization.map_err(|error| AcmeRenewalError::Client {
                        issuer: item.target.issuer.clone(),
                        message: error.to_string(),
                    })?;
                if authorization.status == instant_acme::AuthorizationStatus::Valid {
                    continue;
                }

                let identifier = authorization.identifier().to_string();
                let mut challenge = authorization
                    .challenge(instant_acme::ChallengeType::Http01)
                    .ok_or_else(|| AcmeRenewalError::Client {
                        issuer: item.target.issuer.clone(),
                        message: format!(
                            "authorization for {} did not include an http-01 challenge",
                            identifier
                        ),
                    })?;
                let token = challenge.token.clone();
                let key_authorization = challenge.key_authorization().as_str().to_owned();

                challenge_store
                    .install_key_authorization(&token, &key_authorization)
                    .map_err(|error| AcmeRenewalError::Challenge {
                        token: token.clone(),
                        error,
                    })?;
                published.push(token.clone());
                challenge
                    .set_ready()
                    .await
                    .map_err(|error| AcmeRenewalError::Client {
                        issuer: item.target.issuer.clone(),
                        message: acme_client_error_message_with_http_01_context(
                            error,
                            &item.target.domains,
                            &published,
                        ),
                    })?;
            }
        }

        let retry_policy = instant_acme::RetryPolicy::new().timeout(Duration::from_secs(60));
        order
            .poll_ready(&retry_policy)
            .await
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: acme_client_error_message_with_http_01_context(
                    error,
                    &item.target.domains,
                    &published,
                ),
            })?;
        let private_key_pem = Zeroizing::new(
            order
                .finalize()
                .await
                .map_err(|error| AcmeRenewalError::Client {
                    issuer: item.target.issuer.clone(),
                    message: acme_client_error_message_with_http_01_context(
                        error,
                        &item.target.domains,
                        &published,
                    ),
                })?
                .into_bytes(),
        );
        let fullchain_pem = order
            .poll_certificate(&retry_policy)
            .await
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: acme_client_error_message_with_http_01_context(
                    error,
                    &item.target.domains,
                    &published,
                ),
            })?
            .into_bytes();
        let certificate = install_managed_certificate(
            storage,
            &item.target.vhost_name,
            &fullchain_pem,
            &private_key_pem,
        )
        .map_err(AcmeRenewalError::CertificateInstall)?;

        Ok(AcmeRenewalOutcome {
            vhost_name: item.target.vhost_name.clone(),
            issuer: item.target.issuer.clone(),
            certificate,
            published_challenges: published.len(),
        })
    }
    .await;

    let cleanup = cleanup_http_01_challenges(&challenge_store, &published);
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) | (Err(_), Err(cleanup_error)) => Err(cleanup_error),
    }
}

#[cfg(feature = "acme-client")]
async fn execute_instant_tls_alpn_01_renewal(
    config: &Config,
    item: &AcmeRenewalItem,
) -> Result<AcmeRenewalOutcome, AcmeRenewalError> {
    let storage = config
        .tls
        .acme
        .storage
        .as_deref()
        .ok_or(AcmeRenewalError::MissingStorage)?;
    let account = load_or_create_instant_acme_account(config, &item.target.issuer)
        .await
        .map_err(instant_client_error_to_renewal_error)?;
    let challenge_store = AcmeTlsAlpn01ChallengeStore::new(storage);
    let mut published = Vec::with_capacity(item.target.domains.len());

    let result = async {
        let identifiers: Vec<instant_acme::Identifier> = item
            .target
            .domains
            .iter()
            .map(|domain| instant_acme::Identifier::Dns(domain.clone()))
            .collect();
        let mut order = account
            .new_order(&instant_acme::NewOrder::new(&identifiers))
            .await
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: error.to_string(),
            })?;

        {
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization =
                    authorization.map_err(|error| AcmeRenewalError::Client {
                        issuer: item.target.issuer.clone(),
                        message: error.to_string(),
                    })?;
                if authorization.status == instant_acme::AuthorizationStatus::Valid {
                    continue;
                }

                let identifier = authorization.identifier().to_string();
                let mut challenge = authorization
                    .challenge(instant_acme::ChallengeType::TlsAlpn01)
                    .ok_or_else(|| AcmeRenewalError::Client {
                        issuer: item.target.issuer.clone(),
                        message: format!(
                            "authorization for {} did not include a tls-alpn-01 challenge",
                            identifier
                        ),
                    })?;
                let digest = challenge.key_authorization().digest();
                let (cert_pem, key_pem) = tls_alpn_01_certificate(&identifier, digest.as_ref())?;
                challenge_store
                    .install_challenge_certificate(&identifier, &cert_pem, &key_pem)
                    .map_err(AcmeRenewalError::CertificateInstall)?;
                published.push(identifier.clone());
                challenge
                    .set_ready()
                    .await
                    .map_err(|error| AcmeRenewalError::Client {
                        issuer: item.target.issuer.clone(),
                        message: error.to_string(),
                    })?;
            }
        }

        let retry_policy = instant_acme::RetryPolicy::new().timeout(Duration::from_secs(60));
        order
            .poll_ready(&retry_policy)
            .await
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: error.to_string(),
            })?;
        let private_key_pem = Zeroizing::new(
            order
                .finalize()
                .await
                .map_err(|error| AcmeRenewalError::Client {
                    issuer: item.target.issuer.clone(),
                    message: error.to_string(),
                })?
                .into_bytes(),
        );
        let fullchain_pem = order
            .poll_certificate(&retry_policy)
            .await
            .map_err(|error| AcmeRenewalError::Client {
                issuer: item.target.issuer.clone(),
                message: error.to_string(),
            })?
            .into_bytes();
        let certificate = install_managed_certificate(
            storage,
            &item.target.vhost_name,
            &fullchain_pem,
            &private_key_pem,
        )
        .map_err(AcmeRenewalError::CertificateInstall)?;

        Ok(AcmeRenewalOutcome {
            vhost_name: item.target.vhost_name.clone(),
            issuer: item.target.issuer.clone(),
            certificate,
            published_challenges: published.len(),
        })
    }
    .await;

    let cleanup = cleanup_tls_alpn_01_challenges(&challenge_store, &published);
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) | (Err(_), Err(cleanup_error)) => Err(cleanup_error),
    }
}

#[cfg(feature = "acme-client")]
pub async fn renew_all_instant_acme_targets(
    config: &Config,
    now: SystemTime,
) -> Result<AcmeRenewalRun, AcmeRenewalError> {
    let queue = plan_renewal_queue(config, &[], now);
    execute_instant_acme_queue(config, &queue).await
}

#[cfg(feature = "acme-client")]
pub async fn renew_due_instant_acme_targets(
    config: &Config,
    now: SystemTime,
) -> Result<AcmeRenewalRun, AcmeRenewalError> {
    let observations = observe_configured_certificates(config);
    let queue = plan_renewal_queue(config, &observations, now);
    let due_queue: Vec<AcmeRenewalItem> = queue.into_iter().filter(|item| item.due_now).collect();
    execute_instant_acme_queue(config, &due_queue).await
}

#[cfg(feature = "acme-client")]
pub async fn renew_selected_instant_acme_targets(
    config: &Config,
    now: SystemTime,
    vhost_name: &str,
    force_renew: bool,
) -> Result<AcmeRenewalRun, AcmeRenewalError> {
    let queue = if force_renew {
        plan_renewal_queue(config, &[], now)
    } else {
        let observations = observe_configured_certificates(config);
        plan_renewal_queue(config, &observations, now)
    };
    let selected_queue: Vec<AcmeRenewalItem> = queue
        .into_iter()
        .filter(|item| item.target.vhost_name == vhost_name)
        .filter(|item| force_renew || item.due_now)
        .collect();
    execute_instant_acme_queue(config, &selected_queue).await
}

#[cfg(feature = "acme-client")]
async fn execute_instant_acme_queue(
    config: &Config,
    queue: &[AcmeRenewalItem],
) -> Result<AcmeRenewalRun, AcmeRenewalError> {
    let mut renewed = Vec::with_capacity(queue.len());
    let mut failed = Vec::new();

    for item in queue {
        match execute_instant_acme_renewal(config, item).await {
            Ok(outcome) => renewed.push(outcome),
            Err(error) => failed.push(AcmeRenewalFailure {
                vhost_name: item.target.vhost_name.clone(),
                issuer: item.target.issuer.clone(),
                domains: item.target.domains.clone(),
                error: error.to_string(),
            }),
        }
    }

    Ok(AcmeRenewalRun {
        attempted: queue.len(),
        renewed,
        failed,
    })
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

use std::cmp::Ordering;
use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use toml::value::{Datetime, Offset};
use zeroize::Zeroizing;

use crate::config::{AcmeChallenge, AcmeExternalAccountBindingConfig, Config, normalize_host};

const MANAGED_CERTIFICATE_DIR: &str = "certificates";
const MANAGED_FULLCHAIN_FILE: &str = "fullchain.pem";
const MANAGED_PRIVATE_KEY_FILE: &str = "privkey.pem";
const ACME_ACCOUNT_DIR: &str = "accounts";
const ACME_ACCOUNT_CREDENTIALS_FILE: &str = "credentials.json";
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

#[path = "acme_challenges.rs"]
mod acme_challenges;
#[path = "acme_errors.rs"]
mod acme_errors;
pub use acme_challenges::{
    AcmeHttp01ChallengeStore, AcmeTlsAlpn01ChallengeStore, http_01_token_from_path,
};
#[cfg(feature = "acme-client")]
pub use acme_errors::AcmeInstantClientError;
pub use acme_errors::{
    AcmeAccountStoreError, AcmeCertificateInstallError, AcmeRenewalError, AcmeSecretLoadError,
};

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

pub fn managed_certificate_paths(storage: &Path, vhost_name: &str) -> AcmeCertificatePaths {
    let directory = storage
        .join(MANAGED_CERTIFICATE_DIR)
        .join(managed_certificate_segment(vhost_name));

    AcmeCertificatePaths {
        cert_path: directory.join(MANAGED_FULLCHAIN_FILE),
        key_path: directory.join(MANAGED_PRIVATE_KEY_FILE),
    }
}

pub fn account_credentials_path(storage: &Path, issuer_name: &str) -> AcmeAccountCredentialsPath {
    AcmeAccountCredentialsPath {
        path: storage
            .join(ACME_ACCOUNT_DIR)
            .join(managed_certificate_segment(issuer_name))
            .join(ACME_ACCOUNT_CREDENTIALS_FILE),
    }
}

pub fn observe_configured_certificates(config: &Config) -> Vec<CertificateObservation> {
    renewal_targets(config)
        .into_iter()
        .filter_map(|target| observe_target_certificate(&target).ok().flatten())
        .collect()
}

pub fn observe_target_certificate(
    target: &AcmeRenewalTarget,
) -> io::Result<Option<CertificateObservation>> {
    load_certificate_not_after(&target.certificate.cert_path).map(|not_after| {
        not_after.map(|not_after| CertificateObservation {
            vhost_name: target.vhost_name.clone(),
            not_after,
        })
    })
}

pub fn load_certificate_not_after(path: &Path) -> io::Result<Option<SystemTime>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "certificate path is not a real file",
        ));
    }
    if metadata.len() > MAX_CERTIFICATE_CHAIN_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate file is too large",
        ));
    }

    let file = open_regular_certificate_file(path)?;
    let mut contents = Vec::new();
    file.take((MAX_CERTIFICATE_CHAIN_BYTES as u64).saturating_add(1))
        .read_to_end(&mut contents)?;
    if contents.len() > MAX_CERTIFICATE_CHAIN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate file is too large",
        ));
    }

    let (_, pem) = x509_parser::pem::parse_x509_pem(&contents).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate file does not contain a valid PEM certificate",
        )
    })?;
    let certificate = pem.parse_x509().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate file does not contain a valid X.509 certificate",
        )
    })?;
    let timestamp = certificate.validity().not_after.timestamp();
    if timestamp < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate expiration is before the Unix epoch",
        ));
    }

    Ok(Some(UNIX_EPOCH + Duration::from_secs(timestamp as u64)))
}

pub fn load_account_credentials(
    storage: &Path,
    issuer_name: &str,
) -> Result<Option<instant_acme::AccountCredentials>, AcmeAccountStoreError> {
    let path = account_credentials_path(storage, issuer_name).path;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(account_store_io_error(&path, error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AcmeAccountStoreError::UnsafePath {
            path,
            message: "credentials path is not a real file".to_owned(),
        });
    }
    if metadata.len() > MAX_ACCOUNT_CREDENTIALS_BYTES {
        return Err(AcmeAccountStoreError::Oversized {
            path,
            max_bytes: MAX_ACCOUNT_CREDENTIALS_BYTES,
        });
    }

    let file = open_regular_account_credentials_file(&path)
        .map_err(|error| account_store_io_error(&path, error))?;
    let mut contents = Vec::new();
    file.take(MAX_ACCOUNT_CREDENTIALS_BYTES.saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(|error| account_store_io_error(&path, error))?;
    if contents.len() as u64 > MAX_ACCOUNT_CREDENTIALS_BYTES {
        return Err(AcmeAccountStoreError::Oversized {
            path,
            max_bytes: MAX_ACCOUNT_CREDENTIALS_BYTES,
        });
    }

    serde_json::from_slice(&contents)
        .map(Some)
        .map_err(|error| AcmeAccountStoreError::Deserialize {
            path,
            message: error.to_string(),
        })
}

pub fn store_account_credentials(
    storage: &Path,
    issuer_name: &str,
    credentials: &instant_acme::AccountCredentials,
) -> Result<AcmeAccountCredentialsPath, AcmeAccountStoreError> {
    let credentials_path = account_credentials_path(storage, issuer_name);
    let directory =
        credentials_path
            .path
            .parent()
            .ok_or_else(|| AcmeAccountStoreError::UnsafePath {
                path: credentials_path.path.clone(),
                message: "credentials path has no parent directory".to_owned(),
            })?;
    ensure_safe_account_directory(directory)?;
    ensure_safe_account_destination(&credentials_path.path)?;

    let contents =
        serde_json::to_vec(credentials).map_err(|error| AcmeAccountStoreError::Serialize {
            message: error.to_string(),
        })?;
    if contents.len() as u64 > MAX_ACCOUNT_CREDENTIALS_BYTES {
        return Err(AcmeAccountStoreError::Oversized {
            path: credentials_path.path.clone(),
            max_bytes: MAX_ACCOUNT_CREDENTIALS_BYTES,
        });
    }

    let tmp_path = directory.join(".credentials.json.tmp");
    let result = (|| {
        write_account_credentials_file(&tmp_path, &contents)?;
        fs::rename(&tmp_path, &credentials_path.path)
            .map_err(|error| account_store_io_error(&credentials_path.path, error))?;
        sync_account_directory(directory)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    result.map(|()| credentials_path)
}

pub fn install_managed_certificate(
    storage: &Path,
    vhost_name: &str,
    fullchain_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<AcmeCertificatePaths, AcmeCertificateInstallError> {
    validate_certificate_pem(fullchain_pem)?;
    validate_private_key_pem(private_key_pem)?;

    let paths = managed_certificate_paths(storage, vhost_name);
    let owner = managed_certificate_owner(storage)?;
    install_certificate_files(&paths, fullchain_pem, private_key_pem, owner)?;
    Ok(paths)
}

fn install_certificate_files(
    paths: &AcmeCertificatePaths,
    fullchain_pem: &[u8],
    private_key_pem: &[u8],
    owner: ManagedCertificateOwner,
) -> Result<(), AcmeCertificateInstallError> {
    let directory = certificate_directory(paths)?;
    ensure_safe_directory(&directory, owner)?;
    #[cfg(unix)]
    let directory_fd = open_safe_certificate_directory(&directory)?;
    #[cfg(unix)]
    let directory_fd = Some(&directory_fd);
    #[cfg(not(unix))]
    let directory_fd: Option<&CertificateDirectoryFd> = None;

    let cert_tmp = directory.join(".fullchain.pem.tmp");
    let key_tmp = directory.join(".privkey.pem.tmp");
    let cert_backup = directory.join(".fullchain.pem.previous");
    let key_backup = directory.join(".privkey.pem.previous");
    let mut cert_backed_up = false;
    let mut key_backed_up = false;

    let result = (|| {
        write_new_file(
            &directory,
            &cert_tmp,
            fullchain_pem,
            0o644,
            owner,
            directory_fd,
        )?;
        write_new_file(
            &directory,
            &key_tmp,
            private_key_pem,
            0o600,
            owner,
            directory_fd,
        )?;
        ensure_safe_destination(&paths.cert_path)?;
        ensure_safe_destination(&paths.key_path)?;
        cert_backed_up =
            backup_existing_file(&directory, &paths.cert_path, &cert_backup, directory_fd)?;
        key_backed_up =
            backup_existing_file(&directory, &paths.key_path, &key_backup, directory_fd)?;
        rename_certificate_file(&directory, &cert_tmp, &paths.cert_path, directory_fd)?;
        if let Err(error) =
            rename_certificate_file(&directory, &key_tmp, &paths.key_path, directory_fd)
        {
            if cert_backed_up
                && let Err(restore_error) =
                    restore_backup(&directory, &cert_backup, &paths.cert_path, directory_fd)
            {
                log_acme_certificate_recovery_error(
                    "restoring previous certificate after private-key install failure",
                    &paths.cert_path,
                    &restore_error,
                );
            }
            return Err(error);
        }
        cleanup_backup(&directory, &cert_backup, directory_fd)?;
        cleanup_backup(&directory, &key_backup, directory_fd)?;
        sync_directory(&directory, directory_fd)?;
        Ok(())
    })();

    if result.is_err() {
        if let Err(error) = cleanup_backup(&directory, &cert_tmp, directory_fd) {
            log_acme_certificate_recovery_error(
                "removing temporary certificate file",
                &cert_tmp,
                &error,
            );
        }
        if let Err(error) = cleanup_backup(&directory, &key_tmp, directory_fd) {
            log_acme_certificate_recovery_error(
                "removing temporary private-key file",
                &key_tmp,
                &error,
            );
        }
        if cert_backed_up
            && let Err(error) =
                restore_backup(&directory, &cert_backup, &paths.cert_path, directory_fd)
        {
            log_acme_certificate_recovery_error(
                "restoring previous certificate",
                &paths.cert_path,
                &error,
            );
        }
        if key_backed_up
            && let Err(error) =
                restore_backup(&directory, &key_backup, &paths.key_path, directory_fd)
        {
            log_acme_certificate_recovery_error(
                "restoring previous private key",
                &paths.key_path,
                &error,
            );
        }
    }

    result
}

fn log_acme_certificate_recovery_error(action: &str, path: &Path, error: &dyn fmt::Display) {
    log::error!(
        target: "fluxheim::security",
        "ACME certificate install recovery failed while {action} at {}: {error}",
        path.display()
    );
}

#[cfg(unix)]
type CertificateDirectoryFd = rustix::fd::OwnedFd;

#[cfg(not(unix))]
type CertificateDirectoryFd = ();

fn backup_existing_file(
    directory: &Path,
    path: &Path,
    backup: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<bool, AcmeCertificateInstallError> {
    #[cfg(unix)]
    if let Some(directory_fd) = directory_fd {
        let path_name = certificate_file_name_in_directory(directory, path)?;
        let backup_name = certificate_file_name_in_directory(directory, backup)?;
        match rustix::fs::statat(
            directory_fd,
            path_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() => {
                return Err(AcmeCertificateInstallError::UnsafePath {
                    path: path.to_path_buf(),
                    message: "destination is not a real file".to_owned(),
                });
            }
            Ok(_) => {
                ensure_backup_slot_is_empty(directory, backup, Some(directory_fd))?;
                rustix::fs::linkat(
                    directory_fd,
                    path_name,
                    directory_fd,
                    backup_name,
                    rustix::fs::AtFlags::empty(),
                )
                .map_err(|error| AcmeCertificateInstallError::Io {
                    path: backup.to_path_buf(),
                    error: error.into(),
                })?;
                return Ok(true);
            }
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(false),
            Err(error) => {
                return Err(AcmeCertificateInstallError::Io {
                    path: path.to_path_buf(),
                    error: error.into(),
                });
            }
        }
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(AcmeCertificateInstallError::UnsafePath {
                path: path.to_path_buf(),
                message: "destination is not a real file".to_owned(),
            })
        }
        Ok(_) => {
            ensure_backup_slot_is_empty(directory, backup, None)?;
            fs::hard_link(path, backup).map_err(|error| AcmeCertificateInstallError::Io {
                path: backup.to_path_buf(),
                error,
            })?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        }),
    }
}

fn ensure_backup_slot_is_empty(
    directory: &Path,
    path: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    #[cfg(unix)]
    if let Some(directory_fd) = directory_fd {
        let name = certificate_file_name_in_directory(directory, path)?;
        return match rustix::fs::statat(directory_fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Err(AcmeCertificateInstallError::UnsafePath {
                path: path.to_path_buf(),
                message: "backup path already exists".to_owned(),
            }),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(error) => Err(AcmeCertificateInstallError::Io {
                path: path.to_path_buf(),
                error: error.into(),
            }),
        };
    }

    match fs::symlink_metadata(path) {
        Ok(_) => Err(AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: "backup path already exists".to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        }),
    }
}

fn cleanup_backup(
    directory: &Path,
    path: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    #[cfg(unix)]
    if let Some(directory_fd) = directory_fd {
        let name = certificate_file_name_in_directory(directory, path)?;
        return match rustix::fs::unlinkat(directory_fd, name, rustix::fs::AtFlags::empty()) {
            Ok(()) => Ok(()),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(error) => Err(AcmeCertificateInstallError::Io {
                path: path.to_path_buf(),
                error: error.into(),
            }),
        };
    }

    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        }),
    }
}

fn restore_backup(
    directory: &Path,
    backup: &Path,
    destination: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(directory_fd) = directory_fd {
        let backup_name = certificate_file_name_in_directory(directory, backup)
            .map_err(acme_install_error_to_io_error)?;
        let destination_name = certificate_file_name_in_directory(directory, destination)
            .map_err(acme_install_error_to_io_error)?;
        return match rustix::fs::statat(
            directory_fd,
            backup_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() => Err(
                io::Error::new(io::ErrorKind::InvalidData, "backup is not a regular file"),
            ),
            Ok(_) => {
                rustix::fs::renameat(directory_fd, backup_name, directory_fd, destination_name)
                    .map_err(Into::into)
            }
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(error) => Err(error.into()),
        };
    }

    match fs::symlink_metadata(backup) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
            io::Error::new(io::ErrorKind::InvalidData, "backup is not a regular file"),
        ),
        Ok(_) => fs::rename(backup, destination),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn acme_install_error_to_io_error(error: AcmeCertificateInstallError) -> io::Error {
    match error {
        AcmeCertificateInstallError::Io { error, .. } => error,
        other => io::Error::new(io::ErrorKind::InvalidInput, other.to_string()),
    }
}

fn cleanup_http_01_challenges(
    store: &AcmeHttp01ChallengeStore,
    tokens: &[String],
) -> Result<(), AcmeRenewalError> {
    for token in tokens {
        store
            .remove_key_authorization(token)
            .map_err(|error| AcmeRenewalError::Challenge {
                token: token.clone(),
                error,
            })?;
    }
    Ok(())
}

fn acme_client_error_message_with_http_01_context(
    error: impl fmt::Display,
    domains: &[String],
    tokens: &[String],
) -> String {
    let message = error.to_string();
    let urls = http_01_challenge_urls(domains, tokens);
    if urls.is_empty() {
        return message;
    }
    format!("{message}; published_http_01={}", urls.join(","))
}

fn http_01_challenge_urls(domains: &[String], tokens: &[String]) -> Vec<String> {
    let mut urls = Vec::new();
    for domain in domains {
        for token in tokens {
            let token = redacted_http_01_token(token);
            urls.push(format!(
                "http://{domain}/.well-known/acme-challenge/{token}"
            ));
        }
    }
    urls
}

fn redacted_http_01_token(token: &str) -> String {
    if token.is_empty() {
        return "<empty-token>".to_owned();
    }
    format!("<redacted:{}b>", token.len())
}

#[cfg(feature = "acme-client")]
fn cleanup_tls_alpn_01_challenges(
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
fn tls_alpn_01_certificate(
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

#[cfg(feature = "acme-client")]
fn instant_client_error_to_renewal_error(error: AcmeInstantClientError) -> AcmeRenewalError {
    match error {
        AcmeInstantClientError::MissingStorage => AcmeRenewalError::MissingStorage,
        AcmeInstantClientError::UnknownIssuer { issuer } => {
            AcmeRenewalError::UnknownIssuer { issuer }
        }
        AcmeInstantClientError::ExternalAccountBinding(error) => {
            AcmeRenewalError::ExternalAccountBinding(error)
        }
        AcmeInstantClientError::AccountStore(error) => AcmeRenewalError::Client {
            issuer: "account-store".to_owned(),
            message: error.to_string(),
        },
        AcmeInstantClientError::InvalidExternalAccountBindingHmacKey { issuer, message }
        | AcmeInstantClientError::Account { issuer, message } => {
            AcmeRenewalError::Client { issuer, message }
        }
    }
}

fn load_external_account_binding_from_config(
    issuer: &str,
    eab: &AcmeExternalAccountBindingConfig,
) -> Result<AcmeExternalAccountBindingSecrets, AcmeSecretLoadError> {
    Ok(AcmeExternalAccountBindingSecrets {
        key_id: load_eab_secret(
            issuer,
            "key_id",
            eab.key_id_env.as_deref(),
            eab.key_id_file.as_deref(),
            eab.key_id_credential.as_deref(),
        )?,
        hmac_key: load_eab_secret(
            issuer,
            "hmac_key",
            eab.hmac_key_env.as_deref(),
            eab.hmac_key_file.as_deref(),
            eab.hmac_key_credential.as_deref(),
        )?,
    })
}

#[cfg(feature = "acme-client")]
fn external_account_key_from_secrets(
    issuer: &str,
    secrets: &AcmeExternalAccountBindingSecrets,
) -> Result<instant_acme::ExternalAccountKey, AcmeInstantClientError> {
    let key_bytes = decode_eab_hmac_key(issuer, &secrets.hmac_key)?;
    Ok(instant_acme::ExternalAccountKey::new(
        secrets.key_id.to_string(),
        &key_bytes,
    ))
}

#[cfg(feature = "acme-client")]
fn decode_eab_hmac_key(
    issuer: &str,
    value: &str,
) -> Result<Zeroizing<Vec<u8>>, AcmeInstantClientError> {
    if let Some(decoded) =
        decoded_eab_hmac_key(base64_ng::URL_SAFE_NO_PAD.decode_vec(value.as_bytes()))
    {
        return Ok(decoded);
    }
    if let Some(decoded) = decoded_eab_hmac_key(base64_ng::URL_SAFE.decode_vec(value.as_bytes())) {
        return Ok(decoded);
    }
    if let Some(decoded) =
        decoded_eab_hmac_key(base64_ng::STANDARD_NO_PAD.decode_vec(value.as_bytes()))
    {
        return Ok(decoded);
    }
    if let Some(decoded) = decoded_eab_hmac_key(base64_ng::STANDARD.decode_vec(value.as_bytes())) {
        return Ok(decoded);
    }

    Err(
        AcmeInstantClientError::InvalidExternalAccountBindingHmacKey {
            issuer: issuer.to_owned(),
            message: "expected non-empty base64 or base64url encoded key".to_owned(),
        },
    )
}

#[cfg(feature = "acme-client")]
fn decoded_eab_hmac_key(
    decoded: Result<Vec<u8>, base64_ng::DecodeError>,
) -> Option<Zeroizing<Vec<u8>>> {
    match decoded {
        Ok(decoded) if !decoded.is_empty() && decoded.len() as u64 <= MAX_EAB_SECRET_BYTES => {
            Some(Zeroizing::new(decoded))
        }
        _ => None,
    }
}

fn validate_certificate_pem(contents: &[u8]) -> Result<(), AcmeCertificateInstallError> {
    validate_pem_bytes(
        contents,
        MAX_CERTIFICATE_CHAIN_BYTES,
        b"-----BEGIN CERTIFICATE-----",
        b"-----END CERTIFICATE-----",
        AcmeCertificateInstallError::InvalidCertificatePem,
    )
}

fn validate_private_key_pem(contents: &[u8]) -> Result<(), AcmeCertificateInstallError> {
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

fn certificate_directory(
    paths: &AcmeCertificatePaths,
) -> Result<PathBuf, AcmeCertificateInstallError> {
    let Some(cert_parent) = paths.cert_path.parent() else {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: paths.cert_path.clone(),
            message: "certificate path has no parent directory".to_owned(),
        });
    };
    let Some(key_parent) = paths.key_path.parent() else {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: paths.key_path.clone(),
            message: "private-key path has no parent directory".to_owned(),
        });
    };
    if cert_parent != key_parent {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: paths.key_path.clone(),
            message: "certificate and private key must share a directory".to_owned(),
        });
    }

    Ok(cert_parent.to_path_buf())
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnixFileOwner {
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
type ManagedCertificateOwner = Option<UnixFileOwner>;

#[cfg(not(unix))]
type ManagedCertificateOwner = ();

#[cfg(unix)]
fn managed_certificate_owner(
    storage: &Path,
) -> Result<ManagedCertificateOwner, AcmeCertificateInstallError> {
    if !rustix::process::geteuid().is_root() {
        return Ok(None);
    }

    let mut current = storage;
    loop {
        match fs::symlink_metadata(current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AcmeCertificateInstallError::UnsafePath {
                    path: current.to_path_buf(),
                    message: "path contains a symlink".to_owned(),
                });
            }
            Ok(metadata) => {
                use std::os::unix::fs::MetadataExt;
                return Ok(Some(UnixFileOwner {
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let Some(parent) = current.parent() else {
                    return Ok(None);
                };
                current = parent;
            }
            Err(error) => {
                return Err(AcmeCertificateInstallError::Io {
                    path: current.to_path_buf(),
                    error,
                });
            }
        }
    }
}

#[cfg(not(unix))]
fn managed_certificate_owner(
    _storage: &Path,
) -> Result<ManagedCertificateOwner, AcmeCertificateInstallError> {
    Ok(())
}

fn ensure_safe_directory(
    directory: &Path,
    owner: ManagedCertificateOwner,
) -> Result<(), AcmeCertificateInstallError> {
    reject_existing_symlink_in_path(directory)?;
    fs::create_dir_all(directory).map_err(|error| AcmeCertificateInstallError::Io {
        path: directory.to_path_buf(),
        error,
    })?;
    apply_owner_to_path(directory, owner)?;
    reject_existing_symlink_in_path(directory)?;
    let metadata =
        fs::symlink_metadata(directory).map_err(|error| AcmeCertificateInstallError::Io {
            path: directory.to_path_buf(),
            error,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: directory.to_path_buf(),
            message: "path is not a real directory".to_owned(),
        });
    }

    Ok(())
}

#[cfg(unix)]
fn apply_owner_to_path(
    path: &Path,
    owner: ManagedCertificateOwner,
) -> Result<(), AcmeCertificateInstallError> {
    let Some(owner) = owner else {
        return Ok(());
    };

    rustix::fs::chown(
        path,
        Some(rustix::fs::Uid::from_raw(owner.uid)),
        Some(rustix::fs::Gid::from_raw(owner.gid)),
    )
    .map_err(|error| AcmeCertificateInstallError::Io {
        path: path.to_path_buf(),
        error: error.into(),
    })
}

#[cfg(not(unix))]
fn apply_owner_to_path(
    _path: &Path,
    _owner: ManagedCertificateOwner,
) -> Result<(), AcmeCertificateInstallError> {
    Ok(())
}

#[cfg(unix)]
fn apply_owner_to_file(
    file: &fs::File,
    path: &Path,
    owner: ManagedCertificateOwner,
) -> Result<(), AcmeCertificateInstallError> {
    let Some(owner) = owner else {
        return Ok(());
    };

    rustix::fs::fchown(
        file,
        Some(rustix::fs::Uid::from_raw(owner.uid)),
        Some(rustix::fs::Gid::from_raw(owner.gid)),
    )
    .map_err(|error| AcmeCertificateInstallError::Io {
        path: path.to_path_buf(),
        error: error.into(),
    })
}

#[cfg(not(unix))]
fn apply_owner_to_file(
    _file: &fs::File,
    _path: &Path,
    _owner: ManagedCertificateOwner,
) -> Result<(), AcmeCertificateInstallError> {
    Ok(())
}

fn ensure_safe_destination(path: &Path) -> Result<(), AcmeCertificateInstallError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(AcmeCertificateInstallError::UnsafePath {
                path: path.to_path_buf(),
                message: "destination is not a real file".to_owned(),
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        }),
    }
}

fn reject_existing_symlink_in_path(path: &Path) -> Result<(), AcmeCertificateInstallError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AcmeCertificateInstallError::UnsafePath {
                    path: current,
                    message: "path contains a symlink".to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(AcmeCertificateInstallError::Io {
                    path: current,
                    error,
                });
            }
        }
    }

    Ok(())
}

fn write_new_file(
    directory: &Path,
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: ManagedCertificateOwner,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    #[cfg(unix)]
    if let Some(directory_fd) = directory_fd {
        let name = certificate_file_name_in_directory(directory, path)?;
        let raw_mode = certificate_file_raw_mode(path, mode)?;
        let fd = rustix::fs::openat(
            directory_fd,
            name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(raw_mode),
        )
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error: error.into(),
        })?;
        let mut file = fs::File::from(fd);
        apply_owner_to_file(&file, path, owner)?;
        file.write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(|error| AcmeCertificateInstallError::Io {
                path: path.to_path_buf(),
                error,
            })?;
        return Ok(());
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
        options.custom_flags(UNIX_O_NOFOLLOW);
    }

    let mut file = options
        .open(path)
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        })?;
    apply_owner_to_file(&file, path, owner)?;
    file.write_all(contents)
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        })?;
    file.sync_all()
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        })
}

#[cfg(all(unix, target_os = "macos"))]
fn certificate_file_raw_mode(
    path: &Path,
    mode: u32,
) -> Result<rustix::fs::RawMode, AcmeCertificateInstallError> {
    mode.try_into()
        .map_err(|_| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error: io::Error::new(
                io::ErrorKind::InvalidInput,
                "certificate file mode is unsupported on this platform",
            ),
        })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn certificate_file_raw_mode(
    _path: &Path,
    mode: u32,
) -> Result<rustix::fs::RawMode, AcmeCertificateInstallError> {
    Ok(mode)
}

#[cfg(unix)]
fn open_safe_certificate_directory(
    directory: &Path,
) -> Result<rustix::fd::OwnedFd, AcmeCertificateInstallError> {
    #[cfg(target_os = "linux")]
    {
        match rustix::fs::openat2(
            rustix::fs::CWD,
            directory,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(fd) => return Ok(fd),
            Err(rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL) => {}
            Err(error) => {
                return Err(AcmeCertificateInstallError::Io {
                    path: directory.to_path_buf(),
                    error: error.into(),
                });
            }
        }
    }

    rustix::fs::openat(
        rustix::fs::CWD,
        directory,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| AcmeCertificateInstallError::Io {
        path: directory.to_path_buf(),
        error: error.into(),
    })
}

#[cfg(unix)]
fn certificate_file_name_in_directory<'a>(
    directory: &Path,
    path: &'a Path,
) -> Result<&'a str, AcmeCertificateInstallError> {
    if path.parent() != Some(directory) {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: "certificate file operation must stay within managed directory".to_owned(),
        });
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .ok_or_else(|| AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: "certificate path must end in a safe file name".to_owned(),
        })
}

fn rename_certificate_file(
    directory: &Path,
    source: &Path,
    destination: &Path,
    #[cfg_attr(not(unix), allow(unused_variables))] directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    #[cfg(unix)]
    {
        let directory_fd = directory_fd.ok_or_else(|| AcmeCertificateInstallError::UnsafePath {
            path: directory.to_path_buf(),
            message: "managed certificate directory fd is unavailable".to_owned(),
        })?;
        let source_name = certificate_file_name_in_directory(directory, source)?;
        let destination_name = certificate_file_name_in_directory(directory, destination)?;
        rustix::fs::renameat(directory_fd, source_name, directory_fd, destination_name).map_err(
            |error| AcmeCertificateInstallError::Io {
                path: destination.to_path_buf(),
                error: error.into(),
            },
        )
    }

    #[cfg(not(unix))]
    {
        fs::rename(source, destination).map_err(|error| AcmeCertificateInstallError::Io {
            path: destination.to_path_buf(),
            error,
        })
    }
}

fn ensure_safe_account_directory(directory: &Path) -> Result<(), AcmeAccountStoreError> {
    reject_existing_symlink_in_path(directory).map_err(account_store_unsafe_from_cert_error)?;
    fs::create_dir_all(directory).map_err(|error| account_store_io_error(directory, error))?;
    reject_existing_symlink_in_path(directory).map_err(account_store_unsafe_from_cert_error)?;
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| account_store_io_error(directory, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AcmeAccountStoreError::UnsafePath {
            path: directory.to_path_buf(),
            message: "path is not a real directory".to_owned(),
        });
    }

    Ok(())
}

fn ensure_safe_account_destination(path: &Path) -> Result<(), AcmeAccountStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(AcmeAccountStoreError::UnsafePath {
                path: path.to_path_buf(),
                message: "credentials path is not a real file".to_owned(),
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(account_store_io_error(path, error)),
    }
}

fn write_account_credentials_file(
    path: &Path,
    contents: &[u8],
) -> Result<(), AcmeAccountStoreError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .map_err(|error| account_store_io_error(path, error))?;
    file.write_all(contents)
        .map_err(|error| account_store_io_error(path, error))?;
    file.sync_all()
        .map_err(|error| account_store_io_error(path, error))
}

fn sync_account_directory(path: &Path) -> Result<(), AcmeAccountStoreError> {
    fs::File::open(path)
        .map_err(|error| account_store_io_error(path, error))?
        .sync_all()
        .map_err(|error| account_store_io_error(path, error))
}

#[cfg(target_os = "linux")]
fn open_regular_certificate_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(UNIX_O_NOFOLLOW)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_regular_certificate_file(path: &Path) -> io::Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }

    std::fs::File::open(path)
}

#[cfg(target_os = "linux")]
fn open_regular_account_credentials_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(UNIX_O_NOFOLLOW)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_regular_account_credentials_file(path: &Path) -> io::Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }

    std::fs::File::open(path)
}

fn account_store_io_error(path: &Path, error: io::Error) -> AcmeAccountStoreError {
    AcmeAccountStoreError::Io {
        path: path.to_path_buf(),
        error,
    }
}

fn account_store_unsafe_from_cert_error(
    error: AcmeCertificateInstallError,
) -> AcmeAccountStoreError {
    match error {
        AcmeCertificateInstallError::UnsafePath { path, message } => {
            AcmeAccountStoreError::UnsafePath { path, message }
        }
        AcmeCertificateInstallError::Io { path, error } => {
            AcmeAccountStoreError::Io { path, error }
        }
        AcmeCertificateInstallError::InvalidCertificatePem(message)
        | AcmeCertificateInstallError::InvalidPrivateKeyPem(message) => {
            AcmeAccountStoreError::UnsafePath {
                path: PathBuf::new(),
                message: message.to_owned(),
            }
        }
    }
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

fn sync_directory(
    path: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    #[cfg(unix)]
    if let Some(directory_fd) = directory_fd {
        return rustix::fs::fsync(directory_fd).map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error: error.into(),
        });
    }

    let directory = fs::File::open(path).map_err(|error| AcmeCertificateInstallError::Io {
        path: path.to_path_buf(),
        error,
    })?;
    directory
        .sync_all()
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        })
}

fn sync_directory_io(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

fn load_eab_secret(
    issuer: &str,
    field: &'static str,
    env_name: Option<&str>,
    file_path: Option<&Path>,
    credential_name: Option<&str>,
) -> Result<Zeroizing<String>, AcmeSecretLoadError> {
    let value = match (env_name, file_path, credential_name) {
        (Some(env_name), None, None) => {
            Zeroizing::new(std::env::var(env_name).map_err(|error| {
                AcmeSecretLoadError::EnvRead {
                    issuer: issuer.to_owned(),
                    field,
                    env: env_name.to_owned(),
                    message: error.to_string(),
                }
            })?)
        }
        (None, Some(path), None) => read_eab_secret_file(issuer, field, path)?,
        (None, None, Some(credential_name)) => {
            let path = resolve_eab_credential_path(credential_name);
            read_eab_secret_file(issuer, field, &path)?
        }
        _ => {
            return Err(AcmeSecretLoadError::InvalidSecretSource {
                issuer: issuer.to_owned(),
                field,
            });
        }
    };

    normalize_eab_secret(issuer, field, value)
}

fn resolve_eab_credential_path(credential_name: &str) -> PathBuf {
    std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/secrets"))
        .join(credential_name)
}

fn read_eab_secret_file(
    issuer: &str,
    field: &'static str,
    path: &Path,
) -> Result<Zeroizing<String>, AcmeSecretLoadError> {
    let file = open_regular_eab_secret_file(issuer, field, path)?;
    let metadata = file
        .metadata()
        .map_err(|error| eab_file_error(issuer, field, path, error))?;
    if !metadata.file_type().is_file() {
        return Err(AcmeSecretLoadError::FileRead {
            issuer: issuer.to_owned(),
            field,
            path: path.to_path_buf(),
            message: "not a regular file".to_owned(),
        });
    }
    if metadata.len() > MAX_EAB_SECRET_BYTES {
        return Err(AcmeSecretLoadError::OversizedSecret {
            issuer: issuer.to_owned(),
            field,
            max_bytes: MAX_EAB_SECRET_BYTES,
        });
    }

    let mut secret = Zeroizing::new(String::new());
    let mut limited = file.take(MAX_EAB_SECRET_BYTES.saturating_add(1));
    limited
        .read_to_string(&mut secret)
        .map_err(|error| eab_file_error(issuer, field, path, error))?;
    if secret.len() as u64 > MAX_EAB_SECRET_BYTES {
        return Err(AcmeSecretLoadError::OversizedSecret {
            issuer: issuer.to_owned(),
            field,
            max_bytes: MAX_EAB_SECRET_BYTES,
        });
    }

    Ok(secret)
}

#[cfg(target_os = "linux")]
fn open_regular_http_01_challenge_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(UNIX_O_NOFOLLOW)
        .open(path)
}

#[cfg(not(target_os = "linux"))]
fn open_regular_http_01_challenge_file(path: &Path) -> io::Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACME HTTP-01 challenge file is not a regular file",
        ));
    }

    std::fs::File::open(path)
}

#[cfg(target_os = "linux")]
fn open_regular_eab_secret_file(
    issuer: &str,
    field: &'static str,
    path: &Path,
) -> Result<std::fs::File, AcmeSecretLoadError> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(UNIX_O_NOFOLLOW)
        .open(path)
        .map_err(|error| eab_file_error(issuer, field, path, error))
}

#[cfg(not(target_os = "linux"))]
fn open_regular_eab_secret_file(
    issuer: &str,
    field: &'static str,
    path: &Path,
) -> Result<std::fs::File, AcmeSecretLoadError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| eab_file_error(issuer, field, path, error))?;
    if !metadata.file_type().is_file() {
        return Err(AcmeSecretLoadError::FileRead {
            issuer: issuer.to_owned(),
            field,
            path: path.to_path_buf(),
            message: "not a regular file".to_owned(),
        });
    }

    std::fs::File::open(path).map_err(|error| eab_file_error(issuer, field, path, error))
}

fn eab_file_error(
    issuer: &str,
    field: &'static str,
    path: &Path,
    error: io::Error,
) -> AcmeSecretLoadError {
    AcmeSecretLoadError::FileRead {
        issuer: issuer.to_owned(),
        field,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

fn normalize_eab_secret(
    issuer: &str,
    field: &'static str,
    value: Zeroizing<String>,
) -> Result<Zeroizing<String>, AcmeSecretLoadError> {
    let value = Zeroizing::new(value.trim().to_owned());
    if value.is_empty() {
        return Err(AcmeSecretLoadError::EmptySecret {
            issuer: issuer.to_owned(),
            field,
        });
    }
    if value.len() as u64 > MAX_EAB_SECRET_BYTES {
        return Err(AcmeSecretLoadError::OversizedSecret {
            issuer: issuer.to_owned(),
            field,
            max_bytes: MAX_EAB_SECRET_BYTES,
        });
    }
    Ok(value)
}

pub fn plan_renewal_queue(
    config: &Config,
    observations: &[CertificateObservation],
    now: SystemTime,
) -> Vec<AcmeRenewalItem> {
    let renewal = &config.tls.acme.renewal;
    let renew_after = renewal
        .renew_after
        .as_ref()
        .and_then(toml_offset_datetime_to_system_time);
    let renew_before = Duration::from_secs(renewal.renew_before_secs);

    let mut items: Vec<AcmeRenewalItem> = renewal_targets(config)
        .into_iter()
        .map(|target| {
            let not_after = observations
                .iter()
                .find(|observation| observation.vhost_name == target.vhost_name)
                .map(|observation| observation.not_after);
            let certificate_due_at = not_after
                .map(|time| time.checked_sub(renew_before).unwrap_or(UNIX_EPOCH))
                .unwrap_or(now);
            let due_at = renew_after
                .map(|time| max_system_time(certificate_due_at, time))
                .unwrap_or(certificate_due_at);

            AcmeRenewalItem {
                target,
                not_after,
                due_at,
                due_now: due_at <= now,
            }
        })
        .collect();

    items.sort_by(compare_queue_items);
    items
}

pub fn next_retry_at(
    now: SystemTime,
    failures: u32,
    initial_secs: u64,
    max_secs: u64,
) -> SystemTime {
    let capped_shift = failures.min(63);
    let multiplier = 1_u64.checked_shl(capped_shift).unwrap_or(u64::MAX);
    let delay_secs = initial_secs.saturating_mul(multiplier).min(max_secs);
    now + Duration::from_secs(delay_secs)
}

pub fn toml_offset_datetime_to_system_time(datetime: &Datetime) -> Option<SystemTime> {
    let date = datetime.date?;
    let time = datetime.time?;
    let offset = datetime.offset?;
    let second = u64::from(time.second.unwrap_or(0));
    if second > 59 {
        return None;
    }

    let local_seconds = days_from_civil(date.year.into(), date.month.into(), date.day.into())?
        .checked_mul(86_400)?
        .checked_add(i64::from(time.hour) * 3_600)?
        .checked_add(i64::from(time.minute) * 60)?
        .checked_add(i64::try_from(second).ok()?)?;

    let offset_seconds = match offset {
        Offset::Z => 0,
        Offset::Custom { minutes } => i64::from(minutes) * 60,
    };
    let unix_seconds = local_seconds.checked_sub(offset_seconds)?;
    let nanos = time.nanosecond.unwrap_or(0);

    Some(system_time_from_unix(unix_seconds, nanos))
}

fn normalized_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn managed_certificate_segment(vhost_name: &str) -> String {
    let normalized = vhost_name.trim().to_ascii_lowercase();
    let mut slug = String::with_capacity(normalized.len().min(48));
    let mut last_was_separator = false;

    for character in normalized.chars() {
        let safe = character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-');
        let next = if safe { character } else { '-' };
        if next == '-' && last_was_separator {
            continue;
        }
        last_was_separator = next == '-';
        slug.push(next);
        if slug.len() >= 48 {
            break;
        }
    }

    let slug = slug.trim_matches(['.', '_', '-']);
    let slug = if slug.is_empty() { "vhost" } else { slug };
    format!("{slug}-{}", short_sha256_hex(vhost_name.as_bytes()))
}

fn short_sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut value = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn valid_http_01_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_HTTP_01_TOKEN_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_http_01_key_authorization(value: &str) -> bool {
    let value = value.trim_end_matches(['\r', '\n']);
    !value.is_empty()
        && value.len() as u64 <= MAX_HTTP_01_KEY_AUTHORIZATION_BYTES
        && !value.bytes().any(|byte| {
            byte == b'\0' || byte == b'\r' || byte == b'\n' || byte < 0x20 || byte == 0x7f
        })
}

fn compare_queue_items(left: &AcmeRenewalItem, right: &AcmeRenewalItem) -> Ordering {
    left.due_at
        .cmp(&right.due_at)
        .then_with(|| left.target.vhost_name.cmp(&right.target.vhost_name))
}

fn max_system_time(left: SystemTime, right: SystemTime) -> SystemTime {
    if left >= right { left } else { right }
}

fn system_time_from_unix(seconds: i64, nanos: u32) -> SystemTime {
    if seconds >= 0 {
        UNIX_EPOCH + Duration::new(seconds as u64, nanos)
    } else {
        UNIX_EPOCH - Duration::new(seconds.unsigned_abs(), nanos)
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    Some(era * 146_097 + day_of_era - 719_468)
}

#[cfg(test)]
#[path = "acme_tests.rs"]
mod tests;

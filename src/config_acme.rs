use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use toml::value::{Datetime, Offset};

use crate::config::{ConfigError, valid_credential_name, validate_config_list_len};
use crate::config_path::{validate_non_world_writable_parent, validate_path};

pub(crate) const MAX_ACME_ISSUERS: usize = 128;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub storage: Option<PathBuf>,
    #[serde(default = "default_acme_contact_email")]
    pub contact_email: Option<String>,
    #[serde(default = "default_acme_default_issuer")]
    pub default_issuer: String,
    #[serde(default)]
    pub challenge: AcmeChallenge,
    #[serde(default)]
    pub automation: AcmeAutomationMode,
    #[serde(default)]
    pub renewal: AcmeRenewalConfig,
    #[serde(default = "default_acme_issuers")]
    pub issuers: Vec<AcmeIssuerConfig>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcmeConfigFragment {
    enabled: Option<bool>,
    storage: Option<PathBuf>,
    contact_email: Option<String>,
    default_issuer: Option<String>,
    challenge: Option<AcmeChallenge>,
    automation: Option<AcmeAutomationMode>,
    renewal: Option<AcmeRenewalConfigFragment>,
    issuers: Option<Vec<AcmeIssuerConfig>>,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            storage: None,
            contact_email: default_acme_contact_email(),
            default_issuer: default_acme_default_issuer(),
            challenge: AcmeChallenge::default(),
            automation: AcmeAutomationMode::default(),
            renewal: AcmeRenewalConfig::default(),
            issuers: default_acme_issuers(),
        }
    }
}

impl AcmeConfig {
    pub(crate) fn merge(&mut self, fragment: AcmeConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(storage) = fragment.storage {
            self.storage = Some(storage);
        }
        if let Some(contact_email) = fragment.contact_email {
            self.contact_email = Some(contact_email);
        }
        if let Some(default_issuer) = fragment.default_issuer {
            self.default_issuer = default_issuer;
        }
        if let Some(challenge) = fragment.challenge {
            self.challenge = challenge;
        }
        if let Some(automation) = fragment.automation {
            self.automation = automation;
        }
        if let Some(renewal) = fragment.renewal {
            self.renewal.merge(renewal);
        }
        if let Some(issuers) = fragment.issuers {
            self.issuers = issuers;
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        validate_config_list_len("tls.acme.issuers", self.issuers.len(), MAX_ACME_ISSUERS)?;

        if self.enabled {
            let Some(storage) = &self.storage else {
                return Err(ConfigError::MissingAcmeStorage);
            };
            if storage.as_os_str().is_empty() {
                return Err(ConfigError::EmptyAcmeStorage);
            }
            validate_path("tls.acme.storage", Some(storage))?;
            validate_non_world_writable_parent("tls.acme.storage", Some(storage))?;
            if self.contact_email.as_deref().is_none_or(invalid_email) {
                return Err(ConfigError::InvalidAcmeContactEmail);
            }
        }

        self.renewal.validate()?;

        if self.default_issuer.trim().is_empty() {
            return Err(ConfigError::EmptyAcmeIssuerName {
                scope: "tls.acme.default_issuer",
            });
        }

        let mut seen = HashSet::new();
        for issuer in &self.issuers {
            issuer.validate()?;
            if !seen.insert(issuer.name.clone()) {
                return Err(ConfigError::DuplicateAcmeIssuerName {
                    name: issuer.name.clone(),
                });
            }
        }

        if !self
            .issuers
            .iter()
            .any(|issuer| issuer.name == self.default_issuer)
        {
            return Err(ConfigError::UnknownAcmeIssuer {
                name: self.default_issuer.clone(),
            });
        }

        Ok(())
    }
}

impl AcmeConfigFragment {
    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(storage) = &mut self.storage
            && storage.is_relative()
        {
            *storage = base_dir.join(&storage);
        }
        if let Some(issuers) = &mut self.issuers {
            for issuer in issuers {
                issuer.resolve_relative_paths(base_dir);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum AcmeChallenge {
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    #[default]
    #[serde(rename = "http-01")]
    Http01,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
pub enum AcmeAutomationMode {
    #[default]
    #[serde(rename = "background")]
    Background,
    #[serde(rename = "external")]
    External,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeRenewalConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_acme_renew_before_secs")]
    pub renew_before_secs: u64,
    #[serde(default)]
    pub renew_after: Option<Datetime>,
    #[serde(default = "default_acme_renewal_check_interval_secs")]
    pub check_interval_secs: u64,
    #[serde(default = "default_acme_renewal_retry_initial_secs")]
    pub retry_initial_secs: u64,
    #[serde(default = "default_acme_renewal_retry_max_secs")]
    pub retry_max_secs: u64,
    #[serde(default = "default_true")]
    pub reload_after_renewal: bool,
    #[serde(default = "default_true")]
    pub zero_downtime_reload: bool,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AcmeRenewalConfigFragment {
    enabled: Option<bool>,
    renew_before_secs: Option<u64>,
    renew_after: Option<Datetime>,
    check_interval_secs: Option<u64>,
    retry_initial_secs: Option<u64>,
    retry_max_secs: Option<u64>,
    reload_after_renewal: Option<bool>,
    zero_downtime_reload: Option<bool>,
}

impl Default for AcmeRenewalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            renew_before_secs: default_acme_renew_before_secs(),
            renew_after: None,
            check_interval_secs: default_acme_renewal_check_interval_secs(),
            retry_initial_secs: default_acme_renewal_retry_initial_secs(),
            retry_max_secs: default_acme_renewal_retry_max_secs(),
            reload_after_renewal: true,
            zero_downtime_reload: true,
        }
    }
}

impl AcmeRenewalConfig {
    fn merge(&mut self, fragment: AcmeRenewalConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(renew_before_secs) = fragment.renew_before_secs {
            self.renew_before_secs = renew_before_secs;
        }
        if let Some(renew_after) = fragment.renew_after {
            self.renew_after = Some(renew_after);
        }
        if let Some(check_interval_secs) = fragment.check_interval_secs {
            self.check_interval_secs = check_interval_secs;
        }
        if let Some(retry_initial_secs) = fragment.retry_initial_secs {
            self.retry_initial_secs = retry_initial_secs;
        }
        if let Some(retry_max_secs) = fragment.retry_max_secs {
            self.retry_max_secs = retry_max_secs;
        }
        if let Some(reload_after_renewal) = fragment.reload_after_renewal {
            self.reload_after_renewal = reload_after_renewal;
        }
        if let Some(zero_downtime_reload) = fragment.zero_downtime_reload {
            self.zero_downtime_reload = zero_downtime_reload;
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.renew_before_secs == 0 {
            return Err(ConfigError::InvalidAcmeRenewalDuration {
                field: "tls.acme.renewal.renew_before_secs",
            });
        }
        if self.check_interval_secs == 0 {
            return Err(ConfigError::InvalidAcmeRenewalDuration {
                field: "tls.acme.renewal.check_interval_secs",
            });
        }
        if self.retry_initial_secs == 0 {
            return Err(ConfigError::InvalidAcmeRenewalDuration {
                field: "tls.acme.renewal.retry_initial_secs",
            });
        }
        if self.retry_max_secs == 0 {
            return Err(ConfigError::InvalidAcmeRenewalDuration {
                field: "tls.acme.renewal.retry_max_secs",
            });
        }
        if self.retry_initial_secs > self.retry_max_secs {
            return Err(ConfigError::AcmeRenewalRetryInitialExceedsMax);
        }
        if self
            .renew_after
            .as_ref()
            .is_some_and(invalid_acme_renew_after_datetime)
        {
            return Err(ConfigError::InvalidAcmeRenewAfterDatetime);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeIssuerConfig {
    pub name: String,
    pub directory_url: String,
    #[serde(default)]
    pub eab: Option<AcmeExternalAccountBindingConfig>,
}

impl AcmeIssuerConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(eab) = &mut self.eab {
            eab.resolve_relative_paths(base_dir);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::EmptyAcmeIssuerName {
                scope: "tls.acme.issuers.name",
            });
        }
        if !valid_https_url(&self.directory_url) {
            return Err(ConfigError::InvalidAcmeDirectoryUrl {
                issuer: self.name.clone(),
                url: self.directory_url.clone(),
            });
        }
        if let Some(eab) = &self.eab {
            eab.validate(&self.name)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeExternalAccountBindingConfig {
    #[serde(default)]
    pub key_id_env: Option<String>,
    #[serde(default)]
    pub key_id_file: Option<PathBuf>,
    #[serde(default)]
    pub key_id_credential: Option<String>,
    #[serde(default)]
    pub hmac_key_env: Option<String>,
    #[serde(default)]
    pub hmac_key_file: Option<PathBuf>,
    #[serde(default)]
    pub hmac_key_credential: Option<String>,
}

impl AcmeExternalAccountBindingConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.key_id_file
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        if let Some(path) = &mut self.hmac_key_file
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }

    fn validate(&self, issuer: &str) -> Result<(), ConfigError> {
        validate_secret_source(
            issuer,
            "key_id",
            self.key_id_env.as_deref(),
            self.key_id_file.as_ref(),
            self.key_id_credential.as_deref(),
        )?;
        validate_secret_source(
            issuer,
            "hmac_key",
            self.hmac_key_env.as_deref(),
            self.hmac_key_file.as_ref(),
            self.hmac_key_credential.as_deref(),
        )
    }
}

fn default_acme_contact_email() -> Option<String> {
    None
}

fn default_acme_default_issuer() -> String {
    "letsencrypt".to_owned()
}

fn default_acme_renew_before_secs() -> u64 {
    30 * 24 * 60 * 60
}

fn default_acme_renewal_check_interval_secs() -> u64 {
    60 * 60
}

fn default_acme_renewal_retry_initial_secs() -> u64 {
    5 * 60
}

fn default_acme_renewal_retry_max_secs() -> u64 {
    24 * 60 * 60
}

fn default_acme_issuers() -> Vec<AcmeIssuerConfig> {
    vec![
        AcmeIssuerConfig {
            name: "letsencrypt".to_owned(),
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_owned(),
            eab: None,
        },
        AcmeIssuerConfig {
            name: "letsencrypt-staging".to_owned(),
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_owned(),
            eab: None,
        },
        AcmeIssuerConfig {
            name: "actalis".to_owned(),
            directory_url: "https://acme-api.actalis.com/acme/directory".to_owned(),
            eab: Some(AcmeExternalAccountBindingConfig {
                key_id_env: Some("FLUXHEIM_ACTALIS_EAB_KID".to_owned()),
                key_id_file: None,
                key_id_credential: None,
                hmac_key_env: Some("FLUXHEIM_ACTALIS_EAB_HMAC_KEY".to_owned()),
                hmac_key_file: None,
                hmac_key_credential: None,
            }),
        },
        AcmeIssuerConfig {
            name: "google-trust-services".to_owned(),
            directory_url: "https://dv.acme-v02.api.pki.goog/directory".to_owned(),
            eab: Some(AcmeExternalAccountBindingConfig {
                key_id_env: Some("FLUXHEIM_GTS_EAB_KID".to_owned()),
                key_id_file: None,
                key_id_credential: None,
                hmac_key_env: Some("FLUXHEIM_GTS_EAB_HMAC_KEY".to_owned()),
                hmac_key_file: None,
                hmac_key_credential: None,
            }),
        },
        AcmeIssuerConfig {
            name: "google-trust-services-staging".to_owned(),
            directory_url: "https://dv.acme-v02.test-api.pki.goog/directory".to_owned(),
            eab: Some(AcmeExternalAccountBindingConfig {
                key_id_env: Some("FLUXHEIM_GTS_STAGING_EAB_KID".to_owned()),
                key_id_file: None,
                key_id_credential: None,
                hmac_key_env: Some("FLUXHEIM_GTS_STAGING_EAB_HMAC_KEY".to_owned()),
                hmac_key_file: None,
                hmac_key_credential: None,
            }),
        },
    ]
}

fn valid_https_url(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("https://")
        && value.len() > "https://".len()
        && !value.chars().any(char::is_whitespace)
}

fn invalid_email(value: &str) -> bool {
    let value = value.trim();
    value.is_empty()
        || value.chars().any(char::is_whitespace)
        || !value.contains('@')
        || value.starts_with('@')
        || value.ends_with('@')
}

fn invalid_acme_renew_after_datetime(value: &Datetime) -> bool {
    value.date.is_none()
        || value.time.is_none()
        || value.offset.is_none()
        || value
            .time
            .and_then(|time| time.second)
            .is_some_and(|second| second > 59)
        || matches!(value.offset, Some(Offset::Custom { minutes }) if minutes <= -1_440 || minutes >= 1_440)
}

fn validate_secret_source(
    issuer: &str,
    field: &'static str,
    env: Option<&str>,
    file: Option<&PathBuf>,
    credential: Option<&str>,
) -> Result<(), ConfigError> {
    let env = env.map(str::trim).filter(|value| !value.is_empty());
    let file = file.filter(|path| !path.as_os_str().is_empty());
    let credential = credential.map(str::trim).filter(|value| !value.is_empty());
    let file_field = format!("tls.acme.issuers.{issuer}.eab.{field}_file");
    validate_path(file_field.clone(), file.map(PathBuf::as_path))?;
    validate_non_world_writable_parent(file_field, file.map(PathBuf::as_path))?;

    if let Some(credential) = credential
        && !valid_credential_name(credential)
    {
        return Err(ConfigError::InvalidAcmeEabCredentialName {
            issuer: issuer.to_owned(),
            field,
            credential: credential.to_owned(),
        });
    }

    match (env.is_some(), file.is_some(), credential.is_some()) {
        (true, false, false) | (false, true, false) | (false, false, true) => Ok(()),
        (false, false, false) => Err(ConfigError::InvalidAcmeEabSecretSource {
            issuer: issuer.to_owned(),
            field,
        }),
        _ => Err(ConfigError::ConflictingAcmeEabSecretSource {
            issuer: issuer.to_owned(),
            field,
        }),
    }
}

fn default_true() -> bool {
    true
}

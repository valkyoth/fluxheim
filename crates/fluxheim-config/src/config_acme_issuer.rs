use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, valid_credential_name};
use crate::config_path::{validate_non_world_writable_parent, validate_path};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeIssuerConfig {
    pub name: String,
    pub directory_url: String,
    #[serde(default)]
    pub eab: Option<AcmeExternalAccountBindingConfig>,
}

impl AcmeIssuerConfig {
    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(eab) = &mut self.eab {
            eab.resolve_relative_paths(base_dir);
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
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

pub(crate) fn default_acme_issuers() -> Vec<AcmeIssuerConfig> {
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

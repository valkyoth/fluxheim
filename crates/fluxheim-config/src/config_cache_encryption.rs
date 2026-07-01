use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, valid_credential_name};
use crate::config_net::http_authority_is_numeric_loopback;
use crate::config_path::{validate_non_world_writable_parent, validate_path};

#[derive(Debug, Clone, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskEncryptionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: CacheDiskEncryptionProvider,
    #[serde(default)]
    pub algorithm: CacheDiskEncryptionAlgorithm,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    #[serde(default)]
    pub key_credential: Option<String>,
    #[serde(default)]
    pub openbao: CacheDiskEncryptionOpenBaoConfig,
}

#[derive(Debug, Clone, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskEncryptionConfigFragment {
    enabled: Option<bool>,
    provider: Option<CacheDiskEncryptionProvider>,
    algorithm: Option<CacheDiskEncryptionAlgorithm>,
    key_id: Option<String>,
    key_file: Option<PathBuf>,
    key_credential: Option<String>,
    openbao: Option<CacheDiskEncryptionOpenBaoConfigFragment>,
}

#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheDiskEncryptionProvider {
    #[default]
    Local,
    OpenbaoTransit,
}

#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheDiskEncryptionAlgorithm {
    #[default]
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "xchacha20-poly1305")]
    XChaCha20Poly1305,
}

impl Default for CacheDiskEncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: CacheDiskEncryptionProvider::Local,
            algorithm: CacheDiskEncryptionAlgorithm::Aes256Gcm,
            key_id: None,
            key_file: None,
            key_credential: None,
            openbao: CacheDiskEncryptionOpenBaoConfig::default(),
        }
    }
}

impl CacheDiskEncryptionConfig {
    pub(crate) fn merge(&mut self, fragment: CacheDiskEncryptionConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(provider) = fragment.provider {
            self.provider = provider;
        }
        if let Some(algorithm) = fragment.algorithm {
            self.algorithm = algorithm;
        }
        if let Some(key_id) = fragment.key_id {
            self.key_id = Some(key_id);
        }
        if let Some(key_file) = fragment.key_file {
            self.key_file = Some(key_file);
        }
        if let Some(key_credential) = fragment.key_credential {
            self.key_credential = Some(key_credential);
        }
        if let Some(openbao) = fragment.openbao {
            self.openbao.merge(openbao);
        }
    }

    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(key_file) = &mut self.key_file
            && key_file.is_relative()
        {
            *key_file = base_dir.join(&key_file);
        }
        self.openbao.resolve_relative_paths(base_dir);
    }

    pub(crate) fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        let key_file_field = format!("{scope}.disk.encryption.key_file");
        validate_path(key_file_field.clone(), self.key_file.as_deref())?;
        validate_non_world_writable_parent(key_file_field, self.key_file.as_deref())?;

        if let Some(key_id) = self.key_id.as_deref() {
            validate_cache_encryption_label(scope, "key_id", key_id)?;
        }
        if let Some(credential) = self.key_credential.as_deref()
            && !valid_credential_name(credential)
        {
            return Err(ConfigError::InvalidCacheEncryptionCredentialName {
                scope,
                field: "key_credential",
                credential: credential.to_owned(),
            });
        }

        self.openbao.validate(scope)?;

        if !self.enabled {
            return Ok(());
        }

        match self.provider {
            CacheDiskEncryptionProvider::Local => {
                if self.algorithm != CacheDiskEncryptionAlgorithm::Aes256Gcm {
                    return Err(ConfigError::InvalidCacheEncryptionPolicy {
                        scope,
                        field: "disk.encryption.algorithm",
                        reason: "local provider currently supports only \"aes-256-gcm\"",
                    });
                }
                if self.openbao.is_configured() {
                    return Err(ConfigError::InvalidCacheEncryptionPolicy {
                        scope,
                        field: "disk.encryption.openbao",
                        reason: "openbao settings require provider = \"openbao-transit\"",
                    });
                }
                validate_cache_encryption_secret_choice(
                    scope,
                    "key",
                    self.key_file.as_ref(),
                    self.key_credential.as_deref(),
                )?;
            }
            CacheDiskEncryptionProvider::OpenbaoTransit => {
                if self.key_file.is_some() || self.key_credential.is_some() {
                    return Err(ConfigError::InvalidCacheEncryptionPolicy {
                        scope,
                        field: "disk.encryption.key",
                        reason: "local key sources require provider = \"local\"",
                    });
                }
                self.openbao.validate_enabled(scope)?;
            }
        }

        Ok(())
    }
}

impl CacheDiskEncryptionConfigFragment {
    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(key_file) = &mut self.key_file
            && key_file.is_relative()
        {
            *key_file = base_dir.join(&key_file);
        }
        if let Some(openbao) = &mut self.openbao {
            openbao.resolve_relative_paths(base_dir);
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskEncryptionOpenBaoConfig {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub mount: Option<String>,
    #[serde(default)]
    pub key_name: Option<String>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    #[serde(default)]
    pub token_credential: Option<String>,
}

#[derive(Debug, Clone, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskEncryptionOpenBaoConfigFragment {
    address: Option<String>,
    mount: Option<String>,
    key_name: Option<String>,
    token_file: Option<PathBuf>,
    token_credential: Option<String>,
}

impl CacheDiskEncryptionOpenBaoConfig {
    fn merge(&mut self, fragment: CacheDiskEncryptionOpenBaoConfigFragment) {
        if let Some(address) = fragment.address {
            self.address = Some(address);
        }
        if let Some(mount) = fragment.mount {
            self.mount = Some(mount);
        }
        if let Some(key_name) = fragment.key_name {
            self.key_name = Some(key_name);
        }
        if let Some(token_file) = fragment.token_file {
            self.token_file = Some(token_file);
        }
        if let Some(token_credential) = fragment.token_credential {
            self.token_credential = Some(token_credential);
        }
    }

    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(token_file) = &mut self.token_file
            && token_file.is_relative()
        {
            *token_file = base_dir.join(&token_file);
        }
    }

    fn is_configured(&self) -> bool {
        self.address.is_some()
            || self.mount.is_some()
            || self.key_name.is_some()
            || self.token_file.is_some()
            || self.token_credential.is_some()
    }

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if let Some(address) = self.address.as_deref()
            && invalid_cache_encryption_openbao_address(address)
        {
            return Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope,
                field: "disk.encryption.openbao.address",
                reason: "must be an http://127.0.0.1, http://[::1], or https:// URL without credentials, query, or fragment",
            });
        }
        if let Some(mount) = self.mount.as_deref() {
            validate_cache_encryption_label(scope, "openbao.mount", mount)?;
        }
        if let Some(key_name) = self.key_name.as_deref() {
            validate_cache_encryption_label(scope, "openbao.key_name", key_name)?;
        }
        let token_file_field = format!("{scope}.disk.encryption.openbao.token_file");
        validate_path(token_file_field.clone(), self.token_file.as_deref())?;
        validate_non_world_writable_parent(token_file_field, self.token_file.as_deref())?;
        if let Some(credential) = self.token_credential.as_deref()
            && !valid_credential_name(credential)
        {
            return Err(ConfigError::InvalidCacheEncryptionCredentialName {
                scope,
                field: "openbao.token_credential",
                credential: credential.to_owned(),
            });
        }
        Ok(())
    }

    fn validate_enabled(&self, scope: &'static str) -> Result<(), ConfigError> {
        if self
            .address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope,
                field: "disk.encryption.openbao.address",
                reason: "is required when provider = \"openbao-transit\"",
            });
        }
        if self
            .mount
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope,
                field: "disk.encryption.openbao.mount",
                reason: "is required when provider = \"openbao-transit\"",
            });
        }
        if self
            .key_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return Err(ConfigError::InvalidCacheEncryptionPolicy {
                scope,
                field: "disk.encryption.openbao.key_name",
                reason: "is required when provider = \"openbao-transit\"",
            });
        }
        validate_cache_encryption_secret_choice(
            scope,
            "openbao.token",
            self.token_file.as_ref(),
            self.token_credential.as_deref(),
        )
    }
}

impl CacheDiskEncryptionOpenBaoConfigFragment {
    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(token_file) = &mut self.token_file
            && token_file.is_relative()
        {
            *token_file = base_dir.join(&token_file);
        }
    }
}

fn validate_cache_encryption_secret_choice(
    scope: &'static str,
    field: &'static str,
    file: Option<&PathBuf>,
    credential: Option<&str>,
) -> Result<(), ConfigError> {
    let file = file.filter(|path| !path.as_os_str().is_empty());
    let credential = credential.map(str::trim).filter(|value| !value.is_empty());
    match (file.is_some(), credential.is_some()) {
        (true, false) | (false, true) => Ok(()),
        (false, false) => Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope,
            field,
            reason: "must be read from a file or systemd/container credential",
        }),
        (true, true) => Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope,
            field,
            reason: "cannot use more than one secret source",
        }),
    }
}

fn validate_cache_encryption_label(
    scope: &'static str,
    field: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('.')
        || value.contains("..")
        || value
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':')))
    {
        return Err(ConfigError::InvalidCacheEncryptionPolicy {
            scope,
            field,
            reason: "must be 1-128 safe ASCII label characters",
        });
    }
    Ok(())
}

fn invalid_cache_encryption_openbao_address(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 2048
        || value.chars().any(char::is_whitespace)
        || value.contains('@')
        || value.contains('?')
        || value.contains('#')
    {
        return true;
    }
    if value.starts_with("https://") {
        let rest = value.trim_start_matches("https://");
        let authority = rest.split('/').next().unwrap_or_default();
        return authority.is_empty();
    }
    let Some(rest) = value.strip_prefix("http://") else {
        return true;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    !openbao_plain_http_authority_is_loopback(authority)
}

fn openbao_plain_http_authority_is_loopback(authority: &str) -> bool {
    http_authority_is_numeric_loopback(authority)
}

pub fn fips_allowed_local_openbao_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return false;
    };
    if rest.is_empty()
        || rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
        || rest
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return false;
    }
    let authority = rest
        .split_once('/')
        .map_or(rest, |(authority, _path)| authority);
    !authority.is_empty() && openbao_plain_http_authority_is_loopback(authority)
}

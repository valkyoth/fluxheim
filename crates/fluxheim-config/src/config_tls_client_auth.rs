use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_path::{validate_non_world_writable_parent, validate_path};

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsClientAuthConfig {
    #[serde(default)]
    pub mode: TlsClientAuthMode,
    #[serde(default)]
    pub ca_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TlsClientAuthConfigFragment {
    mode: Option<TlsClientAuthMode>,
    ca_path: Option<PathBuf>,
}

impl TlsClientAuthConfig {
    pub(super) fn merge(&mut self, fragment: TlsClientAuthConfigFragment) {
        if let Some(mode) = fragment.mode {
            self.mode = mode;
        }
        if let Some(ca_path) = fragment.ca_path {
            self.ca_path = Some(ca_path);
        }
    }

    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        match (self.mode, &self.ca_path) {
            (TlsClientAuthMode::Off, None) => return Ok(()),
            (TlsClientAuthMode::Optional | TlsClientAuthMode::Required, None) => {
                return Err(ConfigError::InvalidTlsPolicy {
                    field: "tls.client_auth.ca_path",
                    reason: "tls.client_auth.mode requires a client CA bundle path",
                });
            }
            (_, Some(_)) => {}
        }
        let Some(ca_path) = &self.ca_path else {
            return Ok(());
        };
        if ca_path.as_os_str().is_empty() {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.client_auth.ca_path",
                reason: "tls.client_auth.ca_path cannot be empty",
            });
        }
        validate_path("tls.client_auth.ca_path", Some(ca_path))?;
        validate_non_world_writable_parent("tls.client_auth.ca_path", Some(ca_path))?;
        Ok(())
    }
}

impl TlsClientAuthConfigFragment {
    pub(super) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.ca_path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsClientAuthMode {
    #[default]
    Off,
    Optional,
    Required,
}

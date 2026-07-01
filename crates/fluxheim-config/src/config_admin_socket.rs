use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_path::validate_required_process_path;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminOpsSocketConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_admin_ops_socket_path")]
    pub path: PathBuf,
    #[serde(default = "default_admin_ops_socket_mode")]
    pub mode: String,
    #[serde(default)]
    pub require_bearer_token: bool,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminOpsSocketConfigFragment {
    enabled: Option<bool>,
    path: Option<PathBuf>,
    mode: Option<String>,
    require_bearer_token: Option<bool>,
}

impl Default for AdminOpsSocketConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_admin_ops_socket_path(),
            mode: default_admin_ops_socket_mode(),
            require_bearer_token: false,
        }
    }
}

impl AdminOpsSocketConfig {
    pub(crate) fn merge(&mut self, fragment: AdminOpsSocketConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(path) = fragment.path {
            self.path = path;
        }
        if let Some(mode) = fragment.mode {
            self.mode = mode;
        }
        if let Some(require_bearer_token) = fragment.require_bearer_token {
            self.require_bearer_token = require_bearer_token;
        }
    }

    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if self.path.is_relative() {
            self.path = base_dir.join(&self.path);
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            Err(ConfigError::InvalidAdminOpsSocket {
                field: "admin.ops_socket.enabled",
                reason: "admin ops socket requires Unix-domain socket support",
            })
        }

        #[cfg(unix)]
        {
            validate_required_process_path("admin.ops_socket.path", &self.path)?;
            if self.path.to_str().is_none() {
                return Err(ConfigError::InvalidAdminOpsSocket {
                    field: "admin.ops_socket.path",
                    reason: "admin ops socket path must be valid UTF-8",
                });
            }
            let mode = parse_admin_ops_socket_mode(&self.mode)?;
            if mode & 0o007 != 0 || mode & 0o600 != 0o600 || mode & !0o770 != 0 {
                return Err(ConfigError::InvalidAdminOpsSocket {
                    field: "admin.ops_socket.mode",
                    reason: "admin ops socket mode must grant owner read/write, may grant group read/write, and must not grant world access",
                });
            }
            Ok(())
        }
    }

    pub fn mode_bits(&self) -> u32 {
        parse_admin_ops_socket_mode(&self.mode).unwrap_or(0o600)
    }
}

impl AdminOpsSocketConfigFragment {
    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }
}

fn default_admin_ops_socket_path() -> PathBuf {
    PathBuf::from("/run/fluxheim/fluxheim-ops.sock")
}

fn default_admin_ops_socket_mode() -> String {
    "0600".to_owned()
}

#[cfg(unix)]
fn parse_admin_ops_socket_mode(value: &str) -> Result<u32, ConfigError> {
    let value = value.trim();
    let raw = value.strip_prefix("0o").unwrap_or(value);
    if raw.len() != 3 && raw.len() != 4 {
        return Err(ConfigError::InvalidAdminOpsSocket {
            field: "admin.ops_socket.mode",
            reason: "admin ops socket mode must be an octal string such as \"0600\" or \"0660\"",
        });
    }
    u32::from_str_radix(raw, 8).map_err(|_| ConfigError::InvalidAdminOpsSocket {
        field: "admin.ops_socket.mode",
        reason: "admin ops socket mode must be an octal string such as \"0600\" or \"0660\"",
    })
}

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
pub use crate::config_admin_health::{
    AdminAuthThrottleConfig, AdminAuthThrottleConfigFragment, AdminHealthConfig,
    AdminHealthConfigFragment, AdminHealthResponseMode, AdminSelfHealingConfig,
    AdminSelfHealingConfigFragment, MAX_ADMIN_HEALTH_PATH_BYTES,
};
pub use crate::config_admin_socket::{AdminOpsSocketConfig, AdminOpsSocketConfigFragment};
pub use crate::config_admin_transport::{
    AdminClientCertificateConfig, AdminClientCertificateConfigFragment, AdminRemoteTransportMode,
    AdminTransportConfig, AdminTransportConfigFragment,
};
use crate::config_path::{
    validate_non_world_writable_parent, validate_path, validate_private_state_directory,
};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_admin_listen")]
    pub listen: String,
    #[serde(default = "default_admin_require_loopback")]
    pub require_loopback: bool,
    #[serde(default)]
    pub token_env: Option<String>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    #[serde(default)]
    pub snapshot_store: Option<PathBuf>,
    #[serde(default)]
    pub snapshot_integrity_key_file: Option<PathBuf>,
    #[serde(default)]
    pub transport: AdminTransportConfig,
    #[serde(default)]
    pub ops_socket: AdminOpsSocketConfig,
    #[serde(default)]
    pub health: AdminHealthConfig,
    #[serde(default)]
    pub auth_throttle: AdminAuthThrottleConfig,
    #[serde(default)]
    pub self_healing: AdminSelfHealingConfig,
    #[serde(default)]
    pub client_certificate: AdminClientCertificateConfig,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfigFragment {
    enabled: Option<bool>,
    listen: Option<String>,
    require_loopback: Option<bool>,
    token_env: Option<String>,
    token_file: Option<PathBuf>,
    snapshot_store: Option<PathBuf>,
    snapshot_integrity_key_file: Option<PathBuf>,
    transport: Option<AdminTransportConfigFragment>,
    ops_socket: Option<AdminOpsSocketConfigFragment>,
    health: Option<AdminHealthConfigFragment>,
    auth_throttle: Option<AdminAuthThrottleConfigFragment>,
    self_healing: Option<AdminSelfHealingConfigFragment>,
    client_certificate: Option<AdminClientCertificateConfigFragment>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_admin_listen(),
            require_loopback: default_admin_require_loopback(),
            token_env: None,
            token_file: None,
            snapshot_store: None,
            snapshot_integrity_key_file: None,
            transport: AdminTransportConfig::default(),
            ops_socket: AdminOpsSocketConfig::default(),
            health: AdminHealthConfig::default(),
            auth_throttle: AdminAuthThrottleConfig::default(),
            self_healing: AdminSelfHealingConfig::default(),
            client_certificate: AdminClientCertificateConfig::default(),
        }
    }
}

impl AdminConfig {
    pub fn merge(&mut self, fragment: AdminConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(listen) = fragment.listen {
            self.listen = listen;
        }
        if let Some(require_loopback) = fragment.require_loopback {
            self.require_loopback = require_loopback;
        }
        if let Some(token_env) = fragment.token_env {
            self.token_env = Some(token_env);
        }
        if let Some(token_file) = fragment.token_file {
            self.token_file = Some(token_file);
        }
        if let Some(snapshot_store) = fragment.snapshot_store {
            self.snapshot_store = Some(snapshot_store);
        }
        if let Some(key_file) = fragment.snapshot_integrity_key_file {
            self.snapshot_integrity_key_file = Some(key_file);
        }
        if let Some(transport) = fragment.transport {
            self.transport.merge(transport);
        }
        if let Some(ops_socket) = fragment.ops_socket {
            self.ops_socket.merge(ops_socket);
        }
        if let Some(health) = fragment.health {
            self.health.merge(health);
        }
        if let Some(auth_throttle) = fragment.auth_throttle {
            self.auth_throttle.merge(auth_throttle);
        }
        if let Some(self_healing) = fragment.self_healing {
            self.self_healing.merge(self_healing);
        }
        if let Some(client_certificate) = fragment.client_certificate {
            self.client_certificate.merge(client_certificate);
        }
    }

    pub fn admin_client_certificate_required(&self) -> bool {
        self.client_certificate.required || !self.client_certificate.allow_sha256.is_empty()
    }

    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(token_file) = &mut self.token_file
            && token_file.is_relative()
        {
            *token_file = base_dir.join(&token_file);
        }
        if let Some(snapshot_store) = &mut self.snapshot_store
            && snapshot_store.is_relative()
        {
            *snapshot_store = base_dir.join(&snapshot_store);
        }
        if let Some(key_file) = &mut self.snapshot_integrity_key_file
            && key_file.is_relative()
        {
            *key_file = base_dir.join(&key_file);
        }
        self.ops_socket.resolve_relative_paths(base_dir);
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let listen = self.listen.parse::<SocketAddr>().map_err(|_| {
            ConfigError::InvalidAdminListenAddress {
                address: self.listen.clone(),
            }
        })?;

        validate_optional_env("admin.token_env", self.token_env.as_deref())?;
        reject_empty_admin_path("admin.token_file", self.token_file.as_deref())?;
        reject_empty_admin_path("admin.snapshot_store", self.snapshot_store.as_deref())?;
        reject_empty_admin_path(
            "admin.snapshot_integrity_key_file",
            self.snapshot_integrity_key_file.as_deref(),
        )?;
        validate_path("admin.token_file", self.token_file.as_deref())?;
        validate_path("admin.snapshot_store", self.snapshot_store.as_deref())?;
        validate_private_state_directory("admin.snapshot_store", self.snapshot_store.as_deref())?;
        validate_path(
            "admin.snapshot_integrity_key_file",
            self.snapshot_integrity_key_file.as_deref(),
        )?;
        validate_non_world_writable_parent("admin.token_file", self.token_file.as_deref())?;
        validate_non_world_writable_parent("admin.snapshot_store", self.snapshot_store.as_deref())?;
        validate_non_world_writable_parent(
            "admin.snapshot_integrity_key_file",
            self.snapshot_integrity_key_file.as_deref(),
        )?;
        if let (Some(store), Some(key_file)) = (
            self.snapshot_store.as_deref(),
            self.snapshot_integrity_key_file.as_deref(),
        ) && key_file.starts_with(store)
        {
            return Err(ConfigError::UnsafePath {
                field: "admin.snapshot_integrity_key_file".to_owned(),
                path: key_file.to_path_buf(),
            });
        }
        self.auth_throttle.validate()?;
        self.self_healing.validate()?;
        self.client_certificate.validate()?;
        self.ops_socket.validate()?;

        if !self.enabled {
            if self.ops_socket.enabled {
                return Err(ConfigError::InvalidAdminOpsSocket {
                    field: "admin.ops_socket.enabled",
                    reason: "admin ops socket requires admin.enabled = true",
                });
            }
            return Ok(());
        }

        if self.require_loopback && !listen.ip().is_loopback() {
            return Err(ConfigError::AdminListenNotLoopback {
                address: self.listen.clone(),
            });
        }
        if !listen.ip().is_loopback()
            && self.transport.mode != AdminRemoteTransportMode::TrustedTlsTerminator
        {
            return Err(ConfigError::RemoteAdminRequiresSecureTransport {
                address: self.listen.clone(),
            });
        }
        if self.health.unauthenticated && !listen.ip().is_loopback() {
            return Err(ConfigError::UnauthenticatedAdminHealthNotLoopback {
                address: self.listen.clone(),
            });
        }
        if listen.ip().is_loopback()
            && (self.client_certificate.required
                || !self.client_certificate.allow_sha256.is_empty()
                || !self.client_certificate.deny_sha256.is_empty())
        {
            log::warn!(
                target: "fluxheim::security",
                "admin.client_certificate is configured on a loopback admin listener; this only hardens a trusted TLS/mTLS terminator that strips and injects the configured fingerprint header"
            );
        }

        match (&self.token_env, &self.token_file) {
            (None, None) => Err(ConfigError::MissingAdminAuth),
            (Some(_), Some(_)) => Err(ConfigError::ConflictingAdminAuth),
            (Some(_), None) | (None, Some(_)) => {
                if self.snapshot_store.is_none() {
                    Err(ConfigError::MissingAdminSnapshotStore)
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl AdminConfigFragment {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(token_file) = &mut self.token_file
            && token_file.is_relative()
        {
            *token_file = base_dir.join(&token_file);
        }
        if let Some(snapshot_store) = &mut self.snapshot_store
            && snapshot_store.is_relative()
        {
            *snapshot_store = base_dir.join(&snapshot_store);
        }
        if let Some(key_file) = &mut self.snapshot_integrity_key_file
            && key_file.is_relative()
        {
            *key_file = base_dir.join(&key_file);
        }
        if let Some(ops_socket) = &mut self.ops_socket {
            ops_socket.resolve_relative_paths(base_dir);
        }
    }
}

fn default_admin_listen() -> String {
    "127.0.0.1:9090".to_owned()
}

fn default_admin_require_loopback() -> bool {
    true
}

fn validate_optional_env(field: &'static str, env: Option<&str>) -> Result<(), ConfigError> {
    if env.is_some_and(|value| value.trim().is_empty()) {
        return Err(ConfigError::EmptyAdminSecretSource { field });
    }
    Ok(())
}

fn reject_empty_admin_path(field: &'static str, path: Option<&Path>) -> Result<(), ConfigError> {
    if path.is_some_and(|path| path.as_os_str().is_empty()) {
        return Err(ConfigError::EmptyAdminPath { field });
    }
    Ok(())
}

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_access::validate_client_cert_sha256_list;
use crate::config_header::validate_header_name;
use crate::config_path::{
    validate_non_world_writable_parent, validate_path, validate_required_process_path,
};

pub(crate) const MAX_ADMIN_HEALTH_PATH_BYTES: usize = 2048;
const DEFAULT_ADMIN_HEALTH_PATH: &str = "/_fluxheim/health";

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

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_admin_listen(),
            require_loopback: default_admin_require_loopback(),
            token_env: None,
            token_file: None,
            snapshot_store: None,
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
    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
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
        self.ops_socket.resolve_relative_paths(base_dir);
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        let listen = self.listen.parse::<SocketAddr>().map_err(|_| {
            ConfigError::InvalidAdminListenAddress {
                address: self.listen.clone(),
            }
        })?;

        validate_optional_env("admin.token_env", self.token_env.as_deref())?;
        reject_empty_admin_path("admin.token_file", self.token_file.as_deref())?;
        reject_empty_admin_path("admin.snapshot_store", self.snapshot_store.as_deref())?;
        validate_path("admin.token_file", self.token_file.as_deref())?;
        validate_path("admin.snapshot_store", self.snapshot_store.as_deref())?;
        validate_non_world_writable_parent("admin.token_file", self.token_file.as_deref())?;
        validate_non_world_writable_parent("admin.snapshot_store", self.snapshot_store.as_deref())?;
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

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminOpsSocketConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_admin_ops_socket_path")]
    pub path: PathBuf,
    #[serde(default = "default_admin_ops_socket_mode")]
    pub mode: String,
}

impl Default for AdminOpsSocketConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_admin_ops_socket_path(),
            mode: default_admin_ops_socket_mode(),
        }
    }
}

impl AdminOpsSocketConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if self.path.is_relative() {
            self.path = base_dir.join(&self.path);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            return Err(ConfigError::InvalidAdminOpsSocket {
                field: "admin.ops_socket.enabled",
                reason: "admin ops socket requires Unix-domain socket support",
            });
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

    #[cfg(all(unix, any(test, feature = "proxy")))]
    pub(crate) fn mode_bits(&self) -> u32 {
        parse_admin_ops_socket_mode(&self.mode).unwrap_or(0o600)
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

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminTransportConfig {
    #[serde(default)]
    pub mode: AdminRemoteTransportMode,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminRemoteTransportMode {
    #[default]
    LocalOnly,
    TrustedTlsTerminator,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminClientCertificateConfig {
    #[serde(default)]
    pub required: bool,
    #[serde(default = "default_admin_client_certificate_sha256_header")]
    pub sha256_header: String,
    #[serde(default)]
    pub allow_sha256: Vec<String>,
    #[serde(default)]
    pub deny_sha256: Vec<String>,
}

impl Default for AdminClientCertificateConfig {
    fn default() -> Self {
        Self {
            required: false,
            sha256_header: default_admin_client_certificate_sha256_header(),
            allow_sha256: Vec::new(),
            deny_sha256: Vec::new(),
        }
    }
}

impl AdminClientCertificateConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_header_name(
            "admin.client_certificate.sha256_header",
            &self.sha256_header,
        )?;
        validate_client_cert_sha256_list(
            "admin.client_certificate",
            "allow_sha256",
            &self.allow_sha256,
        )?;
        validate_client_cert_sha256_list(
            "admin.client_certificate",
            "deny_sha256",
            &self.deny_sha256,
        )?;
        Ok(())
    }
}

fn default_admin_client_certificate_sha256_header() -> String {
    "x-client-cert-sha256".to_owned()
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminHealthConfig {
    #[serde(default)]
    pub unauthenticated: bool,
    #[serde(default)]
    pub response: AdminHealthResponseMode,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminHealthResponseMode {
    Minimal,
    #[default]
    Status,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminAuthThrottleConfig {
    #[serde(default = "default_admin_auth_throttle_enabled")]
    pub enabled: bool,
    #[serde(default = "default_admin_auth_throttle_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_admin_auth_throttle_per_source_failures")]
    pub per_source_failures: usize,
    #[serde(default = "default_admin_auth_throttle_global_failures")]
    pub global_failures: usize,
    #[serde(default = "default_admin_auth_throttle_base_lockout_secs")]
    pub base_lockout_secs: u64,
    #[serde(default = "default_admin_auth_throttle_max_lockout_secs")]
    pub max_lockout_secs: u64,
    #[serde(default = "default_admin_auth_throttle_max_sources")]
    pub max_sources: usize,
}

impl Default for AdminAuthThrottleConfig {
    fn default() -> Self {
        Self {
            enabled: default_admin_auth_throttle_enabled(),
            window_secs: default_admin_auth_throttle_window_secs(),
            per_source_failures: default_admin_auth_throttle_per_source_failures(),
            global_failures: default_admin_auth_throttle_global_failures(),
            base_lockout_secs: default_admin_auth_throttle_base_lockout_secs(),
            max_lockout_secs: default_admin_auth_throttle_max_lockout_secs(),
            max_sources: default_admin_auth_throttle_max_sources(),
        }
    }
}

impl AdminAuthThrottleConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.window_secs == 0 {
            return Err(ConfigError::InvalidAdminAuthThrottle {
                field: "admin.auth_throttle.window_secs",
            });
        }
        if self.per_source_failures == 0 {
            return Err(ConfigError::InvalidAdminAuthThrottle {
                field: "admin.auth_throttle.per_source_failures",
            });
        }
        if self.global_failures == 0 {
            return Err(ConfigError::InvalidAdminAuthThrottle {
                field: "admin.auth_throttle.global_failures",
            });
        }
        if self.base_lockout_secs == 0 {
            return Err(ConfigError::InvalidAdminAuthThrottle {
                field: "admin.auth_throttle.base_lockout_secs",
            });
        }
        if self.max_lockout_secs < self.base_lockout_secs {
            return Err(ConfigError::InvalidAdminAuthThrottle {
                field: "admin.auth_throttle.max_lockout_secs",
            });
        }
        if self.max_sources == 0 {
            return Err(ConfigError::InvalidAdminAuthThrottle {
                field: "admin.auth_throttle.max_sources",
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSelfHealingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_admin_validation_window_secs")]
    pub validation_window_secs: u64,
    #[serde(default = "default_admin_health_path")]
    pub health_path: String,
    #[serde(default = "default_admin_min_successful_checks")]
    pub min_successful_checks: usize,
    #[serde(default = "default_admin_max_error_rate_per_mille")]
    pub max_error_rate_per_mille: u16,
}

impl Default for AdminSelfHealingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            validation_window_secs: default_admin_validation_window_secs(),
            health_path: default_admin_health_path(),
            min_successful_checks: default_admin_min_successful_checks(),
            max_error_rate_per_mille: default_admin_max_error_rate_per_mille(),
        }
    }
}

impl AdminSelfHealingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.validation_window_secs == 0 {
            return Err(ConfigError::InvalidAdminSelfHealing {
                field: "admin.self_healing.validation_window_secs",
            });
        }
        if self.min_successful_checks == 0 {
            return Err(ConfigError::InvalidAdminSelfHealing {
                field: "admin.self_healing.min_successful_checks",
            });
        }
        if self.max_error_rate_per_mille > 1000 {
            return Err(ConfigError::InvalidAdminSelfHealing {
                field: "admin.self_healing.max_error_rate_per_mille",
            });
        }
        if !self.health_path.starts_with('/')
            || self.health_path.trim() != self.health_path
            || self.health_path.len() > MAX_ADMIN_HEALTH_PATH_BYTES
            || self
                .health_path
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b' ' | b'\\' | b'?' | b'#'))
            || (self.health_path.starts_with("/_fluxheim/")
                && self.health_path != DEFAULT_ADMIN_HEALTH_PATH)
        {
            return Err(ConfigError::InvalidAdminHealthPath {
                path: self.health_path.clone(),
            });
        }

        Ok(())
    }
}

fn default_admin_listen() -> String {
    "127.0.0.1:9090".to_owned()
}

fn default_admin_require_loopback() -> bool {
    true
}

fn default_admin_auth_throttle_enabled() -> bool {
    true
}

fn default_admin_auth_throttle_window_secs() -> u64 {
    60
}

fn default_admin_auth_throttle_per_source_failures() -> usize {
    10
}

fn default_admin_auth_throttle_global_failures() -> usize {
    100
}

fn default_admin_auth_throttle_base_lockout_secs() -> u64 {
    30
}

fn default_admin_auth_throttle_max_lockout_secs() -> u64 {
    900
}

fn default_admin_auth_throttle_max_sources() -> usize {
    4096
}

fn default_admin_validation_window_secs() -> u64 {
    30
}

fn default_admin_health_path() -> String {
    DEFAULT_ADMIN_HEALTH_PATH.to_owned()
}

fn default_admin_min_successful_checks() -> usize {
    1
}

fn default_admin_max_error_rate_per_mille() -> u16 {
    100
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

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;

pub const MAX_ADMIN_HEALTH_PATH_BYTES: usize = 2048;
const DEFAULT_ADMIN_HEALTH_PATH: &str = "/_fluxheim/health";

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminHealthConfig {
    #[serde(default)]
    pub unauthenticated: bool,
    #[serde(default)]
    pub response: AdminHealthResponseMode,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminHealthConfigFragment {
    unauthenticated: Option<bool>,
    response: Option<AdminHealthResponseMode>,
}

impl AdminHealthConfig {
    pub(crate) fn merge(&mut self, fragment: AdminHealthConfigFragment) {
        if let Some(unauthenticated) = fragment.unauthenticated {
            self.unauthenticated = unauthenticated;
        }
        if let Some(response) = fragment.response {
            self.response = response;
        }
    }
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

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminAuthThrottleConfigFragment {
    enabled: Option<bool>,
    window_secs: Option<u64>,
    per_source_failures: Option<usize>,
    global_failures: Option<usize>,
    base_lockout_secs: Option<u64>,
    max_lockout_secs: Option<u64>,
    max_sources: Option<usize>,
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
    pub(crate) fn merge(&mut self, fragment: AdminAuthThrottleConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(window_secs) = fragment.window_secs {
            self.window_secs = window_secs;
        }
        if let Some(failures) = fragment.per_source_failures {
            self.per_source_failures = failures;
        }
        if let Some(failures) = fragment.global_failures {
            self.global_failures = failures;
        }
        if let Some(lockout_secs) = fragment.base_lockout_secs {
            self.base_lockout_secs = lockout_secs;
        }
        if let Some(lockout_secs) = fragment.max_lockout_secs {
            self.max_lockout_secs = lockout_secs;
        }
        if let Some(max_sources) = fragment.max_sources {
            self.max_sources = max_sources;
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
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

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSelfHealingConfigFragment {
    enabled: Option<bool>,
    validation_window_secs: Option<u64>,
    health_path: Option<String>,
    min_successful_checks: Option<usize>,
    max_error_rate_per_mille: Option<u16>,
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
    pub(crate) fn merge(&mut self, fragment: AdminSelfHealingConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(validation_window_secs) = fragment.validation_window_secs {
            self.validation_window_secs = validation_window_secs;
        }
        if let Some(health_path) = fragment.health_path {
            self.health_path = health_path;
        }
        if let Some(min_successful_checks) = fragment.min_successful_checks {
            self.min_successful_checks = min_successful_checks;
        }
        if let Some(max_error_rate_per_mille) = fragment.max_error_rate_per_mille {
            self.max_error_rate_per_mille = max_error_rate_per_mille;
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
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

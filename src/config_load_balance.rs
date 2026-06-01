use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, valid_http_token, validate_optional_timeout_secs};
use crate::config_header::valid_http_header_name;
use crate::config_net::normalize_host;

pub(crate) const LB_SAFE_RETRY_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "TRACE"];

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceConfig {
    #[serde(default)]
    pub selection: LoadBalanceSelection,
    #[serde(default)]
    pub hash_header: Option<String>,
    #[serde(default)]
    pub hash_cookie: Option<String>,
    #[serde(default = "default_lb_max_iterations")]
    pub max_iterations: usize,
    #[serde(default = "default_lb_all_down_status")]
    pub all_down_status: u16,
    #[serde(default)]
    pub health_check: LoadBalanceHealthCheckConfig,
    #[serde(default)]
    pub passive_health: LoadBalancePassiveHealthConfig,
    #[serde(default)]
    pub slow_start: LoadBalanceSlowStartConfig,
    #[serde(default)]
    pub retry: LoadBalanceRetryConfig,
}

impl Default for LoadBalanceConfig {
    fn default() -> Self {
        Self {
            selection: LoadBalanceSelection::default(),
            hash_header: None,
            hash_cookie: None,
            max_iterations: default_lb_max_iterations(),
            all_down_status: default_lb_all_down_status(),
            health_check: LoadBalanceHealthCheckConfig::default(),
            passive_health: LoadBalancePassiveHealthConfig::default(),
            slow_start: LoadBalanceSlowStartConfig::default(),
            retry: LoadBalanceRetryConfig::default(),
        }
    }
}

impl LoadBalanceConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.selection.requires_hash_header() {
            let Some(header) = self.hash_header.as_deref() else {
                return Err(ConfigError::InvalidLoadBalanceSelection {
                    reason: "header-hash selections require proxy.load_balance.hash_header",
                });
            };
            if !valid_http_header_name(header) {
                return Err(ConfigError::InvalidHeaderName {
                    field: "proxy.load_balance.hash_header",
                    name: header.to_owned(),
                });
            }
        } else if self.hash_header.is_some() {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.hash_header can only be used with header-hash selections",
            });
        }
        if self.selection.requires_hash_cookie() {
            let Some(cookie) = self.hash_cookie.as_deref() else {
                return Err(ConfigError::InvalidLoadBalanceSelection {
                    reason: "cookie-hash selections require proxy.load_balance.hash_cookie",
                });
            };
            if !valid_http_header_name(cookie) {
                return Err(ConfigError::InvalidLoadBalanceSelection {
                    reason: "proxy.load_balance.hash_cookie must be a valid cookie name",
                });
            }
        } else if self.hash_cookie.is_some() {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.hash_cookie can only be used with cookie-hash selections",
            });
        }
        if self.max_iterations == 0 {
            return Err(ConfigError::InvalidLoadBalanceMaxIterations);
        }
        if !(500..=599).contains(&self.all_down_status) {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.all_down_status must be an HTTP 5xx status",
            });
        }

        self.health_check.validate()?;
        self.passive_health.validate()?;
        self.slow_start.validate()?;
        self.retry.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalanceSelection {
    #[default]
    RoundRobin,
    #[serde(
        alias = "weighted-least-connections",
        alias = "ratio-least-connections"
    )]
    LeastConnections,
    LeastTime,
    PowerOfTwo,
    SourceHash,
    UriHash,
    HeaderHash,
    CookieHash,
    ConsistentSourceHash,
    ConsistentUriHash,
    ConsistentHeaderHash,
    ConsistentCookieHash,
}

impl LoadBalanceSelection {
    fn requires_hash_header(self) -> bool {
        matches!(self, Self::HeaderHash | Self::ConsistentHeaderHash)
    }

    fn requires_hash_cookie(self) -> bool {
        matches!(self, Self::CookieHash | Self::ConsistentCookieHash)
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalanceHealthCheckProtocol {
    #[default]
    Tcp,
    Http,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceHealthCheckConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub protocol: LoadBalanceHealthCheckProtocol,
    #[serde(default = "default_lb_health_check_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_lb_health_check_threshold")]
    pub consecutive_success: usize,
    #[serde(default = "default_lb_health_check_threshold")]
    pub consecutive_failure: usize,
    #[serde(default)]
    pub parallel: bool,
    #[serde(default = "default_lb_health_check_method")]
    pub method: String,
    #[serde(default = "default_lb_health_check_path")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub expected_statuses: Vec<u16>,
    #[serde(default)]
    pub expected_status_ranges: Vec<LoadBalanceHealthCheckExpectedStatusRange>,
    #[serde(default)]
    pub expected_headers: Vec<LoadBalanceHealthCheckExpectedHeader>,
    #[serde(default)]
    pub reuse_connection: bool,
    #[serde(default)]
    pub port_override: Option<u16>,
    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,
    #[serde(default)]
    pub read_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceHealthCheckExpectedHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceHealthCheckExpectedStatusRange {
    pub start: u16,
    pub end: u16,
}

impl Default for LoadBalanceHealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            protocol: LoadBalanceHealthCheckProtocol::default(),
            interval_secs: default_lb_health_check_interval_secs(),
            consecutive_success: default_lb_health_check_threshold(),
            consecutive_failure: default_lb_health_check_threshold(),
            parallel: false,
            method: default_lb_health_check_method(),
            path: default_lb_health_check_path(),
            host: None,
            expected_statuses: Vec::new(),
            expected_status_ranges: Vec::new(),
            expected_headers: Vec::new(),
            reuse_connection: false,
            port_override: None,
            connect_timeout_secs: None,
            read_timeout_secs: None,
        }
    }
}

impl LoadBalanceHealthCheckConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.interval_secs == 0 {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.interval_secs",
            });
        }
        if self.consecutive_success == 0 {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.consecutive_success",
            });
        }
        if self.consecutive_failure == 0 {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.consecutive_failure",
            });
        }
        if !valid_health_check_path(&self.path) {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.path",
            });
        }
        if !valid_health_check_method(&self.method) {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.method",
            });
        }
        if let Some(host) = &self.host
            && !valid_health_check_host(host)
        {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.host",
            });
        }
        if self.expected_statuses.len() > 32 {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.expected_statuses",
            });
        }
        let mut seen_statuses = HashSet::new();
        for status in &self.expected_statuses {
            if !(100..=599).contains(status) || !seen_statuses.insert(*status) {
                return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                    field: "proxy.load_balance.health_check.expected_statuses",
                });
            }
        }
        if self.expected_status_ranges.len() > 32 {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.expected_status_ranges",
            });
        }
        for range in &self.expected_status_ranges {
            if !(100..=599).contains(&range.start)
                || !(100..=599).contains(&range.end)
                || range.start > range.end
            {
                return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                    field: "proxy.load_balance.health_check.expected_status_ranges",
                });
            }
        }
        if self.expected_headers.len() > 32 {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.expected_headers",
            });
        }
        let mut seen_headers = HashSet::new();
        for header in &self.expected_headers {
            if !valid_http_header_name(&header.name)
                || header.value.is_empty()
                || header.value.len() > 1024
                || header.value.chars().any(char::is_control)
            {
                return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                    field: "proxy.load_balance.health_check.expected_headers",
                });
            }
            if !seen_headers.insert(header.name.to_ascii_lowercase()) {
                return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                    field: "proxy.load_balance.health_check.expected_headers",
                });
            }
        }
        if self.port_override.is_some_and(|port| port == 0) {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.port_override",
            });
        }
        validate_optional_timeout_secs(
            "proxy.load_balance.health_check.connect_timeout_secs",
            self.connect_timeout_secs,
        )?;
        validate_optional_timeout_secs(
            "proxy.load_balance.health_check.read_timeout_secs",
            self.read_timeout_secs,
        )?;

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalancePassiveHealthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_lb_passive_consecutive_failure")]
    pub consecutive_failure: usize,
    #[serde(default = "default_lb_passive_ejection_secs")]
    pub ejection_secs: u64,
    #[serde(default)]
    pub failure_statuses: Vec<u16>,
    #[serde(default)]
    pub max_latency_ms: u64,
}

impl Default for LoadBalancePassiveHealthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            consecutive_failure: default_lb_passive_consecutive_failure(),
            ejection_secs: default_lb_passive_ejection_secs(),
            failure_statuses: Vec::new(),
            max_latency_ms: 0,
        }
    }
}

impl LoadBalancePassiveHealthConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.consecutive_failure == 0 || self.consecutive_failure > 1000 {
            return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.consecutive_failure",
            });
        }
        if self.ejection_secs == 0 || self.ejection_secs > 3600 {
            return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.ejection_secs",
            });
        }
        if self.max_latency_ms > 600_000 {
            return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.max_latency_ms",
            });
        }
        if self.failure_statuses.len() > 64
            || self
                .failure_statuses
                .iter()
                .any(|status| !(500..=599).contains(status))
        {
            return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.failure_statuses",
            });
        }
        Ok(())
    }
}

fn default_lb_passive_consecutive_failure() -> usize {
    3
}

fn default_lb_passive_ejection_secs() -> u64 {
    30
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceSlowStartConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_lb_slow_start_duration_secs")]
    pub duration_secs: u64,
}

impl Default for LoadBalanceSlowStartConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            duration_secs: default_lb_slow_start_duration_secs(),
        }
    }
}

impl LoadBalanceSlowStartConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.duration_secs == 0 || self.duration_secs > 3600 {
            return Err(ConfigError::InvalidLoadBalanceSlowStart {
                field: "proxy.load_balance.slow_start.duration_secs",
            });
        }
        Ok(())
    }
}

fn default_lb_slow_start_duration_secs() -> u64 {
    30
}

const MAX_LB_RETRIES: u8 = 10;
const MAX_LB_RETRY_METHODS: usize = 16;
const MAX_LB_RETRY_STATUSES: usize = 32;
const MAX_LB_RETRY_BUDGET_PER_WINDOW: u32 = 1_000_000;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceRetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_lb_retry_max_retries")]
    pub max_retries: u8,
    #[serde(default = "default_lb_retry_methods")]
    pub methods: Vec<String>,
    #[serde(default)]
    pub statuses: Vec<u16>,
    #[serde(default)]
    pub budget_per_window: u32,
    #[serde(default = "default_lb_retry_budget_window_secs")]
    pub budget_window_secs: u64,
}

impl Default for LoadBalanceRetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_retries: default_lb_retry_max_retries(),
            methods: default_lb_retry_methods(),
            statuses: Vec::new(),
            budget_per_window: 0,
            budget_window_secs: default_lb_retry_budget_window_secs(),
        }
    }
}

impl LoadBalanceRetryConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_retries > MAX_LB_RETRIES {
            return Err(ConfigError::InvalidLoadBalanceRetry {
                field: "proxy.load_balance.retry.max_retries",
            });
        }
        if self.methods.len() > MAX_LB_RETRY_METHODS {
            return Err(ConfigError::InvalidLoadBalanceRetry {
                field: "proxy.load_balance.retry.methods",
            });
        }
        if self.statuses.len() > MAX_LB_RETRY_STATUSES {
            return Err(ConfigError::InvalidLoadBalanceRetry {
                field: "proxy.load_balance.retry.statuses",
            });
        }
        if self.budget_per_window > MAX_LB_RETRY_BUDGET_PER_WINDOW {
            return Err(ConfigError::InvalidLoadBalanceRetry {
                field: "proxy.load_balance.retry.budget_per_window",
            });
        }
        if self.budget_window_secs == 0 || self.budget_window_secs > 3600 {
            return Err(ConfigError::InvalidLoadBalanceRetry {
                field: "proxy.load_balance.retry.budget_window_secs",
            });
        }
        let mut seen = HashSet::new();
        for method in &self.methods {
            if method.is_empty()
                || method.len() > 32
                || !method
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(ConfigError::InvalidLoadBalanceRetry {
                    field: "proxy.load_balance.retry.methods",
                });
            }
            if !seen.insert(method.clone())
                || !LB_SAFE_RETRY_METHODS
                    .iter()
                    .any(|safe_method| safe_method == method)
            {
                return Err(ConfigError::InvalidLoadBalanceRetry {
                    field: "proxy.load_balance.retry.methods",
                });
            }
        }
        let mut seen_statuses = HashSet::new();
        for status in &self.statuses {
            if !(500..=599).contains(status) || !seen_statuses.insert(*status) {
                return Err(ConfigError::InvalidLoadBalanceRetry {
                    field: "proxy.load_balance.retry.statuses",
                });
            }
        }
        Ok(())
    }
}

fn default_lb_retry_max_retries() -> u8 {
    1
}

fn default_lb_retry_methods() -> Vec<String> {
    vec!["GET".to_owned(), "HEAD".to_owned(), "OPTIONS".to_owned()]
}

fn default_lb_retry_budget_window_secs() -> u64 {
    1
}

fn default_true() -> bool {
    true
}

fn default_lb_max_iterations() -> usize {
    256
}

fn default_lb_all_down_status() -> u16 {
    502
}

fn default_lb_health_check_interval_secs() -> u64 {
    1
}

fn default_lb_health_check_threshold() -> usize {
    1
}

fn default_lb_health_check_method() -> String {
    "GET".to_owned()
}

fn default_lb_health_check_path() -> String {
    "/".to_owned()
}

fn valid_health_check_method(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= 32
        && valid_http_token(method)
        && !method.chars().any(char::is_lowercase)
}

fn valid_health_check_path(path: &str) -> bool {
    path.len() <= 2048
        && path.starts_with('/')
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#')
}

fn valid_health_check_host(host: &str) -> bool {
    host.len() <= 255 && normalize_host(host).is_some()
}

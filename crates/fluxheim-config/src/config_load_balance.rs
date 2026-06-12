use std::collections::HashSet;
use std::fmt;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, valid_http_token, validate_optional_timeout_secs};
use crate::config_header::valid_http_header_name;
use crate::config_net::normalize_host;
use crate::config_path::{validate_non_world_writable_parent, validate_path};

pub const LB_SAFE_RETRY_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "TRACE"];
const LB_HEALTH_CHECK_MAX_EXPECTED_BODY_SUBSTRINGS: usize = 8;
const LB_HEALTH_CHECK_MAX_EXPECTED_BODY_SUBSTRING_BYTES: usize = 1024;
const LB_HEALTH_CHECK_MAX_EXPECTED_BODY_JSON_MATCHERS: usize = 8;
const LB_HEALTH_CHECK_MAX_EXPECTED_BODY_JSON_PATH_BYTES: usize = 256;
const LB_HEALTH_CHECK_MAX_REQUEST_HEADERS: usize = 16;
const LB_HEALTH_CHECK_MAX_REQUEST_HEADER_VALUE_BYTES: usize = 1024;
const LB_HEALTH_CHECK_MAX_EXEC_ARGS: usize = 16;
const LB_HEALTH_CHECK_MAX_EXEC_ARG_BYTES: usize = 256;
const LB_HEALTH_CHECK_MAX_EXEC_ALLOWED_COMMANDS: usize = 16;
const LB_HEALTH_CHECK_MAX_EXEC_COMMAND_BYTES: usize = 512;
const MIN_BOUNDED_LOAD_FACTOR_PER_MILLE: u16 = 1000;
const MAX_BOUNDED_LOAD_FACTOR_PER_MILLE: u16 = 10000;
const DEFAULT_LB_HEALTH_WEIGHT_MIN_PERCENT: u8 = 25;

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
    #[serde(default = "default_bounded_load_factor_per_mille")]
    pub bounded_load_factor_per_mille: u16,
    #[serde(default)]
    pub health_check: LoadBalanceHealthCheckConfig,
    #[serde(default)]
    pub passive_health: LoadBalancePassiveHealthConfig,
    #[serde(default)]
    pub slow_start: LoadBalanceSlowStartConfig,
    #[serde(default)]
    pub retry: LoadBalanceRetryConfig,
    #[serde(default)]
    pub persistence: LoadBalancePersistenceConfig,
    #[serde(default)]
    pub runtime_state_file: Option<PathBuf>,
    #[serde(default)]
    pub queue: LoadBalanceQueueConfig,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceConfigFragment {
    selection: Option<LoadBalanceSelection>,
    hash_header: Option<String>,
    hash_cookie: Option<String>,
    max_iterations: Option<usize>,
    all_down_status: Option<u16>,
    bounded_load_factor_per_mille: Option<u16>,
    health_check: Option<LoadBalanceHealthCheckConfigFragment>,
    passive_health: Option<LoadBalancePassiveHealthConfigFragment>,
    slow_start: Option<LoadBalanceSlowStartConfigFragment>,
    retry: Option<LoadBalanceRetryConfigFragment>,
    persistence: Option<LoadBalancePersistenceConfigFragment>,
    runtime_state_file: Option<PathBuf>,
    queue: Option<LoadBalanceQueueConfigFragment>,
}

impl LoadBalanceConfigFragment {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.runtime_state_file
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }
}

impl Default for LoadBalanceConfig {
    fn default() -> Self {
        Self {
            selection: LoadBalanceSelection::default(),
            hash_header: None,
            hash_cookie: None,
            max_iterations: default_lb_max_iterations(),
            all_down_status: default_lb_all_down_status(),
            bounded_load_factor_per_mille: default_bounded_load_factor_per_mille(),
            health_check: LoadBalanceHealthCheckConfig::default(),
            passive_health: LoadBalancePassiveHealthConfig::default(),
            slow_start: LoadBalanceSlowStartConfig::default(),
            retry: LoadBalanceRetryConfig::default(),
            persistence: LoadBalancePersistenceConfig::default(),
            runtime_state_file: None,
            queue: LoadBalanceQueueConfig::default(),
        }
    }
}

impl LoadBalanceConfig {
    pub fn merge(&mut self, fragment: LoadBalanceConfigFragment) {
        if let Some(selection) = fragment.selection {
            self.selection = selection;
        }
        if let Some(header) = fragment.hash_header {
            self.hash_header = Some(header);
        }
        if let Some(cookie) = fragment.hash_cookie {
            self.hash_cookie = Some(cookie);
        }
        if let Some(max_iterations) = fragment.max_iterations {
            self.max_iterations = max_iterations;
        }
        if let Some(status) = fragment.all_down_status {
            self.all_down_status = status;
        }
        if let Some(factor) = fragment.bounded_load_factor_per_mille {
            self.bounded_load_factor_per_mille = factor;
        }
        if let Some(health_check) = fragment.health_check {
            self.health_check.merge(health_check);
        }
        if let Some(passive_health) = fragment.passive_health {
            self.passive_health.merge(passive_health);
        }
        if let Some(slow_start) = fragment.slow_start {
            self.slow_start.merge(slow_start);
        }
        if let Some(retry) = fragment.retry {
            self.retry.merge(retry);
        }
        if let Some(persistence) = fragment.persistence {
            self.persistence.merge(persistence);
        }
        if let Some(path) = fragment.runtime_state_file {
            self.runtime_state_file = Some(path);
        }
        if let Some(queue) = fragment.queue {
            self.queue.merge(queue);
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
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
        if self.selection == LoadBalanceSelection::LeastSessions && !self.persistence.enabled {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "least-sessions selection requires proxy.load_balance.persistence.enabled = true",
            });
        }
        if !(500..=599).contains(&self.all_down_status) {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.all_down_status must be an HTTP 5xx status",
            });
        }
        if !(MIN_BOUNDED_LOAD_FACTOR_PER_MILLE..=MAX_BOUNDED_LOAD_FACTOR_PER_MILLE)
            .contains(&self.bounded_load_factor_per_mille)
        {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.bounded_load_factor_per_mille must be between 1000 and 10000",
            });
        }
        if self.bounded_load_factor_per_mille != default_bounded_load_factor_per_mille()
            && !self.selection.uses_bounded_load()
        {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.bounded_load_factor_per_mille can only be used with bounded-load consistent-hash selections",
            });
        }

        self.health_check.validate()?;
        self.passive_health.validate()?;
        self.slow_start.validate()?;
        self.retry.validate()?;
        self.persistence.validate()?;
        if let Some(path) = &self.runtime_state_file {
            validate_path("proxy.load_balance.runtime_state_file", Some(path))?;
            validate_non_world_writable_parent(
                "proxy.load_balance.runtime_state_file",
                Some(path),
            )?;
            if self.persistence.enabled
                && matches!(
                    self.persistence.mode,
                    LoadBalancePersistenceMode::Header | LoadBalancePersistenceMode::Cookie
                )
            {
                let persistence_mode = match self.persistence.mode {
                    LoadBalancePersistenceMode::Header => "header",
                    LoadBalancePersistenceMode::Cookie => "cookie",
                    LoadBalancePersistenceMode::SourceIp => "source-ip",
                    LoadBalancePersistenceMode::ManagedCookie => "managed-cookie",
                };
                log::warn!(
                    target: "fluxheim::security",
                    "proxy.load_balance.runtime_state_file is configured with raw {} persistence; client affinity identifiers are written to disk at {}. Use managed-cookie mode or an encrypted, access-restricted volume for session-bearing identifiers.",
                    persistence_mode,
                    path.display()
                );
            }
        }
        self.queue.validate()?;
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
    #[serde(alias = "least-session")]
    LeastSessions,
    LeastTime,
    #[serde(
        alias = "power-of-two-choices",
        alias = "two-choice",
        alias = "weighted-two-choice",
        alias = "weighted-random-two-choice"
    )]
    PowerOfTwo,
    SourceHash,
    UriHash,
    HeaderHash,
    CookieHash,
    ConsistentSourceHash,
    ConsistentUriHash,
    ConsistentHeaderHash,
    ConsistentCookieHash,
    BoundedLoadConsistentSourceHash,
    BoundedLoadConsistentUriHash,
    BoundedLoadConsistentHeaderHash,
    BoundedLoadConsistentCookieHash,
    #[serde(alias = "maglev", alias = "maglev-hash")]
    MaglevSourceHash,
    MaglevUriHash,
    MaglevHeaderHash,
    MaglevCookieHash,
}

impl LoadBalanceSelection {
    pub fn requires_hash_header(self) -> bool {
        matches!(
            self,
            Self::HeaderHash
                | Self::ConsistentHeaderHash
                | Self::BoundedLoadConsistentHeaderHash
                | Self::MaglevHeaderHash
        )
    }

    pub fn requires_hash_cookie(self) -> bool {
        matches!(
            self,
            Self::CookieHash
                | Self::ConsistentCookieHash
                | Self::BoundedLoadConsistentCookieHash
                | Self::MaglevCookieHash
        )
    }

    pub fn uses_bounded_load(self) -> bool {
        matches!(
            self,
            Self::BoundedLoadConsistentSourceHash
                | Self::BoundedLoadConsistentUriHash
                | Self::BoundedLoadConsistentHeaderHash
                | Self::BoundedLoadConsistentCookieHash
        )
    }

    pub fn uses_maglev(self) -> bool {
        matches!(
            self,
            Self::MaglevSourceHash
                | Self::MaglevUriHash
                | Self::MaglevHeaderHash
                | Self::MaglevCookieHash
        )
    }

    #[cfg(feature = "load-balancer")]
    pub fn supports_runtime_weight_override(self) -> bool {
        matches!(
            self,
            Self::RoundRobin | Self::LeastConnections | Self::LeastSessions | Self::LeastTime
        )
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalanceHealthCheckProtocol {
    #[default]
    Tcp,
    Http,
    Grpc,
    Exec,
    Redis,
    Mysql,
    Postgres,
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
    pub request_headers: Vec<LoadBalanceHealthCheckRequestHeader>,
    #[serde(default)]
    pub grpc_service: Option<String>,
    #[serde(default)]
    pub expected_statuses: Vec<u16>,
    #[serde(default)]
    pub expected_status_ranges: Vec<LoadBalanceHealthCheckExpectedStatusRange>,
    #[serde(default)]
    pub expected_headers: Vec<LoadBalanceHealthCheckExpectedHeader>,
    #[serde(default)]
    pub expected_body_contains: Vec<String>,
    #[serde(default)]
    pub expected_body_json: Vec<LoadBalanceHealthCheckExpectedJson>,
    #[serde(default = "default_lb_health_weight_min_percent")]
    pub health_weight_min_percent: u8,
    #[serde(default)]
    pub reuse_connection: bool,
    #[serde(default)]
    pub port_override: Option<u16>,
    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,
    #[serde(default)]
    pub read_timeout_secs: Option<u64>,
    #[serde(default)]
    pub exec_command: Option<String>,
    #[serde(default)]
    pub exec_args: Vec<String>,
    #[serde(default)]
    pub exec_allowed_commands: Vec<String>,
    #[serde(default)]
    pub exec_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceHealthCheckConfigFragment {
    enabled: Option<bool>,
    protocol: Option<LoadBalanceHealthCheckProtocol>,
    interval_secs: Option<u64>,
    consecutive_success: Option<usize>,
    consecutive_failure: Option<usize>,
    parallel: Option<bool>,
    method: Option<String>,
    path: Option<String>,
    host: Option<String>,
    request_headers: Option<Vec<LoadBalanceHealthCheckRequestHeader>>,
    grpc_service: Option<String>,
    expected_statuses: Option<Vec<u16>>,
    expected_status_ranges: Option<Vec<LoadBalanceHealthCheckExpectedStatusRange>>,
    expected_headers: Option<Vec<LoadBalanceHealthCheckExpectedHeader>>,
    expected_body_contains: Option<Vec<String>>,
    expected_body_json: Option<Vec<LoadBalanceHealthCheckExpectedJson>>,
    health_weight_min_percent: Option<u8>,
    reuse_connection: Option<bool>,
    port_override: Option<u16>,
    connect_timeout_secs: Option<u64>,
    read_timeout_secs: Option<u64>,
    exec_command: Option<String>,
    exec_args: Option<Vec<String>>,
    exec_allowed_commands: Option<Vec<String>>,
    exec_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceHealthCheckExpectedHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceHealthCheckRequestHeader {
    pub name: String,
    #[serde(skip_serializing)]
    pub value: String,
}

impl fmt::Debug for LoadBalanceHealthCheckRequestHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadBalanceHealthCheckRequestHeader")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceHealthCheckExpectedJson {
    pub path: String,
    pub equals: String,
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
            request_headers: Vec::new(),
            grpc_service: None,
            expected_statuses: Vec::new(),
            expected_status_ranges: Vec::new(),
            expected_headers: Vec::new(),
            expected_body_contains: Vec::new(),
            expected_body_json: Vec::new(),
            health_weight_min_percent: default_lb_health_weight_min_percent(),
            reuse_connection: false,
            port_override: None,
            connect_timeout_secs: None,
            read_timeout_secs: None,
            exec_command: None,
            exec_args: Vec::new(),
            exec_allowed_commands: Vec::new(),
            exec_timeout_secs: None,
        }
    }
}

impl LoadBalanceHealthCheckConfig {
    fn merge(&mut self, fragment: LoadBalanceHealthCheckConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(protocol) = fragment.protocol {
            self.protocol = protocol;
        }
        if let Some(interval_secs) = fragment.interval_secs {
            self.interval_secs = interval_secs;
        }
        if let Some(consecutive_success) = fragment.consecutive_success {
            self.consecutive_success = consecutive_success;
        }
        if let Some(consecutive_failure) = fragment.consecutive_failure {
            self.consecutive_failure = consecutive_failure;
        }
        if let Some(parallel) = fragment.parallel {
            self.parallel = parallel;
        }
        if let Some(method) = fragment.method {
            self.method = method;
        }
        if let Some(path) = fragment.path {
            self.path = path;
        }
        if let Some(host) = fragment.host {
            self.host = Some(host);
        }
        if let Some(headers) = fragment.request_headers {
            self.request_headers = headers;
        }
        if let Some(service) = fragment.grpc_service {
            self.grpc_service = Some(service);
        }
        if let Some(statuses) = fragment.expected_statuses {
            self.expected_statuses = statuses;
        }
        if let Some(ranges) = fragment.expected_status_ranges {
            self.expected_status_ranges = ranges;
        }
        if let Some(headers) = fragment.expected_headers {
            self.expected_headers = headers;
        }
        if let Some(body) = fragment.expected_body_contains {
            self.expected_body_contains = body;
        }
        if let Some(json) = fragment.expected_body_json {
            self.expected_body_json = json;
        }
        if let Some(percent) = fragment.health_weight_min_percent {
            self.health_weight_min_percent = percent;
        }
        if let Some(reuse) = fragment.reuse_connection {
            self.reuse_connection = reuse;
        }
        if let Some(port) = fragment.port_override {
            self.port_override = Some(port);
        }
        if let Some(timeout) = fragment.connect_timeout_secs {
            self.connect_timeout_secs = Some(timeout);
        }
        if let Some(timeout) = fragment.read_timeout_secs {
            self.read_timeout_secs = Some(timeout);
        }
        if let Some(command) = fragment.exec_command {
            self.exec_command = Some(command);
        }
        if let Some(args) = fragment.exec_args {
            self.exec_args = args;
        }
        if let Some(commands) = fragment.exec_allowed_commands {
            self.exec_allowed_commands = commands;
        }
        if let Some(timeout) = fragment.exec_timeout_secs {
            self.exec_timeout_secs = Some(timeout);
        }
    }

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
        self.validate_exec()?;
        self.validate_protocol_probe()?;
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
        if !self.request_headers.is_empty() && self.protocol == LoadBalanceHealthCheckProtocol::Tcp
        {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.request_headers",
            });
        }
        if self.request_headers.len() > LB_HEALTH_CHECK_MAX_REQUEST_HEADERS {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.request_headers",
            });
        }
        let mut seen_request_headers = HashSet::new();
        for header in &self.request_headers {
            if !valid_health_check_request_header(&header.name, &header.value) {
                return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                    field: "proxy.load_balance.health_check.request_headers",
                });
            }
            if !seen_request_headers.insert(header.name.to_ascii_lowercase()) {
                return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                    field: "proxy.load_balance.health_check.request_headers",
                });
            }
        }
        if let Some(service) = &self.grpc_service
            && (self.protocol != LoadBalanceHealthCheckProtocol::Grpc
                || !valid_health_check_grpc_service(service))
        {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.grpc_service",
            });
        }
        if self.protocol == LoadBalanceHealthCheckProtocol::Grpc
            && (!self.expected_statuses.is_empty()
                || !self.expected_status_ranges.is_empty()
                || !self.expected_headers.is_empty()
                || !self.expected_body_contains.is_empty()
                || !self.expected_body_json.is_empty())
        {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.protocol",
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
        if self.expected_body_contains.len() > LB_HEALTH_CHECK_MAX_EXPECTED_BODY_SUBSTRINGS {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.expected_body_contains",
            });
        }
        let mut seen_body_substrings = HashSet::new();
        for expected in &self.expected_body_contains {
            if expected.is_empty()
                || expected.len() > LB_HEALTH_CHECK_MAX_EXPECTED_BODY_SUBSTRING_BYTES
                || expected.chars().any(char::is_control)
                || !seen_body_substrings.insert(expected)
            {
                return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                    field: "proxy.load_balance.health_check.expected_body_contains",
                });
            }
        }
        if self.expected_body_json.len() > LB_HEALTH_CHECK_MAX_EXPECTED_BODY_JSON_MATCHERS {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.expected_body_json",
            });
        }
        let mut seen_json_paths = HashSet::new();
        for expected in &self.expected_body_json {
            if !valid_health_check_json_path(&expected.path)
                || expected.equals.is_empty()
                || expected.equals.len() > LB_HEALTH_CHECK_MAX_EXPECTED_BODY_SUBSTRING_BYTES
                || expected.equals.chars().any(char::is_control)
                || !seen_json_paths.insert(expected.path.as_str())
            {
                return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                    field: "proxy.load_balance.health_check.expected_body_json",
                });
            }
        }
        if !(1..=100).contains(&self.health_weight_min_percent) {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.health_weight_min_percent",
            });
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
        validate_optional_timeout_secs(
            "proxy.load_balance.health_check.exec_timeout_secs",
            self.exec_timeout_secs,
        )?;

        Ok(())
    }

    fn validate_exec(&self) -> Result<(), ConfigError> {
        if self.protocol != LoadBalanceHealthCheckProtocol::Exec {
            if self.exec_command.is_some()
                || !self.exec_args.is_empty()
                || !self.exec_allowed_commands.is_empty()
                || self.exec_timeout_secs.is_some()
            {
                return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                    field: "proxy.load_balance.health_check.protocol",
                });
            }
            return Ok(());
        }

        let Some(command) = self.exec_command.as_deref() else {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.exec_command",
            });
        };
        if !valid_health_check_exec_command(command) {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.exec_command",
            });
        }
        if self.exec_allowed_commands.is_empty()
            || self.exec_allowed_commands.len() > LB_HEALTH_CHECK_MAX_EXEC_ALLOWED_COMMANDS
        {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.exec_allowed_commands",
            });
        }
        let mut seen = HashSet::new();
        let mut allowed = false;
        for allowed_command in &self.exec_allowed_commands {
            if !valid_health_check_exec_command(allowed_command)
                || !seen.insert(allowed_command.as_str())
            {
                return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                    field: "proxy.load_balance.health_check.exec_allowed_commands",
                });
            }
            if allowed_command == command {
                allowed = true;
            }
        }
        if !allowed {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.exec_allowed_commands",
            });
        }
        if self.exec_args.len() > LB_HEALTH_CHECK_MAX_EXEC_ARGS {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.exec_args",
            });
        }
        for arg in &self.exec_args {
            if !valid_health_check_exec_arg(arg) {
                return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                    field: "proxy.load_balance.health_check.exec_args",
                });
            }
        }
        if self.parallel {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.parallel",
            });
        }
        if self.host.is_some() {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.host",
            });
        }
        if self.connect_timeout_secs.is_some() {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.connect_timeout_secs",
            });
        }
        if self.read_timeout_secs.is_some() {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.read_timeout_secs",
            });
        }
        if !self.request_headers.is_empty()
            || self.grpc_service.is_some()
            || !self.expected_statuses.is_empty()
            || !self.expected_status_ranges.is_empty()
            || !self.expected_headers.is_empty()
            || !self.expected_body_contains.is_empty()
            || !self.expected_body_json.is_empty()
            || self.reuse_connection
            || self.port_override.is_some()
        {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.protocol",
            });
        }
        Ok(())
    }

    fn validate_protocol_probe(&self) -> Result<(), ConfigError> {
        if !matches!(
            self.protocol,
            LoadBalanceHealthCheckProtocol::Redis
                | LoadBalanceHealthCheckProtocol::Mysql
                | LoadBalanceHealthCheckProtocol::Postgres
        ) {
            return Ok(());
        }
        if self.parallel {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.parallel",
            });
        }
        if self.host.is_some() {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.host",
            });
        }
        if !self.request_headers.is_empty()
            || self.grpc_service.is_some()
            || !self.expected_statuses.is_empty()
            || !self.expected_status_ranges.is_empty()
            || !self.expected_headers.is_empty()
            || !self.expected_body_contains.is_empty()
            || !self.expected_body_json.is_empty()
            || self.reuse_connection
            || self.port_override.is_some()
        {
            return Err(ConfigError::InvalidLoadBalanceHealthCheck {
                field: "proxy.load_balance.health_check.protocol",
            });
        }
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
    #[serde(default = "default_lb_passive_min_healthy_backends")]
    pub min_healthy_backends: usize,
    #[serde(default)]
    pub failure_statuses: Vec<u16>,
    #[serde(default)]
    pub failure_status_ranges: Vec<LoadBalanceHealthCheckExpectedStatusRange>,
    #[serde(default)]
    pub max_latency_ms: u64,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalancePassiveHealthConfigFragment {
    enabled: Option<bool>,
    consecutive_failure: Option<usize>,
    ejection_secs: Option<u64>,
    min_healthy_backends: Option<usize>,
    failure_statuses: Option<Vec<u16>>,
    failure_status_ranges: Option<Vec<LoadBalanceHealthCheckExpectedStatusRange>>,
    max_latency_ms: Option<u64>,
}

impl Default for LoadBalancePassiveHealthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            consecutive_failure: default_lb_passive_consecutive_failure(),
            ejection_secs: default_lb_passive_ejection_secs(),
            min_healthy_backends: default_lb_passive_min_healthy_backends(),
            failure_statuses: Vec::new(),
            failure_status_ranges: Vec::new(),
            max_latency_ms: 0,
        }
    }
}

impl LoadBalancePassiveHealthConfig {
    fn merge(&mut self, fragment: LoadBalancePassiveHealthConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(consecutive_failure) = fragment.consecutive_failure {
            self.consecutive_failure = consecutive_failure;
        }
        if let Some(ejection_secs) = fragment.ejection_secs {
            self.ejection_secs = ejection_secs;
        }
        if let Some(min_healthy_backends) = fragment.min_healthy_backends {
            self.min_healthy_backends = min_healthy_backends;
        }
        if let Some(statuses) = fragment.failure_statuses {
            self.failure_statuses = statuses;
        }
        if let Some(ranges) = fragment.failure_status_ranges {
            self.failure_status_ranges = ranges;
        }
        if let Some(max_latency_ms) = fragment.max_latency_ms {
            self.max_latency_ms = max_latency_ms;
        }
    }

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
        if self.min_healthy_backends > 4096 {
            return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.min_healthy_backends",
            });
        }
        if self.max_latency_ms > 600_000 {
            return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.max_latency_ms",
            });
        }
        if self.failure_statuses.len() > 64 {
            return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.failure_statuses",
            });
        }
        let mut seen_statuses = HashSet::new();
        for status in &self.failure_statuses {
            if !(500..=599).contains(status) || !seen_statuses.insert(*status) {
                return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                    field: "proxy.load_balance.passive_health.failure_statuses",
                });
            }
        }
        if self.failure_status_ranges.len() > 64 {
            return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                field: "proxy.load_balance.passive_health.failure_status_ranges",
            });
        }
        for range in &self.failure_status_ranges {
            if !(500..=599).contains(&range.start)
                || !(500..=599).contains(&range.end)
                || range.start > range.end
            {
                return Err(ConfigError::InvalidLoadBalancePassiveHealth {
                    field: "proxy.load_balance.passive_health.failure_status_ranges",
                });
            }
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

fn default_lb_passive_min_healthy_backends() -> usize {
    1
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceSlowStartConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_lb_slow_start_duration_secs")]
    pub duration_secs: u64,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceSlowStartConfigFragment {
    enabled: Option<bool>,
    duration_secs: Option<u64>,
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
    fn merge(&mut self, fragment: LoadBalanceSlowStartConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(duration_secs) = fragment.duration_secs {
            self.duration_secs = duration_secs;
        }
    }

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
const MAX_LB_RETRY_STATUS_RANGES: usize = 32;
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
    pub status_ranges: Vec<LoadBalanceHealthCheckExpectedStatusRange>,
    #[serde(default)]
    pub budget_per_window: u32,
    #[serde(default = "default_lb_retry_budget_window_secs")]
    pub budget_window_secs: u64,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceRetryConfigFragment {
    enabled: Option<bool>,
    max_retries: Option<u8>,
    methods: Option<Vec<String>>,
    statuses: Option<Vec<u16>>,
    status_ranges: Option<Vec<LoadBalanceHealthCheckExpectedStatusRange>>,
    budget_per_window: Option<u32>,
    budget_window_secs: Option<u64>,
}

impl Default for LoadBalanceRetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_retries: default_lb_retry_max_retries(),
            methods: default_lb_retry_methods(),
            statuses: Vec::new(),
            status_ranges: Vec::new(),
            budget_per_window: 0,
            budget_window_secs: default_lb_retry_budget_window_secs(),
        }
    }
}

impl LoadBalanceRetryConfig {
    fn merge(&mut self, fragment: LoadBalanceRetryConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(max_retries) = fragment.max_retries {
            self.max_retries = max_retries;
        }
        if let Some(methods) = fragment.methods {
            self.methods = methods;
        }
        if let Some(statuses) = fragment.statuses {
            self.statuses = statuses;
        }
        if let Some(ranges) = fragment.status_ranges {
            self.status_ranges = ranges;
        }
        if let Some(budget) = fragment.budget_per_window {
            self.budget_per_window = budget;
        }
        if let Some(window) = fragment.budget_window_secs {
            self.budget_window_secs = window;
        }
    }

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
        if self.status_ranges.len() > MAX_LB_RETRY_STATUS_RANGES {
            return Err(ConfigError::InvalidLoadBalanceRetry {
                field: "proxy.load_balance.retry.status_ranges",
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
        for range in &self.status_ranges {
            if !(500..=599).contains(&range.start)
                || !(500..=599).contains(&range.end)
                || range.start > range.end
            {
                return Err(ConfigError::InvalidLoadBalanceRetry {
                    field: "proxy.load_balance.retry.status_ranges",
                });
            }
        }
        Ok(())
    }
}

const MAX_LB_PERSISTENCE_TTL_SECS: u64 = 86_400;
const MAX_LB_PERSISTENCE_TABLE_ENTRIES: usize = 1_000_000;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalancePersistenceMode {
    #[default]
    SourceIp,
    Header,
    Cookie,
    ManagedCookie,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalanceManagedCookieSameSite {
    Strict,
    #[default]
    Lax,
    None,
}

#[cfg(feature = "load-balancer")]
impl LoadBalanceManagedCookieSameSite {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalancePersistenceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: LoadBalancePersistenceMode,
    #[serde(default)]
    pub header: Option<String>,
    #[serde(default)]
    pub cookie: Option<String>,
    #[serde(default = "default_lb_persistence_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default = "default_lb_persistence_table_max_entries")]
    pub table_max_entries: usize,
    #[serde(default)]
    pub managed_cookie_domain: Option<String>,
    #[serde(default)]
    pub managed_cookie_path: Option<String>,
    #[serde(default = "default_lb_managed_cookie_secure")]
    pub managed_cookie_secure: bool,
    #[serde(default = "default_lb_managed_cookie_http_only")]
    pub managed_cookie_http_only: bool,
    #[serde(default)]
    pub managed_cookie_same_site: LoadBalanceManagedCookieSameSite,
    #[serde(default)]
    pub managed_cookie_max_age_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalancePersistenceConfigFragment {
    enabled: Option<bool>,
    mode: Option<LoadBalancePersistenceMode>,
    header: Option<String>,
    cookie: Option<String>,
    ttl_secs: Option<u64>,
    table_max_entries: Option<usize>,
    managed_cookie_domain: Option<String>,
    managed_cookie_path: Option<String>,
    managed_cookie_secure: Option<bool>,
    managed_cookie_http_only: Option<bool>,
    managed_cookie_same_site: Option<LoadBalanceManagedCookieSameSite>,
    managed_cookie_max_age_secs: Option<u64>,
}

impl Default for LoadBalancePersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: LoadBalancePersistenceMode::default(),
            header: None,
            cookie: None,
            ttl_secs: default_lb_persistence_ttl_secs(),
            table_max_entries: default_lb_persistence_table_max_entries(),
            managed_cookie_domain: None,
            managed_cookie_path: None,
            managed_cookie_secure: default_lb_managed_cookie_secure(),
            managed_cookie_http_only: default_lb_managed_cookie_http_only(),
            managed_cookie_same_site: LoadBalanceManagedCookieSameSite::default(),
            managed_cookie_max_age_secs: None,
        }
    }
}

impl LoadBalancePersistenceConfig {
    fn merge(&mut self, fragment: LoadBalancePersistenceConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(mode) = fragment.mode {
            self.mode = mode;
        }
        if let Some(header) = fragment.header {
            self.header = Some(header);
        }
        if let Some(cookie) = fragment.cookie {
            self.cookie = Some(cookie);
        }
        if let Some(ttl_secs) = fragment.ttl_secs {
            self.ttl_secs = ttl_secs;
        }
        if let Some(entries) = fragment.table_max_entries {
            self.table_max_entries = entries;
        }
        if let Some(domain) = fragment.managed_cookie_domain {
            self.managed_cookie_domain = Some(domain);
        }
        if let Some(path) = fragment.managed_cookie_path {
            self.managed_cookie_path = Some(path);
        }
        if let Some(secure) = fragment.managed_cookie_secure {
            self.managed_cookie_secure = secure;
        }
        if let Some(http_only) = fragment.managed_cookie_http_only {
            self.managed_cookie_http_only = http_only;
        }
        if let Some(same_site) = fragment.managed_cookie_same_site {
            self.managed_cookie_same_site = same_site;
        }
        if let Some(max_age) = fragment.managed_cookie_max_age_secs {
            self.managed_cookie_max_age_secs = Some(max_age);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        #[cfg(feature = "privacy-mode")]
        if self.enabled {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.persistence is not available in privacy-mode builds",
            });
        }

        if self.ttl_secs == 0 || self.ttl_secs > MAX_LB_PERSISTENCE_TTL_SECS {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.persistence.ttl_secs must be between 1 and 86400",
            });
        }
        if self.table_max_entries == 0 || self.table_max_entries > MAX_LB_PERSISTENCE_TABLE_ENTRIES
        {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.persistence.table_max_entries must be between 1 and 1000000",
            });
        }
        if self.mode != LoadBalancePersistenceMode::Header && self.header.is_some() {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.persistence.header can only be used with mode = \"header\"",
            });
        }
        if !matches!(
            self.mode,
            LoadBalancePersistenceMode::Cookie | LoadBalancePersistenceMode::ManagedCookie
        ) && self.cookie.is_some()
        {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.persistence.cookie can only be used with mode = \"cookie\" or \"managed-cookie\"",
            });
        }
        match self.mode {
            LoadBalancePersistenceMode::SourceIp => {}
            LoadBalancePersistenceMode::Header => {
                let Some(header) = self.header.as_deref() else {
                    return Err(ConfigError::InvalidLoadBalanceSelection {
                        reason: "proxy.load_balance.persistence.header is required when mode = \"header\"",
                    });
                };
                if !valid_http_header_name(header) {
                    return Err(ConfigError::InvalidHeaderName {
                        field: "proxy.load_balance.persistence.header",
                        name: header.to_owned(),
                    });
                }
            }
            LoadBalancePersistenceMode::Cookie | LoadBalancePersistenceMode::ManagedCookie => {
                let Some(cookie) = self.cookie.as_deref() else {
                    return Err(ConfigError::InvalidLoadBalanceSelection {
                        reason: "proxy.load_balance.persistence.cookie is required when mode = \"cookie\" or \"managed-cookie\"",
                    });
                };
                if !valid_http_header_name(cookie) {
                    return Err(ConfigError::InvalidLoadBalanceSelection {
                        reason: "proxy.load_balance.persistence.cookie must be a valid cookie name",
                    });
                }
            }
        }
        if self.mode != LoadBalancePersistenceMode::ManagedCookie {
            if self.managed_cookie_domain.is_some()
                || self.managed_cookie_path.is_some()
                || self.managed_cookie_max_age_secs.is_some()
                || !self.managed_cookie_secure
                || !self.managed_cookie_http_only
                || self.managed_cookie_same_site != LoadBalanceManagedCookieSameSite::default()
            {
                return Err(ConfigError::InvalidLoadBalanceSelection {
                    reason: "proxy.load_balance.persistence managed_cookie_* fields can only be used with mode = \"managed-cookie\"",
                });
            }
        } else {
            validate_managed_cookie_attributes(self)?;
        }
        Ok(())
    }
}

const MAX_LB_QUEUE_MAX_WAITING: usize = 100_000;
const MAX_LB_QUEUE_TIMEOUT_MS: u64 = 60_000;
const MAX_LB_QUEUE_RETRY_INTERVAL_MS: u64 = 1_000;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceQueueConfig {
    #[serde(default)]
    pub max_waiting: usize,
    #[serde(default)]
    pub timeout_ms: u64,
    #[serde(default = "default_lb_queue_retry_interval_ms")]
    pub retry_interval_ms: u64,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceQueueConfigFragment {
    max_waiting: Option<usize>,
    timeout_ms: Option<u64>,
    retry_interval_ms: Option<u64>,
}

impl Default for LoadBalanceQueueConfig {
    fn default() -> Self {
        Self {
            max_waiting: 0,
            timeout_ms: 0,
            retry_interval_ms: default_lb_queue_retry_interval_ms(),
        }
    }
}

impl LoadBalanceQueueConfig {
    fn merge(&mut self, fragment: LoadBalanceQueueConfigFragment) {
        if let Some(max_waiting) = fragment.max_waiting {
            self.max_waiting = max_waiting;
        }
        if let Some(timeout_ms) = fragment.timeout_ms {
            self.timeout_ms = timeout_ms;
        }
        if let Some(retry_interval_ms) = fragment.retry_interval_ms {
            self.retry_interval_ms = retry_interval_ms;
        }
    }

    #[cfg(feature = "load-balancer")]
    pub fn enabled(&self) -> bool {
        self.max_waiting > 0 && self.timeout_ms > 0
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_waiting > MAX_LB_QUEUE_MAX_WAITING {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.queue.max_waiting must be at most 100000",
            });
        }
        if self.timeout_ms > MAX_LB_QUEUE_TIMEOUT_MS {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.queue.timeout_ms must be at most 60000",
            });
        }
        if self.retry_interval_ms == 0 || self.retry_interval_ms > MAX_LB_QUEUE_RETRY_INTERVAL_MS {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.queue.retry_interval_ms must be between 1 and 1000",
            });
        }
        if self.max_waiting == 0 && self.timeout_ms > 0 {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.queue.max_waiting is required when queue.timeout_ms is set",
            });
        }
        if self.max_waiting > 0 && self.timeout_ms == 0 {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.queue.timeout_ms is required when queue.max_waiting is set",
            });
        }
        Ok(())
    }
}

fn default_lb_persistence_ttl_secs() -> u64 {
    300
}

fn default_lb_persistence_table_max_entries() -> usize {
    65_536
}

fn default_lb_managed_cookie_secure() -> bool {
    true
}

fn default_lb_managed_cookie_http_only() -> bool {
    true
}

fn validate_managed_cookie_attributes(
    config: &LoadBalancePersistenceConfig,
) -> Result<(), ConfigError> {
    if let Some(path) = config.managed_cookie_path.as_deref()
        && (!path.starts_with('/')
            || !path.is_ascii()
            || path.len() > 256
            || path
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b';' | b',')))
    {
        return Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.managed_cookie_path must be an absolute ASCII cookie path without controls, ';', or ','",
        });
    }
    if let Some(domain) = config.managed_cookie_domain.as_deref()
        && (domain.is_empty()
            || !domain.is_ascii()
            || domain.len() > 253
            || domain
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b';' | b',')))
    {
        return Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.managed_cookie_domain must be a non-empty ASCII cookie domain without controls, ';', or ','",
        });
    }
    if let Some(max_age) = config.managed_cookie_max_age_secs
        && (max_age == 0 || max_age > MAX_LB_PERSISTENCE_TTL_SECS)
    {
        return Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.managed_cookie_max_age_secs must be between 1 and 86400",
        });
    }
    if config.managed_cookie_same_site == LoadBalanceManagedCookieSameSite::None
        && !config.managed_cookie_secure
    {
        return Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.managed_cookie_same_site = \"none\" requires managed_cookie_secure = true",
        });
    }
    Ok(())
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

fn default_lb_queue_retry_interval_ms() -> u64 {
    10
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

pub fn default_bounded_load_factor_per_mille() -> u16 {
    1250
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

fn default_lb_health_weight_min_percent() -> u8 {
    DEFAULT_LB_HEALTH_WEIGHT_MIN_PERCENT
}

fn valid_health_check_method(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= 32
        && valid_http_token(method)
        && !method.chars().any(char::is_lowercase)
}

fn valid_health_check_request_header(name: &str, value: &str) -> bool {
    valid_http_header_name(name)
        && !reserved_health_check_request_header(name)
        && value.len() <= LB_HEALTH_CHECK_MAX_REQUEST_HEADER_VALUE_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_health_check_grpc_service(service: &str) -> bool {
    !service.is_empty()
        && service.len() <= 256
        && service
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_health_check_json_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= LB_HEALTH_CHECK_MAX_EXPECTED_BODY_JSON_PATH_BYTES
        && path.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

fn valid_health_check_exec_command(command: &str) -> bool {
    let path = Path::new(command);
    !command.is_empty()
        && command.len() <= LB_HEALTH_CHECK_MAX_EXEC_COMMAND_BYTES
        && path.is_absolute()
        && !command.chars().any(char::is_control)
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir | Component::CurDir))
}

fn valid_health_check_exec_arg(arg: &str) -> bool {
    arg.len() <= LB_HEALTH_CHECK_MAX_EXEC_ARG_BYTES && !arg.chars().any(char::is_control)
}

fn reserved_health_check_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
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

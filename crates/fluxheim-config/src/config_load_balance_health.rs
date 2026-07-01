use std::fmt;

use serde::{Deserialize, Serialize};

const DEFAULT_LB_HEALTH_WEIGHT_MIN_PERCENT: u8 = 25;

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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadBalanceHealthCheckRequestHeader")
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
    pub(crate) fn merge(&mut self, fragment: LoadBalanceHealthCheckConfigFragment) {
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
}

fn default_true() -> bool {
    true
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

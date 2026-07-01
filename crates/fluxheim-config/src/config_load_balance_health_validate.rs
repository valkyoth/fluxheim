use std::collections::HashSet;
use std::path::{Component, Path};

use crate::config::{ConfigError, valid_http_token, validate_optional_timeout_secs};
use crate::config_header::valid_http_header_name;
use crate::config_load_balance_health::{
    LoadBalanceHealthCheckConfig, LoadBalanceHealthCheckProtocol,
};
use crate::config_net::normalize_host;

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

impl LoadBalanceHealthCheckConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
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

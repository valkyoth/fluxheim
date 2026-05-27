use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, validate_config_list_len};
use crate::config_net::valid_ip_matcher;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub require_client_cert: bool,
    #[serde(default)]
    pub allow_client_cert_sha256: Vec<String>,
    #[serde(default)]
    pub deny_client_cert_sha256: Vec<String>,
}

impl Default for AccessPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow: Vec::new(),
            deny: Vec::new(),
            require_client_cert: false,
            allow_client_cert_sha256: Vec::new(),
            deny_client_cert_sha256: Vec::new(),
        }
    }
}

impl AccessPolicyConfig {
    pub(crate) fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        validate_access_rule_list(scope, "allow", &self.allow)?;
        validate_access_rule_list(scope, "deny", &self.deny)?;
        validate_client_cert_sha256_list(
            scope,
            "allow_client_cert_sha256",
            &self.allow_client_cert_sha256,
        )?;
        validate_client_cert_sha256_list(
            scope,
            "deny_client_cert_sha256",
            &self.deny_client_cert_sha256,
        )?;
        Ok(())
    }
}

const MAX_RATE_LIMIT_REQUESTS_PER_SECOND: u32 = 1_000_000;
const MAX_RATE_LIMIT_BURST: u32 = 1_000_000;
const MAX_RATE_LIMIT_TABLE_ENTRIES: usize = 1_000_000;
const MAX_RATE_LIMIT_ENTRY_TTL_SECS: u64 = 86_400;
const MAX_RATE_LIMIT_DELAY_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RateLimitMode {
    #[default]
    Nodelay,
    Delay,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub requests_per_second: u32,
    #[serde(default)]
    pub burst: u32,
    #[serde(default = "default_rate_limit_status")]
    pub status: u16,
    #[serde(default = "default_rate_limit_table_max_entries")]
    pub table_max_entries: usize,
    #[serde(default = "default_rate_limit_entry_ttl_secs")]
    pub entry_ttl_secs: u64,
    #[serde(default)]
    pub mode: RateLimitMode,
    #[serde(default = "default_rate_limit_max_delay_ms")]
    pub max_delay_ms: u64,
    #[serde(default)]
    pub reject_indeterminate: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: 0,
            burst: 0,
            status: default_rate_limit_status(),
            table_max_entries: default_rate_limit_table_max_entries(),
            entry_ttl_secs: default_rate_limit_entry_ttl_secs(),
            mode: RateLimitMode::Nodelay,
            max_delay_ms: default_rate_limit_max_delay_ms(),
            reject_indeterminate: false,
        }
    }
}

impl RateLimitConfig {
    pub(crate) fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.requests_per_second == 0
            || self.requests_per_second > MAX_RATE_LIMIT_REQUESTS_PER_SECOND
        {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "requests_per_second"),
            });
        }
        if self.burst > MAX_RATE_LIMIT_BURST {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "burst"),
            });
        }
        if !(400..=599).contains(&self.status) {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "status"),
            });
        }
        if self.table_max_entries == 0 || self.table_max_entries > MAX_RATE_LIMIT_TABLE_ENTRIES {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "table_max_entries"),
            });
        }
        if self.entry_ttl_secs == 0 || self.entry_ttl_secs > MAX_RATE_LIMIT_ENTRY_TTL_SECS {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "entry_ttl_secs"),
            });
        }
        if matches!(self.mode, RateLimitMode::Delay) && self.max_delay_ms == 0 {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "max_delay_ms"),
            });
        }
        if self.max_delay_ms > MAX_RATE_LIMIT_DELAY_MS {
            return Err(ConfigError::InvalidRateLimit {
                field: rate_limit_field(scope, "max_delay_ms"),
            });
        }

        Ok(())
    }
}

fn default_rate_limit_status() -> u16 {
    429
}

fn default_rate_limit_table_max_entries() -> usize {
    65_536
}

fn default_rate_limit_entry_ttl_secs() -> u64 {
    300
}

fn default_rate_limit_max_delay_ms() -> u64 {
    1000
}

fn rate_limit_field(scope: &'static str, field: &'static str) -> &'static str {
    match (scope, field) {
        ("vhosts.rate_limit", "requests_per_second") => "vhosts.rate_limit.requests_per_second",
        ("vhosts.rate_limit", "burst") => "vhosts.rate_limit.burst",
        ("vhosts.rate_limit", "status") => "vhosts.rate_limit.status",
        ("vhosts.rate_limit", "table_max_entries") => "vhosts.rate_limit.table_max_entries",
        ("vhosts.rate_limit", "entry_ttl_secs") => "vhosts.rate_limit.entry_ttl_secs",
        ("vhosts.rate_limit", "max_delay_ms") => "vhosts.rate_limit.max_delay_ms",
        ("vhosts.routes.rate_limit", "requests_per_second") => {
            "vhosts.routes.rate_limit.requests_per_second"
        }
        ("vhosts.routes.rate_limit", "burst") => "vhosts.routes.rate_limit.burst",
        ("vhosts.routes.rate_limit", "status") => "vhosts.routes.rate_limit.status",
        ("vhosts.routes.rate_limit", "table_max_entries") => {
            "vhosts.routes.rate_limit.table_max_entries"
        }
        ("vhosts.routes.rate_limit", "entry_ttl_secs") => "vhosts.routes.rate_limit.entry_ttl_secs",
        ("vhosts.routes.rate_limit", "max_delay_ms") => "vhosts.routes.rate_limit.max_delay_ms",
        _ => "rate_limit",
    }
}

const MAX_CONCURRENCY_LIMIT: usize = 1_000_000;
const MAX_CONCURRENCY_QUEUE_TIMEOUT_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub max_in_flight: usize,
    #[serde(default)]
    pub max_queue: usize,
    #[serde(default = "default_concurrency_limit_status")]
    pub status: u16,
    #[serde(default)]
    pub queue_timeout_ms: u64,
}

impl Default for ConcurrencyLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_in_flight: 0,
            max_queue: 0,
            status: default_concurrency_limit_status(),
            queue_timeout_ms: 0,
        }
    }
}

impl ConcurrencyLimitConfig {
    pub(crate) fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.max_in_flight == 0 || self.max_in_flight > MAX_CONCURRENCY_LIMIT {
            return Err(ConfigError::InvalidConcurrencyLimit {
                field: concurrency_limit_field(scope, "max_in_flight"),
            });
        }
        if self.max_queue > MAX_CONCURRENCY_LIMIT {
            return Err(ConfigError::InvalidConcurrencyLimit {
                field: concurrency_limit_field(scope, "max_queue"),
            });
        }
        if !(400..=599).contains(&self.status) {
            return Err(ConfigError::InvalidConcurrencyLimit {
                field: concurrency_limit_field(scope, "status"),
            });
        }
        if self.queue_timeout_ms > MAX_CONCURRENCY_QUEUE_TIMEOUT_MS {
            return Err(ConfigError::InvalidConcurrencyLimit {
                field: concurrency_limit_field(scope, "queue_timeout_ms"),
            });
        }

        Ok(())
    }
}

fn default_concurrency_limit_status() -> u16 {
    503
}

fn concurrency_limit_field(scope: &'static str, field: &'static str) -> &'static str {
    match (scope, field) {
        ("vhosts.concurrency", "max_in_flight") => "vhosts.concurrency.max_in_flight",
        ("vhosts.concurrency", "max_queue") => "vhosts.concurrency.max_queue",
        ("vhosts.concurrency", "status") => "vhosts.concurrency.status",
        ("vhosts.concurrency", "queue_timeout_ms") => "vhosts.concurrency.queue_timeout_ms",
        ("vhosts.routes.concurrency", "max_in_flight") => "vhosts.routes.concurrency.max_in_flight",
        ("vhosts.routes.concurrency", "max_queue") => "vhosts.routes.concurrency.max_queue",
        ("vhosts.routes.concurrency", "status") => "vhosts.routes.concurrency.status",
        ("vhosts.routes.concurrency", "queue_timeout_ms") => {
            "vhosts.routes.concurrency.queue_timeout_ms"
        }
        _ => "concurrency",
    }
}

fn default_true() -> bool {
    true
}

const MAX_ACCESS_RULES: usize = 256;

pub(crate) fn validate_access_rule_list(
    scope: &'static str,
    field: &'static str,
    values: &[String],
) -> Result<(), ConfigError> {
    validate_config_list_len(format!("{scope}.{field}"), values.len(), MAX_ACCESS_RULES)?;

    let mut seen = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed != value || !valid_ip_matcher(trimmed) {
            return Err(ConfigError::InvalidAccessRule {
                field: access_rule_field(scope, field),
                value: value.clone(),
            });
        }
        if !seen.insert(trimmed.to_ascii_lowercase()) {
            return Err(ConfigError::DuplicateAccessRule {
                field: access_rule_field(scope, field),
                value: value.clone(),
            });
        }
    }

    Ok(())
}

pub(crate) fn validate_client_cert_sha256_list(
    scope: &'static str,
    field: &'static str,
    values: &[String],
) -> Result<(), ConfigError> {
    validate_config_list_len(format!("{scope}.{field}"), values.len(), MAX_ACCESS_RULES)?;

    let mut seen = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed != value || !valid_sha256_hex(trimmed) {
            return Err(ConfigError::InvalidAccessRule {
                field: access_rule_field(scope, field),
                value: value.clone(),
            });
        }
        if !seen.insert(trimmed.to_ascii_lowercase()) {
            return Err(ConfigError::DuplicateAccessRule {
                field: access_rule_field(scope, field),
                value: value.clone(),
            });
        }
    }

    Ok(())
}

fn access_rule_field(scope: &'static str, field: &'static str) -> &'static str {
    match (scope, field) {
        ("vhosts.access", "allow") => "vhosts.access.allow",
        ("vhosts.access", "deny") => "vhosts.access.deny",
        ("vhosts.access", "allow_client_cert_sha256") => "vhosts.access.allow_client_cert_sha256",
        ("vhosts.access", "deny_client_cert_sha256") => "vhosts.access.deny_client_cert_sha256",
        ("vhosts.routes.access", "allow") => "vhosts.routes.access.allow",
        ("vhosts.routes.access", "deny") => "vhosts.routes.access.deny",
        ("vhosts.routes.access", "allow_client_cert_sha256") => {
            "vhosts.routes.access.allow_client_cert_sha256"
        }
        ("vhosts.routes.access", "deny_client_cert_sha256") => {
            "vhosts.routes.access.deny_client_cert_sha256"
        }
        ("admin.client_certificate", "allow_sha256") => "admin.client_certificate.allow_sha256",
        ("admin.client_certificate", "deny_sha256") => "admin.client_certificate.deny_sha256",
        _ => "access",
    }
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

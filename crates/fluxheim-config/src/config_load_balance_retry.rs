use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_load_balance_health::LoadBalanceHealthCheckExpectedStatusRange;

pub const LB_SAFE_RETRY_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "TRACE"];
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
    pub(crate) fn merge(&mut self, fragment: LoadBalanceRetryConfigFragment) {
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

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
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

fn default_lb_retry_max_retries() -> u8 {
    1
}

fn default_lb_retry_methods() -> Vec<String> {
    vec!["GET".to_owned(), "HEAD".to_owned(), "OPTIONS".to_owned()]
}

fn default_lb_retry_budget_window_secs() -> u64 {
    1
}

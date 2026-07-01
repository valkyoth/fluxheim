use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_load_balance_health::LoadBalanceHealthCheckExpectedStatusRange;

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
    pub(crate) fn merge(&mut self, fragment: LoadBalancePassiveHealthConfigFragment) {
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

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
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

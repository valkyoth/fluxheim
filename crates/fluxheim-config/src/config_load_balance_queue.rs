use serde::{Deserialize, Serialize};

use crate::config::ConfigError;

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
    pub(crate) fn merge(&mut self, fragment: LoadBalanceQueueConfigFragment) {
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

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
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

fn default_lb_queue_retry_interval_ms() -> u64 {
    10
}

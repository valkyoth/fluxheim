use serde::{Deserialize, Serialize};

use crate::config::ConfigError;

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
    pub(crate) fn merge(&mut self, fragment: LoadBalanceSlowStartConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(duration_secs) = fragment.duration_secs {
            self.duration_secs = duration_secs;
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
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

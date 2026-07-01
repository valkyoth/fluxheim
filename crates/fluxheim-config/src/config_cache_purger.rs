use serde::{Deserialize, Serialize};

use crate::config::ConfigError;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePurgerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_purger_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_cache_purger_limit")]
    pub limit: usize,
    #[serde(default = "default_cache_purger_batches")]
    pub batches: usize,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePurgerConfigFragment {
    enabled: Option<bool>,
    interval_secs: Option<u64>,
    limit: Option<usize>,
    batches: Option<usize>,
}

impl Default for CachePurgerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_cache_purger_interval_secs(),
            limit: default_cache_purger_limit(),
            batches: default_cache_purger_batches(),
        }
    }
}

impl CachePurgerConfig {
    pub fn merge(&mut self, fragment: CachePurgerConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(interval_secs) = fragment.interval_secs {
            self.interval_secs = interval_secs;
        }
        if let Some(limit) = fragment.limit {
            self.limit = limit;
        }
        if let Some(batches) = fragment.batches {
            self.batches = batches;
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled {
            #[cfg(not(feature = "cache"))]
            return Err(ConfigError::CachePurgerNotCompiled);
        }

        if self.interval_secs == 0 || self.interval_secs > 86_400 {
            return Err(ConfigError::InvalidCachePurgerPolicy {
                field: "cache_purger.interval_secs",
                reason: "interval must be between 1 and 86400 seconds",
            });
        }
        if self.limit == 0 || self.limit > 100_000 {
            return Err(ConfigError::InvalidCachePurgerPolicy {
                field: "cache_purger.limit",
                reason: "limit must be between 1 and 100000 indexed entries",
            });
        }
        if self.batches == 0 || self.batches > 100 {
            return Err(ConfigError::InvalidCachePurgerPolicy {
                field: "cache_purger.batches",
                reason: "batches must be between 1 and 100",
            });
        }
        Ok(())
    }
}

fn default_cache_purger_interval_secs() -> u64 {
    300
}

fn default_cache_purger_limit() -> usize {
    512
}

fn default_cache_purger_batches() -> usize {
    1
}

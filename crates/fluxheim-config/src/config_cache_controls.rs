use serde::{Deserialize, Serialize};

use crate::config::ConfigError;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheLockConfig {
    #[serde(default = "default_cache_lock_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cache_lock_age_timeout_secs")]
    pub age_timeout_secs: u64,
    #[serde(default = "default_cache_lock_wait_timeout_secs")]
    pub wait_timeout_secs: u64,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheLockConfigFragment {
    enabled: Option<bool>,
    age_timeout_secs: Option<u64>,
    wait_timeout_secs: Option<u64>,
}

impl Default for CacheLockConfig {
    fn default() -> Self {
        Self {
            enabled: default_cache_lock_enabled(),
            age_timeout_secs: default_cache_lock_age_timeout_secs(),
            wait_timeout_secs: default_cache_lock_wait_timeout_secs(),
        }
    }
}

impl CacheLockConfig {
    pub(crate) fn merge(&mut self, fragment: CacheLockConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(age_timeout_secs) = fragment.age_timeout_secs {
            self.age_timeout_secs = age_timeout_secs;
        }
        if let Some(wait_timeout_secs) = fragment.wait_timeout_secs {
            self.wait_timeout_secs = wait_timeout_secs;
        }
    }

    pub(crate) fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if self.age_timeout_secs == 0 {
            return Err(ConfigError::InvalidCacheLockTimeout {
                field: format!("{scope}.lock.age_timeout_secs"),
            });
        }
        if self.wait_timeout_secs == 0 {
            return Err(ConfigError::InvalidCacheLockTimeout {
                field: format!("{scope}.lock.wait_timeout_secs"),
            });
        }
        Ok(())
    }
}

pub const CACHE_PREDICTOR_MAX_CAPACITY: usize = 1_048_576;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePredictorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_predictor_capacity")]
    pub capacity: usize,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePredictorConfigFragment {
    enabled: Option<bool>,
    capacity: Option<usize>,
}

impl Default for CachePredictorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capacity: default_cache_predictor_capacity(),
        }
    }
}

impl CachePredictorConfig {
    pub(crate) fn merge(&mut self, fragment: CachePredictorConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(capacity) = fragment.capacity {
            self.capacity = capacity;
        }
    }

    pub(crate) fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if self.enabled && (self.capacity == 0 || self.capacity > CACHE_PREDICTOR_MAX_CAPACITY) {
            return Err(ConfigError::InvalidCachePredictorCapacity { scope });
        }
        Ok(())
    }
}

fn default_cache_predictor_capacity() -> usize {
    65_536
}

pub const CACHE_ORIGIN_PROTECTION_MAX_CONCURRENT_FILLS: usize = 1024;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheOriginProtectionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_origin_protection_max_concurrent_fills")]
    pub max_concurrent_fills: usize,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheOriginProtectionConfigFragment {
    enabled: Option<bool>,
    max_concurrent_fills: Option<usize>,
}

impl Default for CacheOriginProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_concurrent_fills: default_cache_origin_protection_max_concurrent_fills(),
        }
    }
}

impl CacheOriginProtectionConfig {
    pub(crate) fn merge(&mut self, fragment: CacheOriginProtectionConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(max_concurrent_fills) = fragment.max_concurrent_fills {
            self.max_concurrent_fills = max_concurrent_fills;
        }
    }

    pub(crate) fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if self.enabled
            && (self.max_concurrent_fills == 0
                || self.max_concurrent_fills > CACHE_ORIGIN_PROTECTION_MAX_CONCURRENT_FILLS)
        {
            return Err(ConfigError::InvalidCacheOriginProtectionPolicy {
                scope,
                field: "origin_protection.max_concurrent_fills",
                reason: "max concurrent fills must be between 1 and 1024",
            });
        }
        Ok(())
    }
}

fn default_cache_origin_protection_max_concurrent_fills() -> usize {
    32
}

fn default_cache_lock_enabled() -> bool {
    true
}

fn default_cache_lock_age_timeout_secs() -> u64 {
    30
}

fn default_cache_lock_wait_timeout_secs() -> u64 {
    30
}

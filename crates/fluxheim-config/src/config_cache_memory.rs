use serde::{Deserialize, Serialize};

use crate::config::{ByteSize, ConfigError};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheMemoryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_memory_max_size_bytes")]
    pub max_size_bytes: ByteSize,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheMemoryConfigFragment {
    enabled: Option<bool>,
    max_size_bytes: Option<ByteSize>,
}

impl Default for CacheMemoryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_size_bytes: default_cache_memory_max_size_bytes(),
        }
    }
}

impl CacheMemoryConfig {
    pub(crate) fn merge(&mut self, fragment: CacheMemoryConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(max_size_bytes) = fragment.max_size_bytes {
            self.max_size_bytes = max_size_bytes;
        }
    }

    pub(crate) fn validate(
        &self,
        scope: &'static str,
        max_object_bytes: ByteSize,
    ) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.max_size_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheTierMaxSize {
                field: format!("{scope}.memory.max_size_bytes"),
            });
        }

        if self.max_size_bytes < max_object_bytes {
            return Err(ConfigError::CacheTierSmallerThanMaxObject {
                tier: format!("{scope}.memory"),
            });
        }

        Ok(())
    }
}

fn default_cache_memory_max_size_bytes() -> ByteSize {
    ByteSize::from_bytes(1024 * 1024 * 1024)
}

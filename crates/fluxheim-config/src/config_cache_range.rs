use serde::{Deserialize, Serialize};

use crate::config::{ByteSize, ConfigError};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheRangeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_range_max_bytes")]
    pub max_bytes: ByteSize,
    #[serde(default)]
    pub slice: CacheRangeSliceConfig,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheRangeConfigFragment {
    enabled: Option<bool>,
    max_bytes: Option<ByteSize>,
    slice: Option<CacheRangeSliceConfigFragment>,
}

impl Default for CacheRangeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_bytes: default_cache_range_max_bytes(),
            slice: CacheRangeSliceConfig::default(),
        }
    }
}

impl CacheRangeConfig {
    pub(crate) fn merge(&mut self, fragment: CacheRangeConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(max_bytes) = fragment.max_bytes {
            self.max_bytes = max_bytes;
        }
        if let Some(slice) = fragment.slice {
            self.slice.merge(slice);
        }
    }

    pub(crate) fn validate(
        &self,
        scope: &'static str,
        max_object_bytes: ByteSize,
    ) -> Result<(), ConfigError> {
        if self.max_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.max_bytes",
                reason: "max bytes must be greater than zero",
            });
        }
        if self.enabled && !self.slice.enabled && self.max_bytes > max_object_bytes {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.max_bytes",
                reason: "max bytes must not exceed max_object_bytes",
            });
        }
        self.slice
            .validate(scope, self.enabled, self.max_bytes, max_object_bytes)?;
        Ok(())
    }
}

fn default_cache_range_max_bytes() -> ByteSize {
    ByteSize(8 * 1024 * 1024)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheRangeSliceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cache_range_slice_size_bytes")]
    pub size_bytes: ByteSize,
    #[serde(default = "default_cache_range_slice_max_slices")]
    pub max_slices: u32,
    #[serde(default = "default_cache_range_slice_fill_missing")]
    pub fill_missing: bool,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheRangeSliceConfigFragment {
    enabled: Option<bool>,
    size_bytes: Option<ByteSize>,
    max_slices: Option<u32>,
    fill_missing: Option<bool>,
}

impl Default for CacheRangeSliceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            size_bytes: default_cache_range_slice_size_bytes(),
            max_slices: default_cache_range_slice_max_slices(),
            fill_missing: default_cache_range_slice_fill_missing(),
        }
    }
}

impl CacheRangeSliceConfig {
    fn merge(&mut self, fragment: CacheRangeSliceConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(size_bytes) = fragment.size_bytes {
            self.size_bytes = size_bytes;
        }
        if let Some(max_slices) = fragment.max_slices {
            self.max_slices = max_slices;
        }
        if let Some(fill_missing) = fragment.fill_missing {
            self.fill_missing = fill_missing;
        }
    }

    fn validate(
        &self,
        scope: &'static str,
        range_enabled: bool,
        range_max_bytes: ByteSize,
        max_object_bytes: ByteSize,
    ) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if !range_enabled {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.slice.enabled",
                reason: "slice caching requires range.enabled = true",
            });
        }
        if self.size_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.slice.size_bytes",
                reason: "slice size must be greater than zero",
            });
        }
        if self.size_bytes > max_object_bytes {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.slice.size_bytes",
                reason: "slice size must not exceed max_object_bytes",
            });
        }
        if self.max_slices == 0 {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.slice.max_slices",
                reason: "max slices must be greater than zero",
            });
        }
        let max_assembled = self
            .size_bytes
            .as_u64()
            .saturating_mul(u64::from(self.max_slices));
        if range_max_bytes.as_u64() > max_assembled {
            return Err(ConfigError::InvalidCacheRangePolicy {
                scope,
                field: "range.max_bytes",
                reason: "max bytes must not exceed range.slice.size_bytes * range.slice.max_slices",
            });
        }
        Ok(())
    }
}

fn default_cache_range_slice_size_bytes() -> ByteSize {
    ByteSize(1024 * 1024)
}

fn default_cache_range_slice_max_slices() -> u32 {
    128
}

fn default_cache_range_slice_fill_missing() -> bool {
    true
}

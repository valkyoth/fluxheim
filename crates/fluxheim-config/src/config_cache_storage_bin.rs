use serde::{Deserialize, Serialize};

use crate::config::{ByteSize, ConfigError};

#[derive(Debug, Clone, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskStorageBinConfig {
    #[serde(default = "default_cache_storage_bin_size_bytes")]
    pub bin_size_bytes: ByteSize,
    #[serde(default)]
    pub preallocate: bool,
    #[serde(default = "default_cache_storage_bin_max_open_bins")]
    pub max_open_bins: usize,
}

#[derive(Debug, Clone, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskStorageBinConfigFragment {
    bin_size_bytes: Option<ByteSize>,
    preallocate: Option<bool>,
    max_open_bins: Option<usize>,
}

impl Default for CacheDiskStorageBinConfig {
    fn default() -> Self {
        Self {
            bin_size_bytes: default_cache_storage_bin_size_bytes(),
            preallocate: false,
            max_open_bins: default_cache_storage_bin_max_open_bins(),
        }
    }
}

impl CacheDiskStorageBinConfig {
    pub(crate) fn merge(&mut self, fragment: CacheDiskStorageBinConfigFragment) {
        if let Some(bin_size_bytes) = fragment.bin_size_bytes {
            self.bin_size_bytes = bin_size_bytes;
        }
        if let Some(preallocate) = fragment.preallocate {
            self.preallocate = preallocate;
        }
        if let Some(max_open_bins) = fragment.max_open_bins {
            self.max_open_bins = max_open_bins;
        }
    }

    pub(crate) fn validate(
        &self,
        scope: &'static str,
        disk_max_size_bytes: ByteSize,
        max_object_bytes: ByteSize,
    ) -> Result<(), ConfigError> {
        let field = format!("{scope}.disk.storage_bin.bin_size_bytes");
        if self.bin_size_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheTierMaxSize { field });
        }
        if self.bin_size_bytes < max_object_bytes {
            return Err(ConfigError::CacheStorageBinSmallerThanMaxObject { scope });
        }
        if self.bin_size_bytes > disk_max_size_bytes {
            return Err(ConfigError::CacheStorageBinLargerThanDiskTier { scope });
        }
        if self.max_open_bins == 0 {
            return Err(ConfigError::InvalidCacheStorageBinMaxOpenBins { scope });
        }
        Ok(())
    }
}

fn default_cache_storage_bin_size_bytes() -> ByteSize {
    ByteSize::from_bytes(256 * 1024 * 1024)
}

fn default_cache_storage_bin_max_open_bins() -> usize {
    16
}

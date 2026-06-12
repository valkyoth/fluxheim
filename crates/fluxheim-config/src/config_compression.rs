use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_types::ByteSize;

const DEFAULT_COMPRESSION_MIN_BYTES: u64 = 1024;
const DEFAULT_COMPRESSION_MAX_INPUT_BYTES: u64 = 1024 * 1024;
pub const DEFAULT_COMPRESSION_MAX_OUTPUT_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_COMPRESSION_GZIP_LEVEL: u32 = 4;
const DEFAULT_COMPRESSION_ZSTD_LEVEL: i32 = 3;
const DEFAULT_COMPRESSION_BROTLI_QUALITY: u32 = 4;
const MAX_COMPRESSION_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COMPRESSION_OUTPUT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_compression_gzip_enabled")]
    pub gzip: bool,
    #[serde(default)]
    pub zstd: bool,
    #[serde(default)]
    pub brotli: bool,
    #[serde(default = "default_compression_min_bytes")]
    pub min_bytes: ByteSize,
    #[serde(default = "default_compression_max_input_bytes")]
    pub max_input_bytes: ByteSize,
    #[serde(default = "default_compression_max_output_bytes")]
    pub max_output_bytes: ByteSize,
    #[serde(default = "default_compression_gzip_level")]
    pub gzip_level: u32,
    #[serde(default = "default_compression_zstd_level")]
    pub zstd_level: i32,
    #[serde(default = "default_compression_brotli_quality")]
    pub brotli_quality: u32,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionConfigFragment {
    enabled: Option<bool>,
    gzip: Option<bool>,
    zstd: Option<bool>,
    brotli: Option<bool>,
    min_bytes: Option<ByteSize>,
    max_input_bytes: Option<ByteSize>,
    max_output_bytes: Option<ByteSize>,
    gzip_level: Option<u32>,
    zstd_level: Option<i32>,
    brotli_quality: Option<u32>,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            gzip: true,
            zstd: false,
            brotli: false,
            min_bytes: default_compression_min_bytes(),
            max_input_bytes: default_compression_max_input_bytes(),
            max_output_bytes: default_compression_max_output_bytes(),
            gzip_level: default_compression_gzip_level(),
            zstd_level: default_compression_zstd_level(),
            brotli_quality: default_compression_brotli_quality(),
        }
    }
}

impl CompressionConfig {
    pub fn merge(&mut self, fragment: CompressionConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(gzip) = fragment.gzip {
            self.gzip = gzip;
        }
        if let Some(zstd) = fragment.zstd {
            self.zstd = zstd;
        }
        if let Some(brotli) = fragment.brotli {
            self.brotli = brotli;
        }
        if let Some(min_bytes) = fragment.min_bytes {
            self.min_bytes = min_bytes;
        }
        if let Some(max_input_bytes) = fragment.max_input_bytes {
            self.max_input_bytes = max_input_bytes;
        }
        if let Some(max_output_bytes) = fragment.max_output_bytes {
            self.max_output_bytes = max_output_bytes;
        }
        if let Some(gzip_level) = fragment.gzip_level {
            self.gzip_level = gzip_level;
        }
        if let Some(zstd_level) = fragment.zstd_level {
            self.zstd_level = zstd_level;
        }
        if let Some(brotli_quality) = fragment.brotli_quality {
            self.brotli_quality = brotli_quality;
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if !self.gzip && !self.zstd && !self.brotli {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression",
            });
        }
        if self.min_bytes.as_u64() == 0 || self.min_bytes.as_u64() > self.max_input_bytes.as_u64() {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.min_bytes",
            });
        }
        if self.max_input_bytes.as_u64() == 0
            || self.max_input_bytes.as_u64() > MAX_COMPRESSION_INPUT_BYTES
        {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.max_input_bytes",
            });
        }
        if self.max_output_bytes.as_u64() < self.min_bytes.as_u64()
            || self.max_output_bytes.as_u64() > MAX_COMPRESSION_OUTPUT_BYTES
        {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.max_output_bytes",
            });
        }
        if self.gzip_level > 9 {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.gzip_level",
            });
        }
        if !(1..=19).contains(&self.zstd_level) {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.zstd_level",
            });
        }
        if self.brotli_quality > 11 {
            return Err(ConfigError::InvalidCompressionPolicy {
                field: "compression.brotli_quality",
            });
        }
        Ok(())
    }
}

fn default_compression_min_bytes() -> ByteSize {
    ByteSize::from_bytes(DEFAULT_COMPRESSION_MIN_BYTES)
}

fn default_compression_gzip_enabled() -> bool {
    true
}

fn default_compression_max_input_bytes() -> ByteSize {
    ByteSize::from_bytes(DEFAULT_COMPRESSION_MAX_INPUT_BYTES)
}

fn default_compression_max_output_bytes() -> ByteSize {
    ByteSize::from_bytes(DEFAULT_COMPRESSION_MAX_OUTPUT_BYTES)
}

fn default_compression_gzip_level() -> u32 {
    DEFAULT_COMPRESSION_GZIP_LEVEL
}

fn default_compression_zstd_level() -> i32 {
    DEFAULT_COMPRESSION_ZSTD_LEVEL
}

fn default_compression_brotli_quality() -> u32 {
    DEFAULT_COMPRESSION_BROTLI_QUALITY
}

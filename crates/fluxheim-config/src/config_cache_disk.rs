use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{ByteSize, ConfigError};
use crate::config_cache_encryption::{
    CacheDiskEncryptionConfig, CacheDiskEncryptionConfigFragment,
};
use crate::config_cache_storage_bin::{
    CacheDiskStorageBinConfig, CacheDiskStorageBinConfigFragment,
};
use crate::config_path::{validate_non_world_writable_parent, validate_path};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub backend: CacheDiskBackend,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default = "default_cache_disk_max_size_bytes")]
    pub max_size_bytes: ByteSize,
    #[serde(default)]
    pub storage_bin: CacheDiskStorageBinConfig,
    #[serde(default)]
    pub encryption: CacheDiskEncryptionConfig,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheDiskConfigFragment {
    enabled: Option<bool>,
    backend: Option<CacheDiskBackend>,
    path: Option<PathBuf>,
    max_size_bytes: Option<ByteSize>,
    storage_bin: Option<CacheDiskStorageBinConfigFragment>,
    encryption: Option<CacheDiskEncryptionConfigFragment>,
}

#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheDiskBackend {
    #[default]
    Filesystem,
    StorageBin,
}

impl Default for CacheDiskConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: CacheDiskBackend::Filesystem,
            path: None,
            max_size_bytes: default_cache_disk_max_size_bytes(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        }
    }
}

impl CacheDiskConfig {
    pub(crate) fn merge(&mut self, fragment: CacheDiskConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(backend) = fragment.backend {
            self.backend = backend;
        }
        if let Some(path) = fragment.path {
            self.path = Some(path);
        }
        if let Some(max_size_bytes) = fragment.max_size_bytes {
            self.max_size_bytes = max_size_bytes;
        }
        if let Some(storage_bin) = fragment.storage_bin {
            self.storage_bin.merge(storage_bin);
        }
        if let Some(encryption) = fragment.encryption {
            self.encryption.merge(encryption);
        }
    }

    pub(crate) fn resolve_fragment_relative_paths(
        fragment: &mut CacheDiskConfigFragment,
        base_dir: &Path,
    ) {
        if let Some(path) = &mut fragment.path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        if let Some(encryption) = &mut fragment.encryption {
            encryption.resolve_relative_paths(base_dir);
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

        if self.backend == CacheDiskBackend::StorageBin {
            self.storage_bin
                .validate(scope, self.max_size_bytes, max_object_bytes)?;
        }
        self.encryption.validate(scope)?;

        let Some(path) = &self.path else {
            return Err(ConfigError::MissingCacheDiskPath { scope });
        };

        if path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyCacheDiskPath { scope });
        }
        let path_field = format!("{scope}.disk.path");
        validate_path(path_field.clone(), Some(path))?;
        validate_non_world_writable_parent(path_field, Some(path))?;

        if self.max_size_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidCacheTierMaxSize {
                field: format!("{scope}.disk.max_size_bytes"),
            });
        }

        if self.max_size_bytes < max_object_bytes {
            return Err(ConfigError::CacheTierSmallerThanMaxObject {
                tier: format!("{scope}.disk"),
            });
        }

        Ok(())
    }
}

impl CacheDiskConfigFragment {
    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        CacheDiskConfig::resolve_fragment_relative_paths(self, base_dir);
    }
}

fn default_cache_disk_max_size_bytes() -> ByteSize {
    ByteSize::from_bytes(10 * 1024 * 1024 * 1024)
}

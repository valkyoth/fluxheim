use std::path::PathBuf;

use fluxheim_config::{
    ByteSize, CacheDiskBackend, CacheDiskEncryptionConfig, CacheDiskStorageBinConfig,
};

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct CacheStoragePlan {
    pub memory: Option<MemoryTierPlan>,
    pub disk: Option<DiskTierPlan>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct MemoryTierPlan {
    pub max_size_bytes: ByteSize,
    pub max_object_bytes: ByteSize,
    pub object_slots: usize,
    pub cache_tag_headers: Vec<String>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct DiskTierPlan {
    pub backend: CacheDiskBackend,
    pub path: PathBuf,
    pub max_size_bytes: ByteSize,
    pub max_object_bytes: ByteSize,
    pub cache_tag_headers: Vec<String>,
    pub storage_bin: CacheDiskStorageBinConfig,
    pub encryption: CacheDiskEncryptionConfig,
}

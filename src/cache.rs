#[cfg(feature = "proxy")]
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
#[cfg(feature = "proxy")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "proxy")]
use std::sync::{Mutex, OnceLock, RwLock};

#[cfg(feature = "proxy")]
use async_trait::async_trait;
#[cfg(feature = "proxy")]
use bytes::Bytes;
#[cfg(feature = "proxy")]
use pingora::cache::key::CacheHashKey;
#[cfg(feature = "proxy")]
use pingora::cache::lock::{CacheKeyLockImpl, CacheLock};
#[cfg(feature = "proxy")]
use pingora::cache::storage::{MissFinishType, PurgeType};
#[cfg(feature = "proxy")]
use pingora::cache::{CacheMeta, HitHandler, MissHandler, Storage};
#[cfg(feature = "proxy")]
use pingora::{Error, ErrorType};
#[cfg(feature = "proxy")]
use sha2::{Digest, Sha256};
#[cfg(feature = "proxy")]
use zeroize::Zeroizing;

#[cfg(feature = "proxy")]
use crate::config::CacheDiskEncryptionProvider;
use crate::config::{
    ByteSize, CacheConfig, CacheDiskBackend, CacheDiskEncryptionConfig, CacheDiskStorageBinConfig,
    CacheKeyPart, normalize_host,
};

#[cfg(feature = "proxy")]
const DISK_CACHE_HEADER_OVERHEAD_LIMIT: u64 = 8192;
#[cfg(feature = "proxy")]
const DISK_CACHE_TEMP_FILE_STALE_SECS: u64 = 6 * 60 * 60;
#[cfg(all(feature = "proxy", not(test)))]
const DISK_CACHE_INDEX_CHECKPOINT_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(2);
#[cfg(all(feature = "proxy", test))]
const DISK_CACHE_INDEX_CHECKPOINT_DEBOUNCE: std::time::Duration =
    std::time::Duration::from_millis(200);
#[cfg(feature = "proxy")]
const DISK_CACHE_MAGIC_V1: &[u8] = b"FLUXHEIM-CACHE-v1\n";
#[cfg(feature = "proxy")]
const DISK_CACHE_MAGIC_V2: &[u8] = b"FLUXHEIM-CACHE-v2\n";
#[cfg(feature = "proxy")]
const DISK_CACHE_MAGIC_V3: &[u8] = b"FLUXHEIM-CACHE-v3\n";
#[cfg(feature = "proxy")]
const DISK_CACHE_MAGIC_V4: &[u8] = b"FLUXHEIM-CACHE-v4\n";
#[cfg(feature = "proxy")]
const DISK_CACHE_MAGIC_V5: &[u8] = b"FLUXHEIM-CACHE-v5\n";
#[cfg(feature = "proxy")]
const DISK_CACHE_ENCRYPTED_MAGIC_V1: &[u8] = b"FLUXHEIM-CACHE-ENC-v1\n";
#[cfg(feature = "proxy")]
const DISK_CACHE_INDEX_MAGIC_V1: &str = "FLUXHEIM-DISK-INDEX-v1";
#[cfg(feature = "proxy")]
const DISK_CACHE_INDEX_FILENAME: &str = ".fluxheim-disk-index-v1";
#[cfg(feature = "proxy")]
const STORAGE_BIN_MANIFEST_MAGIC_V1: &str = "FLUXHEIM-STORAGE-BIN-v1";
#[cfg(feature = "proxy")]
const STORAGE_BIN_MANIFEST_FILENAME: &str = ".fluxheim-storage-bin-v1";
#[cfg(feature = "proxy")]
const STORAGE_BIN_INDEX_MAGIC_V1: &str = "FLUXHEIM-STORAGE-BIN-INDEX-v1";
#[cfg(feature = "proxy")]
const STORAGE_BIN_INDEX_FILENAME: &str = ".fluxheim-storage-bin-index-v1";
#[cfg(feature = "proxy")]
const STORAGE_BIN_DATA_DIR: &str = "bins";
#[cfg(feature = "proxy")]
const MAX_CACHE_TAGS_PER_OBJECT: usize = 64;
#[cfg(feature = "proxy")]
const MAX_CACHE_TAG_LEN: usize = 128;
#[cfg(feature = "proxy")]
const MAX_CACHE_TAG_BYTES_PER_OBJECT: usize = 4096;

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

#[cfg(feature = "proxy")]
static PINGORA_MEMORY_STORAGE_REGISTRY: OnceLock<
    Mutex<HashMap<MemoryStorageRegistryKey, &'static PingoraMemoryStorage>>,
> = OnceLock::new();
#[cfg(feature = "proxy")]
static PINGORA_DISK_STORAGE_REGISTRY: OnceLock<
    Mutex<HashMap<DiskStorageRegistryKey, &'static PingoraDiskStorage>>,
> = OnceLock::new();
#[cfg(feature = "proxy")]
static PINGORA_DISK_STORAGE_BACKEND_REGISTRY: OnceLock<
    Mutex<HashMap<DiskStorageRegistryKey, &'static PingoraDiskStorageBackend>>,
> = OnceLock::new();
#[cfg(feature = "proxy")]
static PINGORA_TIERED_STORAGE_REGISTRY: OnceLock<
    Mutex<HashMap<String, &'static PingoraTieredStorage>>,
> = OnceLock::new();
#[cfg(feature = "proxy")]
static PINGORA_CACHE_LOCK_REGISTRY: OnceLock<
    Mutex<HashMap<(u64, u32), &'static CacheKeyLockImpl>>,
> = OnceLock::new();

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
enum StorageRegistryNamespace {
    Global,
    Scope {
        vhost: String,
        route: Option<String>,
    },
}

#[cfg(feature = "proxy")]
impl StorageRegistryNamespace {
    fn from_parts(vhost: Option<&str>, route: Option<&str>) -> Self {
        match vhost {
            Some(vhost) => Self::Scope {
                vhost: vhost.to_owned(),
                route: route.map(str::to_owned),
            },
            None => Self::Global,
        }
    }

    fn metric_scope(&self) -> Option<(&str, Option<&str>)> {
        match self {
            Self::Global => None,
            Self::Scope { vhost, route } => Some((vhost.as_str(), route.as_deref())),
        }
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct MemoryStorageRegistryKey {
    namespace: StorageRegistryNamespace,
    plan: MemoryTierPlan,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct DiskStorageRegistryKey {
    namespace: StorageRegistryNamespace,
    plan: DiskTierPlan,
}

#[cfg(feature = "proxy")]
fn lock_cache_registry<'a, T>(
    registry: &'a Mutex<T>,
    name: &'static str,
) -> std::sync::MutexGuard<'a, T> {
    match registry.lock() {
        Ok(guard) => guard,
        Err(_) => {
            log::error!(
                target: "fluxheim::security",
                "cache storage registry '{name}' lock poisoned; aborting to avoid inconsistent cache state"
            );
            std::process::abort();
        }
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone)]
struct DiskCacheEncryption {
    key_id: Arc<str>,
    provider: DiskCacheEncryptionProvider,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone)]
enum DiskCacheEncryptionProvider {
    Local {
        key: Arc<ring::aead::LessSafeKey>,
    },
    OpenBaoTransit {
        address: Arc<str>,
        mount: Arc<str>,
        key_name: Arc<str>,
        token: Arc<Zeroizing<String>>,
    },
}

#[cfg(feature = "proxy")]
impl DiskCacheEncryption {
    fn from_config(config: &CacheDiskEncryptionConfig) -> std::io::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }

        let key_id = Arc::from(config.key_id.as_deref().unwrap_or(match config.provider {
            CacheDiskEncryptionProvider::Local => "local",
            CacheDiskEncryptionProvider::OpenbaoTransit => "openbao-transit",
        }));
        match config.provider {
            CacheDiskEncryptionProvider::Local => {
                let key_bytes = match (&config.key_file, config.key_credential.as_deref()) {
                    (Some(path), None) => read_cache_encryption_key_file(path)?,
                    (None, Some(credential)) => {
                        let path = cache_encryption_credential_path(credential);
                        read_cache_encryption_key_file(&path)?
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "cache disk encryption requires exactly one local key source",
                        ));
                    }
                };
                let key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &key_bytes)
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "invalid cache disk encryption key",
                        )
                    })?;
                Ok(Some(Self {
                    key_id,
                    provider: DiskCacheEncryptionProvider::Local {
                        key: Arc::new(ring::aead::LessSafeKey::new(key)),
                    },
                }))
            }
            CacheDiskEncryptionProvider::OpenbaoTransit => {
                let token = match (
                    &config.openbao.token_file,
                    config.openbao.token_credential.as_deref(),
                ) {
                    (Some(path), None) => read_cache_encryption_secret_file(path)?,
                    (None, Some(credential)) => {
                        let path = cache_encryption_credential_path(credential);
                        read_cache_encryption_secret_file(&path)?
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "cache disk encryption requires exactly one OpenBao token source",
                        ));
                    }
                };
                let token = token.trim().to_owned();
                if token.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "cache disk encryption OpenBao token must not be empty",
                    ));
                }
                Ok(Some(Self {
                    key_id,
                    provider: DiskCacheEncryptionProvider::OpenBaoTransit {
                        address: Arc::from(
                            config
                                .openbao
                                .address
                                .as_deref()
                                .unwrap_or_default()
                                .trim()
                                .trim_end_matches('/'),
                        ),
                        mount: Arc::from(
                            config
                                .openbao
                                .mount
                                .as_deref()
                                .unwrap_or_default()
                                .trim()
                                .trim_matches('/'),
                        ),
                        key_name: Arc::from(
                            config
                                .openbao
                                .key_name
                                .as_deref()
                                .unwrap_or_default()
                                .trim(),
                        ),
                        token: Arc::new(Zeroizing::new(token)),
                    },
                }))
            }
        }
    }
}

#[cfg(feature = "proxy")]
fn cache_encryption_credential_path(credential_name: &str) -> PathBuf {
    std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/secrets"))
        .join(credential_name)
}

#[cfg(feature = "proxy")]
fn read_cache_encryption_key_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let contents = read_cache_encryption_secret_file(path)?;
    parse_cache_encryption_hex_key(contents.trim())
}

#[cfg(feature = "proxy")]
fn read_cache_encryption_secret_file(path: &Path) -> std::io::Result<Zeroizing<String>> {
    use std::io::Read as _;

    let mut file = SafeDiskCachePath::from_path(path.to_path_buf()).open_existing_file()?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "cache disk encryption secret must be a small regular file",
        ));
    }
    let mut contents = Zeroizing::new(String::new());
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

#[cfg(feature = "proxy")]
fn parse_cache_encryption_hex_key(value: &str) -> std::io::Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "cache disk encryption key must be 64 hex characters",
        ));
    }
    let mut key = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        key[index] = (high << 4) | low;
    }
    Ok(key)
}

#[cfg(feature = "proxy")]
fn hex_value(byte: u8) -> std::io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid hex digit",
        )),
    }
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageBinLayoutPlan {
    pub root: PathBuf,
    pub manifest_path: PathBuf,
    pub data_dir: PathBuf,
    pub bin_size_bytes: ByteSize,
    pub max_size_bytes: ByteSize,
    pub preallocate: bool,
    pub max_open_bins: usize,
}

#[cfg(feature = "proxy")]
impl StorageBinLayoutPlan {
    pub fn from_disk_plan(plan: &DiskTierPlan) -> Option<Self> {
        (plan.backend == CacheDiskBackend::StorageBin).then(|| {
            let root = plan.path.clone();
            Self {
                manifest_path: root.join(STORAGE_BIN_MANIFEST_FILENAME),
                data_dir: root.join(STORAGE_BIN_DATA_DIR),
                root,
                bin_size_bytes: plan.storage_bin.bin_size_bytes,
                max_size_bytes: plan.max_size_bytes,
                preallocate: plan.storage_bin.preallocate,
                max_open_bins: plan.storage_bin.max_open_bins,
            }
        })
    }

    pub fn max_bins(&self) -> u64 {
        let bin_size = self.bin_size_bytes.as_u64();
        if bin_size == 0 {
            return 0;
        }
        self.max_size_bytes.as_u64().div_ceil(bin_size)
    }

    pub fn bin_path(&self, bin_id: u64) -> PathBuf {
        self.data_dir.join(format!("{bin_id:016x}.fhbin"))
    }
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageBinManifest {
    pub bin_size_bytes: ByteSize,
    pub max_size_bytes: ByteSize,
    pub preallocate: bool,
    pub max_open_bins: usize,
}

#[cfg(feature = "proxy")]
impl StorageBinManifest {
    pub fn from_layout(plan: &StorageBinLayoutPlan) -> Self {
        Self {
            bin_size_bytes: plan.bin_size_bytes,
            max_size_bytes: plan.max_size_bytes,
            preallocate: plan.preallocate,
            max_open_bins: plan.max_open_bins,
        }
    }

    pub fn encode(&self) -> String {
        format!(
            "{STORAGE_BIN_MANIFEST_MAGIC_V1}\nbin_size_bytes={}\nmax_size_bytes={}\npreallocate={}\nmax_open_bins={}\n",
            self.bin_size_bytes.as_u64(),
            self.max_size_bytes.as_u64(),
            self.preallocate,
            self.max_open_bins
        )
    }

    pub fn decode(contents: &str) -> std::io::Result<Self> {
        let mut lines = contents.lines();
        match lines.next() {
            Some(STORAGE_BIN_MANIFEST_MAGIC_V1) => {}
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid storage-bin manifest magic",
                ));
            }
        }

        let bin_size_bytes = parse_storage_bin_manifest_u64(lines.next(), "bin_size_bytes")?;
        let max_size_bytes = parse_storage_bin_manifest_u64(lines.next(), "max_size_bytes")?;
        let preallocate = parse_storage_bin_manifest_bool(lines.next(), "preallocate")?;
        let max_open_bins = parse_storage_bin_manifest_usize(lines.next(), "max_open_bins")?;
        if lines.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "storage-bin manifest has trailing fields",
            ));
        }

        Ok(Self {
            bin_size_bytes: ByteSize::from_bytes(bin_size_bytes),
            max_size_bytes: ByteSize::from_bytes(max_size_bytes),
            preallocate,
            max_open_bins,
        })
    }

    pub fn ensure_matches_layout(&self, layout: &StorageBinLayoutPlan) -> std::io::Result<()> {
        let expected = Self::from_layout(layout);
        if self == &expected {
            return Ok(());
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "storage-bin manifest does not match configured cache disk layout",
        ))
    }
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StorageBinObjectLocation {
    pub bin_id: u64,
    pub offset: u64,
    pub len: u64,
}

#[cfg(feature = "proxy")]
impl StorageBinObjectLocation {
    pub fn validate(self, bin_size_bytes: ByteSize) -> std::io::Result<Self> {
        let bin_size = bin_size_bytes.as_u64();
        let end = self.offset.checked_add(self.len).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "storage-bin object location overflows",
            )
        })?;
        if self.len == 0 || end > bin_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "storage-bin object location is outside its bin",
            ));
        }
        Ok(self)
    }
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct StorageBinFileSet {
    layout: StorageBinLayoutPlan,
}

#[cfg(feature = "proxy")]
impl StorageBinFileSet {
    pub fn new(layout: StorageBinLayoutPlan) -> Self {
        Self { layout }
    }

    pub fn write_object(
        &self,
        location: StorageBinObjectLocation,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        if bytes.len() as u64 != location.len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin write length does not match object location",
            ));
        }
        let location = location.validate(self.layout.bin_size_bytes)?;
        let mut file = self.open_bin_for_write(location.bin_id)?;
        write_storage_bin_range(&mut file, location.offset, bytes)
    }

    pub fn read_object(&self, location: StorageBinObjectLocation) -> std::io::Result<Vec<u8>> {
        let location = location.validate(self.layout.bin_size_bytes)?;
        let mut file = self.open_bin_for_read(location.bin_id)?;
        read_storage_bin_range(&mut file, location.offset, location.len)
    }

    pub fn remove_bin(&self, bin_id: u64) -> std::io::Result<()> {
        let path = self.safe_bin_path(bin_id)?;
        let safe_path = SafeDiskCachePath::from_path(path);
        // lgtm[rs/path-injection] bin path is derived from a validated storage-bin root and bounded bin id
        match safe_path.remove_file() {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn open_bin_for_write(&self, bin_id: u64) -> std::io::Result<std::fs::File> {
        let path = self.safe_bin_path(bin_id)?;
        if let Some(parent) = path.parent() {
            prepare_storage_bin_data_dir(&self.layout.root, parent)?;
        }
        let safe_path = SafeDiskCachePath::from_path(path);
        match safe_path.open_read_write_file() {
            Ok(file) => Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let file = safe_path.create_new_read_write_file()?;
                if self.layout.preallocate {
                    file.set_len(self.layout.bin_size_bytes.as_u64())?;
                    file.sync_all()?;
                }
                Ok(file)
            }
            Err(error) => Err(error),
        }
    }

    fn open_bin_for_read(&self, bin_id: u64) -> std::io::Result<std::fs::File> {
        let path = self.safe_bin_path(bin_id)?;
        SafeDiskCachePath::from_path(path).open_existing_file()
    }

    fn safe_bin_path(&self, bin_id: u64) -> std::io::Result<PathBuf> {
        if bin_id >= self.layout.max_bins() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin id exceeds configured cache budget",
            ));
        }
        let path = self.layout.bin_path(bin_id);
        if !path.starts_with(&self.layout.root)
            || cache_path_contains_symlink(&self.layout.root, &path)?
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("storage-bin path is unsafe: {}", path.display()),
            ));
        }
        Ok(path)
    }
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StorageBinFreeRange {
    pub offset: u64,
    pub len: u64,
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct StorageBinFreeMap {
    bin_size_bytes: u64,
    max_size_bytes: u64,
    next_bin_id: u64,
    free: BTreeMap<u64, Vec<StorageBinFreeRange>>,
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Eq, PartialEq)]
struct StorageBinIndexEntry {
    combined_key: String,
    location: StorageBinObjectLocation,
    accessed: std::time::SystemTime,
}

#[cfg(feature = "proxy")]
impl StorageBinFreeMap {
    pub fn new(layout: &StorageBinLayoutPlan) -> Self {
        Self {
            bin_size_bytes: layout.bin_size_bytes.as_u64(),
            max_size_bytes: layout.max_size_bytes.as_u64(),
            next_bin_id: 0,
            free: BTreeMap::new(),
        }
    }

    fn from_occupied(
        layout: &StorageBinLayoutPlan,
        entries: &[StorageBinIndexEntry],
    ) -> std::io::Result<Self> {
        let mut map = Self::new(layout);
        let mut occupied = BTreeMap::<u64, Vec<StorageBinFreeRange>>::new();
        for entry in entries {
            let location = entry.location.validate(layout.bin_size_bytes)?;
            let Some(capacity) = map.bin_capacity(location.bin_id) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "storage-bin index references a bin outside the configured cache budget",
                ));
            };
            if location.offset.saturating_add(location.len) > capacity {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "storage-bin index object exceeds bin capacity",
                ));
            }
            occupied
                .entry(location.bin_id)
                .or_default()
                .push(StorageBinFreeRange {
                    offset: location.offset,
                    len: location.len,
                });
            map.next_bin_id = map.next_bin_id.max(location.bin_id.saturating_add(1));
        }

        for (bin_id, ranges) in occupied {
            let capacity = map.bin_capacity(bin_id).unwrap_or(0);
            let mut ranges = ranges;
            ranges.sort_by_key(|range| range.offset);
            let mut cursor = 0_u64;
            for range in ranges {
                if range.offset < cursor {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "storage-bin index contains overlapping object ranges",
                    ));
                }
                if range.offset > cursor {
                    map.insert_free_range(
                        bin_id,
                        StorageBinFreeRange {
                            offset: cursor,
                            len: range.offset - cursor,
                        },
                    )?;
                }
                cursor = range.offset.saturating_add(range.len);
            }
            if cursor < capacity {
                map.insert_free_range(
                    bin_id,
                    StorageBinFreeRange {
                        offset: cursor,
                        len: capacity - cursor,
                    },
                )?;
            }
        }
        Ok(map)
    }

    pub fn allocate(&mut self, len: u64) -> std::io::Result<Option<StorageBinObjectLocation>> {
        if len == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin allocation length must be greater than zero",
            ));
        }
        if len > self.bin_size_bytes {
            return Ok(None);
        }

        if let Some(location) = self.allocate_from_free_ranges(len)? {
            return Ok(Some(location));
        }

        let Some(capacity) = self.bin_capacity(self.next_bin_id) else {
            return Ok(None);
        };
        if len > capacity {
            return Ok(None);
        }

        let bin_id = self.next_bin_id;
        self.next_bin_id = self.next_bin_id.saturating_add(1);
        let remaining = capacity.saturating_sub(len);
        if remaining > 0 {
            self.insert_free_range(
                bin_id,
                StorageBinFreeRange {
                    offset: len,
                    len: remaining,
                },
            )?;
        }
        Ok(Some(StorageBinObjectLocation {
            bin_id,
            offset: 0,
            len,
        }))
    }

    pub fn release(&mut self, location: StorageBinObjectLocation) -> std::io::Result<()> {
        location.validate(ByteSize::from_bytes(self.bin_size_bytes))?;
        let Some(capacity) = self.bin_capacity(location.bin_id) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin release references a bin outside the configured cache budget",
            ));
        };
        let end = location.offset.saturating_add(location.len);
        if end > capacity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin release exceeds the bin capacity",
            ));
        }
        self.insert_free_range(
            location.bin_id,
            StorageBinFreeRange {
                offset: location.offset,
                len: location.len,
            },
        )
    }

    pub fn free_ranges(&self, bin_id: u64) -> &[StorageBinFreeRange] {
        self.free.get(&bin_id).map(Vec::as_slice).unwrap_or(&[])
    }

    fn allocated_size_bytes(&self) -> u64 {
        (0..self.next_bin_id)
            .filter_map(|bin_id| self.bin_capacity(bin_id))
            .fold(0_u64, u64::saturating_add)
    }

    fn free_size_bytes(&self) -> u64 {
        self.free
            .values()
            .flatten()
            .map(|range| range.len)
            .fold(0_u64, u64::saturating_add)
    }

    fn free_range_count(&self) -> u64 {
        self.free
            .values()
            .map(|ranges| u64::try_from(ranges.len()).unwrap_or(u64::MAX))
            .fold(0_u64, u64::saturating_add)
    }

    fn largest_free_range_bytes(&self) -> u64 {
        self.free
            .values()
            .flatten()
            .map(|range| range.len)
            .max()
            .unwrap_or(0)
    }

    fn bin_files(&self) -> u64 {
        self.next_bin_id
    }

    fn reclaim_free_tail_bins(&mut self) -> Vec<u64> {
        let mut reclaimed = Vec::new();
        while self.next_bin_id > 0 {
            let bin_id = self.next_bin_id - 1;
            let Some(capacity) = self.bin_capacity(bin_id) else {
                break;
            };
            let Some(ranges) = self.free.get(&bin_id) else {
                break;
            };
            if ranges.len() != 1 || ranges[0].offset != 0 || ranges[0].len != capacity {
                break;
            }
            self.free.remove(&bin_id);
            self.next_bin_id -= 1;
            reclaimed.push(bin_id);
        }
        reclaimed
    }

    fn allocate_from_free_ranges(
        &mut self,
        len: u64,
    ) -> std::io::Result<Option<StorageBinObjectLocation>> {
        let mut selected = None;
        for (bin_id, ranges) in &self.free {
            if let Some(index) = ranges.iter().position(|range| range.len >= len) {
                selected = Some((*bin_id, index));
                break;
            }
        }

        let Some((bin_id, index)) = selected else {
            return Ok(None);
        };
        let ranges = self.free.get_mut(&bin_id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "storage-bin free range disappeared during allocation",
            )
        })?;
        let range = ranges[index];
        let location = StorageBinObjectLocation {
            bin_id,
            offset: range.offset,
            len,
        };
        if range.len == len {
            ranges.remove(index);
        } else {
            ranges[index] = StorageBinFreeRange {
                offset: range.offset.saturating_add(len),
                len: range.len.saturating_sub(len),
            };
        }
        if ranges.is_empty() {
            self.free.remove(&bin_id);
        }
        Ok(Some(location))
    }

    fn insert_free_range(
        &mut self,
        bin_id: u64,
        range: StorageBinFreeRange,
    ) -> std::io::Result<()> {
        if range.len == 0 {
            return Ok(());
        }
        let Some(capacity) = self.bin_capacity(bin_id) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin free range references a bin outside the configured cache budget",
            ));
        };
        let end = range.offset.checked_add(range.len).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin free range overflows",
            )
        })?;
        if end > capacity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin free range exceeds the bin capacity",
            ));
        }

        let ranges = self.free.entry(bin_id).or_default();
        ranges.push(range);
        ranges.sort_by_key(|range| range.offset);
        let mut merged: Vec<StorageBinFreeRange> = Vec::with_capacity(ranges.len());
        for range in ranges.drain(..) {
            if let Some(last) = merged.last_mut() {
                let last_end = last.offset.saturating_add(last.len);
                if range.offset <= last_end {
                    let range_end = range.offset.saturating_add(range.len);
                    last.len = range_end.saturating_sub(last.offset).max(last.len);
                    continue;
                }
            }
            merged.push(range);
        }
        *ranges = merged;
        Ok(())
    }

    fn bin_capacity(&self, bin_id: u64) -> Option<u64> {
        let start = bin_id.checked_mul(self.bin_size_bytes)?;
        if start >= self.max_size_bytes {
            return None;
        }
        Some(self.bin_size_bytes.min(self.max_size_bytes - start))
    }
}

#[cfg(feature = "proxy")]
fn parse_storage_bin_manifest_u64(line: Option<&str>, key: &str) -> std::io::Result<u64> {
    parse_storage_bin_manifest_value(line, key)?
        .parse::<u64>()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid storage-bin manifest {key}: {error}"),
            )
        })
}

#[cfg(feature = "proxy")]
fn parse_storage_bin_manifest_usize(line: Option<&str>, key: &str) -> std::io::Result<usize> {
    parse_storage_bin_manifest_value(line, key)?
        .parse::<usize>()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid storage-bin manifest {key}: {error}"),
            )
        })
}

#[cfg(feature = "proxy")]
fn parse_storage_bin_manifest_bool(line: Option<&str>, key: &str) -> std::io::Result<bool> {
    parse_storage_bin_manifest_value(line, key)?
        .parse::<bool>()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid storage-bin manifest {key}: {error}"),
            )
        })
}

#[cfg(feature = "proxy")]
fn parse_storage_bin_manifest_value<'a>(
    line: Option<&'a str>,
    key: &str,
) -> std::io::Result<&'a str> {
    let Some(line) = line else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("missing storage-bin manifest {key}"),
        ));
    };
    let Some(value) = line.strip_prefix(&format!("{key}=")) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("missing storage-bin manifest {key}"),
        ));
    };
    Ok(value)
}

#[cfg(feature = "proxy")]
fn write_storage_bin_range(
    file: &mut std::fs::File,
    offset: u64,
    bytes: &[u8],
) -> std::io::Result<()> {
    use std::io::{Seek as _, Write as _};

    file.seek(std::io::SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(feature = "proxy")]
fn read_storage_bin_range(
    file: &mut std::fs::File,
    offset: u64,
    len: u64,
) -> std::io::Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _};

    let capacity = usize::try_from(len).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "storage-bin object is too large for this platform",
        )
    })?;
    file.seek(std::io::SeekFrom::Start(offset))?;
    let mut bytes = vec![0; capacity];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheRequest<'a> {
    pub method: &'a str,
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub query: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub struct StaticCacheRequest<'a> {
    pub method: &'a str,
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub file_identity: &'a str,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct CacheKey(String);

impl CacheKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachedImageObject {
    pub status: u16,
    pub headers: Vec<CachedHeader>,
    pub body: Arc<[u8]>,
    pub fresh_until_unix_secs: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachedHeader {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MemoryCacheStats {
    pub entries: u64,
    pub weighted_size_bytes: u64,
    pub max_size_bytes: ByteSize,
    pub max_object_bytes: ByteSize,
    #[cfg(feature = "proxy")]
    pub purge_index_entries: u64,
    #[cfg(feature = "proxy")]
    pub purge_index_max_entries: u64,
    #[cfg(feature = "proxy")]
    pub activity: CacheActivityStats,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DiskCacheStats {
    pub backend: &'static str,
    pub entries: u64,
    pub size_bytes: u64,
    pub allocated_size_bytes: u64,
    pub free_size_bytes: u64,
    pub free_range_count: u64,
    pub largest_free_range_bytes: u64,
    pub bin_files: u64,
    pub max_size_bytes: ByteSize,
    pub max_object_bytes: ByteSize,
    pub purge_index_entries: u64,
    pub purge_index_max_entries: u64,
    pub activity: CacheActivityStats,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TieredCacheStats {
    pub memory: MemoryCacheStats,
    pub disk: DiskCacheStats,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheObjectHeaderValue {
    pub name: String,
    pub value: String,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheObjectMetadata {
    pub tier: CacheObjectTier,
    pub purge_indexed: bool,
    pub status: u16,
    pub fresh: bool,
    pub freshness_state: CacheObjectFreshnessState,
    pub serve_stale_while_revalidate: bool,
    pub serve_stale_if_error: bool,
    pub body_bytes: u64,
    pub weight_bytes: u64,
    pub created_unix_secs: Option<u64>,
    pub updated_unix_secs: Option<u64>,
    pub fresh_until_unix_secs: Option<u64>,
    pub age_secs: u64,
    pub fresh_ttl_secs: u64,
    pub stale_while_revalidate_secs: u32,
    pub stale_if_error_secs: u32,
    pub cache_tags: Vec<String>,
    pub header_names: Vec<String>,
    pub header_values: Vec<CacheObjectHeaderValue>,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CacheObjectFreshnessState {
    Fresh,
    Stale,
    Expired,
}

#[cfg(feature = "proxy")]
impl CacheObjectFreshnessState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Expired => "expired",
        }
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CacheObjectTier {
    Memory,
    Disk,
}

#[cfg(feature = "proxy")]
impl CacheObjectTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Disk => "disk",
        }
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct CacheActivityStats {
    pub hits: u64,
    pub misses: u64,
    pub stores: u64,
    pub store_refusals: u64,
    pub evictions: u64,
    pub purges: u64,
}

#[cfg(feature = "proxy")]
#[derive(Debug)]
struct CacheActivityCounters {
    tier: &'static str,
    #[cfg(feature = "metrics")]
    scope: Option<CacheActivityScope>,
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    stores: std::sync::atomic::AtomicU64,
    store_refusals: std::sync::atomic::AtomicU64,
    evictions: std::sync::atomic::AtomicU64,
    purges: std::sync::atomic::AtomicU64,
}

#[cfg(all(feature = "proxy", feature = "metrics"))]
#[derive(Debug, Clone, Eq, PartialEq)]
struct CacheActivityScope {
    vhost: String,
    route: Option<String>,
}

#[cfg(feature = "proxy")]
impl CacheActivityCounters {
    fn new(tier: &'static str) -> Self {
        Self {
            tier,
            #[cfg(feature = "metrics")]
            scope: None,
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
            stores: std::sync::atomic::AtomicU64::new(0),
            store_refusals: std::sync::atomic::AtomicU64::new(0),
            evictions: std::sync::atomic::AtomicU64::new(0),
            purges: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn new_with_metric_scope(tier: &'static str, vhost: &str, route: Option<&str>) -> Self {
        let counters = Self::new(tier);
        #[cfg(feature = "metrics")]
        let counters = Self {
            scope: Some(CacheActivityScope {
                vhost: vhost.to_owned(),
                route: route.map(str::to_owned),
            }),
            ..counters
        };
        #[cfg(not(feature = "metrics"))]
        let _ = (vhost, route);
        counters
    }

    fn snapshot(&self) -> CacheActivityStats {
        CacheActivityStats {
            hits: self.hits.load(std::sync::atomic::Ordering::Relaxed),
            misses: self.misses.load(std::sync::atomic::Ordering::Relaxed),
            stores: self.stores.load(std::sync::atomic::Ordering::Relaxed),
            store_refusals: self
                .store_refusals
                .load(std::sync::atomic::Ordering::Relaxed),
            evictions: self.evictions.load(std::sync::atomic::Ordering::Relaxed),
            purges: self.purges.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    fn reset(&self) {
        self.hits.store(0, std::sync::atomic::Ordering::Relaxed);
        self.misses.store(0, std::sync::atomic::Ordering::Relaxed);
        self.stores.store(0, std::sync::atomic::Ordering::Relaxed);
        self.store_refusals
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.evictions
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.purges.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    fn hit(&self) {
        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.record("hit");
    }

    fn miss(&self) {
        self.misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.record("miss");
    }

    fn store(&self) {
        self.stores
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.record("store");
    }

    fn store_refusal(&self) {
        self.store_refusals
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.record("store_refusal");
    }

    fn eviction(&self) {
        self.evictions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.record("eviction");
    }

    fn purge(&self) {
        self.purges
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.record("purge");
    }

    fn record(&self, _event: &'static str) {
        #[cfg(feature = "metrics")]
        {
            crate::metrics::record_cache_activity(self.tier, _event);
            if let Some(scope) = &self.scope {
                crate::metrics::record_cache_activity_scope(
                    scope.vhost.as_str(),
                    scope.route.as_deref(),
                    self.tier,
                    _event,
                );
            }
        }
        #[cfg(not(feature = "metrics"))]
        let _ = self.tier;
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CacheStoreError {
    ObjectTooLarge {
        object_bytes: u64,
        max_object_bytes: ByteSize,
    },
    ObjectTooHeavy {
        object_bytes: u64,
    },
}

#[derive(Clone)]
pub struct MemoryImageCache {
    inner: moka::sync::Cache<String, StoredImageObject>,
    max_size_bytes: ByteSize,
    max_object_bytes: ByteSize,
}

impl std::fmt::Debug for MemoryImageCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemoryImageCache")
            .field("max_size_bytes", &self.max_size_bytes)
            .field("max_object_bytes", &self.max_object_bytes)
            .finish()
    }
}

impl MemoryImageCache {
    pub fn from_plan(plan: MemoryTierPlan) -> Self {
        Self::new(plan.max_size_bytes, plan.max_object_bytes)
    }

    pub fn new(max_size_bytes: ByteSize, max_object_bytes: ByteSize) -> Self {
        let inner = moka::sync::Cache::builder()
            .max_capacity(max_size_bytes.as_u64())
            .weigher(|_key: &String, value: &StoredImageObject| value.weight)
            .build();

        Self {
            inner,
            max_size_bytes,
            max_object_bytes,
        }
    }

    pub fn get(&self, key: &CacheKey) -> Option<CachedImageObject> {
        self.inner.get(key.as_str()).map(|stored| stored.object)
    }

    pub fn put(&self, key: &CacheKey, object: CachedImageObject) -> Result<(), CacheStoreError> {
        let object_bytes = cached_object_weight(&object);
        if object_bytes > self.max_object_bytes.as_u64() {
            return Err(CacheStoreError::ObjectTooLarge {
                object_bytes,
                max_object_bytes: self.max_object_bytes,
            });
        }
        let weight = u32::try_from(object_bytes)
            .map_err(|_| CacheStoreError::ObjectTooHeavy { object_bytes })?;

        self.inner.insert(
            key.as_str().to_owned(),
            StoredImageObject { object, weight },
        );
        Ok(())
    }

    pub fn purge(&self, key: &CacheKey) {
        self.inner.invalidate(key.as_str());
    }

    pub fn flush_pending_evictions(&self) {
        self.inner.run_pending_tasks();
    }

    pub fn stats(&self) -> MemoryCacheStats {
        self.flush_pending_evictions();
        MemoryCacheStats {
            entries: self.inner.entry_count(),
            weighted_size_bytes: self.inner.weighted_size(),
            max_size_bytes: self.max_size_bytes,
            max_object_bytes: self.max_object_bytes,
            #[cfg(feature = "proxy")]
            purge_index_entries: 0,
            #[cfg(feature = "proxy")]
            purge_index_max_entries: 0,
            #[cfg(feature = "proxy")]
            activity: CacheActivityStats::default(),
        }
    }
}

#[derive(Clone)]
struct StoredImageObject {
    object: CachedImageObject,
    weight: u32,
}

pub fn memory_image_cache_from_config(config: &CacheConfig) -> Option<MemoryImageCache> {
    storage_plan(config).memory.map(MemoryImageCache::from_plan)
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone)]
pub struct CachePurgeIndex {
    inner: Arc<RwLock<CachePurgeIndexInner>>,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Default)]
struct CachePurgeIndexInner {
    entries: HashMap<String, CachePurgeIndexEntry>,
    order: VecDeque<String>,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CachePurgeIndexEntry {
    pub combined_key: String,
    pub primary_key: String,
    pub user_tag: String,
    pub path: Option<String>,
    pub cache_tags: Vec<String>,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct CacheIndexedPurgeResult {
    pub matched: usize,
    pub purged: usize,
    pub truncated: bool,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct CacheStalePurgeResult {
    pub scanned: usize,
    pub stale: usize,
    pub purged: usize,
    pub truncated: bool,
}

#[cfg(feature = "proxy")]
impl CachePurgeIndex {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CachePurgeIndexInner::default())),
        }
    }

    pub fn insert(&self, combined_key: String, primary_key: String, user_tag: String) {
        let path = cache_primary_component(&primary_key, "path");
        self.insert_with_path_and_tags(combined_key, primary_key, user_tag, path, Vec::new());
    }

    pub fn insert_with_path(
        &self,
        combined_key: String,
        primary_key: String,
        user_tag: String,
        path: Option<String>,
    ) {
        self.insert_with_path_and_tags(combined_key, primary_key, user_tag, path, Vec::new());
    }

    pub fn insert_with_path_and_tags(
        &self,
        combined_key: String,
        primary_key: String,
        user_tag: String,
        path: Option<String>,
        cache_tags: Vec<String>,
    ) {
        let Ok(mut inner) = self.inner.write() else {
            return;
        };

        if inner.entries.contains_key(&combined_key) {
            inner.entries.insert(
                combined_key.clone(),
                CachePurgeIndexEntry {
                    combined_key,
                    primary_key,
                    user_tag,
                    path,
                    cache_tags,
                },
            );
            return;
        }

        inner.order.push_back(combined_key.clone());
        inner.entries.insert(
            combined_key.clone(),
            CachePurgeIndexEntry {
                combined_key,
                primary_key,
                user_tag,
                path,
                cache_tags,
            },
        );
    }

    pub fn remove_combined(&self, combined_key: &str) -> bool {
        let Ok(mut inner) = self.inner.write() else {
            return false;
        };
        let removed = inner.entries.remove(combined_key).is_some();
        if removed {
            inner.order.retain(|candidate| candidate != combined_key);
        }
        removed
    }

    pub fn contains_combined(&self, combined_key: &str) -> bool {
        let Ok(inner) = self.inner.read() else {
            return false;
        };
        inner.entries.contains_key(combined_key)
    }

    fn move_combined_keys_to_back(&self, combined_keys: &[String]) {
        if combined_keys.is_empty() {
            return;
        }
        let Ok(mut inner) = self.inner.write() else {
            return;
        };
        let candidates = combined_keys
            .iter()
            .filter(|key| inner.entries.contains_key(key.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return;
        }
        let candidate_set = candidates.iter().cloned().collect::<HashSet<_>>();
        inner.order.retain(|key| !candidate_set.contains(key));
        inner.order.extend(candidates);
    }

    pub fn combined_keys_for_primary(&self, primary_key: &str) -> Vec<String> {
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };
        inner
            .entries
            .values()
            .filter(|entry| entry.primary_key == primary_key)
            .map(|entry| entry.combined_key.clone())
            .collect()
    }

    pub fn entries_with_prefix(&self, prefix: &str, limit: usize) -> Vec<CachePurgeIndexEntry> {
        if prefix.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.entries_matching(limit, |entry| entry.combined_key.starts_with(prefix))
    }

    pub fn entries_for_user_tag(&self, user_tag: &str, limit: usize) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.entries_matching(limit, |entry| entry.user_tag == user_tag)
    }

    pub fn entries_for_user_tag_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || path_prefix.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.entries_matching(limit, |entry| {
            entry.user_tag == user_tag
                && entry
                    .path
                    .as_deref()
                    .is_some_and(|path| path.starts_with(path_prefix))
        })
    }

    pub fn entries_for_user_tag_path_exact(
        &self,
        user_tag: &str,
        path_exact: &str,
        limit: usize,
    ) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || path_exact.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.entries_matching(limit, |entry| {
            entry.user_tag == user_tag
                && entry.path.as_deref().is_some_and(|path| path == path_exact)
        })
    }

    pub fn entries_for_user_tag_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || path_pattern.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.entries_matching(limit, |entry| {
            entry.user_tag == user_tag
                && entry
                    .path
                    .as_deref()
                    .is_some_and(|path| cache_path_wildcard_matches(path_pattern, path))
        })
    }

    pub fn entries_for_user_tag_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
    ) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || cache_tag.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.entries_matching(limit, |entry| {
            entry.user_tag == user_tag && entry.cache_tags.iter().any(|tag| tag == cache_tag)
        })
    }

    fn entries_matching(
        &self,
        limit: usize,
        matches: impl Fn(&CachePurgeIndexEntry) -> bool,
    ) -> Vec<CachePurgeIndexEntry> {
        if limit == 0 {
            return Vec::new();
        }
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };
        inner
            .order
            .iter()
            .filter_map(|key| inner.entries.get(key))
            .filter(|entry| matches(entry))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        let Ok(inner) = self.inner.read() else {
            return 0;
        };
        inner.entries.len()
    }

    pub fn max_entries(&self) -> usize {
        usize::MAX
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(feature = "proxy")]
impl Default for CachePurgeIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "proxy")]
fn cache_path_wildcard_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let mut rest = path;
    let mut first_part = true;

    for part in pattern.split('*').filter(|part| !part.is_empty()) {
        if first_part && anchored_start {
            let Some(after_prefix) = rest.strip_prefix(part) else {
                return false;
            };
            rest = after_prefix;
        } else {
            let Some(index) = rest.find(part) else {
                return false;
            };
            rest = &rest[index + part.len()..];
        }
        first_part = false;
    }

    !anchored_end || pattern.ends_with('*') || rest.is_empty()
}

#[cfg(feature = "proxy")]
fn cache_primary_component(primary_key: &str, name: &str) -> Option<String> {
    let mut rest = primary_key
        .strip_prefix("fluxheim-image-v1;")
        .unwrap_or(primary_key);
    while !rest.is_empty() {
        let (component, after_component) = rest.split_once(':')?;
        let (len, after_len) = after_component.split_once(':')?;
        let len = len.parse::<usize>().ok()?;
        let bytes = after_len.as_bytes();
        if bytes.len() < len {
            return None;
        }
        let value = std::str::from_utf8(&bytes[..len]).ok()?;
        let after_value = &after_len[len..];
        rest = after_value.strip_prefix(';')?;
        if component == name {
            return Some(value.to_owned());
        }
    }
    None
}

#[cfg(feature = "proxy")]
#[derive(Debug)]
pub struct PingoraMemoryStorage {
    inner: moka::sync::Cache<String, PingoraStoredObject>,
    purge_index: CachePurgeIndex,
    max_size_bytes: ByteSize,
    max_object_bytes: ByteSize,
    cache_tag_headers: Arc<[String]>,
    activity: CacheActivityCounters,
}

#[cfg(feature = "proxy")]
impl PingoraMemoryStorage {
    pub fn from_plan(plan: MemoryTierPlan) -> Self {
        Self::new_with_cache_tag_headers(
            plan.max_size_bytes,
            plan.max_object_bytes,
            plan.cache_tag_headers,
        )
    }

    pub fn from_plan_with_metric_scope(
        plan: MemoryTierPlan,
        vhost: &str,
        route: Option<&str>,
    ) -> Self {
        Self::new_with_metric_scope(
            plan.max_size_bytes,
            plan.max_object_bytes,
            plan.cache_tag_headers,
            vhost,
            route,
        )
    }

    pub fn new(max_size_bytes: ByteSize, max_object_bytes: ByteSize) -> Self {
        Self::new_with_cache_tag_headers(
            max_size_bytes,
            max_object_bytes,
            default_cache_tag_headers_for_storage(),
        )
    }

    fn new_with_cache_tag_headers(
        max_size_bytes: ByteSize,
        max_object_bytes: ByteSize,
        cache_tag_headers: Vec<String>,
    ) -> Self {
        Self::new_with_activity(
            max_size_bytes,
            max_object_bytes,
            cache_tag_headers,
            CacheActivityCounters::new("memory"),
        )
    }

    fn new_with_metric_scope(
        max_size_bytes: ByteSize,
        max_object_bytes: ByteSize,
        cache_tag_headers: Vec<String>,
        vhost: &str,
        route: Option<&str>,
    ) -> Self {
        Self::new_with_activity(
            max_size_bytes,
            max_object_bytes,
            cache_tag_headers,
            CacheActivityCounters::new_with_metric_scope("memory", vhost, route),
        )
    }

    fn new_with_activity(
        max_size_bytes: ByteSize,
        max_object_bytes: ByteSize,
        cache_tag_headers: Vec<String>,
        activity: CacheActivityCounters,
    ) -> Self {
        let purge_index = CachePurgeIndex::new();
        let eviction_purge_index = purge_index.clone();
        let inner = moka::sync::Cache::builder()
            .max_capacity(max_size_bytes.as_u64())
            .weigher(|_key: &String, value: &PingoraStoredObject| value.weight)
            .eviction_listener(move |key, _value, _cause| {
                eviction_purge_index.remove_combined(key.as_str());
            })
            .build();
        Self {
            inner,
            purge_index,
            max_size_bytes,
            max_object_bytes,
            cache_tag_headers: Arc::from(cache_tag_headers),
            activity,
        }
    }

    pub fn max_object_bytes(&self) -> ByteSize {
        self.max_object_bytes
    }

    pub fn stats(&self) -> MemoryCacheStats {
        self.inner.run_pending_tasks();
        MemoryCacheStats {
            entries: self.inner.entry_count(),
            weighted_size_bytes: self.inner.weighted_size(),
            max_size_bytes: self.max_size_bytes,
            max_object_bytes: self.max_object_bytes,
            purge_index_entries: self.purge_index.len() as u64,
            purge_index_max_entries: self.purge_index.max_entries() as u64,
            activity: self.activity.snapshot(),
        }
    }

    pub fn reset_activity(&self) {
        self.activity.reset();
    }

    pub fn purge_cache_key(&self, key: &pingora::cache::CacheKey) -> bool {
        let primary = key.primary();
        let combined = key.combined();
        let mut keys = self.purge_index.combined_keys_for_primary(primary.as_str());
        if !keys.iter().any(|candidate| candidate == &combined) {
            keys.push(combined.clone());
        }
        let mut indexed = keys.iter().cloned().collect::<HashSet<_>>();
        keys.extend(
            self.inner
                .iter()
                .filter_map(|(candidate_key, object)| {
                    let candidate_key = candidate_key.as_ref();
                    (object.primary_key.as_deref() == Some(primary.as_str())
                        || candidate_key == combined.as_str())
                    .then(|| candidate_key.clone())
                })
                .filter(|candidate_key| indexed.insert(candidate_key.clone())),
        );

        let mut existed = false;
        for key in keys {
            existed |= self.inner.get(&key).is_some();
            self.inner.invalidate(&key);
            self.purge_index.remove_combined(&key);
        }
        self.inner.run_pending_tasks();
        if existed {
            self.activity.purge();
        }
        existed
    }

    pub fn purge_indexed_user_tag(&self, user_tag: &str, limit: usize) -> CacheIndexedPurgeResult {
        let entries = self.indexed_entries_for_user_tag(user_tag, limit.saturating_add(1));
        self.purge_indexed_entries(entries, limit)
    }

    pub fn soft_purge_indexed_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let entries = self.indexed_entries_for_user_tag(user_tag, limit.saturating_add(1));
        self.soft_purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> CacheIndexedPurgeResult {
        let entries =
            self.indexed_entries_for_path_prefix(user_tag, path_prefix, limit.saturating_add(1));
        self.purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_path_exact(
        &self,
        user_tag: &str,
        path_exact: &str,
        limit: usize,
    ) -> CacheIndexedPurgeResult {
        let entries =
            self.indexed_entries_for_path_exact(user_tag, path_exact, limit.saturating_add(1));
        self.purge_indexed_entries(entries, limit)
    }

    pub fn soft_purge_indexed_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let entries =
            self.indexed_entries_for_path_prefix(user_tag, path_prefix, limit.saturating_add(1));
        self.soft_purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> CacheIndexedPurgeResult {
        let entries =
            self.indexed_entries_for_path_pattern(user_tag, path_pattern, limit.saturating_add(1));
        self.purge_indexed_entries(entries, limit)
    }

    pub fn soft_purge_indexed_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let entries =
            self.indexed_entries_for_path_pattern(user_tag, path_pattern, limit.saturating_add(1));
        self.soft_purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
    ) -> CacheIndexedPurgeResult {
        let entries =
            self.indexed_entries_for_cache_tag(user_tag, cache_tag, limit.saturating_add(1));
        self.purge_indexed_entries(entries, limit)
    }

    pub fn soft_purge_indexed_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let entries =
            self.indexed_entries_for_cache_tag(user_tag, cache_tag, limit.saturating_add(1));
        self.soft_purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_stale_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
        dry_run: bool,
    ) -> pingora::Result<CacheStalePurgeResult> {
        let mut entries = self.indexed_entries_for_user_tag(user_tag, limit.saturating_add(1));
        let truncated = entries.len() > limit;
        entries.truncate(limit);

        let now = std::time::SystemTime::now();
        let scanned = entries.len();
        let mut stale = 0;
        let mut purged = 0;
        let mut deferred_fresh_keys = Vec::new();

        for entry in &entries {
            let Some(object) = self.inner.get(&entry.combined_key) else {
                self.purge_index.remove_combined(&entry.combined_key);
                continue;
            };
            let meta = CacheMeta::deserialize(&object.internal_meta, &object.response_header)?;
            if meta.is_fresh(now) {
                if truncated && !dry_run {
                    deferred_fresh_keys.push(entry.combined_key.clone());
                }
                continue;
            }
            stale += 1;
            if dry_run {
                continue;
            }
            self.inner.invalidate(&entry.combined_key);
            self.purge_index.remove_combined(&entry.combined_key);
            purged += 1;
        }
        if truncated && !dry_run {
            self.purge_index
                .move_combined_keys_to_back(&deferred_fresh_keys);
        }
        self.inner.run_pending_tasks();
        if purged > 0 {
            self.activity.purge();
        }

        Ok(CacheStalePurgeResult {
            scanned,
            stale,
            purged,
            truncated,
        })
    }

    fn purge_indexed_entries(
        &self,
        mut entries: Vec<CachePurgeIndexEntry>,
        limit: usize,
    ) -> CacheIndexedPurgeResult {
        let truncated = entries.len() > limit;
        entries.truncate(limit);

        let mut purged = 0;
        for entry in &entries {
            if self.inner.get(&entry.combined_key).is_some() {
                purged += 1;
            }
            self.inner.invalidate(&entry.combined_key);
            self.purge_index.remove_combined(&entry.combined_key);
        }
        self.inner.run_pending_tasks();
        if purged > 0 {
            self.activity.purge();
        }

        CacheIndexedPurgeResult {
            matched: entries.len(),
            purged,
            truncated,
        }
    }

    fn indexed_entries_for_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
    ) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.indexed_entries_matching(
            self.purge_index.entries_for_user_tag(user_tag, limit),
            limit,
            |entry| entry.user_tag == user_tag,
        )
    }

    fn indexed_entries_for_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || path_prefix.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.indexed_entries_matching(
            self.purge_index
                .entries_for_user_tag_path_prefix(user_tag, path_prefix, limit),
            limit,
            |entry| {
                entry.user_tag == user_tag
                    && entry
                        .path
                        .as_deref()
                        .is_some_and(|path| path.starts_with(path_prefix))
            },
        )
    }

    fn indexed_entries_for_path_exact(
        &self,
        user_tag: &str,
        path_exact: &str,
        limit: usize,
    ) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || path_exact.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.indexed_entries_matching(
            self.purge_index
                .entries_for_user_tag_path_exact(user_tag, path_exact, limit),
            limit,
            |entry| {
                entry.user_tag == user_tag
                    && entry.path.as_deref().is_some_and(|path| path == path_exact)
            },
        )
    }

    fn indexed_entries_for_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || path_pattern.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.indexed_entries_matching(
            self.purge_index
                .entries_for_user_tag_path_pattern(user_tag, path_pattern, limit),
            limit,
            |entry| {
                entry.user_tag == user_tag
                    && entry
                        .path
                        .as_deref()
                        .is_some_and(|path| cache_path_wildcard_matches(path_pattern, path))
            },
        )
    }

    fn indexed_entries_for_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
    ) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || cache_tag.is_empty() || limit == 0 {
            return Vec::new();
        }
        self.indexed_entries_matching(
            self.purge_index
                .entries_for_user_tag_cache_tag(user_tag, cache_tag, limit),
            limit,
            |entry| {
                entry.user_tag == user_tag && entry.cache_tags.iter().any(|tag| tag == cache_tag)
            },
        )
    }

    fn indexed_entries_matching(
        &self,
        mut entries: Vec<CachePurgeIndexEntry>,
        limit: usize,
        matches: impl Fn(&CachePurgeIndexEntry) -> bool,
    ) -> Vec<CachePurgeIndexEntry> {
        if limit == 0 {
            return Vec::new();
        }
        let mut seen = entries
            .iter()
            .map(|entry| entry.combined_key.clone())
            .collect::<HashSet<_>>();
        for (combined_key, object) in self.inner.iter() {
            if entries.len() >= limit {
                break;
            }
            let combined_key = combined_key.as_ref();
            if seen.contains(combined_key) {
                continue;
            }
            let Some(entry) = cache_purge_entry_from_stored_object(combined_key, &object) else {
                continue;
            };
            if !matches(&entry) {
                continue;
            }
            seen.insert(entry.combined_key.clone());
            entries.push(entry);
        }
        entries
    }

    fn soft_purge_indexed_entries(
        &self,
        mut entries: Vec<CachePurgeIndexEntry>,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let truncated = entries.len() > limit;
        entries.truncate(limit);

        let mut purged = 0;
        for entry in &entries {
            let Some(mut object) = self.inner.get(&entry.combined_key) else {
                self.purge_index.remove_combined(&entry.combined_key);
                continue;
            };
            let meta = stale_cache_meta(&object.internal_meta, &object.response_header)?;
            let (internal_meta, response_header) = meta.serialize()?;
            let weight_bytes =
                pingora_object_weight(&internal_meta, &response_header, &object.body);
            if weight_bytes > self.max_object_bytes.as_u64() {
                self.inner.invalidate(&entry.combined_key);
                self.purge_index.remove_combined(&entry.combined_key);
                self.activity.store_refusal();
                continue;
            }
            let weight = u32::try_from(weight_bytes).map_err(|_| {
                self.activity.store_refusal();
                Error::because(
                    ErrorType::InternalError,
                    "cache object weight exceeds moka object weight limit",
                    std::io::Error::other("cache object too heavy"),
                )
            })?;

            object.internal_meta = internal_meta;
            object.response_header = response_header;
            object.weight = weight;
            self.inner.insert(entry.combined_key.clone(), object);
            purged += 1;
        }
        self.inner.run_pending_tasks();
        if purged > 0 {
            self.activity.purge();
        }

        Ok(CacheIndexedPurgeResult {
            matched: entries.len(),
            purged,
            truncated,
        })
    }

    fn lookup_object(&self, key: &pingora::cache::CacheKey) -> Option<PingoraStoredObject> {
        self.inner.get(&key.combined())
    }

    pub fn inspect_cache_key(
        &self,
        key: &pingora::cache::CacheKey,
    ) -> pingora::Result<Option<CacheObjectMetadata>> {
        let Some(object) = self.lookup_object(key) else {
            return Ok(None);
        };
        let purge_indexed = self.purge_index.contains_combined(&key.combined());
        cache_object_metadata(CacheObjectTier::Memory, purge_indexed, &object)
    }

    fn put_object(
        &self,
        store_key: PingoraStoreKey,
        meta: CacheMeta,
        body: Arc<[u8]>,
    ) -> pingora::Result<usize> {
        let cache_tags = cache_tags_from_meta(&meta, &self.cache_tag_headers);
        let (internal_meta, response_header) = meta.serialize()?;
        let mut store_key = store_key;
        store_key.cache_tags = cache_tags;
        Ok(self
            .put_serialized_object(store_key, internal_meta, response_header, body)?
            .unwrap_or(0))
    }

    fn put_serialized_object(
        &self,
        store_key: PingoraStoreKey,
        internal_meta: Vec<u8>,
        response_header: Vec<u8>,
        body: Arc<[u8]>,
    ) -> pingora::Result<Option<usize>> {
        let weight_bytes = pingora_object_weight(&internal_meta, &response_header, &body);
        if weight_bytes > self.max_object_bytes.as_u64() {
            self.activity.store_refusal();
            return Ok(None);
        }
        let weight = u32::try_from(weight_bytes).map_err(|_| {
            self.activity.store_refusal();
            Error::because(
                ErrorType::InternalError,
                "cache object weight exceeds moka object weight limit",
                std::io::Error::other("cache object too heavy"),
            )
        })?;

        let body_len = body.len();
        let combined_key = store_key.combined.clone();
        self.inner.insert(
            store_key.combined,
            PingoraStoredObject {
                combined_key: Some(combined_key.clone()),
                primary_key: Some(store_key.primary.clone()),
                user_tag: Some(store_key.user_tag.clone()),
                index_path: store_key.index_path.clone(),
                cache_tags: store_key.cache_tags.clone(),
                internal_meta,
                response_header,
                body,
                weight,
            },
        );
        self.purge_index.insert_with_path_and_tags(
            combined_key,
            store_key.primary,
            store_key.user_tag,
            store_key.index_path,
            store_key.cache_tags,
        );
        self.activity.store();
        Ok(Some(body_len))
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug)]
pub struct PingoraDiskStorage {
    root: PathBuf,
    purge_index: CachePurgeIndex,
    disk_index: DiskObjectIndex,
    checkpoint_state: Arc<Mutex<DiskIndexCheckpointState>>,
    max_size_bytes: ByteSize,
    max_object_bytes: ByteSize,
    cache_tag_headers: Arc<[String]>,
    encryption: Option<DiskCacheEncryption>,
    activity: CacheActivityCounters,
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
pub struct StorageBinDiskStorage {
    layout: StorageBinLayoutPlan,
    files: StorageBinFileSet,
    free_map: Mutex<StorageBinFreeMap>,
    objects: Arc<RwLock<HashMap<String, StorageBinObjectEntry>>>,
    index_state: Arc<Mutex<DiskIndexCheckpointState>>,
    purge_index: CachePurgeIndex,
    max_size_bytes: ByteSize,
    max_object_bytes: ByteSize,
    cache_tag_headers: Arc<[String]>,
    encryption: Option<DiskCacheEncryption>,
    activity: CacheActivityCounters,
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone)]
struct StorageBinObjectEntry {
    location: StorageBinObjectLocation,
    size: u64,
    accessed: std::time::SystemTime,
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
impl StorageBinDiskStorage {
    pub fn from_plan(plan: DiskTierPlan) -> std::io::Result<Self> {
        Self::from_plan_with_activity(plan, CacheActivityCounters::new("disk"))
    }

    pub fn from_plan_with_metric_scope(
        plan: DiskTierPlan,
        vhost: &str,
        route: Option<&str>,
    ) -> std::io::Result<Self> {
        Self::from_plan_with_activity(
            plan,
            CacheActivityCounters::new_with_metric_scope("disk", vhost, route),
        )
    }

    fn from_plan_with_activity(
        plan: DiskTierPlan,
        activity: CacheActivityCounters,
    ) -> std::io::Result<Self> {
        if plan.backend != CacheDiskBackend::StorageBin {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "StorageBinDiskStorage requires cache.disk.backend = \"storage-bin\"",
            ));
        }
        let encryption = DiskCacheEncryption::from_config(&plan.encryption).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("storage-bin {} encryption: {error}", plan.path.display()),
            )
        })?;
        let mut layout = StorageBinLayoutPlan::from_disk_plan(&plan).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin layout requires storage-bin disk backend",
            )
        })?;
        let root = prepare_disk_cache_root(&layout.root).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("storage-bin root {}: {error}", layout.root.display()),
            )
        })?;
        layout = StorageBinLayoutPlan {
            root: root.clone(),
            manifest_path: root.join(STORAGE_BIN_MANIFEST_FILENAME),
            data_dir: root.join(STORAGE_BIN_DATA_DIR),
            ..layout
        };
        prepare_storage_bin_layout(&layout).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("storage-bin layout {}: {error}", layout.root.display()),
            )
        })?;
        let recovered_entries = read_storage_bin_index(&layout).map_err(|error| {
            let hint = if error.kind() == std::io::ErrorKind::PermissionDenied {
                "; ensure the cache directory, storage-bin index, and bin files are owned and readable/writable by the Fluxheim runtime user"
            } else {
                ""
            };
            std::io::Error::new(
                error.kind(),
                format!(
                    "storage-bin index {}: {error}{hint}",
                    storage_bin_index_path(&layout.root).display()
                ),
            )
        })?;
        let mut recovered_objects = HashMap::new();
        let recovered_purge_index = CachePurgeIndex::new();
        let mut valid_entries = Vec::new();
        for entry in recovered_entries {
            let object = match read_storage_bin_index_entry_object(
                &layout,
                plan.max_object_bytes,
                encryption.as_ref(),
                &entry,
            ) {
                Ok(object) => object,
                Err(_) => continue,
            };
            if object.combined_key.as_deref() != Some(entry.combined_key.as_str()) {
                continue;
            }
            if let Some(primary_key) = object.primary_key.clone() {
                let user_tag = object.user_tag.unwrap_or_default();
                let path = object
                    .index_path
                    .or_else(|| cache_primary_component(&primary_key, "path"));
                recovered_purge_index.insert_with_path_and_tags(
                    entry.combined_key.clone(),
                    primary_key,
                    user_tag,
                    path,
                    object.cache_tags,
                );
            }
            recovered_objects.insert(
                entry.combined_key.clone(),
                StorageBinObjectEntry {
                    location: entry.location,
                    size: entry.location.len,
                    accessed: entry.accessed,
                },
            );
            valid_entries.push(entry);
        }
        // Loading storage must not rewrite the index. Commands such as
        // --validate-config or acme-renew may be run by an operator as root,
        // while the service itself runs as the fluxheim user. Rewriting here
        // can leave the index owned by the wrong user and break the next
        // service start. The next cache mutation writes a compact index.
        let free_map =
            StorageBinFreeMap::from_occupied(&layout, &valid_entries).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("storage-bin free map {}: {error}", layout.root.display()),
                )
            })?;
        Ok(Self {
            free_map: Mutex::new(free_map),
            files: StorageBinFileSet::new(layout.clone()),
            layout,
            objects: Arc::new(RwLock::new(recovered_objects)),
            index_state: Arc::new(Mutex::new(DiskIndexCheckpointState::default())),
            purge_index: recovered_purge_index,
            max_size_bytes: plan.max_size_bytes,
            max_object_bytes: plan.max_object_bytes,
            cache_tag_headers: Arc::from(plan.cache_tag_headers),
            encryption,
            activity,
        })
    }

    pub fn stats(&self) -> std::io::Result<DiskCacheStats> {
        let (entries, size_bytes) = match self.objects.read() {
            Ok(objects) => (
                objects.len() as u64,
                objects.values().map(|entry| entry.size).sum(),
            ),
            Err(_) => (0, 0),
        };
        let (
            allocated_size_bytes,
            free_size_bytes,
            free_range_count,
            largest_free_range_bytes,
            bin_files,
        ) = match self.free_map.lock() {
            Ok(free_map) => (
                free_map.allocated_size_bytes(),
                free_map.free_size_bytes(),
                free_map.free_range_count(),
                free_map.largest_free_range_bytes(),
                free_map.bin_files(),
            ),
            Err(_) => (0, 0, 0, 0, 0),
        };
        Ok(DiskCacheStats {
            backend: "storage-bin",
            entries,
            size_bytes,
            allocated_size_bytes,
            free_size_bytes,
            free_range_count,
            largest_free_range_bytes,
            bin_files,
            max_size_bytes: self.max_size_bytes,
            max_object_bytes: self.max_object_bytes,
            purge_index_entries: self.purge_index.len() as u64,
            purge_index_max_entries: self.purge_index.max_entries() as u64,
            activity: self.activity.snapshot(),
        })
    }

    pub fn reset_activity(&self) {
        self.activity.reset();
    }

    fn put_object(
        &self,
        store_key: PingoraStoreKey,
        internal_meta: Vec<u8>,
        response_header: Vec<u8>,
        body: Arc<[u8]>,
    ) -> pingora::Result<Option<usize>> {
        let object_bytes = pingora_object_weight(&internal_meta, &response_header, &body);
        let header_overhead = disk_cache_header_overhead(&store_key);
        let encoded_object_bytes = object_bytes.saturating_add(header_overhead);
        if object_bytes > self.max_object_bytes.as_u64()
            || header_overhead > DISK_CACHE_HEADER_OVERHEAD_LIMIT
            || encoded_object_bytes > self.layout.bin_size_bytes.as_u64()
        {
            self.activity.store_refusal();
            return Ok(None);
        }

        let encoded = encode_disk_cache_object_maybe_encrypted(
            self.encryption.as_ref(),
            &store_key,
            &internal_meta,
            &response_header,
            &body,
        )
        .map_err(|error| cache_io_error("encode storage-bin cache object", error))?;
        let encoded_len = encoded.len() as u64;
        if !self
            .evict_until_admissible(&store_key.combined, encoded_len)
            .map_err(|error| cache_io_error("evict storage-bin cache objects", error))?
        {
            self.activity.store_refusal();
            return Ok(None);
        }

        let replaced = {
            let mut objects = self.objects.write().map_err(|_| {
                cache_io_error(
                    "lock storage-bin object index",
                    std::io::Error::other("storage-bin object index lock poisoned"),
                )
            })?;
            objects.remove(&store_key.combined)
        };
        if let Some(previous) = replaced {
            let _ = self.release_location(previous.location);
            self.purge_index.remove_combined(&store_key.combined);
            self.schedule_storage_bin_index();
        }

        let location = {
            let mut free_map = self.free_map.lock().map_err(|_| {
                cache_io_error(
                    "lock storage-bin free map",
                    std::io::Error::other("storage-bin free map lock poisoned"),
                )
            })?;
            match free_map
                .allocate(encoded_len)
                .map_err(|error| cache_io_error("allocate storage-bin object", error))?
            {
                Some(location) => location,
                None => {
                    self.activity.store_refusal();
                    return Ok(None);
                }
            }
        };

        if let Err(error) = self.files.write_object(location, &encoded) {
            let _ = self.release_location(location);
            self.activity.store_refusal();
            return Err(cache_io_error("write storage-bin cache object", error));
        }

        {
            let mut objects = self.objects.write().map_err(|_| {
                cache_io_error(
                    "lock storage-bin object index",
                    std::io::Error::other("storage-bin object index lock poisoned"),
                )
            })?;
            objects.insert(
                store_key.combined.clone(),
                StorageBinObjectEntry {
                    location,
                    size: encoded_len,
                    accessed: std::time::SystemTime::now(),
                },
            )
        };
        self.schedule_storage_bin_index();
        self.purge_index.insert_with_path_and_tags(
            store_key.combined,
            store_key.primary,
            store_key.user_tag,
            store_key.index_path,
            store_key.cache_tags,
        );
        self.activity.store();
        Ok(Some(body.len()))
    }

    fn evict_until_admissible(
        &self,
        incoming_combined_key: &str,
        object_bytes: u64,
    ) -> std::io::Result<bool> {
        let max_size = self.max_size_bytes.as_u64();
        if object_bytes > max_size {
            return Ok(false);
        }

        let mut evicted = Vec::new();
        {
            let mut objects = self
                .objects
                .write()
                .map_err(|_| std::io::Error::other("storage-bin object index lock poisoned"))?;
            let existing_size = objects
                .get(incoming_combined_key)
                .map(|entry| entry.size)
                .unwrap_or(0);
            let current_size = objects
                .values()
                .fold(0_u64, |total, entry| total.saturating_add(entry.size));
            let projected_size = current_size
                .saturating_sub(existing_size)
                .saturating_add(object_bytes);
            if projected_size <= max_size {
                return Ok(true);
            }

            let mut bytes_to_free = projected_size - max_size;
            let mut candidates = objects
                .iter()
                .filter(|(combined_key, _)| combined_key.as_str() != incoming_combined_key)
                .map(|(combined_key, entry)| {
                    (
                        combined_key.clone(),
                        entry.accessed,
                        entry.location.bin_id,
                        entry.location.offset,
                        entry.size,
                    )
                })
                .collect::<Vec<_>>();
            candidates.sort_by(|left, right| {
                left.1
                    .cmp(&right.1)
                    .then_with(|| left.2.cmp(&right.2))
                    .then_with(|| left.3.cmp(&right.3))
                    .then_with(|| left.0.cmp(&right.0))
            });

            for (combined_key, _, _, _, _) in candidates {
                if bytes_to_free == 0 {
                    break;
                }
                if let Some(entry) = objects.remove(&combined_key) {
                    bytes_to_free = bytes_to_free.saturating_sub(entry.size);
                    evicted.push((combined_key, entry));
                }
            }

            if bytes_to_free > 0 {
                for (combined_key, entry) in evicted.drain(..) {
                    objects.insert(combined_key, entry);
                }
                return Ok(false);
            }
        }

        for (combined_key, entry) in evicted {
            self.release_location(entry.location)?;
            self.purge_index.remove_combined(&combined_key);
            self.activity.eviction();
        }
        self.schedule_storage_bin_index();
        Ok(true)
    }

    fn lookup_object_by_combined(
        &self,
        combined_key: &str,
    ) -> pingora::Result<Option<PingoraStoredObject>> {
        let entry = match self.objects.read() {
            Ok(objects) => objects.get(combined_key).cloned(),
            Err(_) => None,
        };
        let Some(entry) = entry else {
            self.activity.miss();
            return Ok(None);
        };
        let bytes = self
            .files
            .read_object(entry.location)
            .map_err(|error| cache_io_error("read storage-bin cache object", error))?;
        let object = parse_disk_cache_object_maybe_encrypted(
            &bytes,
            self.max_object_bytes,
            self.encryption.as_ref(),
        )
        .map_err(|error| cache_io_error("parse storage-bin cache object", error))?;
        if let Ok(mut objects) = self.objects.write()
            && let Some(entry) = objects.get_mut(combined_key)
        {
            entry.accessed = std::time::SystemTime::now();
        }
        self.activity.hit();
        Ok(Some(object))
    }

    fn object_for_combined_without_activity(
        &self,
        combined_key: &str,
    ) -> pingora::Result<Option<PingoraStoredObject>> {
        let entry = match self.objects.read() {
            Ok(objects) => objects.get(combined_key).cloned(),
            Err(_) => None,
        };
        let Some(entry) = entry else {
            return Ok(None);
        };
        self.read_object_entry(entry).map(Some)
    }

    fn read_object_entry(
        &self,
        entry: StorageBinObjectEntry,
    ) -> pingora::Result<PingoraStoredObject> {
        let bytes = self
            .files
            .read_object(entry.location)
            .map_err(|error| cache_io_error("read storage-bin cache object", error))?;
        parse_disk_cache_object_maybe_encrypted(
            &bytes,
            self.max_object_bytes,
            self.encryption.as_ref(),
        )
        .map_err(|error| cache_io_error("parse storage-bin cache object", error))
    }

    pub fn inspect_cache_key(
        &self,
        key: &pingora::cache::CacheKey,
    ) -> pingora::Result<Option<CacheObjectMetadata>> {
        let Some(object) = self.lookup_object_by_combined(&key.combined())? else {
            return Ok(None);
        };
        let purge_indexed = self.purge_index.contains_combined(&key.combined());
        cache_object_metadata(CacheObjectTier::Disk, purge_indexed, &object)
    }

    pub fn purge_cache_key(&self, key: &pingora::cache::CacheKey) -> std::io::Result<bool> {
        let primary = key.primary();
        let combined = key.combined();
        let mut keys = self.purge_index.combined_keys_for_primary(primary.as_str());
        if !keys.iter().any(|candidate| candidate == &combined) {
            keys.push(combined.clone());
        }
        let mut indexed = keys.iter().cloned().collect::<HashSet<_>>();

        let objects = match self.objects.read() {
            Ok(objects) => objects
                .iter()
                .map(|(combined_key, entry)| (combined_key.clone(), entry.clone()))
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };
        for (candidate_key, entry) in objects {
            if !indexed.insert(candidate_key.clone()) {
                continue;
            }
            let Ok(object) = self.read_object_entry(entry) else {
                continue;
            };
            if object.primary_key.as_deref() == Some(primary.as_str()) || candidate_key == combined
            {
                keys.push(candidate_key);
            }
        }

        let mut purged = false;
        for key in keys {
            purged |= self.purge_combined(&key)?;
        }
        Ok(purged)
    }

    pub fn purge_indexed_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let entries = self
            .indexed_entries_for_user_tag(user_tag, limit.saturating_add(1))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        self.purge_indexed_entries(entries, limit)
    }

    pub fn soft_purge_indexed_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let entries = self.indexed_entries_for_user_tag(user_tag, limit.saturating_add(1))?;
        self.soft_purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let entries = self
            .indexed_entries_for_path_prefix(user_tag, path_prefix, limit.saturating_add(1))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        self.purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_path_exact(
        &self,
        user_tag: &str,
        path_exact: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let entries = self
            .indexed_entries_for_path_exact(user_tag, path_exact, limit.saturating_add(1))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        self.purge_indexed_entries(entries, limit)
    }

    pub fn soft_purge_indexed_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let entries =
            self.indexed_entries_for_path_prefix(user_tag, path_prefix, limit.saturating_add(1))?;
        self.soft_purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let entries = self
            .indexed_entries_for_path_pattern(user_tag, path_pattern, limit.saturating_add(1))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        self.purge_indexed_entries(entries, limit)
    }

    pub fn soft_purge_indexed_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let entries =
            self.indexed_entries_for_path_pattern(user_tag, path_pattern, limit.saturating_add(1))?;
        self.soft_purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let entries = self
            .indexed_entries_for_cache_tag(user_tag, cache_tag, limit.saturating_add(1))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        self.purge_indexed_entries(entries, limit)
    }

    pub fn soft_purge_indexed_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let entries =
            self.indexed_entries_for_cache_tag(user_tag, cache_tag, limit.saturating_add(1))?;
        self.soft_purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_stale_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
        dry_run: bool,
    ) -> pingora::Result<CacheStalePurgeResult> {
        let mut entries = self.indexed_entries_for_user_tag(user_tag, limit.saturating_add(1))?;
        let truncated = entries.len() > limit;
        entries.truncate(limit);

        let now = std::time::SystemTime::now();
        let scanned = entries.len();
        let mut stale = 0;
        let mut purged = 0;
        let mut deferred_fresh_keys = Vec::new();

        for entry in &entries {
            let Some(object) = self.object_for_combined_without_activity(&entry.combined_key)?
            else {
                self.purge_index.remove_combined(&entry.combined_key);
                continue;
            };
            let meta = CacheMeta::deserialize(&object.internal_meta, &object.response_header)?;
            if meta.is_fresh(now) {
                if truncated && !dry_run {
                    deferred_fresh_keys.push(entry.combined_key.clone());
                }
                continue;
            }
            stale += 1;
            if dry_run {
                continue;
            }
            if self
                .purge_combined(&entry.combined_key)
                .map_err(|error| cache_io_error("purge stale storage-bin cache object", error))?
            {
                purged += 1;
            }
        }
        if truncated && !dry_run {
            self.purge_index
                .move_combined_keys_to_back(&deferred_fresh_keys);
        }

        Ok(CacheStalePurgeResult {
            scanned,
            stale,
            purged,
            truncated,
        })
    }

    fn purge_indexed_entries(
        &self,
        mut entries: Vec<CachePurgeIndexEntry>,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let truncated = entries.len() > limit;
        entries.truncate(limit);

        let mut purged = 0;
        for entry in &entries {
            if self.purge_combined(&entry.combined_key)? {
                purged += 1;
            }
        }

        Ok(CacheIndexedPurgeResult {
            matched: entries.len(),
            purged,
            truncated,
        })
    }

    fn indexed_entries_for_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
    ) -> pingora::Result<Vec<CachePurgeIndexEntry>> {
        if user_tag.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        self.indexed_entries_matching(
            self.purge_index.entries_for_user_tag(user_tag, limit),
            limit,
            |entry| entry.user_tag == user_tag,
        )
    }

    fn indexed_entries_for_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> pingora::Result<Vec<CachePurgeIndexEntry>> {
        if user_tag.is_empty() || path_prefix.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        self.indexed_entries_matching(
            self.purge_index
                .entries_for_user_tag_path_prefix(user_tag, path_prefix, limit),
            limit,
            |entry| {
                entry.user_tag == user_tag
                    && entry
                        .path
                        .as_deref()
                        .is_some_and(|path| path.starts_with(path_prefix))
            },
        )
    }

    fn indexed_entries_for_path_exact(
        &self,
        user_tag: &str,
        path_exact: &str,
        limit: usize,
    ) -> pingora::Result<Vec<CachePurgeIndexEntry>> {
        if user_tag.is_empty() || path_exact.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        self.indexed_entries_matching(
            self.purge_index
                .entries_for_user_tag_path_exact(user_tag, path_exact, limit),
            limit,
            |entry| {
                entry.user_tag == user_tag
                    && entry.path.as_deref().is_some_and(|path| path == path_exact)
            },
        )
    }

    fn indexed_entries_for_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> pingora::Result<Vec<CachePurgeIndexEntry>> {
        if user_tag.is_empty() || path_pattern.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        self.indexed_entries_matching(
            self.purge_index
                .entries_for_user_tag_path_pattern(user_tag, path_pattern, limit),
            limit,
            |entry| {
                entry.user_tag == user_tag
                    && entry
                        .path
                        .as_deref()
                        .is_some_and(|path| cache_path_wildcard_matches(path_pattern, path))
            },
        )
    }

    fn indexed_entries_for_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
    ) -> pingora::Result<Vec<CachePurgeIndexEntry>> {
        if user_tag.is_empty() || cache_tag.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        self.indexed_entries_matching(
            self.purge_index
                .entries_for_user_tag_cache_tag(user_tag, cache_tag, limit),
            limit,
            |entry| {
                entry.user_tag == user_tag && entry.cache_tags.iter().any(|tag| tag == cache_tag)
            },
        )
    }

    fn indexed_entries_matching(
        &self,
        mut entries: Vec<CachePurgeIndexEntry>,
        limit: usize,
        matches: impl Fn(&CachePurgeIndexEntry) -> bool,
    ) -> pingora::Result<Vec<CachePurgeIndexEntry>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut seen = entries
            .iter()
            .map(|entry| entry.combined_key.clone())
            .collect::<HashSet<_>>();
        let objects = match self.objects.read() {
            Ok(objects) => objects
                .iter()
                .map(|(combined_key, entry)| (combined_key.clone(), entry.clone()))
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };
        for (combined_key, object_entry) in objects {
            if entries.len() >= limit || seen.contains(&combined_key) {
                continue;
            }
            let object = match self.read_object_entry(object_entry) {
                Ok(object) => object,
                Err(_) => continue,
            };
            let Some(entry) = cache_purge_entry_from_stored_object(&combined_key, &object) else {
                continue;
            };
            if !matches(&entry) {
                continue;
            }
            seen.insert(entry.combined_key.clone());
            entries.push(entry);
        }
        Ok(entries)
    }

    fn soft_purge_indexed_entries(
        &self,
        mut entries: Vec<CachePurgeIndexEntry>,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let truncated = entries.len() > limit;
        entries.truncate(limit);

        let mut purged = 0;
        for entry in &entries {
            let Some(object) = self.object_for_combined_without_activity(&entry.combined_key)?
            else {
                self.purge_index.remove_combined(&entry.combined_key);
                continue;
            };
            let meta = stale_cache_meta(&object.internal_meta, &object.response_header)?;
            let (internal_meta, response_header) = meta.serialize()?;
            let store_key = PingoraStoreKey {
                combined: object
                    .combined_key
                    .unwrap_or_else(|| entry.combined_key.clone()),
                primary: object.primary_key.unwrap_or_default(),
                user_tag: object.user_tag.unwrap_or_default(),
                index_path: entry.path.clone(),
                cache_tags: object.cache_tags.clone(),
            };
            if self
                .put_object(store_key, internal_meta, response_header, object.body)?
                .is_some()
            {
                purged += 1;
            }
        }

        Ok(CacheIndexedPurgeResult {
            matched: entries.len(),
            purged,
            truncated,
        })
    }

    pub fn purge_combined(&self, combined_key: &str) -> std::io::Result<bool> {
        let removed = match self.objects.write() {
            Ok(mut objects) => objects.remove(combined_key),
            Err(_) => None,
        };
        let Some(entry) = removed else {
            return Ok(false);
        };
        self.release_location(entry.location)?;
        self.purge_index.remove_combined(combined_key);
        self.schedule_storage_bin_index();
        self.activity.purge();
        Ok(true)
    }

    fn write_index(&self) -> std::io::Result<()> {
        write_storage_bin_index_from_objects(&self.layout, &self.objects)
    }

    fn flush_storage_bin_index_if_dirty(&self) -> std::io::Result<bool> {
        {
            let mut state = self
                .index_state
                .lock()
                .map_err(|_| std::io::Error::other("storage-bin index state lock poisoned"))?;
            if !state.dirty {
                return Ok(false);
            }
            state.dirty = false;
        }

        if let Err(error) = self.write_index() {
            if let Ok(mut state) = self.index_state.lock() {
                state.dirty = true;
            }
            return Err(error);
        }

        if let Ok(mut state) = self.index_state.lock()
            && !state.dirty
        {
            state.scheduled = false;
        }
        Ok(true)
    }

    #[cfg(test)]
    fn storage_bin_index_flags(&self) -> (bool, bool) {
        match self.index_state.lock() {
            Ok(state) => (state.dirty, state.scheduled),
            Err(_) => (false, false),
        }
    }

    fn schedule_storage_bin_index(&self) {
        let mut state = match self.index_state.lock() {
            Ok(state) => state,
            Err(_) => return,
        };
        state.dirty = true;
        if state.scheduled {
            return;
        }
        state.scheduled = true;

        let layout = self.layout.clone();
        let objects = Arc::clone(&self.objects);
        let index_state = Arc::clone(&self.index_state);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(DISK_CACHE_INDEX_CHECKPOINT_DEBOUNCE);
                {
                    let mut state = match index_state.lock() {
                        Ok(state) => state,
                        Err(_) => return,
                    };
                    if !state.dirty {
                        state.scheduled = false;
                        return;
                    }
                    state.dirty = false;
                }

                if let Err(error) = write_storage_bin_index_from_objects(&layout, &objects) {
                    log::warn!(
                        "failed to write storage-bin cache index for {}: {error}",
                        layout.root.display()
                    );
                }

                let mut state = match index_state.lock() {
                    Ok(state) => state,
                    Err(_) => return,
                };
                if !state.dirty {
                    state.scheduled = false;
                    return;
                }
            }
        });
    }

    fn release_location(&self, location: StorageBinObjectLocation) -> std::io::Result<()> {
        let reclaimed = {
            let mut free_map = self
                .free_map
                .lock()
                .map_err(|_| std::io::Error::other("storage-bin free map lock poisoned"))?;
            free_map.release(location)?;
            free_map.reclaim_free_tail_bins()
        };

        for bin_id in reclaimed {
            if let Err(error) = self.files.remove_bin(bin_id) {
                log::warn!(
                    "failed to remove reclaimed storage-bin cache file {} for {}: {error}",
                    bin_id,
                    self.layout.root.display()
                );
            }
        }
        Ok(())
    }
}

#[cfg(feature = "proxy")]
impl Drop for StorageBinDiskStorage {
    fn drop(&mut self) {
        if let Err(error) = self.flush_storage_bin_index_if_dirty() {
            log::warn!(
                "failed to flush storage-bin cache index for {} during shutdown: {error}",
                self.layout.root.display()
            );
        }
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug)]
pub enum PingoraDiskStorageBackend {
    Filesystem(Box<PingoraDiskStorage>),
    StorageBin(Box<StorageBinDiskStorage>),
}

#[cfg(feature = "proxy")]
impl PingoraDiskStorageBackend {
    pub fn from_plan(plan: DiskTierPlan) -> std::io::Result<Self> {
        match plan.backend {
            CacheDiskBackend::Filesystem => PingoraDiskStorage::from_plan(plan)
                .map(|storage| Self::Filesystem(Box::new(storage))),
            CacheDiskBackend::StorageBin => StorageBinDiskStorage::from_plan(plan)
                .map(|storage| Self::StorageBin(Box::new(storage))),
        }
    }

    pub fn from_plan_with_metric_scope(
        plan: DiskTierPlan,
        vhost: &str,
        route: Option<&str>,
    ) -> std::io::Result<Self> {
        match plan.backend {
            CacheDiskBackend::Filesystem => {
                PingoraDiskStorage::from_plan_with_metric_scope(plan, vhost, route)
                    .map(|storage| Self::Filesystem(Box::new(storage)))
            }
            CacheDiskBackend::StorageBin => {
                StorageBinDiskStorage::from_plan_with_metric_scope(plan, vhost, route)
                    .map(|storage| Self::StorageBin(Box::new(storage)))
            }
        }
    }

    pub fn root(&self) -> &Path {
        match self {
            Self::Filesystem(storage) => storage.root(),
            Self::StorageBin(storage) => &storage.layout.root,
        }
    }

    pub fn stats(&self) -> std::io::Result<DiskCacheStats> {
        match self {
            Self::Filesystem(storage) => storage.stats(),
            Self::StorageBin(storage) => storage.stats(),
        }
    }

    pub fn reset_activity(&self) {
        match self {
            Self::Filesystem(storage) => storage.reset_activity(),
            Self::StorageBin(storage) => storage.reset_activity(),
        }
    }

    fn record_hit(&self) {
        match self {
            Self::Filesystem(storage) => storage.activity.hit(),
            Self::StorageBin(storage) => storage.activity.hit(),
        }
    }

    fn record_miss(&self) {
        match self {
            Self::Filesystem(storage) => storage.activity.miss(),
            Self::StorageBin(storage) => storage.activity.miss(),
        }
    }

    fn max_object_bytes(&self) -> ByteSize {
        match self {
            Self::Filesystem(storage) => storage.max_object_bytes,
            Self::StorageBin(storage) => storage.max_object_bytes,
        }
    }

    fn put_serialized_object(
        &self,
        store_key: PingoraStoreKey,
        internal_meta: Vec<u8>,
        response_header: Vec<u8>,
        body: Arc<[u8]>,
    ) -> pingora::Result<Option<usize>> {
        match self {
            Self::Filesystem(storage) => {
                storage.put_serialized_object(store_key, internal_meta, response_header, body)
            }
            Self::StorageBin(storage) => {
                storage.put_object(store_key, internal_meta, response_header, body)
            }
        }
    }

    pub fn purge_cache_key(&self, key: &pingora::cache::CacheKey) -> std::io::Result<bool> {
        match self {
            Self::Filesystem(storage) => storage.purge_cache_key(key),
            Self::StorageBin(storage) => storage.purge_cache_key(key),
        }
    }

    pub fn purge_indexed_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        match self {
            Self::Filesystem(storage) => storage.purge_indexed_user_tag(user_tag, limit),
            Self::StorageBin(storage) => storage.purge_indexed_user_tag(user_tag, limit),
        }
    }

    pub fn soft_purge_indexed_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        match self {
            Self::Filesystem(storage) => storage.soft_purge_indexed_user_tag(user_tag, limit),
            Self::StorageBin(storage) => storage.soft_purge_indexed_user_tag(user_tag, limit),
        }
    }

    pub fn purge_indexed_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        match self {
            Self::Filesystem(storage) => {
                storage.purge_indexed_path_prefix(user_tag, path_prefix, limit)
            }
            Self::StorageBin(storage) => {
                storage.purge_indexed_path_prefix(user_tag, path_prefix, limit)
            }
        }
    }

    pub fn purge_indexed_path_exact(
        &self,
        user_tag: &str,
        path_exact: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        match self {
            Self::Filesystem(storage) => {
                storage.purge_indexed_path_exact(user_tag, path_exact, limit)
            }
            Self::StorageBin(storage) => {
                storage.purge_indexed_path_exact(user_tag, path_exact, limit)
            }
        }
    }

    pub fn soft_purge_indexed_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        match self {
            Self::Filesystem(storage) => {
                storage.soft_purge_indexed_path_prefix(user_tag, path_prefix, limit)
            }
            Self::StorageBin(storage) => {
                storage.soft_purge_indexed_path_prefix(user_tag, path_prefix, limit)
            }
        }
    }

    pub fn purge_indexed_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        match self {
            Self::Filesystem(storage) => {
                storage.purge_indexed_path_pattern(user_tag, path_pattern, limit)
            }
            Self::StorageBin(storage) => {
                storage.purge_indexed_path_pattern(user_tag, path_pattern, limit)
            }
        }
    }

    pub fn soft_purge_indexed_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        match self {
            Self::Filesystem(storage) => {
                storage.soft_purge_indexed_path_pattern(user_tag, path_pattern, limit)
            }
            Self::StorageBin(storage) => {
                storage.soft_purge_indexed_path_pattern(user_tag, path_pattern, limit)
            }
        }
    }

    pub fn purge_indexed_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        match self {
            Self::Filesystem(storage) => {
                storage.purge_indexed_cache_tag(user_tag, cache_tag, limit)
            }
            Self::StorageBin(storage) => {
                storage.purge_indexed_cache_tag(user_tag, cache_tag, limit)
            }
        }
    }

    pub fn soft_purge_indexed_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        match self {
            Self::Filesystem(storage) => {
                storage.soft_purge_indexed_cache_tag(user_tag, cache_tag, limit)
            }
            Self::StorageBin(storage) => {
                storage.soft_purge_indexed_cache_tag(user_tag, cache_tag, limit)
            }
        }
    }

    pub fn purge_indexed_stale_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
        dry_run: bool,
    ) -> pingora::Result<CacheStalePurgeResult> {
        match self {
            Self::Filesystem(storage) => {
                storage.purge_indexed_stale_user_tag(user_tag, limit, dry_run)
            }
            Self::StorageBin(storage) => {
                storage.purge_indexed_stale_user_tag(user_tag, limit, dry_run)
            }
        }
    }

    pub fn inspect_cache_key(
        &self,
        key: &pingora::cache::CacheKey,
    ) -> pingora::Result<Option<CacheObjectMetadata>> {
        match self {
            Self::Filesystem(storage) => storage.inspect_cache_key(key),
            Self::StorageBin(storage) => storage.inspect_cache_key(key),
        }
    }

    fn lookup_object(
        &self,
        key: &pingora::cache::CacheKey,
    ) -> pingora::Result<Option<PingoraStoredObject>> {
        match self {
            Self::Filesystem(storage) => storage.lookup_object(key),
            Self::StorageBin(storage) => {
                storage.object_for_combined_without_activity(&key.combined())
            }
        }
    }
}

#[cfg(feature = "proxy")]
impl PingoraDiskStorage {
    pub fn from_plan(plan: DiskTierPlan) -> std::io::Result<Self> {
        reject_unimplemented_disk_backend(plan.backend)?;
        let encryption = DiskCacheEncryption::from_config(&plan.encryption).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("disk cache {} encryption: {error}", plan.path.display()),
            )
        })?;
        Self::new_with_cache_tag_headers_and_encryption(
            plan.path,
            plan.max_size_bytes,
            plan.max_object_bytes,
            plan.cache_tag_headers,
            encryption,
        )
    }

    pub fn from_plan_with_metric_scope(
        plan: DiskTierPlan,
        vhost: &str,
        route: Option<&str>,
    ) -> std::io::Result<Self> {
        reject_unimplemented_disk_backend(plan.backend)?;
        let encryption = DiskCacheEncryption::from_config(&plan.encryption).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("disk cache {} encryption: {error}", plan.path.display()),
            )
        })?;
        Self::new_with_metric_scope(
            plan.path,
            plan.max_size_bytes,
            plan.max_object_bytes,
            plan.cache_tag_headers,
            encryption,
            vhost,
            route,
        )
    }

    pub fn new(
        root: PathBuf,
        max_size_bytes: ByteSize,
        max_object_bytes: ByteSize,
    ) -> std::io::Result<Self> {
        Self::new_with_cache_tag_headers(
            root,
            max_size_bytes,
            max_object_bytes,
            default_cache_tag_headers_for_storage(),
        )
    }

    fn new_with_cache_tag_headers(
        root: PathBuf,
        max_size_bytes: ByteSize,
        max_object_bytes: ByteSize,
        cache_tag_headers: Vec<String>,
    ) -> std::io::Result<Self> {
        Self::new_with_cache_tag_headers_and_encryption(
            root,
            max_size_bytes,
            max_object_bytes,
            cache_tag_headers,
            None,
        )
    }

    fn new_with_cache_tag_headers_and_encryption(
        root: PathBuf,
        max_size_bytes: ByteSize,
        max_object_bytes: ByteSize,
        cache_tag_headers: Vec<String>,
        encryption: Option<DiskCacheEncryption>,
    ) -> std::io::Result<Self> {
        Self::new_with_activity(
            root,
            max_size_bytes,
            max_object_bytes,
            cache_tag_headers,
            encryption,
            CacheActivityCounters::new("disk"),
        )
    }

    fn new_with_metric_scope(
        root: PathBuf,
        max_size_bytes: ByteSize,
        max_object_bytes: ByteSize,
        cache_tag_headers: Vec<String>,
        encryption: Option<DiskCacheEncryption>,
        vhost: &str,
        route: Option<&str>,
    ) -> std::io::Result<Self> {
        Self::new_with_activity(
            root,
            max_size_bytes,
            max_object_bytes,
            cache_tag_headers,
            encryption,
            CacheActivityCounters::new_with_metric_scope("disk", vhost, route),
        )
    }

    fn new_with_activity(
        root: PathBuf,
        max_size_bytes: ByteSize,
        max_object_bytes: ByteSize,
        cache_tag_headers: Vec<String>,
        encryption: Option<DiskCacheEncryption>,
        activity: CacheActivityCounters,
    ) -> std::io::Result<Self> {
        let root = prepare_disk_cache_root(&root).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("disk cache root {}: {error}", root.display()),
            )
        })?;
        cleanup_stale_disk_cache_temp_files(
            &root,
            std::time::Duration::from_secs(DISK_CACHE_TEMP_FILE_STALE_SECS),
        )
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("disk cache temp cleanup {}: {error}", root.display()),
            )
        })?;
        let storage = Self {
            root,
            purge_index: CachePurgeIndex::new(),
            disk_index: DiskObjectIndex::new(),
            checkpoint_state: Arc::new(Mutex::new(DiskIndexCheckpointState::default())),
            max_size_bytes,
            max_object_bytes,
            cache_tag_headers: Arc::from(cache_tag_headers),
            encryption,
            activity,
        };
        storage.rebuild_disk_indexes().map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "disk cache index rebuild {}: {error}",
                    storage.root.display()
                ),
            )
        })?;
        Ok(storage)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn stats(&self) -> std::io::Result<DiskCacheStats> {
        let (entries, size_bytes) = self.disk_index.stats();
        Ok(DiskCacheStats {
            backend: "filesystem",
            entries: entries as u64,
            size_bytes,
            allocated_size_bytes: size_bytes,
            free_size_bytes: 0,
            free_range_count: 0,
            largest_free_range_bytes: 0,
            bin_files: 0,
            max_size_bytes: self.max_size_bytes,
            max_object_bytes: self.max_object_bytes,
            purge_index_entries: self.purge_index.len() as u64,
            purge_index_max_entries: self.purge_index.max_entries() as u64,
            activity: self.activity.snapshot(),
        })
    }

    pub fn reset_activity(&self) {
        self.activity.reset();
    }

    fn rebuild_disk_indexes(&self) -> std::io::Result<()> {
        let mut candidates = read_disk_index_checkpoint(&self.root)?.unwrap_or_default();
        candidates.extend(disk_cache_entries(&self.root)?);
        let candidates = merge_disk_cache_entries(candidates);
        let mut valid_entries = Vec::new();
        for entry in candidates {
            let Some(read_path) = self.safe_existing_object_path(&entry.path)? else {
                continue;
            };
            let object = match read_disk_cache_object(&self.root, &read_path, self.max_object_bytes)
                .and_then(|bytes| {
                    parse_disk_cache_object_maybe_encrypted(
                        &bytes,
                        self.max_object_bytes,
                        self.encryption.as_ref(),
                    )
                }) {
                Ok(object) => object,
                Err(_) => {
                    let _ = remove_disk_cache_object(&self.root, &read_path);
                    continue;
                }
            };
            let Some(combined_key) = object.combined_key.clone() else {
                let _ = remove_disk_cache_object(&self.root, &read_path);
                continue;
            };
            let Some(primary_key) = object.primary_key.clone() else {
                let _ = remove_disk_cache_object(&self.root, &read_path);
                continue;
            };
            let user_tag = object.user_tag.unwrap_or_default();
            let path = object
                .index_path
                .or_else(|| cache_primary_component(&primary_key, "path"));
            let mut entry = entry;
            entry.combined_key = Some(combined_key.clone());
            valid_entries.push(entry);
            self.purge_index.insert_with_path_and_tags(
                combined_key,
                primary_key,
                user_tag,
                path,
                object.cache_tags,
            );
        }
        self.disk_index.replace_all(valid_entries);
        let startup_sentinel = self.root.join(".fluxheim-startup-budget-sentinel");
        let _ = self.evict_until_admissible(&startup_sentinel, 0)?;
        let _ = self.write_disk_index_checkpoint();
        Ok(())
    }

    pub fn purge_cache_key(&self, key: &pingora::cache::CacheKey) -> std::io::Result<bool> {
        self.purge_cache_primary(key)
    }

    fn purge_cache_primary(&self, key: &pingora::cache::CacheKey) -> std::io::Result<bool> {
        let primary = key.primary();
        let combined = key.combined();
        let exact_path = self.path_for_key(key);
        let mut purged = self.purge_object_path(exact_path.clone())?;
        self.purge_index.remove_combined(&combined);

        let mut indexed = HashSet::from([combined]);
        for indexed_key in self.purge_index.combined_keys_for_primary(primary.as_str()) {
            if !indexed.insert(indexed_key.clone()) {
                continue;
            }
            let path = self.path_for_combined_key(&indexed_key);
            if path == exact_path {
                continue;
            }
            purged |= self.purge_object_path(path)?;
            self.purge_index.remove_combined(&indexed_key);
        }

        for entry in self.disk_index.entries() {
            if entry.path == exact_path {
                continue;
            }

            let Some(read_path) = self.safe_existing_object_path(&entry.path)? else {
                continue;
            };
            let object = match read_disk_cache_object(&self.root, &read_path, self.max_object_bytes)
                .and_then(|bytes| {
                    parse_disk_cache_object_maybe_encrypted(
                        &bytes,
                        self.max_object_bytes,
                        self.encryption.as_ref(),
                    )
                }) {
                Ok(object) => object,
                Err(_) => continue,
            };
            if object.primary_key.as_deref() == Some(primary.as_str()) {
                purged |= self.purge_object_path(entry.path)?;
            }
        }

        Ok(purged)
    }

    pub fn purge_indexed_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let entries = self.indexed_entries_for_user_tag(user_tag, limit.saturating_add(1))?;
        self.purge_indexed_entries(entries, limit)
    }

    pub fn soft_purge_indexed_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let entries = self
            .indexed_entries_for_user_tag(user_tag, limit.saturating_add(1))
            .map_err(|error| cache_io_error("scan soft purge disk cache index", error))?;
        self.soft_purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let entries =
            self.indexed_entries_for_path_prefix(user_tag, path_prefix, limit.saturating_add(1))?;
        self.purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_path_exact(
        &self,
        user_tag: &str,
        path_exact: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let entries =
            self.indexed_entries_for_path_exact(user_tag, path_exact, limit.saturating_add(1))?;
        self.purge_indexed_entries(entries, limit)
    }

    pub fn soft_purge_indexed_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let entries = self
            .indexed_entries_for_path_prefix(user_tag, path_prefix, limit.saturating_add(1))
            .map_err(|error| cache_io_error("scan soft purge disk cache index", error))?;
        self.soft_purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let entries =
            self.indexed_entries_for_path_pattern(user_tag, path_pattern, limit.saturating_add(1))?;
        self.purge_indexed_entries(entries, limit)
    }

    pub fn soft_purge_indexed_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let entries = self
            .indexed_entries_for_path_pattern(user_tag, path_pattern, limit.saturating_add(1))
            .map_err(|error| cache_io_error("scan soft purge disk cache index", error))?;
        self.soft_purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let entries =
            self.indexed_entries_for_cache_tag(user_tag, cache_tag, limit.saturating_add(1))?;
        self.purge_indexed_entries(entries, limit)
    }

    pub fn soft_purge_indexed_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let entries = self
            .indexed_entries_for_cache_tag(user_tag, cache_tag, limit.saturating_add(1))
            .map_err(|error| cache_io_error("scan soft purge disk cache index", error))?;
        self.soft_purge_indexed_entries(entries, limit)
    }

    pub fn purge_indexed_stale_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
        dry_run: bool,
    ) -> pingora::Result<CacheStalePurgeResult> {
        let mut entries = self
            .indexed_entries_for_user_tag(user_tag, limit.saturating_add(1))
            .map_err(|error| cache_io_error("scan stale purge disk cache index", error))?;
        let truncated = entries.len() > limit;
        entries.truncate(limit);

        let now = std::time::SystemTime::now();
        let scanned = entries.len();
        let mut stale = 0;
        let mut purged = 0;
        let mut deferred_fresh_keys = Vec::new();

        for entry in &entries {
            let Some(object) = self.lookup_object_by_combined(&entry.combined_key)? else {
                self.purge_index.remove_combined(&entry.combined_key);
                continue;
            };
            let meta = CacheMeta::deserialize(&object.internal_meta, &object.response_header)?;
            if meta.is_fresh(now) {
                if truncated && !dry_run {
                    deferred_fresh_keys.push(entry.combined_key.clone());
                }
                continue;
            }
            stale += 1;
            if dry_run {
                continue;
            }
            let path = self.path_for_combined_key(&entry.combined_key);
            if self
                .purge_object_path(path)
                .map_err(|error| cache_io_error("purge stale disk cache object", error))?
            {
                purged += 1;
            }
            self.purge_index.remove_combined(&entry.combined_key);
        }
        if truncated && !dry_run {
            self.purge_index
                .move_combined_keys_to_back(&deferred_fresh_keys);
        }

        Ok(CacheStalePurgeResult {
            scanned,
            stale,
            purged,
            truncated,
        })
    }

    fn purge_indexed_entries(
        &self,
        mut entries: Vec<CachePurgeIndexEntry>,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let truncated = entries.len() > limit;
        entries.truncate(limit);

        let mut purged = 0;
        for entry in &entries {
            let path = self.path_for_combined_key(&entry.combined_key);
            if self.purge_object_path(path)? {
                purged += 1;
            }
            self.purge_index.remove_combined(&entry.combined_key);
        }

        Ok(CacheIndexedPurgeResult {
            matched: entries.len(),
            purged,
            truncated,
        })
    }

    fn indexed_entries_for_user_tag(
        &self,
        user_tag: &str,
        limit: usize,
    ) -> std::io::Result<Vec<CachePurgeIndexEntry>> {
        if user_tag.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        self.indexed_entries_matching(
            self.purge_index.entries_for_user_tag(user_tag, limit),
            limit,
            |entry| entry.user_tag == user_tag,
        )
    }

    fn indexed_entries_for_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> std::io::Result<Vec<CachePurgeIndexEntry>> {
        if user_tag.is_empty() || path_prefix.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        self.indexed_entries_matching(
            self.purge_index
                .entries_for_user_tag_path_prefix(user_tag, path_prefix, limit),
            limit,
            |entry| {
                entry.user_tag == user_tag
                    && entry
                        .path
                        .as_deref()
                        .is_some_and(|path| path.starts_with(path_prefix))
            },
        )
    }

    fn indexed_entries_for_path_exact(
        &self,
        user_tag: &str,
        path_exact: &str,
        limit: usize,
    ) -> std::io::Result<Vec<CachePurgeIndexEntry>> {
        if user_tag.is_empty() || path_exact.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        self.indexed_entries_matching(
            self.purge_index
                .entries_for_user_tag_path_exact(user_tag, path_exact, limit),
            limit,
            |entry| {
                entry.user_tag == user_tag
                    && entry.path.as_deref().is_some_and(|path| path == path_exact)
            },
        )
    }

    fn indexed_entries_for_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> std::io::Result<Vec<CachePurgeIndexEntry>> {
        if user_tag.is_empty() || path_pattern.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        self.indexed_entries_matching(
            self.purge_index
                .entries_for_user_tag_path_pattern(user_tag, path_pattern, limit),
            limit,
            |entry| {
                entry.user_tag == user_tag
                    && entry
                        .path
                        .as_deref()
                        .is_some_and(|path| cache_path_wildcard_matches(path_pattern, path))
            },
        )
    }

    fn indexed_entries_for_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
    ) -> std::io::Result<Vec<CachePurgeIndexEntry>> {
        if user_tag.is_empty() || cache_tag.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        self.indexed_entries_matching(
            self.purge_index
                .entries_for_user_tag_cache_tag(user_tag, cache_tag, limit),
            limit,
            |entry| {
                entry.user_tag == user_tag && entry.cache_tags.iter().any(|tag| tag == cache_tag)
            },
        )
    }

    fn indexed_entries_matching(
        &self,
        mut entries: Vec<CachePurgeIndexEntry>,
        limit: usize,
        matches: impl Fn(&CachePurgeIndexEntry) -> bool,
    ) -> std::io::Result<Vec<CachePurgeIndexEntry>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut seen = entries
            .iter()
            .map(|entry| entry.combined_key.clone())
            .collect::<HashSet<_>>();
        for disk_entry in self.disk_index.entries() {
            if entries.len() >= limit {
                break;
            }
            let Some(read_path) = self.safe_existing_object_path(&disk_entry.path)? else {
                continue;
            };
            let object = match read_disk_cache_object(&self.root, &read_path, self.max_object_bytes)
                .and_then(|bytes| {
                    parse_disk_cache_object_maybe_encrypted(
                        &bytes,
                        self.max_object_bytes,
                        self.encryption.as_ref(),
                    )
                }) {
                Ok(object) => object,
                Err(_) => continue,
            };
            let Some(combined_key) = object.combined_key.as_deref() else {
                continue;
            };
            if seen.contains(combined_key) {
                continue;
            }
            let Some(entry) = cache_purge_entry_from_stored_object(combined_key, &object) else {
                continue;
            };
            if !matches(&entry) {
                continue;
            }
            seen.insert(entry.combined_key.clone());
            entries.push(entry);
        }
        Ok(entries)
    }

    fn soft_purge_indexed_entries(
        &self,
        mut entries: Vec<CachePurgeIndexEntry>,
        limit: usize,
    ) -> pingora::Result<CacheIndexedPurgeResult> {
        let truncated = entries.len() > limit;
        entries.truncate(limit);

        let mut purged = 0;
        for entry in &entries {
            let Some(object) = self.lookup_object_by_combined(&entry.combined_key)? else {
                self.purge_index.remove_combined(&entry.combined_key);
                continue;
            };
            let meta = stale_cache_meta(&object.internal_meta, &object.response_header)?;
            let (internal_meta, response_header) = meta.serialize()?;
            let combined_key = object
                .combined_key
                .unwrap_or_else(|| entry.combined_key.clone());
            let primary_key = object.primary_key.unwrap_or_default();
            let user_tag = object.user_tag.unwrap_or_default();
            let path = self.path_for_combined_key(&entry.combined_key);
            let parent = path.parent().ok_or_else(|| {
                Error::because(
                    ErrorType::InternalError,
                    "disk cache path has no parent",
                    std::io::Error::other("disk cache path has no parent"),
                )
            })?;
            self.ensure_safe_cache_parent(parent)
                .map_err(|error| cache_io_error("validate soft purge disk cache shard", error))?;
            require_disk_cache_write_destination(&path).map_err(|error| {
                cache_io_error("validate soft purge disk cache destination", error)
            })?;
            self.write_object_atomically(
                &path,
                &PingoraStoreKey {
                    combined: combined_key,
                    primary: primary_key,
                    user_tag,
                    index_path: entry.path.clone(),
                    cache_tags: object.cache_tags.clone(),
                },
                &internal_meta,
                &response_header,
                &object.body,
            )
            .map_err(|error| cache_io_error("soft purge disk cache object", error))?;
            purged += 1;
        }
        if purged > 0 {
            self.activity.purge();
        }

        Ok(CacheIndexedPurgeResult {
            matched: entries.len(),
            purged,
            truncated,
        })
    }

    fn purge_object_path(&self, path: PathBuf) -> std::io::Result<bool> {
        match remove_disk_cache_object(&self.root, &path) {
            Ok(true) => {
                self.remove_disk_index_entry(&path);
                self.schedule_disk_index_checkpoint();
                self.activity.purge();
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn lookup_object(
        &self,
        key: &pingora::cache::CacheKey,
    ) -> pingora::Result<Option<PingoraStoredObject>> {
        self.lookup_object_by_combined(&key.combined())
    }

    pub fn inspect_cache_key(
        &self,
        key: &pingora::cache::CacheKey,
    ) -> pingora::Result<Option<CacheObjectMetadata>> {
        let Some(object) = self.lookup_object(key)? else {
            return Ok(None);
        };
        let purge_indexed = self.purge_index.contains_combined(&key.combined());
        cache_object_metadata(CacheObjectTier::Disk, purge_indexed, &object)
    }

    fn lookup_object_by_combined(
        &self,
        combined_key: &str,
    ) -> pingora::Result<Option<PingoraStoredObject>> {
        let path = self.path_for_combined_key(combined_key);
        let Some(read_path) = self
            .safe_existing_object_path(&path)
            .map_err(|error| cache_io_error("validate disk cache object path", error))?
        else {
            return Ok(None);
        };
        let bytes = match read_disk_cache_object(&self.root, &read_path, self.max_object_bytes) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(cache_io_error("read disk cache object", error)),
        };
        match parse_disk_cache_object_maybe_encrypted(
            &bytes,
            self.max_object_bytes,
            self.encryption.as_ref(),
        ) {
            Ok(object) => {
                let _ = self.index_existing_object_path_with_combined_key(
                    &read_path,
                    object.combined_key.clone(),
                );
                if let (Some(combined_key), Some(primary_key)) =
                    (object.combined_key.clone(), object.primary_key.clone())
                {
                    let user_tag = object.user_tag.clone().unwrap_or_default();
                    let path = object
                        .index_path
                        .clone()
                        .or_else(|| cache_primary_component(&primary_key, "path"));
                    self.purge_index.insert_with_path_and_tags(
                        combined_key,
                        primary_key,
                        user_tag,
                        path,
                        object.cache_tags.clone(),
                    );
                }
                Ok(Some(object))
            }
            Err(error) => {
                if remove_disk_cache_object(&self.root, &path).unwrap_or(false) {
                    self.remove_disk_index_entry(&path);
                    self.purge_index.remove_combined(combined_key);
                    self.schedule_disk_index_checkpoint();
                }
                Err(cache_io_error("parse disk cache object", error))
            }
        }
    }

    fn put_serialized_object(
        &self,
        store_key: PingoraStoreKey,
        internal_meta: Vec<u8>,
        response_header: Vec<u8>,
        body: Arc<[u8]>,
    ) -> pingora::Result<Option<usize>> {
        let object_bytes = pingora_object_weight(&internal_meta, &response_header, &body);
        let header_overhead = disk_cache_header_overhead(&store_key);
        let encoded_object_bytes = object_bytes.saturating_add(header_overhead);
        if object_bytes > self.max_object_bytes.as_u64()
            || header_overhead > DISK_CACHE_HEADER_OVERHEAD_LIMIT
            || encoded_object_bytes > self.max_size_bytes.as_u64()
        {
            self.activity.store_refusal();
            return Ok(None);
        }

        let path = self.path_for_combined_key(&store_key.combined);
        let combined_key = store_key.combined.clone();
        if !self
            .evict_until_admissible(&path, encoded_object_bytes)
            .map_err(|error| cache_io_error("evict disk cache objects", error))?
        {
            self.activity.store_refusal();
            return Ok(None);
        }

        let parent = path.parent().ok_or_else(|| {
            Error::because(
                ErrorType::InternalError,
                "disk cache path has no parent",
                std::io::Error::other("disk cache path has no parent"),
            )
        })?;
        self.ensure_safe_cache_parent(parent)
            .map_err(|error| cache_io_error("create disk cache shard", error))?;
        require_disk_cache_write_destination(&path)
            .map_err(|error| cache_io_error("validate disk cache object destination", error))?;
        self.write_object_atomically(&path, &store_key, &internal_meta, &response_header, &body)
            .map_err(|error| {
                self.activity.store_refusal();
                cache_io_error("write disk cache object", error)
            })?;
        self.index_existing_object_path_with_combined_key(&path, Some(combined_key.clone()))
            .map_err(|error| cache_io_error("index disk cache object", error))?;
        self.schedule_disk_index_checkpoint();
        self.purge_index.insert_with_path_and_tags(
            combined_key,
            store_key.primary,
            store_key.user_tag,
            store_key.index_path,
            store_key.cache_tags,
        );
        self.activity.store();
        Ok(Some(body.len()))
    }

    fn put_streamed_object(
        &self,
        store_key: PingoraStoreKey,
        internal_meta: Vec<u8>,
        response_header: Vec<u8>,
        body_path: &Path,
        body_len: u64,
    ) -> pingora::Result<Option<usize>> {
        let object_bytes = pingora_object_weight_len(&internal_meta, &response_header, body_len);
        let header_overhead = disk_cache_header_overhead(&store_key);
        let encoded_object_bytes = object_bytes.saturating_add(header_overhead);
        if object_bytes > self.max_object_bytes.as_u64()
            || header_overhead > DISK_CACHE_HEADER_OVERHEAD_LIMIT
            || encoded_object_bytes > self.max_size_bytes.as_u64()
        {
            self.activity.store_refusal();
            return Ok(None);
        }

        let path = self.path_for_combined_key(&store_key.combined);
        let combined_key = store_key.combined.clone();
        if !self
            .evict_until_admissible(&path, encoded_object_bytes)
            .map_err(|error| cache_io_error("evict disk cache objects", error))?
        {
            self.activity.store_refusal();
            return Ok(None);
        }

        let parent = path.parent().ok_or_else(|| {
            Error::because(
                ErrorType::InternalError,
                "disk cache path has no parent",
                std::io::Error::other("disk cache path has no parent"),
            )
        })?;
        self.ensure_safe_cache_parent(parent)
            .map_err(|error| cache_io_error("create disk cache shard", error))?;
        require_disk_cache_write_destination(&path)
            .map_err(|error| cache_io_error("validate disk cache object destination", error))?;
        self.write_streamed_object_atomically(
            &path,
            &store_key,
            &internal_meta,
            &response_header,
            body_path,
            body_len,
        )
        .map_err(|error| {
            self.activity.store_refusal();
            cache_io_error("write streamed disk cache object", error)
        })?;
        self.index_existing_object_path_with_combined_key(&path, Some(combined_key.clone()))
            .map_err(|error| cache_io_error("index streamed disk cache object", error))?;
        self.schedule_disk_index_checkpoint();
        self.purge_index.insert_with_path_and_tags(
            combined_key,
            store_key.primary,
            store_key.user_tag,
            store_key.index_path,
            store_key.cache_tags,
        );
        self.activity.store();
        let created = usize::try_from(body_len).unwrap_or(usize::MAX);
        Ok(Some(created))
    }

    fn evict_until_admissible(&self, path: &Path, object_bytes: u64) -> std::io::Result<bool> {
        let current_size = self.disk_index.total_size();
        let existing_size = self.disk_index.entry_size(path).unwrap_or(0);
        let max_size = self.max_size_bytes.as_u64();
        let projected_size = current_size
            .saturating_sub(existing_size)
            .saturating_add(object_bytes);
        if projected_size <= max_size {
            return Ok(true);
        }

        let mut bytes_to_free = projected_size.saturating_sub(max_size);
        let mut index_changed = false;
        while bytes_to_free > 0 {
            let candidates = self.disk_index.oldest_entries_to_free(path, bytes_to_free);
            if candidates.is_empty() {
                if index_changed {
                    self.schedule_disk_index_checkpoint();
                }
                return Ok(false);
            }

            for entry in candidates {
                match remove_disk_cache_object(&self.root, &entry.path) {
                    Ok(true) => {
                        self.remove_disk_index_entry(&entry.path);
                        index_changed = true;
                        self.activity.eviction();
                        bytes_to_free = bytes_to_free.saturating_sub(entry.size);
                        if bytes_to_free == 0 {
                            self.schedule_disk_index_checkpoint();
                            return Ok(true);
                        }
                    }
                    Ok(false) => {
                        if self.remove_disk_index_entry(&entry.path) {
                            index_changed = true;
                            bytes_to_free = bytes_to_free.saturating_sub(entry.size);
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        if index_changed {
            self.schedule_disk_index_checkpoint();
        }
        Ok(true)
    }

    fn index_existing_object_path_with_combined_key(
        &self,
        path: &Path,
        combined_key: Option<String>,
    ) -> std::io::Result<()> {
        if cache_path_contains_symlink(&self.root, path)? {
            return Ok(());
        }
        let canonical = match path.canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if !canonical.starts_with(&self.root) {
            return Ok(());
        }
        let Some(metadata) = symlink_free_regular_metadata(&self.root, path)? else {
            return Ok(());
        };
        self.disk_index.upsert(DiskCacheEntry {
            combined_key: combined_key.or_else(|| {
                self.combined_key_for_existing_object_path(path)
                    .ok()
                    .flatten()
            }),
            path: canonical,
            size: metadata.len(),
            modified: metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
            accessed: std::time::SystemTime::now(),
        });
        Ok(())
    }

    fn combined_key_for_existing_object_path(
        &self,
        path: &Path,
    ) -> std::io::Result<Option<String>> {
        let bytes = read_disk_cache_object(&self.root, path, self.max_object_bytes)?;
        let object = parse_disk_cache_object_maybe_encrypted(
            &bytes,
            self.max_object_bytes,
            self.encryption.as_ref(),
        )?;
        Ok(object.combined_key)
    }

    fn remove_disk_index_entry(&self, path: &Path) -> bool {
        let Some(entry) = self.disk_index.remove(path) else {
            return false;
        };
        if let Some(combined_key) = entry.combined_key {
            self.purge_index.remove_combined(&combined_key);
        }
        true
    }

    fn path_for_key(&self, key: &pingora::cache::CacheKey) -> PathBuf {
        self.path_for_combined_key(&key.combined())
    }

    fn path_for_combined_key(&self, key: &str) -> PathBuf {
        let digest = Sha256::digest(key.as_bytes());
        let mut encoded = String::with_capacity(digest.len() * 2);
        for byte in digest {
            let _ = write!(&mut encoded, "{byte:02x}");
        }
        let shard = &encoded[..2];
        self.root.join(shard).join(format!("{encoded}.fhc"))
    }

    fn write_object_atomically(
        &self,
        path: &Path,
        store_key: &PingoraStoreKey,
        internal_meta: &[u8],
        response_header: &[u8],
        body: &[u8],
    ) -> std::io::Result<()> {
        let mut last_error = None;
        for _ in 0..4 {
            let tmp_path = self.tmp_path_for(path)?;
            let tmp_path = SafeDiskCachePath::from_path(tmp_path);
            let destination = SafeDiskCachePath::from_path(path.to_path_buf());
            let write_result = write_disk_cache_object(
                tmp_path.as_path(),
                self.encryption.as_ref(),
                store_key,
                internal_meta,
                response_header,
                body,
            )
            .and_then(|()| destination.rename_from(&tmp_path));
            match write_result {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = tmp_path.remove_file();
                    last_error = Some(error);
                }
                Err(error) => {
                    let _ = tmp_path.remove_file();
                    return Err(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "disk cache temporary path collision",
            )
        }))
    }

    fn create_body_temp(&self) -> std::io::Result<(PathBuf, std::fs::File)> {
        let temp_dir = self.body_temp_dir()?;
        let mut last_error = None;
        for _ in 0..4 {
            let tmp_path = self.random_temp_path_in(&temp_dir, "body")?;
            match create_new_disk_cache_file(&tmp_path) {
                Ok(file) => return Ok((tmp_path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "disk cache temporary path collision",
            )
        }))
    }

    fn body_temp_dir(&self) -> std::io::Result<PathBuf> {
        let temp_dir = self.root.join("tmp");
        match std::fs::symlink_metadata(&temp_dir) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "disk cache temp directory is not a real directory: {}",
                        temp_dir.display()
                    ),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(&temp_dir)?;
            }
            Err(error) => return Err(error),
        }
        if cache_path_contains_symlink(&self.root, &temp_dir)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "disk cache temp directory contains symlink: {}",
                    temp_dir.display()
                ),
            ));
        }
        let canonical = temp_dir.canonicalize()?;
        if canonical.starts_with(&self.root) {
            Ok(canonical)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "disk cache temp directory escaped root: {}",
                    canonical.display()
                ),
            ))
        }
    }

    fn write_streamed_object_atomically(
        &self,
        path: &Path,
        store_key: &PingoraStoreKey,
        internal_meta: &[u8],
        response_header: &[u8],
        body_path: &Path,
        body_len: u64,
    ) -> std::io::Result<()> {
        let mut last_error = None;
        for _ in 0..4 {
            let tmp_path = self.tmp_path_for(path)?;
            let tmp_path = SafeDiskCachePath::from_path(tmp_path);
            let destination = SafeDiskCachePath::from_path(path.to_path_buf());
            let write_result = write_disk_cache_object_from_body_file(
                tmp_path.as_path(),
                self.encryption.as_ref(),
                store_key,
                internal_meta,
                response_header,
                body_path,
                body_len,
            )
            .and_then(|()| destination.rename_from(&tmp_path));
            match write_result {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = tmp_path.remove_file();
                    last_error = Some(error);
                }
                Err(error) => {
                    let _ = tmp_path.remove_file();
                    return Err(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "disk cache temporary path collision",
            )
        }))
    }

    fn tmp_path_for(&self, path: &Path) -> std::io::Result<PathBuf> {
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("disk cache path has no parent"))?;
        self.random_temp_path_in(parent, "object")
    }

    fn random_temp_path_in(&self, parent: &Path, label: &str) -> std::io::Result<PathBuf> {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|error| {
            std::io::Error::other(format!("generate cache temp nonce: {error}"))
        })?;
        let mut encoded = String::with_capacity(nonce.len() * 2);
        for byte in nonce {
            let _ = write!(&mut encoded, "{byte:02x}");
        }
        Ok(parent.join(format!(
            ".fluxheim-{label}-{}.{}.tmp",
            std::process::id(),
            encoded
        )))
    }

    fn safe_existing_object_path(&self, path: &Path) -> std::io::Result<Option<PathBuf>> {
        if cache_path_contains_symlink(&self.root, path)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "disk cache object path contains symlink: {}",
                    path.display()
                ),
            ));
        }

        let canonical = match path.canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };

        if !canonical.starts_with(&self.root) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("disk cache object escaped root: {}", canonical.display()),
            ));
        }

        let metadata = SafeDiskCachePath::from_path(canonical.clone()).metadata()?;
        if !metadata.is_file() {
            return Ok(None);
        }

        self.disk_index
            .touch(&canonical, std::time::SystemTime::now());
        Ok(Some(canonical))
    }

    fn write_disk_index_checkpoint(&self) -> std::io::Result<()> {
        write_disk_index_checkpoint_from_index(&self.root, &self.disk_index)
    }

    #[cfg(test)]
    fn disk_index_checkpoint_flags(&self) -> (bool, bool) {
        match self.checkpoint_state.lock() {
            Ok(state) => (state.dirty, state.scheduled),
            Err(_) => (false, false),
        }
    }

    fn schedule_disk_index_checkpoint(&self) {
        let mut state = match self.checkpoint_state.lock() {
            Ok(state) => state,
            Err(_) => return,
        };
        state.dirty = true;
        if state.scheduled {
            return;
        }
        state.scheduled = true;

        let root = self.root.clone();
        let disk_index = self.disk_index.clone();
        let checkpoint_state = Arc::clone(&self.checkpoint_state);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(DISK_CACHE_INDEX_CHECKPOINT_DEBOUNCE);
                {
                    let mut state = match checkpoint_state.lock() {
                        Ok(state) => state,
                        Err(_) => return,
                    };
                    if !state.dirty {
                        state.scheduled = false;
                        return;
                    }
                    state.dirty = false;
                }

                if let Err(error) = write_disk_index_checkpoint_from_index(&root, &disk_index) {
                    log::warn!(
                        "failed to write disk cache checkpoint for {}: {error}",
                        root.display()
                    );
                }

                let mut state = match checkpoint_state.lock() {
                    Ok(state) => state,
                    Err(_) => return,
                };
                if !state.dirty {
                    state.scheduled = false;
                    return;
                }
            }
        });
    }

    fn ensure_safe_cache_parent(&self, parent: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(parent)?;
        if cache_path_contains_symlink(&self.root, parent)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("disk cache shard contains symlink: {}", parent.display()),
            ));
        }

        let canonical = parent.canonicalize()?;
        if canonical.starts_with(&self.root) && canonical.is_dir() {
            return Ok(());
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("disk cache shard escaped root: {}", canonical.display()),
        ))
    }
}

#[cfg(feature = "proxy")]
fn reject_unimplemented_disk_backend(backend: CacheDiskBackend) -> std::io::Result<()> {
    match backend {
        CacheDiskBackend::Filesystem => Ok(()),
        CacheDiskBackend::StorageBin => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "cache.disk.backend = \"storage-bin\" requires the generic disk storage backend factory",
        )),
    }
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
fn prepare_storage_bin_layout(
    layout: &StorageBinLayoutPlan,
) -> std::io::Result<StorageBinManifest> {
    let root = prepare_disk_cache_root(&layout.root)?;
    let canonical_layout = StorageBinLayoutPlan {
        root: root.clone(),
        manifest_path: root.join(STORAGE_BIN_MANIFEST_FILENAME),
        data_dir: root.join(STORAGE_BIN_DATA_DIR),
        bin_size_bytes: layout.bin_size_bytes,
        max_size_bytes: layout.max_size_bytes,
        preallocate: layout.preallocate,
        max_open_bins: layout.max_open_bins,
    };

    prepare_storage_bin_data_dir(&root, &canonical_layout.data_dir)?;
    match read_storage_bin_manifest(&root, &canonical_layout.manifest_path)? {
        Some(manifest) => {
            manifest.ensure_matches_layout(&canonical_layout)?;
            Ok(manifest)
        }
        None => {
            let manifest = StorageBinManifest::from_layout(&canonical_layout);
            write_storage_bin_manifest(&root, &canonical_layout.manifest_path, &manifest)?;
            Ok(manifest)
        }
    }
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
fn prepare_storage_bin_data_dir(root: &Path, data_dir: &Path) -> std::io::Result<PathBuf> {
    if cache_path_contains_symlink(root, data_dir)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin data directory contains symlink: {}",
                data_dir.display()
            ),
        ));
    }
    match cache_path_file_type_no_follow(data_dir)? {
        Some(file_type) if file_type.is_symlink() || !file_type.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "storage-bin data directory is not a real directory: {}",
                    data_dir.display()
                ),
            ));
        }
        Some(_) => {}
        None => {
            create_cache_dir_all(data_dir)?;
        }
    }
    if cache_path_contains_symlink(root, data_dir)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin data directory contains symlink: {}",
                data_dir.display()
            ),
        ));
    }
    let canonical = data_dir.canonicalize()?;
    if !canonical.starts_with(root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin data directory escaped root: {}",
                canonical.display()
            ),
        ));
    }
    Ok(canonical)
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
fn read_storage_bin_manifest(
    root: &Path,
    path: &Path,
) -> std::io::Result<Option<StorageBinManifest>> {
    use std::io::Read as _;

    if cache_path_contains_symlink(root, path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin manifest path contains symlink: {}",
                path.display()
            ),
        ));
    }
    let canonical = match path.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !canonical.starts_with(root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin manifest escaped root: {}", canonical.display()),
        ));
    }

    // lgtm[rs/path-injection] path is derived from the validated cache root and
    // opened through NOFOLLOW helpers after canonical root containment checks.
    let mut file = SafeDiskCachePath::from_path(canonical).open_existing_file()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    StorageBinManifest::decode(&contents).map(Some)
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
fn write_storage_bin_manifest(
    root: &Path,
    path: &Path,
    manifest: &StorageBinManifest,
) -> std::io::Result<()> {
    use std::io::Write as _;

    if !path.starts_with(root) || cache_path_contains_symlink(root, path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin manifest path is unsafe: {}", path.display()),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin manifest path has no parent: {}",
                path.display()
            ),
        )
    })?;
    let temp_path = storage_bin_manifest_temp_path(parent)?;
    let path = SafeDiskCachePath::from_path(path.to_path_buf());
    let temp_path = SafeDiskCachePath::from_path(temp_path);
    let write_result = (|| {
        let mut file = create_new_disk_cache_file(temp_path.as_path())?;
        file.write_all(manifest.encode().as_bytes())?;
        file.sync_all()?;
        path.rename_from(&temp_path)
    })();
    if write_result.is_err() {
        let _ = temp_path.remove_file();
    }
    write_result
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
fn storage_bin_manifest_temp_path(parent: &Path) -> std::io::Result<PathBuf> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|error| {
        std::io::Error::other(format!("generate storage-bin manifest temp nonce: {error}"))
    })?;
    let mut encoded = String::with_capacity(nonce.len() * 2);
    for byte in nonce {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    Ok(parent.join(format!(
        ".fluxheim-storage-bin-manifest.{}.{}.tmp",
        std::process::id(),
        encoded
    )))
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
fn storage_bin_index_path(root: &Path) -> PathBuf {
    root.join(STORAGE_BIN_INDEX_FILENAME)
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
fn read_storage_bin_index(
    layout: &StorageBinLayoutPlan,
) -> std::io::Result<Vec<StorageBinIndexEntry>> {
    use std::io::Read as _;

    let path = storage_bin_index_path(&layout.root);
    if cache_path_contains_symlink(&layout.root, &path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin index path contains symlink: {}",
                path.display()
            ),
        ));
    }
    let canonical = match path.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if !canonical.starts_with(&layout.root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin index escaped root: {}", canonical.display()),
        ));
    }

    // lgtm[rs/path-injection] path is derived from a validated storage-bin root
    // and opened through NOFOLLOW helpers after canonical root containment checks.
    let mut file = SafeDiskCachePath::from_path(canonical).open_existing_file()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    parse_storage_bin_index(layout, &contents)
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
fn parse_storage_bin_index(
    layout: &StorageBinLayoutPlan,
    contents: &str,
) -> std::io::Result<Vec<StorageBinIndexEntry>> {
    let mut lines = contents.lines();
    match lines.next() {
        Some(STORAGE_BIN_INDEX_MAGIC_V1) => {}
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid storage-bin index magic",
            ));
        }
    }
    let mut entries = Vec::new();
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid storage-bin index line",
            ));
        }
        let combined_key = storage_bin_hex_decode_string(fields[0])?;
        let location = StorageBinObjectLocation {
            bin_id: parse_storage_bin_index_u64(fields[1], "bin id")?,
            offset: parse_storage_bin_index_u64(fields[2], "offset")?,
            len: parse_storage_bin_index_u64(fields[3], "length")?,
        }
        .validate(layout.bin_size_bytes)?;
        entries.push(StorageBinIndexEntry {
            combined_key,
            location,
            accessed: unix_secs_system_time(parse_storage_bin_index_u64(fields[4], "accessed")?),
        });
    }
    Ok(entries)
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
fn write_storage_bin_index(
    layout: &StorageBinLayoutPlan,
    entries: &[StorageBinIndexEntry],
) -> std::io::Result<()> {
    use std::io::Write as _;

    let path = storage_bin_index_path(&layout.root);
    if !path.starts_with(&layout.root) || cache_path_contains_symlink(&layout.root, &path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin index path is unsafe: {}", path.display()),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin index path has no parent: {}", path.display()),
        )
    })?;
    let temp_path = storage_bin_index_temp_path(parent)?;
    let path = SafeDiskCachePath::from_path(path);
    let temp_path = SafeDiskCachePath::from_path(temp_path);
    let write_result = (|| {
        let mut file = create_new_disk_cache_file(temp_path.as_path())?;
        writeln!(file, "{STORAGE_BIN_INDEX_MAGIC_V1}")?;
        let mut entries = entries.to_vec();
        entries.sort_by(|left, right| left.combined_key.cmp(&right.combined_key));
        for entry in entries {
            entry.location.validate(layout.bin_size_bytes)?;
            writeln!(
                file,
                "{}\t{}\t{}\t{}\t{}",
                storage_bin_hex_encode(entry.combined_key.as_bytes()),
                entry.location.bin_id,
                entry.location.offset,
                entry.location.len,
                system_time_unix_secs(entry.accessed).unwrap_or(0)
            )?;
        }
        file.sync_all()?;
        path.rename_from(&temp_path)
    })();
    if write_result.is_err() {
        let _ = temp_path.remove_file();
    }
    write_result
}

#[cfg(feature = "proxy")]
fn write_storage_bin_index_from_objects(
    layout: &StorageBinLayoutPlan,
    objects: &RwLock<HashMap<String, StorageBinObjectEntry>>,
) -> std::io::Result<()> {
    let entries = match objects.read() {
        Ok(objects) => objects
            .iter()
            .map(|(combined_key, entry)| StorageBinIndexEntry {
                combined_key: combined_key.clone(),
                location: entry.location,
                accessed: entry.accessed,
            })
            .collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };
    write_storage_bin_index(layout, &entries)
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
fn read_storage_bin_index_entry_object(
    layout: &StorageBinLayoutPlan,
    max_object_bytes: ByteSize,
    encryption: Option<&DiskCacheEncryption>,
    entry: &StorageBinIndexEntry,
) -> std::io::Result<PingoraStoredObject> {
    let files = StorageBinFileSet::new(layout.clone());
    let bytes = files.read_object(entry.location)?;
    parse_disk_cache_object_maybe_encrypted(&bytes, max_object_bytes, encryption)
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(test), allow(dead_code))]
fn storage_bin_index_temp_path(parent: &Path) -> std::io::Result<PathBuf> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|error| {
        std::io::Error::other(format!("generate storage-bin index temp nonce: {error}"))
    })?;
    let mut encoded = String::with_capacity(nonce.len() * 2);
    for byte in nonce {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    Ok(parent.join(format!(
        ".fluxheim-storage-bin-index.{}.{}.tmp",
        std::process::id(),
        encoded
    )))
}

#[cfg(feature = "proxy")]
fn parse_storage_bin_index_u64(value: &str, field: &str) -> std::io::Result<u64> {
    value.parse::<u64>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid storage-bin index {field}: {error}"),
        )
    })
}

#[cfg(feature = "proxy")]
fn storage_bin_hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(feature = "proxy")]
fn storage_bin_hex_decode_string(value: &str) -> std::io::Result<String> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid storage-bin index hex key",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = storage_bin_hex_nibble(chunk[0]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid storage-bin index hex key",
            )
        })?;
        let low = storage_bin_hex_nibble(chunk[1]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid storage-bin index hex key",
            )
        })?;
        bytes.push((high << 4) | low);
    }
    String::from_utf8(bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("storage-bin index key is not utf-8: {error}"),
        )
    })
}

#[cfg(feature = "proxy")]
fn storage_bin_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug, Default)]
struct DiskIndexCheckpointState {
    dirty: bool,
    scheduled: bool,
}

#[cfg(feature = "proxy")]
fn write_disk_index_checkpoint_from_index(
    root: &Path,
    disk_index: &DiskObjectIndex,
) -> std::io::Result<()> {
    let mut entries = disk_index.entries();
    match read_disk_index_checkpoint(root)? {
        Some(existing) => entries.extend(existing),
        None => entries.extend(disk_cache_entries(root)?),
    }
    write_disk_index_checkpoint(root, merge_disk_cache_entries(entries))
}

#[cfg(feature = "proxy")]
fn prepare_disk_cache_root(root: &Path) -> std::io::Result<PathBuf> {
    if configured_cache_path_contains_symlink(root)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "disk cache root must not be below a symlinked directory: {}",
                root.display()
            ),
        ));
    }

    match cache_path_file_type_no_follow(root)? {
        Some(file_type) if file_type.is_symlink() || !file_type.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "disk cache root must be a real directory: {}",
                    root.display()
                ),
            ));
        }
        Some(_) => {}
        None => {
            create_cache_dir_all(root)?;
        }
    }

    if configured_cache_path_contains_symlink(root)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "disk cache root must not be below a symlinked directory: {}",
                root.display()
            ),
        ));
    }

    root.canonicalize()
}

#[cfg(feature = "proxy")]
fn cache_path_file_type_no_follow(path: &Path) -> std::io::Result<Option<rustix::fs::FileType>> {
    match rustix::fs::statat(rustix::fs::CWD, path, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(rustix::fs::FileType::from_raw_mode(stat.st_mode))),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
        Err(error) => Err(rustix_to_io_error(error)),
    }
}

#[cfg(feature = "proxy")]
fn create_cache_dir_all(path: &Path) -> std::io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(
            component,
            std::path::Component::Prefix(_)
                | std::path::Component::RootDir
                | std::path::Component::CurDir
        ) {
            continue;
        }
        if matches!(component, std::path::Component::ParentDir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "cache directory path must not contain parent traversal: {}",
                    path.display()
                ),
            ));
        }

        match cache_path_file_type_no_follow(&current)? {
            Some(file_type) if file_type.is_symlink() || !file_type.is_dir() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "cache directory path is not a real directory: {}",
                        current.display()
                    ),
                ));
            }
            Some(_) => {}
            None => {
                let mode = rustix::fs::Mode::RWXU | rustix::fs::Mode::RGRP | rustix::fs::Mode::XGRP;
                match rustix::fs::mkdir(&current, mode) {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(rustix_to_io_error(error)),
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "proxy")]
fn configured_cache_path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

#[cfg(feature = "proxy")]
fn cache_path_contains_symlink(root: &Path, path: &Path) -> std::io::Result<bool> {
    let Ok(relative) = path.strip_prefix(root) else {
        return Ok(true);
    };

    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Ok(true);
        }
    }

    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!("inspect cache path {}: {error}", current.display()),
                ));
            }
        }
    }

    Ok(false)
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone)]
struct SafeCacheScanDir {
    path: PathBuf,
}

#[cfg(feature = "proxy")]
impl SafeCacheScanDir {
    fn as_path(&self) -> &Path {
        &self.path
    }

    fn read_entries(&self) -> std::io::Result<std::fs::ReadDir> {
        std::fs::read_dir(&self.path)
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone)]
struct SafeDiskCachePath {
    path: PathBuf,
}

#[cfg(feature = "proxy")]
impl SafeDiskCachePath {
    fn from_path(path: PathBuf) -> Self {
        Self { path }
    }

    fn as_path(&self) -> &Path {
        &self.path
    }

    fn parent_and_name(&self) -> std::io::Result<(&Path, &std::ffi::OsStr)> {
        let parent = self.path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("disk cache path has no parent: {}", self.path.display()),
            )
        })?;
        let name = self.path.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("disk cache path has no file name: {}", self.path.display()),
            )
        })?;
        Ok((parent, name))
    }

    fn open_parent_dir(&self) -> std::io::Result<std::fs::File> {
        let (parent, _) = self.parent_and_name()?;
        let fd = rustix::fs::open(
            parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map_err(rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.open_existing_file()?.metadata()
    }

    fn create_new_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn create_new_read_write_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn open_existing_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn open_read_write_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn rename_from(&self, source: &SafeDiskCachePath) -> std::io::Result<()> {
        let (_, source_name) = source.parent_and_name()?;
        let (_, destination_name) = self.parent_and_name()?;
        let source_parent = source.open_parent_dir()?;
        let destination_parent = self.open_parent_dir()?;
        rustix::fs::renameat(
            &source_parent,
            source_name,
            &destination_parent,
            destination_name,
        )
        .map_err(rustix_to_io_error)
    }

    fn remove_file(&self) -> std::io::Result<()> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        rustix::fs::unlinkat(&parent, name, rustix::fs::AtFlags::empty())
            .map_err(rustix_to_io_error)
    }
}

#[cfg(feature = "proxy")]
fn rustix_to_io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(feature = "proxy")]
fn safe_existing_cache_scan_dir(
    root: &Path,
    path: &Path,
) -> std::io::Result<Option<SafeCacheScanDir>> {
    if cache_path_contains_symlink(root, path)? {
        return Ok(None);
    }
    let canonical = match path.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if canonical.starts_with(root) && canonical.is_dir() {
        Ok(Some(SafeCacheScanDir { path: canonical }))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "proxy")]
fn disk_cache_shard_dirs(root: &Path) -> std::io::Result<Vec<SafeCacheScanDir>> {
    let mut dirs = Vec::new();
    for high in b"0123456789abcdef" {
        for low in b"0123456789abcdef" {
            let shard = [*high as char, *low as char].iter().collect::<String>();
            if let Some(dir) = safe_existing_cache_scan_dir(root, &root.join(shard))? {
                dirs.push(dir);
            }
        }
    }
    Ok(dirs)
}

#[cfg(feature = "proxy")]
fn disk_cache_temp_dir(root: &Path) -> std::io::Result<Option<SafeCacheScanDir>> {
    safe_existing_cache_scan_dir(root, &root.join("tmp"))
}

#[cfg(feature = "proxy")]
fn disk_index_checkpoint_path(root: &Path) -> PathBuf {
    root.join(DISK_CACHE_INDEX_FILENAME)
}

#[cfg(feature = "proxy")]
fn read_disk_index_checkpoint(root: &Path) -> std::io::Result<Option<Vec<DiskCacheEntry>>> {
    use std::io::Read as _;

    let path = disk_index_checkpoint_path(root);
    if cache_path_contains_symlink(root, &path)? {
        return Ok(None);
    }
    let mut file = match open_existing_disk_cache_file(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let checkpoint_modified = file.metadata()?.modified().unwrap_or(std::time::UNIX_EPOCH);
    if disk_index_checkpoint_is_stale(root, checkpoint_modified)? {
        return Ok(None);
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let mut lines = contents.lines();
    if lines.next() != Some(DISK_CACHE_INDEX_MAGIC_V1) {
        return Ok(None);
    }

    let mut entries = Vec::new();
    for line in lines {
        let Some(entry) = parse_disk_index_checkpoint_line(root, line)? else {
            return Ok(None);
        };
        entries.push(entry);
    }

    Ok(Some(entries))
}

#[cfg(feature = "proxy")]
fn disk_index_checkpoint_is_stale(
    root: &Path,
    checkpoint_modified: std::time::SystemTime,
) -> std::io::Result<bool> {
    for shard in disk_cache_shard_dirs(root)? {
        let modified = shard
            .as_path()
            .metadata()?
            .modified()
            .unwrap_or(std::time::UNIX_EPOCH);
        if modified > checkpoint_modified {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(feature = "proxy")]
fn parse_disk_index_checkpoint_line(
    root: &Path,
    line: &str,
) -> std::io::Result<Option<DiskCacheEntry>> {
    let mut fields = line.split('\t');
    let Some(relative_path) = fields.next() else {
        return Ok(None);
    };
    let Some(size) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
        return Ok(None);
    };
    let Some(modified) = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .map(unix_secs_system_time)
    else {
        return Ok(None);
    };
    let Some(accessed) = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .map(unix_secs_system_time)
    else {
        return Ok(None);
    };
    if fields.next().is_some() {
        return Ok(None);
    }

    let Some(path) = safe_disk_index_relative_path(root, relative_path) else {
        return Ok(None);
    };
    let Some(metadata) = symlink_free_regular_metadata(root, &path)? else {
        return Ok(None);
    };
    if metadata.len() != size {
        return Ok(None);
    }

    Ok(Some(DiskCacheEntry {
        combined_key: None,
        path,
        size,
        modified,
        accessed,
    }))
}

#[cfg(feature = "proxy")]
fn safe_disk_index_relative_path(root: &Path, relative_path: &str) -> Option<PathBuf> {
    let relative = Path::new(relative_path);
    let components = relative.components().collect::<Vec<_>>();
    if components.len() != 2 {
        return None;
    }
    let std::path::Component::Normal(shard) = components[0] else {
        return None;
    };
    let std::path::Component::Normal(file_name) = components[1] else {
        return None;
    };
    let shard = shard.to_str()?;
    let file_name = file_name.to_str()?;
    if shard.len() != 2 || !shard.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let encoded = file_name.strip_suffix(".fhc")?;
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(root.join(shard).join(file_name))
}

#[cfg(feature = "proxy")]
fn write_disk_index_checkpoint(
    root: &Path,
    mut entries: Vec<DiskCacheEntry>,
) -> std::io::Result<()> {
    use std::io::Write as _;

    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let path = disk_index_checkpoint_path(root);
    let temp_path = disk_index_temp_path(root)?;
    let path = SafeDiskCachePath::from_path(path);
    let temp_path = SafeDiskCachePath::from_path(temp_path);
    let write_result = (|| {
        let mut file = create_new_disk_cache_file(temp_path.as_path())?;
        writeln!(file, "{DISK_CACHE_INDEX_MAGIC_V1}")?;
        for entry in entries {
            let Ok(relative) = entry.path.strip_prefix(root) else {
                continue;
            };
            let Some(relative) = relative.to_str() else {
                continue;
            };
            writeln!(
                file,
                "{}\t{}\t{}\t{}",
                relative,
                entry.size,
                system_time_unix_secs(entry.modified).unwrap_or(0),
                system_time_unix_secs(entry.accessed).unwrap_or(0)
            )?;
        }
        file.sync_all()?;
        path.rename_from(&temp_path)
    })();
    if write_result.is_err() {
        let _ = temp_path.remove_file();
    }
    write_result
}

#[cfg(feature = "proxy")]
fn merge_disk_cache_entries(entries: Vec<DiskCacheEntry>) -> Vec<DiskCacheEntry> {
    let mut merged = HashMap::<PathBuf, DiskCacheEntry>::new();
    for entry in entries {
        merged
            .entry(entry.path.clone())
            .and_modify(|current| {
                current.size = entry.size;
                current.modified = current.modified.max(entry.modified);
                current.accessed = current.accessed.max(entry.accessed);
            })
            .or_insert(entry);
    }
    merged.into_values().collect()
}

#[cfg(feature = "proxy")]
fn disk_index_temp_path(root: &Path) -> std::io::Result<PathBuf> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|error| {
        std::io::Error::other(format!("generate disk index temp nonce: {error}"))
    })?;
    let mut encoded = String::with_capacity(nonce.len() * 2);
    for byte in nonce {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    Ok(root.join(format!(
        ".fluxheim-disk-index-{}.{}.tmp",
        std::process::id(),
        encoded
    )))
}

#[cfg(feature = "proxy")]
fn unix_secs_system_time(secs: u64) -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)
}

#[cfg(feature = "proxy")]
fn symlink_free_regular_metadata(
    root: &Path,
    path: &Path,
) -> std::io::Result<Option<std::fs::Metadata>> {
    if cache_path_contains_symlink(root, path)? {
        return Ok(None);
    }
    let safe_path = SafeDiskCachePath::from_path(path.to_path_buf());
    let metadata = match safe_path.metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.is_file() {
        Ok(Some(metadata))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug)]
pub struct PingoraTieredStorage {
    memory: &'static PingoraMemoryStorage,
    disk: &'static PingoraDiskStorageBackend,
}

#[cfg(feature = "proxy")]
impl PingoraTieredStorage {
    pub fn new(
        memory: &'static PingoraMemoryStorage,
        disk: &'static PingoraDiskStorageBackend,
    ) -> Self {
        Self { memory, disk }
    }

    pub fn memory(&self) -> &'static PingoraMemoryStorage {
        self.memory
    }

    pub fn disk(&self) -> &'static PingoraDiskStorageBackend {
        self.disk
    }

    pub fn stats(&self) -> std::io::Result<TieredCacheStats> {
        Ok(TieredCacheStats {
            memory: self.memory.stats(),
            disk: self.disk.stats()?,
        })
    }

    pub fn reset_activity(&self) {
        self.memory.reset_activity();
        self.disk.reset_activity();
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone)]
struct PingoraStoreKey {
    combined: String,
    primary: String,
    user_tag: String,
    index_path: Option<String>,
    cache_tags: Vec<String>,
}

#[cfg(feature = "proxy")]
impl PingoraStoreKey {
    fn from_cache_key_and_meta(
        key: &pingora::cache::CacheKey,
        meta: &CacheMeta,
        cache_tag_headers: &[String],
    ) -> Self {
        Self {
            combined: key.combined(),
            primary: key.primary(),
            user_tag: key.user_tag.clone(),
            index_path: key
                .primary_key_str()
                .and_then(|primary| cache_primary_component(primary, "path")),
            cache_tags: cache_tags_from_meta(meta, cache_tag_headers),
        }
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone)]
struct PingoraStoredObject {
    combined_key: Option<String>,
    primary_key: Option<String>,
    user_tag: Option<String>,
    index_path: Option<String>,
    cache_tags: Vec<String>,
    internal_meta: Vec<u8>,
    response_header: Vec<u8>,
    body: Arc<[u8]>,
    weight: u32,
}

#[cfg(feature = "proxy")]
fn cache_purge_entry_from_stored_object(
    fallback_combined_key: &str,
    object: &PingoraStoredObject,
) -> Option<CachePurgeIndexEntry> {
    let combined_key = object
        .combined_key
        .clone()
        .unwrap_or_else(|| fallback_combined_key.to_owned());
    let primary_key = object.primary_key.clone()?;
    let user_tag = object.user_tag.clone().unwrap_or_default();
    let path = object
        .index_path
        .clone()
        .or_else(|| cache_primary_component(&primary_key, "path"));
    Some(CachePurgeIndexEntry {
        combined_key,
        primary_key,
        user_tag,
        path,
        cache_tags: object.cache_tags.clone(),
    })
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Eq, PartialEq)]
struct DiskCacheEntry {
    combined_key: Option<String>,
    path: PathBuf,
    size: u64,
    modified: std::time::SystemTime,
    accessed: std::time::SystemTime,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct DiskObjectLruKey {
    accessed: std::time::SystemTime,
    modified: std::time::SystemTime,
    path: PathBuf,
}

#[cfg(feature = "proxy")]
impl DiskObjectLruKey {
    fn from_entry(entry: &DiskCacheEntry) -> Self {
        Self {
            accessed: entry.accessed,
            modified: entry.modified,
            path: entry.path.clone(),
        }
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone)]
struct DiskObjectIndex {
    inner: Arc<RwLock<DiskObjectIndexInner>>,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Default)]
struct DiskObjectIndexInner {
    entries: HashMap<PathBuf, DiskCacheEntry>,
    lru: BTreeSet<DiskObjectLruKey>,
    total_size: u64,
}

#[cfg(feature = "proxy")]
impl DiskObjectIndex {
    fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(DiskObjectIndexInner::default())),
        }
    }

    fn replace_all(&self, entries: Vec<DiskCacheEntry>) {
        let Ok(mut inner) = self.inner.write() else {
            return;
        };
        inner.entries.clear();
        inner.lru.clear();
        inner.total_size = 0;
        for entry in entries {
            inner.total_size = inner.total_size.saturating_add(entry.size);
            inner.lru.insert(DiskObjectLruKey::from_entry(&entry));
            inner.entries.insert(entry.path.clone(), entry);
        }
    }

    fn upsert(&self, entry: DiskCacheEntry) {
        let Ok(mut inner) = self.inner.write() else {
            return;
        };
        if let Some(previous) = inner.entries.insert(entry.path.clone(), entry.clone()) {
            inner.total_size = inner.total_size.saturating_sub(previous.size);
            inner.lru.remove(&DiskObjectLruKey::from_entry(&previous));
        }
        inner.total_size = inner.total_size.saturating_add(entry.size);
        inner.lru.insert(DiskObjectLruKey::from_entry(&entry));
    }

    fn remove(&self, path: &Path) -> Option<DiskCacheEntry> {
        let Ok(mut inner) = self.inner.write() else {
            return None;
        };
        let previous = inner.entries.remove(path)?;
        inner.total_size = inner.total_size.saturating_sub(previous.size);
        inner.lru.remove(&DiskObjectLruKey::from_entry(&previous));
        Some(previous)
    }

    fn touch(&self, path: &Path, accessed: std::time::SystemTime) {
        let Ok(mut inner) = self.inner.write() else {
            return;
        };
        if let Some(entry) = inner.entries.get_mut(path) {
            let previous = DiskObjectLruKey::from_entry(entry);
            entry.accessed = accessed;
            let updated = DiskObjectLruKey::from_entry(entry);
            inner.lru.remove(&previous);
            inner.lru.insert(updated);
        }
    }

    fn snapshot(&self) -> (Vec<DiskCacheEntry>, u64) {
        let Ok(inner) = self.inner.read() else {
            return (Vec::new(), 0);
        };
        (inner.entries.values().cloned().collect(), inner.total_size)
    }

    fn entries(&self) -> Vec<DiskCacheEntry> {
        self.snapshot().0
    }

    fn total_size(&self) -> u64 {
        let Ok(inner) = self.inner.read() else {
            return 0;
        };
        inner.total_size
    }

    fn entry_size(&self, path: &Path) -> Option<u64> {
        let Ok(inner) = self.inner.read() else {
            return None;
        };
        inner.entries.get(path).map(|entry| entry.size)
    }

    fn oldest_entries_to_free(
        &self,
        excluded_path: &Path,
        bytes_to_free: u64,
    ) -> Vec<DiskCacheEntry> {
        if bytes_to_free == 0 {
            return Vec::new();
        }
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };
        let mut selected = Vec::new();
        let mut selected_bytes = 0_u64;
        for key in &inner.lru {
            if key.path == excluded_path {
                continue;
            }
            let Some(entry) = inner.entries.get(&key.path) else {
                continue;
            };
            selected_bytes = selected_bytes.saturating_add(entry.size);
            selected.push(entry.clone());
            if selected_bytes >= bytes_to_free {
                break;
            }
        }
        selected
    }

    fn stats(&self) -> (usize, u64) {
        let Ok(inner) = self.inner.read() else {
            return (0, 0);
        };
        (inner.entries.len(), inner.total_size)
    }
}

#[cfg(feature = "proxy")]
fn disk_cache_entries(root: &Path) -> std::io::Result<Vec<DiskCacheEntry>> {
    let mut entries = Vec::new();
    for shard in disk_cache_shard_dirs(root)? {
        for entry in shard.read_entries()? {
            let entry = entry?;
            let Some((path, metadata)) = safe_cache_object_entry(root, shard.as_path(), &entry)?
            else {
                continue;
            };
            entries.push(DiskCacheEntry {
                combined_key: None,
                path,
                size: metadata.len(),
                modified: metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
                accessed: metadata.accessed().unwrap_or(std::time::UNIX_EPOCH),
            });
        }
    }
    Ok(entries)
}

#[cfg(feature = "proxy")]
fn safe_cache_object_entry(
    root: &Path,
    shard_path: &Path,
    entry: &std::fs::DirEntry,
) -> std::io::Result<Option<(PathBuf, std::fs::Metadata)>> {
    let file_type = entry.file_type()?;
    if file_type.is_symlink() || !file_type.is_file() {
        return Ok(None);
    }

    let file_name = entry.file_name();
    let Some(name) = file_name.to_str() else {
        return Ok(None);
    };
    let Some(encoded) = name.strip_suffix(".fhc") else {
        return Ok(None);
    };
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(None);
    }

    let path = shard_path.join(name);
    if cache_path_contains_symlink(root, &path)? {
        return Ok(None);
    }

    let canonical = path.canonicalize()?;
    if !canonical.starts_with(root) {
        return Ok(None);
    }

    let metadata = entry.metadata()?;
    if metadata.is_file() {
        Ok(Some((canonical, metadata)))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "proxy")]
fn cleanup_stale_disk_cache_temp_files(
    root: &Path,
    min_age: std::time::Duration,
) -> std::io::Result<usize> {
    let mut removed = 0_usize;

    if let Some(temp_dir) = disk_cache_temp_dir(root)? {
        removed =
            removed.saturating_add(cleanup_stale_disk_cache_temp_dir(root, &temp_dir, min_age)?);
    }

    for shard_path in disk_cache_shard_dirs(root)? {
        removed = removed.saturating_add(cleanup_stale_disk_cache_temp_dir(
            root,
            &shard_path,
            min_age,
        )?);
    }

    Ok(removed)
}

#[cfg(feature = "proxy")]
fn cleanup_stale_disk_cache_temp_dir(
    root: &Path,
    dir: &SafeCacheScanDir,
    min_age: std::time::Duration,
) -> std::io::Result<usize> {
    let mut removed = 0_usize;
    let now = std::time::SystemTime::now();
    for entry in dir.read_entries()? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if !is_fluxheim_disk_cache_temp_name(name) {
            continue;
        }
        let path = dir.as_path().join(name);
        if cache_path_contains_symlink(root, &path)? {
            continue;
        }
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(root) {
            continue;
        }
        let Some(metadata) = symlink_free_regular_metadata(root, &canonical)? else {
            continue;
        };
        let modified = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
        let age = now
            .duration_since(modified)
            .unwrap_or(std::time::Duration::ZERO);
        if age < min_age {
            continue;
        }
        SafeDiskCachePath::from_path(canonical).remove_file()?;
        removed = removed.saturating_add(1);
    }
    Ok(removed)
}

#[cfg(feature = "proxy")]
fn is_fluxheim_disk_cache_temp_name(name: &str) -> bool {
    (name.starts_with(".fluxheim-body-") || name.starts_with(".fluxheim-object-"))
        && name.ends_with(".tmp")
}

#[cfg(feature = "proxy")]
fn remove_disk_cache_object(root: &Path, path: &Path) -> std::io::Result<bool> {
    if path.extension() != Some(std::ffi::OsStr::new("fhc")) {
        return Ok(false);
    }
    if cache_path_contains_symlink(root, path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "disk cache object path contains symlink: {}",
                path.display()
            ),
        ));
    }

    let safe_path = SafeDiskCachePath::from_path(path.to_path_buf());
    let metadata = match safe_path.metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() {
        return Ok(false);
    }

    match safe_path.remove_file() {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "proxy")]
pub fn pingora_memory_storage_from_config(
    config: &CacheConfig,
) -> Option<&'static PingoraMemoryStorage> {
    storage_plan(config).memory.map(|plan| {
        pingora_memory_storage_from_plan_with_key(plan, StorageRegistryNamespace::Global)
    })
}

#[cfg(feature = "proxy")]
pub fn pingora_memory_storage_from_config_with_metric_scope(
    config: &CacheConfig,
    vhost: &str,
    route: Option<&str>,
) -> Option<&'static PingoraMemoryStorage> {
    let namespace = StorageRegistryNamespace::from_parts(Some(vhost), route);
    storage_plan(config)
        .memory
        .map(|plan| pingora_memory_storage_from_plan_with_key(plan, namespace))
}

#[cfg(feature = "proxy")]
pub fn pingora_memory_storage_from_plan(plan: MemoryTierPlan) -> &'static PingoraMemoryStorage {
    Box::leak(Box::new(PingoraMemoryStorage::from_plan(plan)))
}

#[cfg(feature = "proxy")]
fn pingora_memory_storage_from_plan_with_key(
    plan: MemoryTierPlan,
    namespace: StorageRegistryNamespace,
) -> &'static PingoraMemoryStorage {
    let key = MemoryStorageRegistryKey {
        namespace,
        plan: plan.clone(),
    };
    let registry = PINGORA_MEMORY_STORAGE_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut storage = lock_cache_registry(registry, "memory-storage");
    if let Some(existing) = storage.get(&key) {
        return existing;
    }
    let created = if let Some((vhost, route)) = key.namespace.metric_scope() {
        Box::leak(Box::new(PingoraMemoryStorage::from_plan_with_metric_scope(
            plan, vhost, route,
        ))) as &'static PingoraMemoryStorage
    } else {
        Box::leak(Box::new(PingoraMemoryStorage::from_plan(plan))) as &'static PingoraMemoryStorage
    };
    storage.insert(key, created);
    created
}

#[cfg(feature = "proxy")]
pub fn pingora_disk_storage_from_config(
    config: &CacheConfig,
) -> std::io::Result<Option<&'static PingoraDiskStorage>> {
    storage_plan(config)
        .disk
        .map(|plan| pingora_disk_storage_from_plan_with_key(plan, StorageRegistryNamespace::Global))
        .transpose()
}

#[cfg(feature = "proxy")]
pub fn pingora_disk_storage_from_config_with_metric_scope(
    config: &CacheConfig,
    vhost: &str,
    route: Option<&str>,
) -> std::io::Result<Option<&'static PingoraDiskStorage>> {
    let namespace = StorageRegistryNamespace::from_parts(Some(vhost), route);
    storage_plan(config)
        .disk
        .map(|plan| pingora_disk_storage_from_plan_with_key(plan, namespace))
        .transpose()
}

#[cfg(feature = "proxy")]
pub fn pingora_disk_storage_from_plan(
    plan: DiskTierPlan,
) -> std::io::Result<&'static PingoraDiskStorage> {
    PingoraDiskStorage::from_plan(plan)
        .map(|storage| Box::leak(Box::new(storage)) as &'static PingoraDiskStorage)
}

#[cfg(feature = "proxy")]
fn pingora_disk_storage_from_plan_with_key(
    plan: DiskTierPlan,
    namespace: StorageRegistryNamespace,
) -> std::io::Result<&'static PingoraDiskStorage> {
    let key = DiskStorageRegistryKey {
        namespace,
        plan: plan.clone(),
    };
    let registry = PINGORA_DISK_STORAGE_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut storage = lock_cache_registry(registry, "disk-storage");
    if let Some(existing) = storage.get(&key) {
        return Ok(*existing);
    }
    let created = if let Some((vhost, route)) = key.namespace.metric_scope() {
        PingoraDiskStorage::from_plan_with_metric_scope(plan, vhost, route)
    } else {
        PingoraDiskStorage::from_plan(plan)
    }
    .map(|storage| Box::leak(Box::new(storage)) as &'static PingoraDiskStorage)?;
    storage.insert(key, created);
    Ok(created)
}

#[cfg(feature = "proxy")]
pub fn pingora_disk_storage_backend_from_config_with_metric_scope(
    config: &CacheConfig,
    vhost: &str,
    route: Option<&str>,
) -> std::io::Result<Option<&'static PingoraDiskStorageBackend>> {
    let namespace = StorageRegistryNamespace::from_parts(Some(vhost), route);
    storage_plan(config)
        .disk
        .map(|plan| pingora_disk_storage_backend_from_plan_with_key(plan, namespace))
        .transpose()
}

#[cfg(feature = "proxy")]
pub fn pingora_disk_storage_backend_from_plan(
    plan: DiskTierPlan,
) -> std::io::Result<&'static PingoraDiskStorageBackend> {
    PingoraDiskStorageBackend::from_plan(plan)
        .map(|storage| Box::leak(Box::new(storage)) as &'static PingoraDiskStorageBackend)
}

#[cfg(feature = "proxy")]
fn pingora_disk_storage_backend_from_plan_with_key(
    plan: DiskTierPlan,
    namespace: StorageRegistryNamespace,
) -> std::io::Result<&'static PingoraDiskStorageBackend> {
    let key = DiskStorageRegistryKey {
        namespace,
        plan: plan.clone(),
    };
    let registry = PINGORA_DISK_STORAGE_BACKEND_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut storage = lock_cache_registry(registry, "disk-storage-backend");
    if let Some(existing) = storage.get(&key) {
        return Ok(*existing);
    }
    let created = if let Some((vhost, route)) = key.namespace.metric_scope() {
        PingoraDiskStorageBackend::from_plan_with_metric_scope(plan, vhost, route)
    } else {
        PingoraDiskStorageBackend::from_plan(plan)
    }
    .map(|storage| Box::leak(Box::new(storage)) as &'static PingoraDiskStorageBackend)?;
    storage.insert(key, created);
    Ok(created)
}

#[cfg(feature = "proxy")]
pub fn pingora_tiered_storage_from_parts(
    memory: &'static PingoraMemoryStorage,
    disk: &'static PingoraDiskStorageBackend,
) -> &'static PingoraTieredStorage {
    let key = format!("{:p}:{:p}", memory, disk);
    let registry = PINGORA_TIERED_STORAGE_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut storage = lock_cache_registry(registry, "tiered-storage");
    if let Some(existing) = storage.get(&key) {
        return existing;
    }
    let created = Box::leak(Box::new(PingoraTieredStorage::new(memory, disk)));
    storage.insert(key, created);
    created
}

#[cfg(feature = "proxy")]
pub fn pingora_cache_lock(age_timeout: std::time::Duration) -> &'static CacheKeyLockImpl {
    let key = (age_timeout.as_secs(), age_timeout.subsec_nanos());
    let registry = PINGORA_CACHE_LOCK_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = lock_cache_registry(registry, "cache-lock");
    if let Some(existing) = locks.get(&key) {
        return *existing;
    }
    let created = Box::leak(CacheLock::new_boxed(age_timeout)) as &'static CacheKeyLockImpl;
    locks.insert(key, created);
    created
}

pub fn storage_plan(config: &CacheConfig) -> CacheStoragePlan {
    let memory = config.memory.enabled.then(|| MemoryTierPlan {
        max_size_bytes: config.memory.max_size_bytes,
        max_object_bytes: config.max_object_bytes,
        object_slots: object_slots(config.memory.max_size_bytes, config.max_object_bytes),
        cache_tag_headers: config.tag_headers.clone(),
    });

    let disk = config
        .disk
        .enabled
        .then(|| {
            config.disk.path.as_ref().map(|path| DiskTierPlan {
                backend: config.disk.backend,
                path: path.clone(),
                max_size_bytes: config.disk.max_size_bytes,
                max_object_bytes: config.max_object_bytes,
                cache_tag_headers: config.tag_headers.clone(),
                storage_bin: config.disk.storage_bin.clone(),
                encryption: config.disk.encryption.clone(),
            })
        })
        .flatten();

    CacheStoragePlan { memory, disk }
}

fn cached_object_weight(object: &CachedImageObject) -> u64 {
    let headers = object.headers.iter().fold(0_u64, |total, header| {
        total
            .saturating_add(header.name.len() as u64)
            .saturating_add(header.value.len() as u64)
    });
    (object.body.len() as u64).saturating_add(headers)
}

#[cfg(feature = "proxy")]
fn pingora_object_weight(internal_meta: &[u8], response_header: &[u8], body: &[u8]) -> u64 {
    pingora_object_weight_len(internal_meta, response_header, body.len() as u64)
}

#[cfg(feature = "proxy")]
fn pingora_object_weight_len(internal_meta: &[u8], response_header: &[u8], body_len: u64) -> u64 {
    (internal_meta.len() as u64)
        .saturating_add(response_header.len() as u64)
        .saturating_add(body_len)
}

#[cfg(feature = "proxy")]
fn cache_object_metadata(
    tier: CacheObjectTier,
    purge_indexed: bool,
    object: &PingoraStoredObject,
) -> pingora::Result<Option<CacheObjectMetadata>> {
    let meta = CacheMeta::deserialize(&object.internal_meta, &object.response_header)?;
    let now = std::time::SystemTime::now();
    let fresh = meta.is_fresh(now);
    let serve_stale_while_revalidate = !fresh && meta.serve_stale_while_revalidate(now);
    let serve_stale_if_error = !fresh && meta.serve_stale_if_error(now);
    let freshness_state = if fresh {
        CacheObjectFreshnessState::Fresh
    } else if serve_stale_while_revalidate || serve_stale_if_error {
        CacheObjectFreshnessState::Stale
    } else {
        CacheObjectFreshnessState::Expired
    };
    let mut header_names = meta
        .headers()
        .keys()
        .map(|name| name.as_str().to_ascii_lowercase())
        .collect::<Vec<_>>();
    header_names.sort();
    header_names.dedup();
    let header_values = cache_object_header_values_from_meta(&meta, &header_names);

    Ok(Some(CacheObjectMetadata {
        tier,
        purge_indexed,
        status: meta.response_header().status.as_u16(),
        fresh,
        freshness_state,
        serve_stale_while_revalidate,
        serve_stale_if_error,
        body_bytes: object.body.len() as u64,
        weight_bytes: pingora_object_weight(
            &object.internal_meta,
            &object.response_header,
            &object.body,
        ),
        created_unix_secs: system_time_unix_secs(meta.created()),
        updated_unix_secs: system_time_unix_secs(meta.updated()),
        fresh_until_unix_secs: system_time_unix_secs(meta.fresh_until()),
        age_secs: meta.age().as_secs(),
        fresh_ttl_secs: meta.fresh_sec(),
        stale_while_revalidate_secs: meta.stale_while_revalidate_sec(),
        stale_if_error_secs: meta.stale_if_error_sec(),
        cache_tags: object.cache_tags.clone(),
        header_names,
        header_values,
    }))
}

#[cfg(feature = "proxy")]
fn cache_object_header_values_from_meta(
    meta: &CacheMeta,
    header_names: &[String],
) -> Vec<CacheObjectHeaderValue> {
    const MAX_CACHE_LOOKUP_HEADER_VALUES: usize = 64;
    const MAX_CACHE_LOOKUP_HEADER_VALUE_BYTES: usize = 8192;

    let mut values = Vec::new();
    let mut total_bytes = 0_usize;
    for name in header_names {
        for value in meta.headers().get_all(name) {
            if values.len() >= MAX_CACHE_LOOKUP_HEADER_VALUES {
                return values;
            }
            let Ok(value) = value.to_str() else {
                continue;
            };
            let value_bytes = value.len();
            if value_bytes > MAX_CACHE_LOOKUP_HEADER_VALUE_BYTES
                || total_bytes.saturating_add(value_bytes) > MAX_CACHE_LOOKUP_HEADER_VALUE_BYTES
            {
                continue;
            }
            total_bytes += value_bytes;
            values.push(CacheObjectHeaderValue {
                name: name.clone(),
                value: value.to_owned(),
            });
        }
    }
    values
}

#[cfg(feature = "proxy")]
fn system_time_unix_secs(time: std::time::SystemTime) -> Option<u64> {
    time.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(feature = "proxy")]
fn stale_cache_meta(internal_meta: &[u8], response_header: &[u8]) -> pingora::Result<CacheMeta> {
    let previous = CacheMeta::deserialize(internal_meta, response_header)?;
    let now = std::time::SystemTime::now();
    let fresh_until = now
        .checked_sub(std::time::Duration::from_secs(1))
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let mut meta = CacheMeta::new(
        fresh_until,
        previous.created(),
        previous.stale_while_revalidate_sec(),
        previous.stale_if_error_sec(),
        previous.response_header_copy(),
    );
    if let Some(variance) = previous.variance() {
        meta.set_variance(variance);
    }
    if let Some(epoch_override) = previous.epoch_override() {
        meta.set_epoch_override(epoch_override);
    }
    Ok(meta)
}

#[cfg(feature = "proxy")]
fn disk_cache_header_overhead(store_key: &PingoraStoreKey) -> u64 {
    let combined_len = store_key.combined.len() as u64;
    let primary_len = store_key.primary.len() as u64;
    let user_tag_len = store_key.user_tag.len() as u64;
    let cache_tags_len = encoded_cache_tags_len(&store_key.cache_tags) as u64;
    let index_path_len = store_key.index_path.as_deref().unwrap_or_default().len() as u64;
    (DISK_CACHE_MAGIC_V5.len() as u64)
        .saturating_add(decimal_line_len(combined_len))
        .saturating_add(decimal_line_len(primary_len))
        .saturating_add(decimal_line_len(user_tag_len))
        .saturating_add(decimal_line_len(cache_tags_len))
        .saturating_add(decimal_line_len(index_path_len))
        .saturating_add(combined_len)
        .saturating_add(primary_len)
        .saturating_add(user_tag_len)
        .saturating_add(cache_tags_len)
        .saturating_add(index_path_len)
}

#[cfg(feature = "proxy")]
fn decimal_line_len(value: u64) -> u64 {
    value.to_string().len() as u64 + 1
}

#[cfg(feature = "proxy")]
#[async_trait]
impl Storage for PingoraMemoryStorage {
    async fn lookup(
        &'static self,
        key: &pingora::cache::CacheKey,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<Option<(CacheMeta, HitHandler)>> {
        let Some(object) = self.lookup_object(key) else {
            self.activity.miss();
            return Ok(None);
        };
        self.activity.hit();
        let meta = CacheMeta::deserialize(&object.internal_meta, &object.response_header)?;
        let handler = PingoraMemoryHitHandler {
            body: object.body,
            offset: 0,
            end: None,
        };
        Ok(Some((meta, Box::new(handler))))
    }

    async fn get_miss_handler(
        &'static self,
        key: &pingora::cache::CacheKey,
        meta: &CacheMeta,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<MissHandler> {
        Ok(Box::new(PingoraMemoryMissHandler {
            storage: self,
            store_key: PingoraStoreKey::from_cache_key_and_meta(key, meta, &self.cache_tag_headers),
            serialized_meta: meta.serialize()?,
            body: Vec::new(),
            max_object_bytes: self.max_object_bytes.as_u64(),
            exceeded_limit: false,
        }))
    }

    async fn purge(
        &'static self,
        key: &pingora::cache::key::CompactCacheKey,
        _purge_type: PurgeType,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<bool> {
        let key = key.combined();
        let existed = self.inner.get(&key).is_some();
        self.inner.invalidate(&key);
        self.purge_index.remove_combined(&key);
        self.inner.run_pending_tasks();
        if existed {
            self.activity.purge();
        }
        Ok(existed)
    }

    async fn update_meta(
        &'static self,
        key: &pingora::cache::CacheKey,
        meta: &CacheMeta,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<bool> {
        let combined_key = key.combined();
        let Some(mut object) = self.inner.get(&combined_key) else {
            return Ok(false);
        };
        let (internal_meta, response_header) = meta.serialize()?;
        let weight_bytes = pingora_object_weight(&internal_meta, &response_header, &object.body);
        if weight_bytes > self.max_object_bytes.as_u64() {
            self.inner.invalidate(&combined_key);
            self.purge_index.remove_combined(&combined_key);
            self.inner.run_pending_tasks();
            self.activity.store_refusal();
            return Ok(false);
        }
        let weight = u32::try_from(weight_bytes).map_err(|_| {
            self.activity.store_refusal();
            Error::because(
                ErrorType::InternalError,
                "cache object weight exceeds moka object weight limit",
                std::io::Error::other("cache object too heavy"),
            )
        })?;

        object.internal_meta = internal_meta;
        object.response_header = response_header;
        object.cache_tags = cache_tags_from_meta(meta, &self.cache_tag_headers);
        object.index_path = key
            .primary_key_str()
            .and_then(|primary| cache_primary_component(primary, "path"));
        object.weight = weight;
        self.purge_index.insert_with_path_and_tags(
            combined_key.clone(),
            object.primary_key.clone().unwrap_or_else(|| key.primary()),
            key.user_tag.clone(),
            key.primary_key_str()
                .and_then(|primary| cache_primary_component(primary, "path")),
            object.cache_tags.clone(),
        );
        self.inner.insert(combined_key, object);
        self.activity.store();
        Ok(true)
    }

    fn support_streaming_partial_write(&self) -> bool {
        false
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync + 'static) {
        self
    }
}

#[cfg(feature = "proxy")]
#[async_trait]
impl Storage for PingoraDiskStorage {
    async fn lookup(
        &'static self,
        key: &pingora::cache::CacheKey,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<Option<(CacheMeta, HitHandler)>> {
        let Some(object) = self.lookup_object(key)? else {
            self.activity.miss();
            return Ok(None);
        };
        self.activity.hit();
        let meta = CacheMeta::deserialize(&object.internal_meta, &object.response_header)?;
        let handler = PingoraMemoryHitHandler {
            body: object.body,
            offset: 0,
            end: None,
        };
        Ok(Some((meta, Box::new(handler))))
    }

    async fn get_miss_handler(
        &'static self,
        key: &pingora::cache::CacheKey,
        meta: &CacheMeta,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<MissHandler> {
        let store_key =
            PingoraStoreKey::from_cache_key_and_meta(key, meta, &self.cache_tag_headers);
        let (temp_path, temp_file) = self
            .create_body_temp()
            .map_err(|error| cache_io_error("create disk cache streamed body temp file", error))?;
        Ok(Box::new(PingoraDiskMissHandler {
            storage: self,
            store_key,
            serialized_meta: meta.serialize()?,
            temp_path: Some(temp_path),
            temp_file: Some(temp_file),
            body_len: 0,
            max_object_bytes: self.max_object_bytes.as_u64(),
            exceeded_limit: false,
        }))
    }

    async fn purge(
        &'static self,
        key: &pingora::cache::key::CompactCacheKey,
        _purge_type: PurgeType,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<bool> {
        let combined_key = key.combined();
        let path = self.path_for_combined_key(&combined_key);
        let purged = self
            .purge_object_path(path)
            .map_err(|error| cache_io_error("purge disk cache object", error))?;
        self.purge_index.remove_combined(&combined_key);
        Ok(purged)
    }

    async fn update_meta(
        &'static self,
        key: &pingora::cache::CacheKey,
        meta: &CacheMeta,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<bool> {
        let Some(object) = self.lookup_object(key)? else {
            return Ok(false);
        };
        let (internal_meta, response_header) = meta.serialize()?;
        Ok(self
            .put_serialized_object(
                PingoraStoreKey::from_cache_key_and_meta(key, meta, &self.cache_tag_headers),
                internal_meta,
                response_header,
                object.body,
            )?
            .is_some())
    }

    fn support_streaming_partial_write(&self) -> bool {
        false
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync + 'static) {
        self
    }
}

#[cfg(feature = "proxy")]
#[async_trait]
impl Storage for StorageBinDiskStorage {
    async fn lookup(
        &'static self,
        key: &pingora::cache::CacheKey,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<Option<(CacheMeta, HitHandler)>> {
        let Some(object) = self.lookup_object_by_combined(&key.combined())? else {
            return Ok(None);
        };
        let meta = CacheMeta::deserialize(&object.internal_meta, &object.response_header)?;
        let handler = PingoraMemoryHitHandler {
            body: object.body,
            offset: 0,
            end: None,
        };
        Ok(Some((meta, Box::new(handler))))
    }

    async fn get_miss_handler(
        &'static self,
        key: &pingora::cache::CacheKey,
        meta: &CacheMeta,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<MissHandler> {
        Ok(Box::new(StorageBinMissHandler {
            storage: self,
            store_key: PingoraStoreKey::from_cache_key_and_meta(key, meta, &self.cache_tag_headers),
            serialized_meta: meta.serialize()?,
            body: Vec::new(),
            max_object_bytes: self.max_object_bytes.as_u64(),
            exceeded_limit: false,
        }))
    }

    async fn purge(
        &'static self,
        key: &pingora::cache::key::CompactCacheKey,
        _purge_type: PurgeType,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<bool> {
        self.purge_combined(&key.combined())
            .map_err(|error| cache_io_error("purge storage-bin cache object", error))
    }

    async fn update_meta(
        &'static self,
        key: &pingora::cache::CacheKey,
        meta: &CacheMeta,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<bool> {
        let Some(object) = self.lookup_object_by_combined(&key.combined())? else {
            return Ok(false);
        };
        let (internal_meta, response_header) = meta.serialize()?;
        Ok(self
            .put_object(
                PingoraStoreKey::from_cache_key_and_meta(key, meta, &self.cache_tag_headers),
                internal_meta,
                response_header,
                object.body,
            )?
            .is_some())
    }

    fn support_streaming_partial_write(&self) -> bool {
        false
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync + 'static) {
        self
    }
}

#[cfg(feature = "proxy")]
#[async_trait]
impl Storage for PingoraDiskStorageBackend {
    async fn lookup(
        &'static self,
        key: &pingora::cache::CacheKey,
        trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<Option<(CacheMeta, HitHandler)>> {
        match self {
            Self::Filesystem(storage) => storage.lookup(key, trace).await,
            Self::StorageBin(storage) => storage.lookup(key, trace).await,
        }
    }

    async fn get_miss_handler(
        &'static self,
        key: &pingora::cache::CacheKey,
        meta: &CacheMeta,
        trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<MissHandler> {
        match self {
            Self::Filesystem(storage) => storage.get_miss_handler(key, meta, trace).await,
            Self::StorageBin(storage) => storage.get_miss_handler(key, meta, trace).await,
        }
    }

    async fn purge(
        &'static self,
        key: &pingora::cache::key::CompactCacheKey,
        purge_type: PurgeType,
        trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<bool> {
        match self {
            Self::Filesystem(storage) => storage.purge(key, purge_type, trace).await,
            Self::StorageBin(storage) => storage.purge(key, purge_type, trace).await,
        }
    }

    async fn update_meta(
        &'static self,
        key: &pingora::cache::CacheKey,
        meta: &CacheMeta,
        trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<bool> {
        match self {
            Self::Filesystem(storage) => storage.update_meta(key, meta, trace).await,
            Self::StorageBin(storage) => storage.update_meta(key, meta, trace).await,
        }
    }

    fn support_streaming_partial_write(&self) -> bool {
        false
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync + 'static) {
        self
    }
}

#[cfg(feature = "proxy")]
#[async_trait]
impl Storage for PingoraTieredStorage {
    async fn lookup(
        &'static self,
        key: &pingora::cache::CacheKey,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<Option<(CacheMeta, HitHandler)>> {
        if let Some(object) = self.memory.lookup_object(key) {
            self.memory.activity.hit();
            let meta = CacheMeta::deserialize(&object.internal_meta, &object.response_header)?;
            let handler = PingoraMemoryHitHandler {
                body: object.body,
                offset: 0,
                end: None,
            };
            return Ok(Some((meta, Box::new(handler))));
        }
        self.memory.activity.miss();

        let Some(object) = self.disk.lookup_object(key)? else {
            self.disk.record_miss();
            return Ok(None);
        };
        self.disk.record_hit();
        let meta = CacheMeta::deserialize(&object.internal_meta, &object.response_header)?;
        let primary_key = object.primary_key.clone().unwrap_or_else(|| key.primary());
        let _promoted = self.memory.put_serialized_object(
            PingoraStoreKey {
                combined: key.combined(),
                primary: primary_key,
                user_tag: key.user_tag.clone(),
                index_path: key
                    .primary_key_str()
                    .and_then(|primary| cache_primary_component(primary, "path")),
                cache_tags: object.cache_tags.clone(),
            },
            object.internal_meta.clone(),
            object.response_header.clone(),
            Arc::clone(&object.body),
        );
        let handler = PingoraMemoryHitHandler {
            body: object.body,
            offset: 0,
            end: None,
        };
        Ok(Some((meta, Box::new(handler))))
    }

    async fn get_miss_handler(
        &'static self,
        key: &pingora::cache::CacheKey,
        meta: &CacheMeta,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<MissHandler> {
        Ok(Box::new(PingoraTieredMissHandler {
            storage: self,
            store_key: PingoraStoreKey::from_cache_key_and_meta(
                key,
                meta,
                &self.memory.cache_tag_headers,
            ),
            serialized_meta: meta.serialize()?,
            body: Vec::new(),
            max_object_bytes: self
                .memory
                .max_object_bytes
                .as_u64()
                .min(self.disk.max_object_bytes().as_u64()),
            exceeded_limit: false,
        }))
    }

    async fn purge(
        &'static self,
        key: &pingora::cache::key::CompactCacheKey,
        purge_type: PurgeType,
        trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<bool> {
        let memory_purged = self.memory.purge(key, purge_type, trace).await?;
        let disk_purged = self.disk.purge(key, purge_type, trace).await?;
        Ok(memory_purged || disk_purged)
    }

    async fn update_meta(
        &'static self,
        key: &pingora::cache::CacheKey,
        meta: &CacheMeta,
        trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<bool> {
        let memory_updated = self.memory.update_meta(key, meta, trace).await?;
        let disk_updated = self.disk.update_meta(key, meta, trace).await?;
        Ok(memory_updated || disk_updated)
    }

    fn support_streaming_partial_write(&self) -> bool {
        false
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync + 'static) {
        self
    }
}

#[cfg(feature = "proxy")]
struct PingoraMemoryHitHandler {
    body: Arc<[u8]>,
    offset: usize,
    end: Option<usize>,
}

#[cfg(feature = "proxy")]
#[async_trait]
impl pingora::cache::storage::HandleHit for PingoraMemoryHitHandler {
    async fn read_body(&mut self) -> pingora::Result<Option<Bytes>> {
        let end = self.end.unwrap_or(self.body.len()).min(self.body.len());
        if self.offset >= end {
            return Ok(None);
        }

        let chunk = Bytes::copy_from_slice(&self.body[self.offset..end]);
        self.offset = end;
        Ok(Some(chunk))
    }

    async fn finish(
        self: Box<Self>,
        _storage: &'static (dyn Storage + Sync),
        _key: &pingora::cache::CacheKey,
        _trace: &pingora::cache::trace::SpanHandle,
    ) -> pingora::Result<()> {
        Ok(())
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(&mut self, start: usize, end: Option<usize>) -> pingora::Result<()> {
        if start > self.body.len() {
            return Error::e_explain(
                ErrorType::InternalError,
                format!(
                    "cache seek start out of range: {start} > {}",
                    self.body.len()
                ),
            );
        }
        self.offset = start;
        self.end = end;
        Ok(())
    }

    fn get_eviction_weight(&self) -> usize {
        self.body.len()
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn std::any::Any + Send + Sync) {
        self
    }
}

#[cfg(feature = "proxy")]
struct PingoraMemoryMissHandler {
    storage: &'static PingoraMemoryStorage,
    store_key: PingoraStoreKey,
    serialized_meta: (Vec<u8>, Vec<u8>),
    body: Vec<u8>,
    max_object_bytes: u64,
    exceeded_limit: bool,
}

#[cfg(feature = "proxy")]
#[async_trait]
impl pingora::cache::storage::HandleMiss for PingoraMemoryMissHandler {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> pingora::Result<()> {
        if self.exceeded_limit {
            return Ok(());
        }

        let next_len = (self.body.len() as u64).saturating_add(data.len() as u64);
        if next_len > self.max_object_bytes {
            self.exceeded_limit = true;
            self.body.clear();
            return Ok(());
        }
        self.body.extend_from_slice(&data);
        Ok(())
    }

    async fn finish(self: Box<Self>) -> pingora::Result<MissFinishType> {
        if self.exceeded_limit {
            return Ok(MissFinishType::Created(0));
        }

        let meta = CacheMeta::deserialize(&self.serialized_meta.0, &self.serialized_meta.1)?;
        let created =
            self.storage
                .put_object(self.store_key, meta, Arc::<[u8]>::from(self.body))?;
        Ok(MissFinishType::Created(created))
    }
}

#[cfg(feature = "proxy")]
struct PingoraDiskMissHandler {
    storage: &'static PingoraDiskStorage,
    store_key: PingoraStoreKey,
    serialized_meta: (Vec<u8>, Vec<u8>),
    temp_path: Option<PathBuf>,
    temp_file: Option<std::fs::File>,
    body_len: u64,
    max_object_bytes: u64,
    exceeded_limit: bool,
}

#[cfg(feature = "proxy")]
impl PingoraDiskMissHandler {
    fn cleanup_temp(&mut self) {
        let _ = self.temp_file.take();
        if let Some(path) = self.temp_path.take() {
            let _ = SafeDiskCachePath::from_path(path).remove_file();
        }
    }
}

#[cfg(feature = "proxy")]
impl Drop for PingoraDiskMissHandler {
    fn drop(&mut self) {
        self.cleanup_temp();
    }
}

#[cfg(feature = "proxy")]
#[async_trait]
impl pingora::cache::storage::HandleMiss for PingoraDiskMissHandler {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> pingora::Result<()> {
        if self.exceeded_limit {
            return Ok(());
        }

        let next_len = self.body_len.saturating_add(data.len() as u64);
        if next_len > self.max_object_bytes {
            self.exceeded_limit = true;
            self.cleanup_temp();
            return Ok(());
        }
        let Some(file) = self.temp_file.as_mut() else {
            return Err(cache_io_error(
                "write disk cache streamed body",
                std::io::Error::other("disk cache streamed body temp file is closed"),
            ));
        };
        use std::io::Write as _;
        file.write_all(&data)
            .map_err(|error| cache_io_error("write disk cache streamed body", error))?;
        self.body_len = next_len;
        Ok(())
    }

    async fn finish(self: Box<Self>) -> pingora::Result<MissFinishType> {
        let mut this = *self;
        if this.exceeded_limit {
            this.cleanup_temp();
            return Ok(MissFinishType::Created(0));
        }

        if let Some(file) = this.temp_file.take() {
            file.sync_all()
                .map_err(|error| cache_io_error("sync disk cache streamed body", error))?;
        }
        let Some(temp_path) = this.temp_path.as_deref() else {
            return Err(cache_io_error(
                "finish disk cache streamed body",
                std::io::Error::other("disk cache streamed body temp file is missing"),
            ));
        };
        let Some(created) = this.storage.put_streamed_object(
            this.store_key.clone(),
            this.serialized_meta.0.clone(),
            this.serialized_meta.1.clone(),
            temp_path,
            this.body_len,
        )?
        else {
            this.cleanup_temp();
            return Ok(MissFinishType::Created(0));
        };
        this.cleanup_temp();
        Ok(MissFinishType::Created(created))
    }
}

#[cfg(feature = "proxy")]
struct StorageBinMissHandler {
    storage: &'static StorageBinDiskStorage,
    store_key: PingoraStoreKey,
    serialized_meta: (Vec<u8>, Vec<u8>),
    body: Vec<u8>,
    max_object_bytes: u64,
    exceeded_limit: bool,
}

#[cfg(feature = "proxy")]
#[async_trait]
impl pingora::cache::storage::HandleMiss for StorageBinMissHandler {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> pingora::Result<()> {
        if self.exceeded_limit {
            return Ok(());
        }

        let next_len = (self.body.len() as u64).saturating_add(data.len() as u64);
        if next_len > self.max_object_bytes {
            self.exceeded_limit = true;
            self.body.clear();
            return Ok(());
        }
        self.body.extend_from_slice(&data);
        Ok(())
    }

    async fn finish(self: Box<Self>) -> pingora::Result<MissFinishType> {
        if self.exceeded_limit {
            return Ok(MissFinishType::Created(0));
        }

        let body = Arc::<[u8]>::from(self.body);
        let Some(created) = self.storage.put_object(
            self.store_key,
            self.serialized_meta.0,
            self.serialized_meta.1,
            body,
        )?
        else {
            return Ok(MissFinishType::Created(0));
        };
        Ok(MissFinishType::Created(created))
    }
}

#[cfg(feature = "proxy")]
struct PingoraTieredMissHandler {
    storage: &'static PingoraTieredStorage,
    store_key: PingoraStoreKey,
    serialized_meta: (Vec<u8>, Vec<u8>),
    body: Vec<u8>,
    max_object_bytes: u64,
    exceeded_limit: bool,
}

#[cfg(feature = "proxy")]
#[async_trait]
impl pingora::cache::storage::HandleMiss for PingoraTieredMissHandler {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> pingora::Result<()> {
        if self.exceeded_limit {
            return Ok(());
        }

        let next_len = (self.body.len() as u64).saturating_add(data.len() as u64);
        if next_len > self.max_object_bytes {
            self.exceeded_limit = true;
            self.body.clear();
            return Ok(());
        }
        self.body.extend_from_slice(&data);
        Ok(())
    }

    async fn finish(self: Box<Self>) -> pingora::Result<MissFinishType> {
        if self.exceeded_limit {
            return Ok(MissFinishType::Created(0));
        }

        let body = Arc::<[u8]>::from(self.body);
        let memory_created = self.storage.memory.put_serialized_object(
            self.store_key.clone(),
            self.serialized_meta.0.clone(),
            self.serialized_meta.1.clone(),
            Arc::clone(&body),
        )?;
        let disk_created = self.storage.disk.put_serialized_object(
            self.store_key,
            self.serialized_meta.0,
            self.serialized_meta.1,
            body,
        )?;
        Ok(MissFinishType::Created(
            memory_created.or(disk_created).unwrap_or(0),
        ))
    }
}

#[cfg(feature = "proxy")]
fn write_disk_cache_object(
    path: &Path,
    encryption: Option<&DiskCacheEncryption>,
    store_key: &PingoraStoreKey,
    internal_meta: &[u8],
    response_header: &[u8],
    body: &[u8],
) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut file = create_new_disk_cache_file(path)?;
    file.write_all(&encode_disk_cache_object_maybe_encrypted(
        encryption,
        store_key,
        internal_meta,
        response_header,
        body,
    )?)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(feature = "proxy")]
fn encode_disk_cache_object_maybe_encrypted(
    encryption: Option<&DiskCacheEncryption>,
    store_key: &PingoraStoreKey,
    internal_meta: &[u8],
    response_header: &[u8],
    body: &[u8],
) -> std::io::Result<Vec<u8>> {
    let encoded = encode_disk_cache_object(store_key, internal_meta, response_header, body)?;
    match encryption {
        Some(encryption) => encrypt_disk_cache_object(encryption, &store_key.combined, &encoded),
        None => Ok(encoded),
    }
}

#[cfg(feature = "proxy")]
fn encode_disk_cache_object(
    store_key: &PingoraStoreKey,
    internal_meta: &[u8],
    response_header: &[u8],
    body: &[u8],
) -> std::io::Result<Vec<u8>> {
    use std::io::Write as _;

    let encoded_cache_tags = encode_cache_tags(&store_key.cache_tags);

    let index_path = store_key.index_path.as_deref().unwrap_or_default();

    let mut encoded = Vec::with_capacity(
        DISK_CACHE_MAGIC_V5.len()
            + 128
            + store_key.combined.len()
            + store_key.primary.len()
            + store_key.user_tag.len()
            + encoded_cache_tags.len()
            + index_path.len()
            + internal_meta.len()
            + response_header.len()
            + body.len(),
    );
    encoded.write_all(DISK_CACHE_MAGIC_V5)?;
    writeln!(encoded, "{}", store_key.combined.len())?;
    writeln!(encoded, "{}", store_key.primary.len())?;
    writeln!(encoded, "{}", store_key.user_tag.len())?;
    writeln!(encoded, "{}", encoded_cache_tags.len())?;
    writeln!(encoded, "{}", index_path.len())?;
    writeln!(encoded, "{}", internal_meta.len())?;
    writeln!(encoded, "{}", response_header.len())?;
    writeln!(encoded, "{}", body.len())?;
    encoded.write_all(store_key.combined.as_bytes())?;
    encoded.write_all(store_key.primary.as_bytes())?;
    encoded.write_all(store_key.user_tag.as_bytes())?;
    encoded.write_all(encoded_cache_tags.as_bytes())?;
    encoded.write_all(index_path.as_bytes())?;
    encoded.write_all(internal_meta)?;
    encoded.write_all(response_header)?;
    encoded.write_all(body)?;
    Ok(encoded)
}

#[cfg(feature = "proxy")]
fn encrypt_disk_cache_object(
    encryption: &DiskCacheEncryption,
    combined_key: &str,
    plaintext: &[u8],
) -> std::io::Result<Vec<u8>> {
    use std::io::Write as _;

    let aad = cache_encryption_aad(&encryption.key_id, combined_key);
    let (nonce, ciphertext) = match &encryption.provider {
        DiskCacheEncryptionProvider::Local { key } => {
            let mut nonce = [0_u8; 12];
            getrandom::fill(&mut nonce).map_err(|error| {
                std::io::Error::other(format!("generate cache encryption nonce: {error}"))
            })?;
            let nonce_value = ring::aead::Nonce::assume_unique_for_key(nonce);
            let mut ciphertext = plaintext.to_vec();
            key.seal_in_place_append_tag(nonce_value, ring::aead::Aad::from(aad), &mut ciphertext)
                .map_err(|_| std::io::Error::other("encrypt cache object"))?;
            (nonce.to_vec(), ciphertext)
        }
        DiskCacheEncryptionProvider::OpenBaoTransit {
            address,
            mount,
            key_name,
            token,
        } => {
            let ciphertext = openbao_transit_encrypt(
                address,
                mount,
                key_name,
                token.as_ref().as_str(),
                plaintext,
                &aad,
            )?;
            (Vec::new(), ciphertext.into_bytes())
        }
    };

    let mut encoded = Vec::with_capacity(
        DISK_CACHE_ENCRYPTED_MAGIC_V1.len()
            + 128
            + encryption.key_id.len()
            + combined_key.len()
            + nonce.len()
            + ciphertext.len(),
    );
    encoded.write_all(DISK_CACHE_ENCRYPTED_MAGIC_V1)?;
    writeln!(encoded, "{}", encryption.key_id.len())?;
    writeln!(encoded, "{}", combined_key.len())?;
    writeln!(encoded, "{}", nonce.len())?;
    writeln!(encoded, "{}", ciphertext.len())?;
    encoded.write_all(encryption.key_id.as_bytes())?;
    encoded.write_all(combined_key.as_bytes())?;
    encoded.write_all(&nonce)?;
    encoded.write_all(&ciphertext)?;
    Ok(encoded)
}

#[cfg(feature = "proxy")]
fn decrypt_disk_cache_object_if_needed(
    bytes: &[u8],
    encryption: Option<&DiskCacheEncryption>,
) -> std::io::Result<Vec<u8>> {
    if bytes.get(..DISK_CACHE_ENCRYPTED_MAGIC_V1.len()) != Some(DISK_CACHE_ENCRYPTED_MAGIC_V1) {
        if encryption.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unencrypted cache object found while cache disk encryption is enabled",
            ));
        }
        return Ok(bytes.to_vec());
    }

    let Some(encryption) = encryption else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted cache object found but cache disk encryption is disabled",
        ));
    };

    let mut offset = DISK_CACHE_ENCRYPTED_MAGIC_V1.len();
    let key_id_len = parse_disk_cache_len(bytes, &mut offset)?;
    let combined_key_len = parse_disk_cache_len(bytes, &mut offset)?;
    let nonce_len = parse_disk_cache_len(bytes, &mut offset)?;
    let ciphertext_len = parse_disk_cache_len(bytes, &mut offset)?;
    let total_len = offset
        .checked_add(key_id_len)
        .and_then(|value| value.checked_add(combined_key_len))
        .and_then(|value| value.checked_add(nonce_len))
        .and_then(|value| value.checked_add(ciphertext_len))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encrypted cache object size overflow",
            )
        })?;
    if total_len != bytes.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted cache object length mismatch",
        ));
    }

    let key_id_end = offset + key_id_len;
    let combined_key_end = key_id_end + combined_key_len;
    let nonce_end = combined_key_end + nonce_len;
    let key_id = cache_object_utf8(&bytes[offset..key_id_end], "encryption key id")?;
    if key_id != encryption.key_id.as_ref() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted cache object key id does not match configured key",
        ));
    }
    let combined_key = cache_object_utf8(&bytes[key_id_end..combined_key_end], "combined key")?;
    let aad = cache_encryption_aad(&encryption.key_id, &combined_key);
    match &encryption.provider {
        DiskCacheEncryptionProvider::Local { key } => {
            if nonce_len != 12 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid encrypted cache object nonce length",
                ));
            }
            let mut nonce = [0_u8; 12];
            nonce.copy_from_slice(&bytes[combined_key_end..nonce_end]);
            let mut plaintext = bytes[nonce_end..].to_vec();
            key.open_in_place(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::from(aad),
                &mut plaintext,
            )
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "decrypt cache object")
            })?;
            let plaintext_len = plaintext
                .len()
                .checked_sub(ring::aead::AES_256_GCM.tag_len())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "short encrypted cache object",
                    )
                })?;
            plaintext.truncate(plaintext_len);
            Ok(plaintext)
        }
        DiskCacheEncryptionProvider::OpenBaoTransit {
            address,
            mount,
            key_name,
            token,
        } => {
            if nonce_len != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid OpenBao encrypted cache object nonce length",
                ));
            }
            let ciphertext = cache_object_utf8(&bytes[nonce_end..], "openbao ciphertext")?;
            openbao_transit_decrypt(
                address,
                mount,
                key_name,
                token.as_ref().as_str(),
                &ciphertext,
                &aad,
            )
        }
    }
}

#[cfg(feature = "proxy")]
fn cache_encryption_aad(key_id: &str, combined_key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + key_id.len() + combined_key.len());
    aad.extend_from_slice(b"fluxheim-cache-disk-v1\0");
    aad.extend_from_slice(key_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(combined_key.as_bytes());
    aad
}

#[cfg(feature = "proxy")]
fn openbao_transit_encrypt(
    address: &str,
    mount: &str,
    key_name: &str,
    token: &str,
    plaintext: &[u8],
    aad: &[u8],
) -> std::io::Result<String> {
    let request = serde_json::json!({
        "plaintext": base64_standard_encode(plaintext)?,
        "associated_data": base64_standard_encode(aad)?,
    });
    let mut response = ureq::post(openbao_transit_url(address, mount, "encrypt", key_name))
        .header("X-Vault-Token", token)
        .header("Accept", "application/json")
        .send_json(request)
        .map_err(|error| openbao_io_error("encrypt", error))?;
    let value: serde_json::Value = response
        .body_mut()
        .read_json()
        .map_err(|error| openbao_io_error("encrypt response", error))?;
    value
        .pointer("/data/ciphertext")
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.starts_with("vault:v"))
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "OpenBao Transit encrypt response did not include a ciphertext",
            )
        })
}

#[cfg(feature = "proxy")]
fn openbao_transit_decrypt(
    address: &str,
    mount: &str,
    key_name: &str,
    token: &str,
    ciphertext: &str,
    aad: &[u8],
) -> std::io::Result<Vec<u8>> {
    let request = serde_json::json!({
        "ciphertext": ciphertext,
        "associated_data": base64_standard_encode(aad)?,
    });
    let mut response = ureq::post(openbao_transit_url(address, mount, "decrypt", key_name))
        .header("X-Vault-Token", token)
        .header("Accept", "application/json")
        .send_json(request)
        .map_err(|error| openbao_io_error("decrypt", error))?;
    let value: serde_json::Value = response
        .body_mut()
        .read_json()
        .map_err(|error| openbao_io_error("decrypt response", error))?;
    let plaintext = value
        .pointer("/data/plaintext")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "OpenBao Transit decrypt response did not include plaintext",
            )
        })?;
    base64_ng::STANDARD
        .decode_vec(plaintext.as_bytes())
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "OpenBao Transit decrypt response plaintext is not valid base64",
            )
        })
}

#[cfg(feature = "proxy")]
fn base64_standard_encode(input: &[u8]) -> std::io::Result<String> {
    base64_ng::STANDARD.encode_string(input).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("base64 encode failed: {error}"),
        )
    })
}

#[cfg(feature = "proxy")]
fn openbao_io_error(operation: &str, error: ureq::Error) -> std::io::Error {
    std::io::Error::other(format!("OpenBao Transit {operation} failed: {error}"))
}

#[cfg(feature = "proxy")]
fn openbao_transit_url(address: &str, mount: &str, operation: &str, key_name: &str) -> String {
    format!(
        "{}/v1/{}/{}/{}",
        address.trim_end_matches('/'),
        openbao_path_encode(mount.trim_matches('/')),
        operation,
        openbao_path_encode(key_name.trim_matches('/'))
    )
}

#[cfg(feature = "proxy")]
fn openbao_path_encode(value: &str) -> String {
    value
        .split('/')
        .map(percent_encode_openbao_path_segment)
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(feature = "proxy")]
fn percent_encode_openbao_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(feature = "proxy")]
fn write_disk_cache_object_from_body_file(
    path: &Path,
    encryption: Option<&DiskCacheEncryption>,
    store_key: &PingoraStoreKey,
    internal_meta: &[u8],
    response_header: &[u8],
    body_path: &Path,
    body_len: u64,
) -> std::io::Result<()> {
    use std::io::{Read as _, Write as _};

    if encryption.is_some() {
        let body_file = open_existing_disk_cache_file(body_path)?;
        let metadata = body_file.metadata()?;
        if !metadata.is_file() || metadata.len() != body_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "disk cache streamed body length changed before commit",
            ));
        }
        let mut body = Vec::new();
        let copied = body_file
            .take(body_len.saturating_add(1))
            .read_to_end(&mut body)? as u64;
        if copied != body_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "disk cache streamed body ended before expected length",
            ));
        }
        return write_disk_cache_object(
            path,
            encryption,
            store_key,
            internal_meta,
            response_header,
            &body,
        );
    }

    let mut file = create_new_disk_cache_file(path)?;
    let encoded_cache_tags = encode_cache_tags(&store_key.cache_tags);

    let index_path = store_key.index_path.as_deref().unwrap_or_default();

    file.write_all(DISK_CACHE_MAGIC_V5)?;
    writeln!(file, "{}", store_key.combined.len())?;
    writeln!(file, "{}", store_key.primary.len())?;
    writeln!(file, "{}", store_key.user_tag.len())?;
    writeln!(file, "{}", encoded_cache_tags.len())?;
    writeln!(file, "{}", index_path.len())?;
    writeln!(file, "{}", internal_meta.len())?;
    writeln!(file, "{}", response_header.len())?;
    writeln!(file, "{body_len}")?;
    file.write_all(store_key.combined.as_bytes())?;
    file.write_all(store_key.primary.as_bytes())?;
    file.write_all(store_key.user_tag.as_bytes())?;
    file.write_all(encoded_cache_tags.as_bytes())?;
    file.write_all(index_path.as_bytes())?;
    file.write_all(internal_meta)?;
    file.write_all(response_header)?;

    let body_file = open_existing_disk_cache_file(body_path)?;
    let metadata = body_file.metadata()?;
    if !metadata.is_file() || metadata.len() != body_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "disk cache streamed body length changed before commit",
        ));
    }
    let copied = std::io::copy(&mut body_file.take(body_len.saturating_add(1)), &mut file)?;
    if copied != body_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "disk cache streamed body ended before expected length",
        ));
    }
    file.sync_all()?;
    Ok(())
}

#[cfg(feature = "proxy")]
fn create_new_disk_cache_file(path: &Path) -> std::io::Result<std::fs::File> {
    SafeDiskCachePath::from_path(path.to_path_buf()).create_new_file()
}

#[cfg(feature = "proxy")]
fn open_existing_disk_cache_file(path: &Path) -> std::io::Result<std::fs::File> {
    SafeDiskCachePath::from_path(path.to_path_buf()).open_existing_file()
}

#[cfg(feature = "proxy")]
fn read_disk_cache_object(
    root: &Path,
    path: &Path,
    max_object_bytes: ByteSize,
) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    if cache_path_contains_symlink(root, path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "disk cache object path contains symlink: {}",
                path.display()
            ),
        ));
    }

    let canonical = path.canonicalize()?;
    if !canonical.starts_with(root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("disk cache object escaped root: {}", canonical.display()),
        ));
    }

    let file = SafeDiskCachePath::from_path(canonical).open_existing_file()?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "disk cache object is not a regular file: {}",
                path.display()
            ),
        ));
    }

    let max_encoded_bytes = max_object_bytes
        .as_u64()
        .saturating_add(DISK_CACHE_HEADER_OVERHEAD_LIMIT);
    if metadata.len() > max_encoded_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "disk cache object is larger than configured object limit: {}",
                path.display()
            ),
        ));
    }

    let mut bytes = Vec::new();
    let mut reader = file.take(max_encoded_bytes.saturating_add(1));
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_encoded_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "disk cache object grew beyond configured object limit: {}",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

#[cfg(feature = "proxy")]
fn require_disk_cache_write_destination(path: &Path) -> std::io::Result<()> {
    match SafeDiskCachePath::from_path(path.to_path_buf()).metadata() {
        Ok(metadata) if !metadata.is_file() => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "disk cache object destination is unsafe: {}",
                path.display()
            ),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "disk cache object destination is unsafe: {}",
                        path.display()
                    ),
                ));
            }
            Err(error)
        }
    }
}

#[cfg(feature = "proxy")]
fn parse_disk_cache_object(
    bytes: &[u8],
    max_object_bytes: ByteSize,
) -> std::io::Result<PingoraStoredObject> {
    let (mut offset, format_version) =
        if bytes.get(..DISK_CACHE_MAGIC_V5.len()) == Some(DISK_CACHE_MAGIC_V5) {
            (DISK_CACHE_MAGIC_V5.len(), 5_u8)
        } else if bytes.get(..DISK_CACHE_MAGIC_V4.len()) == Some(DISK_CACHE_MAGIC_V4) {
            (DISK_CACHE_MAGIC_V4.len(), 4_u8)
        } else if bytes.get(..DISK_CACHE_MAGIC_V3.len()) == Some(DISK_CACHE_MAGIC_V3) {
            (DISK_CACHE_MAGIC_V3.len(), 3_u8)
        } else if bytes.get(..DISK_CACHE_MAGIC_V2.len()) == Some(DISK_CACHE_MAGIC_V2) {
            (DISK_CACHE_MAGIC_V2.len(), 2_u8)
        } else if bytes.get(..DISK_CACHE_MAGIC_V1.len()) == Some(DISK_CACHE_MAGIC_V1) {
            (DISK_CACHE_MAGIC_V1.len(), 1_u8)
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid cache object magic",
            ));
        };

    let combined_key_len = if format_version >= 3 {
        parse_disk_cache_len(bytes, &mut offset)?
    } else {
        0
    };
    let primary_key_len = if format_version >= 2 {
        parse_disk_cache_len(bytes, &mut offset)?
    } else {
        0
    };
    let user_tag_len = if format_version >= 3 {
        parse_disk_cache_len(bytes, &mut offset)?
    } else {
        0
    };
    let cache_tags_len = if format_version >= 4 {
        parse_disk_cache_len(bytes, &mut offset)?
    } else {
        0
    };
    let index_path_len = if format_version >= 5 {
        parse_disk_cache_len(bytes, &mut offset)?
    } else {
        0
    };
    let internal_meta_len = parse_disk_cache_len(bytes, &mut offset)?;
    let response_header_len = parse_disk_cache_len(bytes, &mut offset)?;
    let body_len = parse_disk_cache_len(bytes, &mut offset)?;
    let object_bytes = (internal_meta_len as u64)
        .saturating_add(response_header_len as u64)
        .saturating_add(body_len as u64);
    if object_bytes > max_object_bytes.as_u64() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "cache object exceeds max object size",
        ));
    }

    let total_len = offset
        .checked_add(combined_key_len)
        .and_then(|value| value.checked_add(primary_key_len))
        .and_then(|value| value.checked_add(user_tag_len))
        .and_then(|value| value.checked_add(cache_tags_len))
        .and_then(|value| value.checked_add(index_path_len))
        .and_then(|value| value.checked_add(internal_meta_len))
        .and_then(|value| value.checked_add(response_header_len))
        .and_then(|value| value.checked_add(body_len))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cache object size overflow",
            )
        })?;
    if total_len != bytes.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "cache object length mismatch",
        ));
    }

    let weight = u32::try_from(object_bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "cache object weight exceeds u32",
        )
    })?;
    let combined_key_end = offset + combined_key_len;
    let primary_key_end = combined_key_end + primary_key_len;
    let user_tag_end = primary_key_end + user_tag_len;
    let cache_tags_end = user_tag_end + cache_tags_len;
    let index_path_end = cache_tags_end + index_path_len;
    let internal_meta_end = index_path_end + internal_meta_len;
    let response_header_end = internal_meta_end + response_header_len;
    let combined_key = if format_version >= 3 {
        Some(cache_object_utf8(
            &bytes[offset..combined_key_end],
            "combined key",
        )?)
    } else {
        None
    };
    let primary_key = if format_version >= 2 {
        Some(cache_object_utf8(
            &bytes[combined_key_end..primary_key_end],
            "primary key",
        )?)
    } else {
        None
    };
    let user_tag = if format_version >= 3 {
        Some(cache_object_utf8(
            &bytes[primary_key_end..user_tag_end],
            "user tag",
        )?)
    } else {
        None
    };
    let cache_tags = if format_version >= 4 {
        decode_cache_tags(&bytes[user_tag_end..cache_tags_end])?
    } else {
        Vec::new()
    };
    let index_path = if format_version >= 5 {
        let value = cache_object_utf8(&bytes[cache_tags_end..index_path_end], "index path")?;
        (!value.is_empty()).then_some(value)
    } else {
        None
    };
    Ok(PingoraStoredObject {
        combined_key,
        primary_key,
        user_tag,
        index_path,
        cache_tags,
        internal_meta: bytes[index_path_end..internal_meta_end].to_vec(),
        response_header: bytes[internal_meta_end..response_header_end].to_vec(),
        body: Arc::from(&bytes[response_header_end..][..]),
        weight,
    })
}

#[cfg(feature = "proxy")]
fn parse_disk_cache_object_maybe_encrypted(
    bytes: &[u8],
    max_object_bytes: ByteSize,
    encryption: Option<&DiskCacheEncryption>,
) -> std::io::Result<PingoraStoredObject> {
    let bytes = decrypt_disk_cache_object_if_needed(bytes, encryption)?;
    parse_disk_cache_object(&bytes, max_object_bytes)
}

#[cfg(feature = "proxy")]
fn cache_object_utf8(bytes: &[u8], field: &str) -> std::io::Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{field}: {error}"))
        })
}

#[cfg_attr(not(feature = "proxy"), allow(dead_code))]
fn default_cache_tag_headers_for_storage() -> Vec<String> {
    ["surrogate-key", "cache-tag", "x-cache-tags"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[cfg(feature = "proxy")]
fn cache_tags_from_meta(meta: &CacheMeta, header_names: &[String]) -> Vec<String> {
    let mut tags = Vec::new();
    let mut total_bytes = 0_usize;
    for name in header_names {
        for value in meta.headers().get_all(name) {
            let Ok(value) = value.to_str() else {
                continue;
            };
            collect_cache_tags(value, &mut tags, &mut total_bytes);
            if tags.len() >= MAX_CACHE_TAGS_PER_OBJECT {
                return tags;
            }
        }
    }
    tags
}

#[cfg(feature = "proxy")]
fn collect_cache_tags(value: &str, tags: &mut Vec<String>, total_bytes: &mut usize) {
    for candidate in value.split(|character: char| character == ',' || character.is_whitespace()) {
        if tags.len() >= MAX_CACHE_TAGS_PER_OBJECT || *total_bytes >= MAX_CACHE_TAG_BYTES_PER_OBJECT
        {
            return;
        }
        let candidate = candidate.trim();
        if !is_valid_cache_tag(candidate) || tags.iter().any(|tag| tag == candidate) {
            continue;
        }
        let next_bytes = total_bytes.saturating_add(candidate.len());
        if next_bytes > MAX_CACHE_TAG_BYTES_PER_OBJECT {
            return;
        }
        tags.push(candidate.to_owned());
        *total_bytes = next_bytes;
    }
}

#[cfg(feature = "proxy")]
fn is_valid_cache_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= MAX_CACHE_TAG_LEN
        && tag.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b'=')
        })
}

#[cfg(feature = "proxy")]
fn encode_cache_tags(tags: &[String]) -> String {
    tags.join("\n")
}

#[cfg(feature = "proxy")]
fn encoded_cache_tags_len(tags: &[String]) -> usize {
    encode_cache_tags(tags).len()
}

#[cfg(feature = "proxy")]
fn decode_cache_tags(bytes: &[u8]) -> std::io::Result<Vec<String>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let tags = cache_object_utf8(bytes, "cache tags")?;
    let mut decoded = Vec::new();
    let mut total_bytes = 0_usize;
    collect_cache_tags(&tags, &mut decoded, &mut total_bytes);
    Ok(decoded)
}

#[cfg(feature = "proxy")]
fn parse_disk_cache_len(bytes: &[u8], offset: &mut usize) -> std::io::Result<usize> {
    let Some(relative_newline) = bytes[*offset..].iter().position(|byte| *byte == b'\n') else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "cache object header missing newline",
        ));
    };
    let end = *offset + relative_newline;
    let value = std::str::from_utf8(&bytes[*offset..end])
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid length"))?
        .parse::<usize>()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid length"))?;
    *offset = end + 1;
    Ok(value)
}

#[cfg(feature = "proxy")]
fn cache_io_error(context: &'static str, error: std::io::Error) -> Box<Error> {
    Error::because(ErrorType::InternalError, context, error)
}

fn object_slots(max_size_bytes: ByteSize, max_object_bytes: ByteSize) -> usize {
    if max_object_bytes.as_u64() == 0 {
        return 0;
    }

    let slots = (max_size_bytes.as_u64() / max_object_bytes.as_u64()).max(1);
    usize::try_from(slots).unwrap_or(usize::MAX)
}

#[cfg(feature = "proxy")]
pub fn pingora_image_cache_key(
    namespace: &str,
    config: &CacheConfig,
    request: &CacheRequest<'_>,
    user_tag: &str,
) -> Option<pingora::cache::CacheKey> {
    image_cache_key(config, request)
        .map(|key| pingora::cache::CacheKey::new(namespace, key.as_str(), user_tag))
}

#[cfg(feature = "proxy")]
pub fn pingora_static_cache_key(
    namespace: &str,
    config: &CacheConfig,
    request: &StaticCacheRequest<'_>,
    user_tag: &str,
) -> Option<pingora::cache::CacheKey> {
    static_cache_key(config, request)
        .map(|key| pingora::cache::CacheKey::new(namespace, key.as_str(), user_tag))
}

pub fn eligible_image_request(config: &CacheConfig, request: &CacheRequest<'_>) -> bool {
    config.enabled
        && config.has_enabled_tier()
        && method_allowed(config, request.method)
        && image_extension(request.path).is_some_and(|extension| {
            config
                .image_extensions
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(extension))
        })
}

pub fn image_cache_key(config: &CacheConfig, request: &CacheRequest<'_>) -> Option<CacheKey> {
    if !eligible_image_request(config, request) {
        return None;
    }

    let mut key = String::from("fluxheim-image-v1;");
    if let Some(namespace) = config.key_namespace.as_deref() {
        append_component(&mut key, "namespace", namespace);
    }
    for part in &config.key_parts {
        match part {
            CacheKeyPart::Method => append_component(&mut key, "method", request.method),
            CacheKeyPart::Host => append_component(
                &mut key,
                "host",
                &request.host.and_then(normalize_host).unwrap_or_default(),
            ),
            CacheKeyPart::Path => append_component(&mut key, "path", request.path),
            CacheKeyPart::Query if config.include_query => {
                append_component(&mut key, "query", request.query.unwrap_or_default());
            }
            CacheKeyPart::Query => {}
        }
    }
    Some(CacheKey(key))
}

pub fn eligible_static_request(config: &CacheConfig, request: &StaticCacheRequest<'_>) -> bool {
    config.enabled
        && config.local_static
        && config.has_enabled_tier()
        && request.method == "GET"
        && image_extension(request.path).is_some_and(|extension| {
            config
                .image_extensions
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(extension))
        })
}

pub fn static_cache_key(
    config: &CacheConfig,
    request: &StaticCacheRequest<'_>,
) -> Option<CacheKey> {
    if !eligible_static_request(config, request) {
        return None;
    }

    let mut key = String::from("fluxheim-image-v1;");
    if let Some(namespace) = config.key_namespace.as_deref() {
        append_component(&mut key, "namespace", namespace);
    }
    for part in &config.key_parts {
        match part {
            CacheKeyPart::Method => append_component(&mut key, "method", request.method),
            CacheKeyPart::Host => append_component(
                &mut key,
                "host",
                &request.host.and_then(normalize_host).unwrap_or_default(),
            ),
            CacheKeyPart::Path => append_component(&mut key, "path", request.path),
            CacheKeyPart::Query if config.include_query => {
                append_component(&mut key, "query", request.query.unwrap_or_default());
            }
            CacheKeyPart::Query => {}
        }
    }
    append_component(&mut key, "file", request.file_identity);
    Some(CacheKey(key))
}

fn method_allowed(config: &CacheConfig, method: &str) -> bool {
    config.methods.iter().any(|candidate| candidate == method)
}

fn image_extension(path: &str) -> Option<&str> {
    let file_name = path.rsplit('/').next()?;
    if file_name.is_empty() || file_name == "." || file_name == ".." {
        return None;
    }

    let (stem, extension) = file_name.rsplit_once('.')?;
    if stem.is_empty() || extension.is_empty() {
        return None;
    }

    Some(extension)
}

fn append_component(key: &mut String, label: &str, value: &str) {
    let _ = write!(key, "{label}:{}:{value};", value.len());
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    #[cfg(feature = "proxy")]
    use std::sync::Arc;

    #[cfg(feature = "proxy")]
    use bytes::Bytes;
    #[cfg(feature = "proxy")]
    use pingora::cache::key::CacheHashKey;

    use super::{
        CacheRequest, CacheStoreError, CachedHeader, CachedImageObject, MemoryImageCache,
        StaticCacheRequest, eligible_image_request, image_cache_key,
        memory_image_cache_from_config, static_cache_key, storage_plan,
    };
    #[cfg(feature = "proxy")]
    use crate::config::CacheDiskEncryptionProvider;
    use crate::config::{
        ByteSize, CacheConfig, CacheDiskBackend, CacheDiskConfig, CacheDiskEncryptionConfig,
        CacheDiskStorageBinConfig, CacheKeyPart, CacheMemoryConfig,
    };
    #[cfg(feature = "proxy")]
    use crate::http_types::PingoraResponseHeader as ResponseHeader;
    #[cfg(feature = "proxy")]
    use crate::test_support::unique_temp_path;

    fn enabled_cache() -> CacheConfig {
        CacheConfig {
            enabled: true,
            memory: crate::config::CacheMemoryConfig {
                enabled: true,
                ..crate::config::CacheMemoryConfig::default()
            },
            ..CacheConfig::default()
        }
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn runtime_pingora_memory_storage_is_reused_for_same_config_scope() {
        let config = enabled_cache();
        let first =
            super::pingora_memory_storage_from_config_with_metric_scope(&config, "vhost", None)
                .unwrap();
        let second =
            super::pingora_memory_storage_from_config_with_metric_scope(&config, "vhost", None)
                .unwrap();
        let route = super::pingora_memory_storage_from_config_with_metric_scope(
            &config,
            "vhost",
            Some("r"),
        )
        .unwrap();

        assert!(std::ptr::eq(first, second));
        assert!(!std::ptr::eq(first, route));
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn runtime_pingora_cache_lock_is_reused_for_same_timeout() {
        let first = super::pingora_cache_lock(std::time::Duration::from_secs(30));
        let second = super::pingora_cache_lock(std::time::Duration::from_secs(30));
        let other = super::pingora_cache_lock(std::time::Duration::from_secs(31));
        let subsecond = super::pingora_cache_lock(std::time::Duration::new(30, 500_000_000));

        assert!(std::ptr::addr_eq(first, second));
        assert!(!std::ptr::addr_eq(first, other));
        assert!(!std::ptr::addr_eq(first, subsecond));
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn cache_purge_index_retains_all_live_mappings() {
        let index = super::CachePurgeIndex::new();

        index.insert(
            "combined:a".to_owned(),
            "fluxheim-image-v1;path:9:/old/a.js;".to_owned(),
            "vhost-a".to_owned(),
        );
        index.insert(
            "combined:b".to_owned(),
            "fluxheim-image-v1;path:12:/assets/b.js;".to_owned(),
            "vhost-b".to_owned(),
        );
        index.insert(
            "combined:c".to_owned(),
            "fluxheim-image-v1;path:12:/assets/c.js;".to_owned(),
            "vhost-b".to_owned(),
        );

        assert_eq!(index.len(), 3);
        assert_eq!(
            index.combined_keys_for_primary("fluxheim-image-v1;path:9:/old/a.js;"),
            vec!["combined:a".to_owned()]
        );
        assert_eq!(
            index.combined_keys_for_primary("fluxheim-image-v1;path:12:/assets/b.js;"),
            vec!["combined:b".to_owned()]
        );
        assert_eq!(
            index
                .entries_for_user_tag("vhost-b", 8)
                .into_iter()
                .map(|entry| entry.combined_key)
                .collect::<Vec<_>>(),
            vec!["combined:b".to_owned(), "combined:c".to_owned()]
        );
        assert_eq!(
            index
                .entries_with_prefix("combined:", 1)
                .into_iter()
                .map(|entry| entry.combined_key)
                .collect::<Vec<_>>(),
            vec!["combined:a".to_owned()]
        );
        assert_eq!(
            index
                .entries_for_user_tag_path_prefix("vhost-b", "/assets/", 8)
                .into_iter()
                .map(|entry| entry.combined_key)
                .collect::<Vec<_>>(),
            vec!["combined:b".to_owned(), "combined:c".to_owned()]
        );
        assert_eq!(
            index
                .entries_for_user_tag_path_pattern("vhost-b", "/assets/*.js", 8)
                .into_iter()
                .map(|entry| entry.combined_key)
                .collect::<Vec<_>>(),
            vec!["combined:b".to_owned(), "combined:c".to_owned()]
        );
        assert!(index.remove_combined("combined:b"));
        assert_eq!(index.len(), 2);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn disk_object_index_returns_oldest_entries_without_resorting_snapshot() {
        let index = super::DiskObjectIndex::new();
        let base = std::time::UNIX_EPOCH;
        let path_a = PathBuf::from("/cache/a.fhc");
        let path_b = PathBuf::from("/cache/b.fhc");
        let path_c = PathBuf::from("/cache/c.fhc");

        index.upsert(super::DiskCacheEntry {
            combined_key: None,
            path: path_a.clone(),
            size: 10,
            modified: base + std::time::Duration::from_secs(1),
            accessed: base + std::time::Duration::from_secs(30),
        });
        index.upsert(super::DiskCacheEntry {
            combined_key: None,
            path: path_b.clone(),
            size: 20,
            modified: base + std::time::Duration::from_secs(1),
            accessed: base + std::time::Duration::from_secs(10),
        });
        index.upsert(super::DiskCacheEntry {
            combined_key: None,
            path: path_c.clone(),
            size: 30,
            modified: base + std::time::Duration::from_secs(1),
            accessed: base + std::time::Duration::from_secs(20),
        });

        let selected = index.oldest_entries_to_free(PathBuf::from("/cache/miss.fhc").as_path(), 25);
        assert_eq!(
            selected
                .iter()
                .map(|entry| entry.path.as_path())
                .collect::<Vec<_>>(),
            vec![path_b.as_path(), path_c.as_path()]
        );

        index.touch(&path_a, base + std::time::Duration::from_secs(5));
        let selected = index.oldest_entries_to_free(&path_b, 10);
        assert_eq!(
            selected
                .iter()
                .map(|entry| entry.path.as_path())
                .collect::<Vec<_>>(),
            vec![path_a.as_path()]
        );
        assert!(index.remove(&path_a).is_some());
        assert_eq!(index.total_size(), 50);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn cache_tags_from_meta_collects_bounded_deduplicated_tags() {
        let mut meta = pingora_meta("max-age=60");
        meta.response_header_mut()
            .insert_header("Surrogate-Key", "article:1 collection/news article:1")
            .unwrap();
        meta.response_header_mut()
            .append_header("Cache-Tag", "tenant/main,asset/logo invalid tag")
            .unwrap();
        meta.response_header_mut()
            .append_header("X-Cache-Tags", "bad@tag")
            .unwrap();

        assert_eq!(
            super::cache_tags_from_meta(&meta, &super::default_cache_tag_headers_for_storage()),
            vec![
                "article:1".to_owned(),
                "collection/news".to_owned(),
                "tenant/main".to_owned(),
                "asset/logo".to_owned(),
                "invalid".to_owned(),
                "tag".to_owned(),
            ]
        );
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn cache_path_wildcard_matches_absolute_path_patterns() {
        assert!(super::cache_path_wildcard_matches(
            "/assets/*.png",
            "/assets/logo.png"
        ));
        assert!(super::cache_path_wildcard_matches(
            "/assets/*/logo.*",
            "/assets/icons/logo.webp"
        ));
        assert!(!super::cache_path_wildcard_matches(
            "/assets/*.png",
            "/assets/logo.webp"
        ));
        assert!(!super::cache_path_wildcard_matches(
            "/assets/*.png",
            "/img/logo.png"
        ));
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn cache_primary_component_reads_length_delimited_path() {
        let primary = "fluxheim-image-v1;method:3:GET;path:19:/assets/logos/a.png;query:0:;";

        assert_eq!(
            super::cache_primary_component(primary, "path").as_deref(),
            Some("/assets/logos/a.png")
        );
        assert_eq!(
            super::cache_primary_component(primary, "method").as_deref(),
            Some("GET")
        );
        assert_eq!(super::cache_primary_component(primary, "missing"), None);
    }

    #[test]
    fn disabled_cache_is_never_eligible() {
        let request = CacheRequest {
            method: "GET",
            host: Some("example.test"),
            path: "/images/hero.jpg",
            query: None,
        };

        assert!(!eligible_image_request(&CacheConfig::default(), &request));
        assert_eq!(image_cache_key(&CacheConfig::default(), &request), None);
    }

    #[test]
    fn enabled_cache_without_storage_tier_is_not_eligible() {
        let config = CacheConfig {
            enabled: true,
            ..CacheConfig::default()
        };
        let request = CacheRequest {
            method: "GET",
            host: Some("example.test"),
            path: "/images/hero.jpg",
            query: None,
        };

        assert!(!eligible_image_request(&config, &request));
        assert_eq!(image_cache_key(&config, &request), None);
    }

    #[test]
    fn allows_configured_image_methods_and_extensions() {
        let request = CacheRequest {
            method: "GET",
            host: Some("example.test"),
            path: "/assets/HERO.WebP",
            query: None,
        };

        assert!(eligible_image_request(&enabled_cache(), &request));
    }

    #[test]
    fn default_cache_policy_allows_common_static_extensions() {
        let config = enabled_cache();
        for path in [
            "/assets/site.css",
            "/assets/app.mjs",
            "/assets/app.wasm",
            "/assets/fonts/site.woff2",
            "/favicon.ico",
        ] {
            let request = CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path,
                query: None,
            };
            assert!(eligible_image_request(&config, &request), "{path}");
        }
    }

    #[test]
    fn rejects_unconfigured_methods() {
        let request = CacheRequest {
            method: "POST",
            host: Some("example.test"),
            path: "/assets/hero.webp",
            query: None,
        };

        assert!(!eligible_image_request(&enabled_cache(), &request));
    }

    #[test]
    fn rejects_paths_without_image_extensions() {
        let config = enabled_cache();
        for path in [
            "/assets/",
            "/assets/hero",
            "/assets/.hidden",
            "/assets/hero.",
        ] {
            let request = CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path,
                query: None,
            };
            assert!(!eligible_image_request(&config, &request), "{path}");
        }
    }

    #[test]
    fn cache_key_is_deterministic_and_includes_host_and_query() {
        let config = enabled_cache();
        let first = CacheRequest {
            method: "GET",
            host: Some("Example.TEST:443"),
            path: "/img/logo.png",
            query: Some("v=1"),
        };
        let second = CacheRequest {
            method: "GET",
            host: Some("example.test"),
            path: "/img/logo.png",
            query: Some("v=2"),
        };

        let first_key = image_cache_key(&config, &first).unwrap();
        assert_eq!(
            first_key.as_str(),
            "fluxheim-image-v1;method:3:GET;host:12:example.test;path:13:/img/logo.png;query:3:v=1;"
        );
        assert_eq!(image_cache_key(&config, &first), Some(first_key.clone()));
        assert_ne!(image_cache_key(&config, &second), Some(first_key));
    }

    #[test]
    fn cache_key_can_ignore_query_when_configured() {
        let config = CacheConfig {
            include_query: false,
            ..enabled_cache()
        };
        let first = CacheRequest {
            method: "GET",
            host: Some("example.test"),
            path: "/assets/app.js",
            query: Some("v=1"),
        };
        let second = CacheRequest {
            method: "GET",
            host: Some("example.test"),
            path: "/assets/app.js",
            query: Some("v=2"),
        };

        let key = image_cache_key(&config, &first).unwrap();
        assert_eq!(
            key.as_str(),
            "fluxheim-image-v1;method:3:GET;host:12:example.test;path:14:/assets/app.js;"
        );
        assert_eq!(image_cache_key(&config, &second), Some(key));
    }

    #[test]
    fn cache_key_parts_choose_safe_identity_components() {
        let config = CacheConfig {
            key_parts: vec![CacheKeyPart::Host, CacheKeyPart::Path],
            ..enabled_cache()
        };
        let first = CacheRequest {
            method: "GET",
            host: Some("example.test"),
            path: "/assets/app.js",
            query: Some("v=1"),
        };
        let second = CacheRequest {
            method: "HEAD",
            host: Some("example.test"),
            path: "/assets/app.js",
            query: Some("v=2"),
        };

        let key = image_cache_key(&config, &first).unwrap();
        assert_eq!(
            key.as_str(),
            "fluxheim-image-v1;host:12:example.test;path:14:/assets/app.js;"
        );
        assert_eq!(image_cache_key(&config, &second), Some(key));
    }

    #[test]
    fn cache_key_parts_query_still_obeys_include_query() {
        let config = CacheConfig {
            key_parts: vec![CacheKeyPart::Path, CacheKeyPart::Query],
            include_query: false,
            ..enabled_cache()
        };
        let request = CacheRequest {
            method: "GET",
            host: Some("example.test"),
            path: "/assets/app.js",
            query: Some("v=1"),
        };

        let key = image_cache_key(&config, &request).unwrap();
        assert_eq!(key.as_str(), "fluxheim-image-v1;path:14:/assets/app.js;");
    }

    #[test]
    fn cache_key_includes_operator_namespace_when_configured() {
        let config = CacheConfig {
            key_namespace: Some("repoheim-assets-v1".to_owned()),
            ..enabled_cache()
        };
        let request = CacheRequest {
            method: "GET",
            host: Some("example.test"),
            path: "/assets/app.js",
            query: Some("v=1"),
        };

        let key = image_cache_key(&config, &request).unwrap();
        assert_eq!(
            key.as_str(),
            "fluxheim-image-v1;namespace:18:repoheim-assets-v1;method:3:GET;host:12:example.test;path:14:/assets/app.js;query:3:v=1;"
        );

        let other_config = CacheConfig {
            key_namespace: Some("repoheim-assets-v2".to_owned()),
            ..enabled_cache()
        };
        assert_ne!(image_cache_key(&other_config, &request).unwrap(), key);
    }

    #[test]
    fn static_cache_key_requires_explicit_local_static_opt_in() {
        let mut config = enabled_cache();
        config.local_static = false;
        let request = StaticCacheRequest {
            method: "GET",
            host: Some("example.test"),
            path: "/asset.webp",
            query: None,
            file_identity: "/srv/site/asset.webp:1:2",
        };

        assert_eq!(static_cache_key(&config, &request), None);

        config.local_static = true;
        let key = static_cache_key(&config, &request).unwrap();
        assert!(key.as_str().contains("path:11:/asset.webp"));
        assert!(key.as_str().contains("/srv/site/asset.webp:1:2"));
    }

    #[test]
    fn storage_plan_derives_memory_slots_from_byte_budget() {
        let config = CacheConfig {
            enabled: true,
            max_object_bytes: ByteSize::from_bytes(32 * 1024 * 1024),
            memory: CacheMemoryConfig {
                enabled: true,
                max_size_bytes: ByteSize::from_bytes(1024 * 1024 * 1024),
            },
            ..CacheConfig::default()
        };

        let plan = storage_plan(&config);
        let memory = plan.memory.unwrap();
        assert_eq!(
            memory.max_size_bytes,
            ByteSize::from_bytes(1024 * 1024 * 1024)
        );
        assert_eq!(
            memory.max_object_bytes,
            ByteSize::from_bytes(32 * 1024 * 1024)
        );
        assert_eq!(memory.object_slots, 32);
        assert_eq!(plan.disk, None);
    }

    #[test]
    fn storage_plan_includes_disk_path_and_limits() {
        let config = CacheConfig {
            enabled: true,
            max_object_bytes: ByteSize::from_bytes(64 * 1024 * 1024),
            disk: CacheDiskConfig {
                enabled: true,
                path: Some(PathBuf::from("/var/cache/fluxheim/example.test")),
                max_size_bytes: ByteSize::from_bytes(8 * 1024 * 1024 * 1024),
                ..CacheDiskConfig::default()
            },
            ..CacheConfig::default()
        };

        let plan = storage_plan(&config);
        assert_eq!(plan.memory, None);
        assert_eq!(
            plan.disk.unwrap(),
            super::DiskTierPlan {
                backend: CacheDiskBackend::Filesystem,
                path: PathBuf::from("/var/cache/fluxheim/example.test"),
                max_size_bytes: ByteSize::from_bytes(8 * 1024 * 1024 * 1024),
                max_object_bytes: ByteSize::from_bytes(64 * 1024 * 1024),
                cache_tag_headers: super::default_cache_tag_headers_for_storage(),
                storage_bin: CacheDiskStorageBinConfig::default(),
                encryption: CacheDiskEncryptionConfig::default(),
            }
        );
    }

    #[test]
    fn storage_plan_preserves_reserved_storage_bin_options() {
        let config = CacheConfig {
            enabled: true,
            max_object_bytes: ByteSize::from_bytes(32 * 1024 * 1024),
            disk: CacheDiskConfig {
                enabled: true,
                backend: CacheDiskBackend::StorageBin,
                path: Some(PathBuf::from("/var/cache/fluxheim/example.test")),
                max_size_bytes: ByteSize::from_bytes(1024 * 1024 * 1024),
                storage_bin: CacheDiskStorageBinConfig {
                    bin_size_bytes: ByteSize::from_bytes(512 * 1024 * 1024),
                    preallocate: true,
                    max_open_bins: 4,
                },
                ..CacheDiskConfig::default()
            },
            ..CacheConfig::default()
        };

        let plan = storage_plan(&config).disk.unwrap();

        assert_eq!(plan.backend, CacheDiskBackend::StorageBin);
        assert_eq!(
            plan.storage_bin.bin_size_bytes,
            ByteSize::from_bytes(512 * 1024 * 1024)
        );
        assert!(plan.storage_bin.preallocate);
        assert_eq!(plan.storage_bin.max_open_bins, 4);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_layout_plan_derives_manifest_and_bin_paths() {
        let plan = super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: PathBuf::from("/var/cache/fluxheim/example.test"),
            max_size_bytes: ByteSize::from_bytes(1024 * 1024 * 1024),
            max_object_bytes: ByteSize::from_bytes(32 * 1024 * 1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(256 * 1024 * 1024),
                preallocate: true,
                max_open_bins: 8,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        };

        let layout = super::StorageBinLayoutPlan::from_disk_plan(&plan).unwrap();

        assert_eq!(
            layout.manifest_path,
            PathBuf::from("/var/cache/fluxheim/example.test/.fluxheim-storage-bin-v1")
        );
        assert_eq!(
            layout.bin_path(42),
            PathBuf::from("/var/cache/fluxheim/example.test/bins/000000000000002a.fhbin")
        );
        assert_eq!(layout.max_bins(), 4);
        assert!(layout.preallocate);
        assert_eq!(layout.max_open_bins, 8);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_manifest_round_trips() {
        let manifest = super::StorageBinManifest {
            bin_size_bytes: ByteSize::from_bytes(128 * 1024 * 1024),
            max_size_bytes: ByteSize::from_bytes(1024 * 1024 * 1024),
            preallocate: true,
            max_open_bins: 4,
        };

        let decoded = super::StorageBinManifest::decode(&manifest.encode()).unwrap();

        assert_eq!(decoded, manifest);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_prepare_writes_and_reuses_manifest() {
        let root = unique_test_cache_dir("storage-bin-manifest");
        let plan = super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(256),
            max_object_bytes: ByteSize::from_bytes(64),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(128),
                preallocate: true,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        };
        let layout = super::StorageBinLayoutPlan::from_disk_plan(&plan).unwrap();

        let written = super::prepare_storage_bin_layout(&layout).unwrap();
        let reused = super::prepare_storage_bin_layout(&layout).unwrap();

        assert_eq!(reused, written);
        assert!(root.join(".fluxheim-storage-bin-v1").is_file());
        assert!(root.join("bins").is_dir());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn cache_path_symlink_check_allows_missing_storage_bin_index() {
        let root = unique_test_cache_dir("storage-bin-missing-index-path");
        std::fs::create_dir_all(&root).unwrap();
        let index_path = root.join(".fluxheim-storage-bin-index-v1");

        assert!(!index_path.exists());
        assert!(!super::cache_path_contains_symlink(&root, &index_path).unwrap());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_prepare_rejects_mismatched_manifest() {
        let root = unique_test_cache_dir("storage-bin-manifest-mismatch");
        let plan = super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(256),
            max_object_bytes: ByteSize::from_bytes(64),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(128),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        };
        let layout = super::StorageBinLayoutPlan::from_disk_plan(&plan).unwrap();
        super::prepare_storage_bin_layout(&layout).unwrap();

        let changed = super::StorageBinLayoutPlan {
            bin_size_bytes: ByteSize::from_bytes(64),
            ..layout
        };
        let error = super::prepare_storage_bin_layout(&changed).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_object_location_rejects_out_of_bin_ranges() {
        assert_eq!(
            super::StorageBinObjectLocation {
                bin_id: 7,
                offset: 8,
                len: 16,
            }
            .validate(ByteSize::from_bytes(64))
            .unwrap(),
            super::StorageBinObjectLocation {
                bin_id: 7,
                offset: 8,
                len: 16,
            }
        );
        assert!(
            super::StorageBinObjectLocation {
                bin_id: 7,
                offset: 48,
                len: 17,
            }
            .validate(ByteSize::from_bytes(64))
            .is_err()
        );
        assert!(
            super::StorageBinObjectLocation {
                bin_id: 7,
                offset: 8,
                len: 0,
            }
            .validate(ByteSize::from_bytes(64))
            .is_err()
        );
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_free_map_allocates_and_reuses_ranges() {
        let plan = super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: PathBuf::from("/var/cache/fluxheim/example.test"),
            max_size_bytes: ByteSize::from_bytes(192),
            max_object_bytes: ByteSize::from_bytes(64),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(64),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        };
        let layout = super::StorageBinLayoutPlan::from_disk_plan(&plan).unwrap();
        let mut free_map = super::StorageBinFreeMap::new(&layout);

        let first = free_map.allocate(24).unwrap().unwrap();
        let second = free_map.allocate(24).unwrap().unwrap();
        free_map.release(first).unwrap();
        let reused = free_map.allocate(16).unwrap().unwrap();

        assert_eq!(
            first,
            super::StorageBinObjectLocation {
                bin_id: 0,
                offset: 0,
                len: 24,
            }
        );
        assert_eq!(
            second,
            super::StorageBinObjectLocation {
                bin_id: 0,
                offset: 24,
                len: 24,
            }
        );
        assert_eq!(
            reused,
            super::StorageBinObjectLocation {
                bin_id: 0,
                offset: 0,
                len: 16,
            }
        );
        assert_eq!(
            free_map.free_ranges(0),
            &[
                super::StorageBinFreeRange { offset: 16, len: 8 },
                super::StorageBinFreeRange {
                    offset: 48,
                    len: 16
                },
            ]
        );
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_free_map_honors_global_cache_budget() {
        let plan = super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: PathBuf::from("/var/cache/fluxheim/example.test"),
            max_size_bytes: ByteSize::from_bytes(96),
            max_object_bytes: ByteSize::from_bytes(64),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(64),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        };
        let layout = super::StorageBinLayoutPlan::from_disk_plan(&plan).unwrap();
        let mut free_map = super::StorageBinFreeMap::new(&layout);

        assert_eq!(free_map.allocate(64).unwrap().unwrap().bin_id, 0);
        assert_eq!(
            free_map.allocate(32).unwrap().unwrap(),
            super::StorageBinObjectLocation {
                bin_id: 1,
                offset: 0,
                len: 32,
            }
        );
        assert!(free_map.allocate(1).unwrap().is_none());
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_free_map_reclaims_fully_free_tail_bins() {
        let plan = super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: PathBuf::from("/var/cache/fluxheim/example.test"),
            max_size_bytes: ByteSize::from_bytes(192),
            max_object_bytes: ByteSize::from_bytes(64),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(64),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        };
        let layout = super::StorageBinLayoutPlan::from_disk_plan(&plan).unwrap();
        let mut free_map = super::StorageBinFreeMap::new(&layout);
        let first = free_map.allocate(32).unwrap().unwrap();
        let second = free_map.allocate(64).unwrap().unwrap();
        assert_eq!(free_map.bin_files(), 2);

        free_map.release(second).unwrap();
        assert_eq!(free_map.reclaim_free_tail_bins(), vec![1]);
        assert_eq!(free_map.bin_files(), 1);

        free_map.release(first).unwrap();
        assert_eq!(free_map.reclaim_free_tail_bins(), vec![0]);
        assert_eq!(free_map.bin_files(), 0);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_file_set_writes_and_reads_bounded_ranges() {
        let root = unique_test_cache_dir("storage-bin-files");
        let plan = super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(128),
            max_object_bytes: ByteSize::from_bytes(64),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(64),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        };
        let layout = super::StorageBinLayoutPlan::from_disk_plan(&plan).unwrap();
        super::prepare_storage_bin_layout(&layout).unwrap();
        let files = super::StorageBinFileSet::new(layout);
        let location = super::StorageBinObjectLocation {
            bin_id: 0,
            offset: 8,
            len: 11,
        };

        files.write_object(location, b"hello-cache").unwrap();

        assert_eq!(files.read_object(location).unwrap(), b"hello-cache");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_file_set_preallocates_bin_files_when_configured() {
        let root = unique_test_cache_dir("storage-bin-preallocate");
        let plan = super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(128),
            max_object_bytes: ByteSize::from_bytes(64),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(64),
                preallocate: true,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        };
        let layout = super::StorageBinLayoutPlan::from_disk_plan(&plan).unwrap();
        super::prepare_storage_bin_layout(&layout).unwrap();
        let bin_path = layout.bin_path(0);
        let files = super::StorageBinFileSet::new(layout);

        files
            .write_object(
                super::StorageBinObjectLocation {
                    bin_id: 0,
                    offset: 0,
                    len: 3,
                },
                b"bin",
            )
            .unwrap();

        assert_eq!(std::fs::metadata(bin_path).unwrap().len(), 64);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_disk_storage_round_trips_object() {
        let root = unique_test_cache_dir("storage-bin-storage-round-trip");
        let storage = super::StorageBinDiskStorage::from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(1024),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "/asset.webp", "vhost");
        let meta = pingora_meta("max-age=60");
        let store_key = super::PingoraStoreKey::from_cache_key_and_meta(
            &key,
            &meta,
            &super::default_cache_tag_headers_for_storage(),
        );
        let (internal_meta, response_header) = meta.serialize().unwrap();

        assert_eq!(
            storage
                .put_object(
                    store_key,
                    internal_meta,
                    response_header,
                    Arc::from(&b"storage-bin-body"[..]),
                )
                .unwrap(),
            Some("storage-bin-body".len())
        );
        let object = storage
            .lookup_object_by_combined(&key.combined())
            .unwrap()
            .unwrap();

        assert_eq!(object.body.as_ref(), b"storage-bin-body");
        assert_eq!(storage.stats().unwrap().entries, 1);
        assert_eq!(storage.stats().unwrap().activity.stores, 1);
        assert_eq!(storage.stats().unwrap().activity.hits, 1);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_disk_storage_encrypts_local_key_objects() {
        let root = unique_test_cache_dir("storage-bin-encrypted-storage");
        let key_path = root.join("cache-key.hex");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            &key_path,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
        )
        .unwrap();
        let storage_root = root.join("objects");
        let storage = super::StorageBinDiskStorage::from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: storage_root.clone(),
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(1024),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig {
                enabled: true,
                key_id: Some("storage-bin-test-key-v1".to_owned()),
                key_file: Some(key_path),
                ..CacheDiskEncryptionConfig::default()
            },
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "/encrypted-bin.webp", "vhost");
        let meta = pingora_meta("max-age=60");
        let store_key = super::PingoraStoreKey::from_cache_key_and_meta(
            &key,
            &meta,
            &super::default_cache_tag_headers_for_storage(),
        );
        let (internal_meta, response_header) = meta.serialize().unwrap();

        storage
            .put_object(
                store_key,
                internal_meta,
                response_header,
                Arc::from(&b"storage-bin-secret-body"[..]),
            )
            .unwrap();

        let bin_bytes = std::fs::read(storage.layout.bin_path(0)).unwrap();
        assert!(
            bin_bytes
                .windows(super::DISK_CACHE_ENCRYPTED_MAGIC_V1.len())
                .any(|window| window == super::DISK_CACHE_ENCRYPTED_MAGIC_V1)
        );
        assert!(
            !bin_bytes
                .windows(b"storage-bin-secret-body".len())
                .any(|window| window == b"storage-bin-secret-body")
        );

        let object = storage
            .lookup_object_by_combined(&key.combined())
            .unwrap()
            .unwrap();
        assert_eq!(object.body.as_ref(), b"storage-bin-secret-body");

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_disk_storage_rewrites_same_key_in_full_bin() {
        let root = unique_test_cache_dir("storage-bin-storage-rewrite");
        let storage = super::StorageBinDiskStorage::from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(1800),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(2048),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "/rewrite.webp", "vhost");

        for body_byte in [b'a', b'b'] {
            let meta = pingora_meta("max-age=60");
            let store_key = super::PingoraStoreKey::from_cache_key_and_meta(
                &key,
                &meta,
                &super::default_cache_tag_headers_for_storage(),
            );
            let (internal_meta, response_header) = meta.serialize().unwrap();
            assert_eq!(
                storage
                    .put_object(
                        store_key,
                        internal_meta,
                        response_header,
                        Arc::from(vec![body_byte; 1300].into_boxed_slice()),
                    )
                    .unwrap(),
                Some(1300)
            );
        }

        let object = storage
            .lookup_object_by_combined(&key.combined())
            .unwrap()
            .unwrap();
        assert_eq!(object.body.as_ref(), vec![b'b'; 1300].as_slice());
        let stats = storage.stats().unwrap();
        assert_eq!(stats.backend, "storage-bin");
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.allocated_size_bytes, 2048);
        assert!(stats.free_size_bytes > 0);
        assert_eq!(stats.free_range_count, 1);
        assert!(stats.largest_free_range_bytes > 0);
        assert_eq!(stats.bin_files, 1);
        assert_eq!(stats.activity.stores, 2);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_index_round_trips_locations() {
        let root = unique_test_cache_dir("storage-bin-index-round-trip");
        let plan = super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(1024),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        };
        let layout = super::StorageBinLayoutPlan::from_disk_plan(&plan).unwrap();
        super::prepare_storage_bin_layout(&layout).unwrap();
        let entries = vec![super::StorageBinIndexEntry {
            combined_key: "vhost\tkey".to_owned(),
            location: super::StorageBinObjectLocation {
                bin_id: 1,
                offset: 32,
                len: 64,
            },
            accessed: std::time::UNIX_EPOCH + std::time::Duration::from_secs(42),
        }];

        super::write_storage_bin_index(&layout, &entries).unwrap();
        let decoded = super::read_storage_bin_index(&layout).unwrap();

        assert_eq!(decoded, entries);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_disk_storage_recovers_objects_after_restart() {
        let root = unique_test_cache_dir("storage-bin-storage-restart");
        let plan = super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(1024),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        };
        let storage = super::StorageBinDiskStorage::from_plan(plan.clone()).unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "/restart.webp", "vhost");
        let meta = pingora_meta("max-age=60");
        let store_key = super::PingoraStoreKey::from_cache_key_and_meta(
            &key,
            &meta,
            &super::default_cache_tag_headers_for_storage(),
        );
        let (internal_meta, response_header) = meta.serialize().unwrap();
        storage
            .put_object(
                store_key,
                internal_meta,
                response_header,
                Arc::from(&b"restart-body"[..]),
            )
            .unwrap();
        storage.write_index().unwrap();

        let recovered = super::StorageBinDiskStorage::from_plan(plan).unwrap();
        let object = recovered
            .lookup_object_by_combined(&key.combined())
            .unwrap()
            .unwrap();

        assert_eq!(object.body.as_ref(), b"restart-body");
        assert_eq!(recovered.stats().unwrap().entries, 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_disk_storage_debounces_index_after_insert_burst() {
        let root = unique_test_cache_dir("storage-bin-index-debounce");
        let storage = super::StorageBinDiskStorage::from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(512),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(1024),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let index_path = super::storage_bin_index_path(&root);
        let meta = pingora_meta("max-age=60");

        for name in ["first", "second", "third"] {
            let key = pingora::cache::CacheKey::new("fluxheim-test", name, "vhost");
            let store_key = super::PingoraStoreKey::from_cache_key_and_meta(
                &key,
                &meta,
                &super::default_cache_tag_headers_for_storage(),
            );
            let (internal_meta, response_header) = meta.serialize().unwrap();
            storage
                .put_object(
                    store_key,
                    internal_meta,
                    response_header,
                    Arc::from(&b"body"[..]),
                )
                .unwrap();
        }

        assert!(!index_path.exists());
        assert_eq!(storage.storage_bin_index_flags(), (true, true));
        for _ in 0..20 {
            if index_path.exists() && storage.storage_bin_index_flags() == (false, false) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(index_path.exists());
        assert_eq!(storage.storage_bin_index_flags(), (false, false));
        assert_eq!(
            super::read_storage_bin_index(&storage.layout)
                .unwrap()
                .len(),
            3
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_disk_storage_flushes_pending_index_on_drop() {
        let root = unique_test_cache_dir("storage-bin-index-drop-flush");
        let plan = super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(1024),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        };
        let layout = super::StorageBinLayoutPlan::from_disk_plan(&plan).unwrap();
        let storage = super::StorageBinDiskStorage::from_plan(plan).unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "/drop.webp", "vhost");
        let meta = pingora_meta("max-age=60");
        let store_key = super::PingoraStoreKey::from_cache_key_and_meta(
            &key,
            &meta,
            &super::default_cache_tag_headers_for_storage(),
        );
        let (internal_meta, response_header) = meta.serialize().unwrap();
        storage
            .put_object(
                store_key,
                internal_meta,
                response_header,
                Arc::from(&b"drop-body"[..]),
            )
            .unwrap();
        assert_eq!(storage.storage_bin_index_flags(), (true, true));

        drop(storage);

        let entries = super::read_storage_bin_index(&layout).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].combined_key, key.combined());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_disk_storage_purges_and_reuses_ranges() {
        let root = unique_test_cache_dir("storage-bin-storage-purge");
        let storage = super::StorageBinDiskStorage::from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(1024),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "/purge.webp", "vhost");
        let meta = pingora_meta("max-age=60");
        let (internal_meta, response_header) = meta.serialize().unwrap();
        let store_key = super::PingoraStoreKey::from_cache_key_and_meta(
            &key,
            &meta,
            &super::default_cache_tag_headers_for_storage(),
        );

        storage
            .put_object(
                store_key,
                internal_meta,
                response_header,
                Arc::from(&b"purge-body"[..]),
            )
            .unwrap();

        assert!(storage.purge_combined(&key.combined()).unwrap());
        assert!(
            storage
                .lookup_object_by_combined(&key.combined())
                .unwrap()
                .is_none()
        );
        assert_eq!(storage.stats().unwrap().entries, 0);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_disk_storage_evicts_oldest_object_to_admit_new_object() {
        let root = unique_test_cache_dir("storage-bin-storage-evict");
        let storage = super::StorageBinDiskStorage::from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(1024),
            max_object_bytes: ByteSize::from_bytes(512),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(1024),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let meta = pingora_meta("max-age=60");
        let mut keys = Vec::new();
        for name in ["first", "second", "third"] {
            let key = pingora::cache::CacheKey::new("fluxheim-test", name, "vhost");
            let store_key = super::PingoraStoreKey::from_cache_key_and_meta(
                &key,
                &meta,
                &super::default_cache_tag_headers_for_storage(),
            );
            let (internal_meta, response_header) = meta.serialize().unwrap();
            storage
                .put_object(
                    store_key,
                    internal_meta,
                    response_header,
                    Arc::from(vec![b'x'; 320].into_boxed_slice()),
                )
                .unwrap();
            keys.push(key);
        }

        assert!(
            storage
                .lookup_object_by_combined(&keys[0].combined())
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .lookup_object_by_combined(&keys[2].combined())
                .unwrap()
                .is_some()
        );
        assert!(storage.stats().unwrap().entries < 3);
        assert!(storage.stats().unwrap().activity.evictions > 0);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_disk_storage_reclaims_tail_bin_after_purge() {
        let root = unique_test_cache_dir("storage-bin-storage-tail-reclaim");
        let storage = super::StorageBinDiskStorage::from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1800),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(2048),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let meta = pingora_meta("max-age=60");
        let first = pingora::cache::CacheKey::new("fluxheim-test", "/first.webp", "vhost");
        let second = pingora::cache::CacheKey::new("fluxheim-test", "/second.webp", "vhost");
        for key in [&first, &second] {
            let store_key = super::PingoraStoreKey::from_cache_key_and_meta(
                key,
                &meta,
                &super::default_cache_tag_headers_for_storage(),
            );
            let (internal_meta, response_header) = meta.serialize().unwrap();
            storage
                .put_object(
                    store_key,
                    internal_meta,
                    response_header,
                    Arc::from(vec![b'x'; 1300].into_boxed_slice()),
                )
                .unwrap();
        }
        assert_eq!(storage.stats().unwrap().bin_files, 2);
        assert!(storage.layout.bin_path(1).exists());

        assert!(storage.purge_combined(&second.combined()).unwrap());

        let stats = storage.stats().unwrap();
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.bin_files, 1);
        assert!(!storage.layout.bin_path(1).exists());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_disk_storage_implements_pingora_storage() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("storage-bin-storage-trait");
        let storage = Box::leak(Box::new(
            super::StorageBinDiskStorage::from_plan(super::DiskTierPlan {
                backend: CacheDiskBackend::StorageBin,
                path: root.clone(),
                max_size_bytes: ByteSize::from_bytes(2048),
                max_object_bytes: ByteSize::from_bytes(512),
                cache_tag_headers: super::default_cache_tag_headers_for_storage(),
                storage_bin: CacheDiskStorageBinConfig {
                    bin_size_bytes: ByteSize::from_bytes(1024),
                    preallocate: false,
                    max_open_bins: 4,
                },
                encryption: CacheDiskEncryptionConfig::default(),
            })
            .unwrap(),
        ));
        let key = pingora::cache::CacheKey::new("fluxheim-test", "/trait.webp", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"trait-"), false)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        let finish = block_on(miss.finish()).unwrap();
        assert!(matches!(
            finish,
            pingora::cache::storage::MissFinishType::Created(10)
        ));

        let (_meta, mut hit) = block_on(storage.lookup(&key, &span)).unwrap().unwrap();
        assert_eq!(
            block_on(hit.read_body()).unwrap(),
            Some(Bytes::from_static(b"trait-body"))
        );
        assert_eq!(block_on(hit.read_body()).unwrap(), None);
        assert!(block_on(storage.update_meta(&key, &pingora_meta("max-age=120"), &span)).unwrap());
        assert!(
            block_on(storage.purge(
                &key.to_compact(),
                pingora::cache::PurgeType::Invalidation,
                &span
            ))
            .unwrap()
        );
        assert!(block_on(storage.lookup(&key, &span)).unwrap().is_none());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn storage_bin_disk_storage_supports_indexed_management() {
        let root = unique_test_cache_dir("storage-bin-storage-indexed-management");
        let storage = super::StorageBinDiskStorage::from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(512),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(1024),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let meta = pingora_meta("max-age=60");

        let asset_key = pingora::cache::CacheKey::new("fluxheim-test", "/assets/a.webp", "vhost");
        let mut asset_store_key = super::PingoraStoreKey::from_cache_key_and_meta(
            &asset_key,
            &meta,
            &super::default_cache_tag_headers_for_storage(),
        );
        asset_store_key.index_path = Some("/assets/a.webp".to_owned());
        asset_store_key.cache_tags = vec!["blue".to_owned()];
        let (internal_meta, response_header) = meta.serialize().unwrap();
        storage
            .put_object(
                asset_store_key,
                internal_meta,
                response_header,
                Arc::from(&b"asset-body"[..]),
            )
            .unwrap();

        assert!(
            storage
                .inspect_cache_key(&asset_key)
                .unwrap()
                .is_some_and(|metadata| metadata.purge_indexed)
        );
        let result = storage
            .purge_indexed_path_pattern("vhost", "/assets/*.webp", 8)
            .unwrap();
        assert_eq!(result.matched, 1);
        assert_eq!(result.purged, 1);

        let tagged_key = pingora::cache::CacheKey::new("fluxheim-test", "/images/b.webp", "vhost");
        let mut tagged_store_key = super::PingoraStoreKey::from_cache_key_and_meta(
            &tagged_key,
            &meta,
            &super::default_cache_tag_headers_for_storage(),
        );
        tagged_store_key.index_path = Some("/images/b.webp".to_owned());
        tagged_store_key.cache_tags = vec!["green".to_owned()];
        let (internal_meta, response_header) = meta.serialize().unwrap();
        storage
            .put_object(
                tagged_store_key,
                internal_meta,
                response_header,
                Arc::from(&b"tagged-body"[..]),
            )
            .unwrap();

        let result = storage
            .soft_purge_indexed_cache_tag("vhost", "green", 8)
            .unwrap();
        assert_eq!(result.matched, 1);
        assert_eq!(result.purged, 1);
        let result = storage
            .purge_indexed_stale_user_tag("vhost", 8, false)
            .unwrap();
        assert_eq!(result.scanned, 1);
        assert_eq!(result.stale, 1);
        assert_eq!(result.purged, 1);
        assert_eq!(storage.stats().unwrap().entries, 0);

        storage.reset_activity();
        assert_eq!(storage.stats().unwrap().activity.purges, 0);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn storage_plan_ignores_disabled_tiers() {
        let config = CacheConfig {
            enabled: true,
            memory: CacheMemoryConfig {
                enabled: false,
                max_size_bytes: ByteSize::from_bytes(1024 * 1024 * 1024),
            },
            disk: CacheDiskConfig {
                enabled: false,
                path: Some(PathBuf::from("/var/cache/fluxheim")),
                max_size_bytes: ByteSize::from_bytes(10 * 1024 * 1024 * 1024),
                ..CacheDiskConfig::default()
            },
            ..CacheConfig::default()
        };

        assert_eq!(
            storage_plan(&config),
            super::CacheStoragePlan {
                memory: None,
                disk: None,
            }
        );
    }

    #[test]
    fn memory_cache_stores_and_returns_cached_images() {
        let config = enabled_cache();
        let cache = memory_image_cache_from_config(&config).unwrap();
        let key = image_cache_key(
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/assets/logo.png",
                query: None,
            },
        )
        .unwrap();
        let object = cached_image(b"png-bytes");

        cache.put(&key, object.clone()).unwrap();

        assert_eq!(cache.get(&key), Some(object));
        assert_eq!(cache.stats().entries, 1);
    }

    #[test]
    fn memory_cache_rejects_objects_larger_than_per_object_limit() {
        let cache = MemoryImageCache::new(ByteSize::from_bytes(128), ByteSize::from_bytes(4));
        let config = enabled_cache();
        let key = image_cache_key(
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/assets/logo.png",
                query: None,
            },
        )
        .unwrap();

        let error = cache.put(&key, cached_image(b"too-large")).unwrap_err();

        assert!(matches!(
            error,
            CacheStoreError::ObjectTooLarge {
                object_bytes,
                max_object_bytes
            } if object_bytes > 4 && max_object_bytes == ByteSize::from_bytes(4)
        ));
        assert_eq!(cache.get(&key), None);
    }

    #[test]
    fn memory_cache_eviction_is_bound_by_configured_ram_budget() {
        let cache = MemoryImageCache::new(ByteSize::from_bytes(64), ByteSize::from_bytes(64));
        let config = enabled_cache();
        let first = image_cache_key(
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/assets/one.png",
                query: None,
            },
        )
        .unwrap();
        let second = image_cache_key(
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/assets/two.png",
                query: None,
            },
        )
        .unwrap();

        cache
            .put(&first, cached_image(b"12345678901234567890"))
            .unwrap();
        cache
            .put(&second, cached_image(b"abcdefghijklmnopqrst"))
            .unwrap();
        cache.flush_pending_evictions();

        assert!(cache.stats().weighted_size_bytes <= 64);
        assert!(cache.get(&first).is_none() || cache.get(&second).is_none());
    }

    #[test]
    fn memory_cache_purges_by_cache_key() {
        let config = enabled_cache();
        let cache = memory_image_cache_from_config(&config).unwrap();
        let key = image_cache_key(
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/assets/logo.png",
                query: None,
            },
        )
        .unwrap();
        cache.put(&key, cached_image(b"png-bytes")).unwrap();

        cache.purge(&key);
        cache.flush_pending_evictions();

        assert_eq!(cache.get(&key), None);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn builds_pingora_cache_key_with_user_tag() {
        let config = enabled_cache();
        let request = CacheRequest {
            method: "GET",
            host: Some("example.test"),
            path: "/img/logo.png",
            query: None,
        };

        let key =
            super::pingora_image_cache_key("fluxheim-image-v1", &config, &request, "example-vhost")
                .unwrap();

        assert_eq!(key.namespace_str(), Some("fluxheim-image-v1"));
        assert_eq!(key.user_tag, "example-vhost");
        assert_eq!(
            key.primary_key_str(),
            Some(
                "fluxheim-image-v1;method:3:GET;host:12:example.test;path:13:/img/logo.png;query:0:;"
            )
        );
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_round_trips_cached_body() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(1024),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 2,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let key = pingora::cache::CacheKey::new("fluxheim-test", "image-key", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"cached-"), false)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        let finish = block_on(miss.finish()).unwrap();
        assert!(matches!(
            finish,
            pingora::cache::storage::MissFinishType::Created(11)
        ));

        let (stored_meta, mut hit) = block_on(storage.lookup(&key, &span)).unwrap().unwrap();
        assert!(stored_meta.is_fresh(std::time::SystemTime::now()));
        assert_eq!(
            block_on(hit.read_body()).unwrap(),
            Some(Bytes::from_static(b"cached-body"))
        );
        assert_eq!(block_on(hit.read_body()).unwrap(), None);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_tracks_activity_counters() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(1024),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 2,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let key = pingora::cache::CacheKey::new("fluxheim-test", "activity-key", "vhost");
        let missing = pingora::cache::CacheKey::new("fluxheim-test", "missing-key", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        assert!(block_on(storage.lookup(&missing, &span)).unwrap().is_none());
        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        block_on(miss.finish()).unwrap();
        assert!(block_on(storage.lookup(&key, &span)).unwrap().is_some());
        assert!(
            block_on(storage.purge(
                &key.to_compact(),
                pingora::cache::PurgeType::Invalidation,
                &span
            ))
            .unwrap()
        );

        let activity = storage.stats().activity;
        assert_eq!(activity.misses, 1);
        assert_eq!(activity.stores, 1);
        assert_eq!(activity.hits, 1);
        assert_eq!(activity.purges, 1);
        assert_eq!(activity.store_refusals, 0);

        storage.reset_activity();

        assert_eq!(
            storage.stats().activity,
            super::CacheActivityStats::default()
        );
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_refuses_oversized_miss_without_storing() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(1024),
            max_object_bytes: ByteSize::from_bytes(8),
            object_slots: 2,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let key = pingora::cache::CacheKey::new("fluxheim-test", "oversized-key", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"12345"), false)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"6789"), true)).unwrap();
        let finish = block_on(miss.finish()).unwrap();

        assert!(matches!(
            finish,
            pingora::cache::storage::MissFinishType::Created(0)
        ));
        assert!(block_on(storage.lookup(&key, &span)).unwrap().is_none());
        assert_eq!(storage.stats().entries, 0);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_keeps_partial_streaming_disabled() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(1024),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 2,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });

        assert!(!storage.support_streaming_partial_write());
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_supports_seek_and_purge() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(1024),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 2,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let key = pingora::cache::CacheKey::new("fluxheim-test", "range-key", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"0123456789"), true)).unwrap();
        block_on(miss.finish()).unwrap();

        let (_stored_meta, mut hit) = block_on(storage.lookup(&key, &span)).unwrap().unwrap();
        assert!(hit.can_seek());
        hit.seek(2, Some(5)).unwrap();
        assert_eq!(
            block_on(hit.read_body()).unwrap(),
            Some(Bytes::from_static(b"234"))
        );

        assert!(
            block_on(storage.purge(
                &key.to_compact(),
                pingora::cache::PurgeType::Invalidation,
                &span
            ))
            .unwrap()
        );
        assert!(block_on(storage.lookup(&key, &span)).unwrap().is_none());
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_purges_variants_by_primary_key() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 4,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let base_key = pingora::cache::CacheKey::new("fluxheim-test", "vary-key", "vhost");
        let mut br_key = base_key.clone();
        br_key.set_variance_key([1; 16]);
        let mut gzip_key = base_key.clone();
        gzip_key.set_variance_key([2; 16]);
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        for (key, body) in [(&br_key, b"br".as_slice()), (&gzip_key, b"gzip".as_slice())] {
            let mut miss = block_on(storage.get_miss_handler(key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::copy_from_slice(body), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }

        assert!(block_on(storage.lookup(&br_key, &span)).unwrap().is_some());
        assert!(
            block_on(storage.lookup(&gzip_key, &span))
                .unwrap()
                .is_some()
        );
        assert_eq!(storage.purge_index.len(), 2);

        assert!(storage.purge_cache_key(&base_key));
        assert!(block_on(storage.lookup(&br_key, &span)).unwrap().is_none());
        assert!(
            block_on(storage.lookup(&gzip_key, &span))
                .unwrap()
                .is_none()
        );
        assert!(storage.purge_index.is_empty());
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_purges_indexed_user_tag() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 4,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let first = pingora::cache::CacheKey::new("fluxheim-test", "first", "vhost-a");
        let second = pingora::cache::CacheKey::new("fluxheim-test", "second", "vhost-a");
        let other = pingora::cache::CacheKey::new("fluxheim-test", "other", "vhost-b");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        for key in [&first, &second, &other] {
            let mut miss = block_on(storage.get_miss_handler(key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }

        let result = storage.purge_indexed_user_tag("vhost-a", 8);

        assert_eq!(
            result,
            super::CacheIndexedPurgeResult {
                matched: 2,
                purged: 2,
                truncated: false,
            }
        );
        assert!(block_on(storage.lookup(&first, &span)).unwrap().is_none());
        assert!(block_on(storage.lookup(&second, &span)).unwrap().is_none());
        assert!(block_on(storage.lookup(&other, &span)).unwrap().is_some());
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_purges_indexed_cache_tag() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 4,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let first = pingora::cache::CacheKey::new("fluxheim-test", "first", "vhost-a");
        let second = pingora::cache::CacheKey::new("fluxheim-test", "second", "vhost-a");
        let other = pingora::cache::CacheKey::new("fluxheim-test", "other", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let mut tagged = pingora_meta("max-age=60");
        tagged
            .response_header_mut()
            .insert_header("Surrogate-Key", "article:1 listing")
            .unwrap();
        let mut untagged = pingora_meta("max-age=60");
        untagged
            .response_header_mut()
            .insert_header("Surrogate-Key", "article:2")
            .unwrap();

        for key in [&first, &second] {
            let mut miss = block_on(storage.get_miss_handler(key, &tagged, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }
        let mut miss = block_on(storage.get_miss_handler(&other, &untagged, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        block_on(miss.finish()).unwrap();

        let result = storage.purge_indexed_cache_tag("vhost-a", "article:1", 8);

        assert_eq!(
            result,
            super::CacheIndexedPurgeResult {
                matched: 2,
                purged: 2,
                truncated: false,
            }
        );
        assert!(block_on(storage.lookup(&first, &span)).unwrap().is_none());
        assert!(block_on(storage.lookup(&second, &span)).unwrap().is_none());
        assert!(block_on(storage.lookup(&other, &span)).unwrap().is_some());
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_indexed_purge_scans_live_objects_when_index_entry_is_missing() {
        use pingora::cache::Storage;
        use pingora::cache::key::CacheHashKey;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 4,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let key = pingora::cache::CacheKey::new("fluxheim-test", "scan-live-key", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let mut meta = pingora_meta("max-age=60");
        meta.response_header_mut()
            .insert_header("Surrogate-Key", "article:missing-index")
            .unwrap();

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        block_on(miss.finish()).unwrap();
        assert!(storage.purge_index.remove_combined(&key.combined()));

        let result = storage.purge_indexed_cache_tag("vhost-a", "article:missing-index", 8);

        assert_eq!(
            result,
            super::CacheIndexedPurgeResult {
                matched: 1,
                purged: 1,
                truncated: false,
            }
        );
        assert!(block_on(storage.lookup(&key, &span)).unwrap().is_none());
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_removes_purge_entries_for_evicted_objects() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(768),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 2,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        for index in 0..8 {
            let key = pingora::cache::CacheKey::new(
                "fluxheim-test",
                format!("evict-key-{index}"),
                "vhost-a",
            );
            let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from(vec![b'x'; 128]), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }
        storage.inner.run_pending_tasks();

        assert_eq!(
            storage.purge_index.len(),
            usize::try_from(storage.inner.entry_count()).unwrap()
        );
        for (combined_key, _) in storage.inner.iter() {
            assert!(storage.purge_index.contains_combined(combined_key.as_ref()));
        }
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_soft_purges_indexed_cache_tag() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 4,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let key = pingora::cache::CacheKey::new("fluxheim-test", "soft-key", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let mut meta = pingora_meta("max-age=60");
        meta.response_header_mut()
            .insert_header("Surrogate-Key", "article:1")
            .unwrap();

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        block_on(miss.finish()).unwrap();
        assert!(
            block_on(storage.lookup(&key, &span))
                .unwrap()
                .unwrap()
                .0
                .is_fresh(std::time::SystemTime::now())
        );

        let result = storage
            .soft_purge_indexed_cache_tag("vhost-a", "article:1", 8)
            .unwrap();

        assert_eq!(
            result,
            super::CacheIndexedPurgeResult {
                matched: 1,
                purged: 1,
                truncated: false,
            }
        );
        let (soft_purged_meta, mut hit) = block_on(storage.lookup(&key, &span)).unwrap().unwrap();
        assert!(!soft_purged_meta.is_fresh(std::time::SystemTime::now()));
        assert_eq!(
            block_on(hit.read_body()).unwrap(),
            Some(Bytes::from_static(b"body"))
        );
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_uses_configured_cache_tag_headers() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 4,
            cache_tag_headers: vec!["x-app-cache-tags".to_owned()],
        });
        let key = pingora::cache::CacheKey::new("fluxheim-test", "custom-tag", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let mut meta = pingora_meta("max-age=60");
        meta.response_header_mut()
            .insert_header("Surrogate-Key", "ignored")
            .unwrap();
        meta.response_header_mut()
            .insert_header("X-App-Cache-Tags", "custom:1")
            .unwrap();

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        block_on(miss.finish()).unwrap();

        assert_eq!(
            storage.purge_indexed_cache_tag("vhost-a", "ignored", 8),
            super::CacheIndexedPurgeResult {
                matched: 0,
                purged: 0,
                truncated: false,
            }
        );
        assert!(block_on(storage.lookup(&key, &span)).unwrap().is_some());
        assert_eq!(
            storage.purge_indexed_cache_tag("vhost-a", "custom:1", 8),
            super::CacheIndexedPurgeResult {
                matched: 1,
                purged: 1,
                truncated: false,
            }
        );
        assert!(block_on(storage.lookup(&key, &span)).unwrap().is_none());
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_purges_indexed_stale_entries() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 4,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let stale_key = pingora::cache::CacheKey::new("fluxheim-test", "stale", "vhost-a");
        let fresh_key = pingora::cache::CacheKey::new("fluxheim-test", "fresh", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let stale = stale_pingora_meta("max-age=60");
        let fresh = pingora_meta("max-age=60");

        for (key, meta) in [(&stale_key, &stale), (&fresh_key, &fresh)] {
            let mut miss = block_on(storage.get_miss_handler(key, meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }

        let result = storage
            .purge_indexed_stale_user_tag("vhost-a", 8, false)
            .unwrap();

        assert_eq!(
            result,
            super::CacheStalePurgeResult {
                scanned: 2,
                stale: 1,
                purged: 1,
                truncated: false,
            }
        );
        assert!(
            block_on(storage.lookup(&stale_key, &span))
                .unwrap()
                .is_none()
        );
        assert!(
            block_on(storage.lookup(&fresh_key, &span))
                .unwrap()
                .is_some()
        );
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_stale_purge_advances_past_fresh_page() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 8,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let fresh_first = pingora::cache::CacheKey::new("fluxheim-test", "fresh-first", "vhost-a");
        let fresh_second =
            pingora::cache::CacheKey::new("fluxheim-test", "fresh-second", "vhost-a");
        let stale_key = pingora::cache::CacheKey::new("fluxheim-test", "stale-third", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let fresh = pingora_meta("max-age=60");
        let stale = stale_pingora_meta("max-age=60");

        for (key, meta) in [
            (&fresh_first, &fresh),
            (&fresh_second, &fresh),
            (&stale_key, &stale),
        ] {
            let mut miss = block_on(storage.get_miss_handler(key, meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }

        let first = storage
            .purge_indexed_stale_user_tag("vhost-a", 1, false)
            .unwrap();
        let second = storage
            .purge_indexed_stale_user_tag("vhost-a", 1, false)
            .unwrap();
        let third = storage
            .purge_indexed_stale_user_tag("vhost-a", 1, false)
            .unwrap();

        assert_eq!(
            first,
            super::CacheStalePurgeResult {
                scanned: 1,
                stale: 0,
                purged: 0,
                truncated: true,
            }
        );
        assert_eq!(
            second,
            super::CacheStalePurgeResult {
                scanned: 1,
                stale: 0,
                purged: 0,
                truncated: true,
            }
        );
        assert_eq!(
            third,
            super::CacheStalePurgeResult {
                scanned: 1,
                stale: 1,
                purged: 1,
                truncated: true,
            }
        );
        assert!(
            block_on(storage.lookup(&stale_key, &span))
                .unwrap()
                .is_none()
        );
        assert!(
            block_on(storage.lookup(&fresh_first, &span))
                .unwrap()
                .is_some()
        );
        assert!(
            block_on(storage.lookup(&fresh_second, &span))
                .unwrap()
                .is_some()
        );
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_dry_runs_indexed_stale_entries() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 4,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let stale_key = pingora::cache::CacheKey::new("fluxheim-test", "stale-dry", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let stale = stale_pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&stale_key, &stale, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        block_on(miss.finish()).unwrap();

        let result = storage
            .purge_indexed_stale_user_tag("vhost-a", 8, true)
            .unwrap();

        assert_eq!(
            result,
            super::CacheStalePurgeResult {
                scanned: 1,
                stale: 1,
                purged: 0,
                truncated: false,
            }
        );
        assert!(
            block_on(storage.lookup(&stale_key, &span))
                .unwrap()
                .is_some()
        );
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_purges_indexed_path_prefix() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 8,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let config = enabled_cache();
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");
        let asset = super::pingora_image_cache_key(
            "fluxheim-image-v1",
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/assets/logo.png",
                query: None,
            },
            "vhost-a",
        )
        .unwrap();
        let nested_asset = super::pingora_image_cache_key(
            "fluxheim-image-v1",
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/assets/icons/menu.png",
                query: None,
            },
            "vhost-a",
        )
        .unwrap();
        let image = super::pingora_image_cache_key(
            "fluxheim-image-v1",
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/img/logo.png",
                query: None,
            },
            "vhost-a",
        )
        .unwrap();

        for key in [&asset, &nested_asset, &image] {
            let mut miss = block_on(storage.get_miss_handler(key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }

        let result = storage.purge_indexed_path_prefix("vhost-a", "/assets/", 8);

        assert_eq!(
            result,
            super::CacheIndexedPurgeResult {
                matched: 2,
                purged: 2,
                truncated: false,
            }
        );
        assert!(block_on(storage.lookup(&asset, &span)).unwrap().is_none());
        assert!(
            block_on(storage.lookup(&nested_asset, &span))
                .unwrap()
                .is_none()
        );
        assert!(block_on(storage.lookup(&image, &span)).unwrap().is_some());
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_memory_storage_purges_indexed_path_pattern() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 8,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let config = enabled_cache();
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");
        let png = super::pingora_image_cache_key(
            "fluxheim-image-v1",
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/assets/logo.png",
                query: None,
            },
            "vhost-a",
        )
        .unwrap();
        let webp = super::pingora_image_cache_key(
            "fluxheim-image-v1",
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/assets/logo.webp",
                query: None,
            },
            "vhost-a",
        )
        .unwrap();
        let nested_png = super::pingora_image_cache_key(
            "fluxheim-image-v1",
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/assets/icons/menu.png",
                query: None,
            },
            "vhost-a",
        )
        .unwrap();

        for key in [&png, &webp, &nested_png] {
            let mut miss = block_on(storage.get_miss_handler(key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }

        let result = storage.purge_indexed_path_pattern("vhost-a", "/assets/*.png", 8);

        assert_eq!(
            result,
            super::CacheIndexedPurgeResult {
                matched: 2,
                purged: 2,
                truncated: false,
            }
        );
        assert!(block_on(storage.lookup(&png, &span)).unwrap().is_none());
        assert!(
            block_on(storage.lookup(&nested_png, &span))
                .unwrap()
                .is_none()
        );
        assert!(block_on(storage.lookup(&webp, &span)).unwrap().is_some());
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_round_trips_cached_body() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("round-trip");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "disk-key", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"disk-"), false)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        assert_eq!(std::fs::read_dir(root.join("tmp")).unwrap().count(), 1);
        let finish = block_on(miss.finish()).unwrap();
        assert!(matches!(
            finish,
            pingora::cache::storage::MissFinishType::Created(9)
        ));
        assert_eq!(std::fs::read_dir(root.join("tmp")).unwrap().count(), 0);

        let (stored_meta, mut hit) = block_on(storage.lookup(&key, &span)).unwrap().unwrap();
        assert!(stored_meta.is_fresh(std::time::SystemTime::now()));
        assert_eq!(
            block_on(hit.read_body()).unwrap(),
            Some(Bytes::from_static(b"disk-body"))
        );
        assert_eq!(block_on(hit.read_body()).unwrap(), None);
        assert_eq!(storage.stats().unwrap().entries, 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_encrypts_local_key_objects() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("encrypted-round-trip");
        let key_path = root.join("cache-key.hex");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            &key_path,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
        )
        .unwrap();
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.join("objects"),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig {
                enabled: true,
                key_id: Some("test-key-v1".to_owned()),
                key_file: Some(key_path),
                ..CacheDiskEncryptionConfig::default()
            },
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "encrypted-key", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"secret-cache-body"), true)).unwrap();
        block_on(miss.finish()).unwrap();

        let object_path = storage.path_for_combined_key(&key.combined());
        let encoded = std::fs::read(&object_path).unwrap();
        assert!(encoded.starts_with(super::DISK_CACHE_ENCRYPTED_MAGIC_V1));
        assert!(
            !encoded
                .windows(b"secret-cache-body".len())
                .any(|window| window == b"secret-cache-body")
        );

        let (_stored_meta, mut hit) = block_on(storage.lookup(&key, &span)).unwrap().unwrap();
        assert_eq!(
            block_on(hit.read_body()).unwrap(),
            Some(Bytes::from_static(b"secret-cache-body"))
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn openbao_transit_encryption_config_loads_token_secret() {
        let root = unique_test_cache_dir("openbao-token");
        let token_path = root.join("token");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&token_path, "test-token\n").unwrap();

        let encryption = super::DiskCacheEncryption::from_config(&CacheDiskEncryptionConfig {
            enabled: true,
            provider: CacheDiskEncryptionProvider::OpenbaoTransit,
            key_id: Some("bao-v1".to_owned()),
            openbao: crate::config::CacheDiskEncryptionOpenBaoConfig {
                address: Some("https://openbao.internal.example".to_owned()),
                mount: Some("transit/cache".to_owned()),
                key_name: Some("fluxheim-cache".to_owned()),
                token_file: Some(token_path),
                token_credential: None,
            },
            ..CacheDiskEncryptionConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(encryption.key_id.as_ref(), "bao-v1");
        match encryption.provider {
            super::DiskCacheEncryptionProvider::OpenBaoTransit {
                address,
                mount,
                key_name,
                token,
            } => {
                assert_eq!(address.as_ref(), "https://openbao.internal.example");
                assert_eq!(mount.as_ref(), "transit/cache");
                assert_eq!(key_name.as_ref(), "fluxheim-cache");
                assert_eq!(token.as_ref().as_str(), "test-token");
            }
            super::DiskCacheEncryptionProvider::Local { .. } => {
                panic!("expected openbao transit provider")
            }
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn openbao_transit_url_encodes_mount_and_key_segments() {
        assert_eq!(
            super::openbao_transit_url(
                "https://openbao.example/",
                "/transit/cache/",
                "encrypt",
                "tenant one/key:1",
            ),
            "https://openbao.example/v1/transit/cache/encrypt/tenant%20one/key%3A1"
        );
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn openbao_transit_encrypt_decrypt_uses_http_api() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let encrypt_request = answer_openbao_request(
                &listener,
                "/v1/transit/cache/encrypt/fluxheim-cache",
                r#"{"data":{"ciphertext":"vault:v1:test-ciphertext"}}"#,
            );
            let decrypt_request = answer_openbao_request(
                &listener,
                "/v1/transit/cache/decrypt/fluxheim-cache",
                r#"{"data":{"plaintext":"c2VjcmV0LWJvZHk="}}"#,
            );
            (encrypt_request, decrypt_request)
        });

        let ciphertext = super::openbao_transit_encrypt(
            &address,
            "transit/cache",
            "fluxheim-cache",
            "test-token",
            b"secret-body",
            b"cache-aad",
        )
        .unwrap();
        assert_eq!(ciphertext, "vault:v1:test-ciphertext");
        let plaintext = super::openbao_transit_decrypt(
            &address,
            "transit/cache",
            "fluxheim-cache",
            "test-token",
            &ciphertext,
            b"cache-aad",
        )
        .unwrap();
        assert_eq!(plaintext, b"secret-body");

        let (encrypt_request, decrypt_request) = server.join().unwrap();
        assert!(
            encrypt_request
                .to_lowercase()
                .contains("x-vault-token: test-token")
        );
        assert!(encrypt_request.contains("\"plaintext\""));
        assert!(encrypt_request.contains("\"c2VjcmV0LWJvZHk=\""));
        assert!(encrypt_request.contains("\"associated_data\""));
        assert!(encrypt_request.contains("\"Y2FjaGUtYWFk\""));
        assert!(
            decrypt_request
                .to_lowercase()
                .contains("x-vault-token: test-token")
        );
        assert!(decrypt_request.contains("\"ciphertext\""));
        assert!(decrypt_request.contains("\"vault:v1:test-ciphertext\""));
        assert!(decrypt_request.contains("\"associated_data\""));
        assert!(decrypt_request.contains("\"Y2FjaGUtYWFk\""));
    }

    #[cfg(feature = "proxy")]
    fn answer_openbao_request(
        listener: &std::net::TcpListener,
        expected_path: &str,
        response_body: &str,
    ) -> String {
        use std::io::{Read as _, Write as _};

        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut buffer = Vec::new();
        let mut scratch = [0_u8; 1024];
        let mut expected_len = None;
        loop {
            let read = stream.read(&mut scratch).unwrap();
            assert!(read > 0, "mock OpenBao connection closed early");
            buffer.extend_from_slice(&scratch[..read]);
            if expected_len.is_none()
                && let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n")
            {
                let headers = String::from_utf8_lossy(&buffer[..header_end]).to_lowercase();
                let content_len = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                expected_len = Some(header_end + 4 + content_len);
            }
            if expected_len.is_some_and(|len| buffer.len() >= len) {
                break;
            }
        }
        let request = String::from_utf8(buffer).unwrap();
        let normalized_request = request.to_lowercase();
        assert!(
            normalized_request
                .starts_with(&format!("post {expected_path} http/1.1").to_lowercase()),
            "unexpected OpenBao request: {request}"
        );
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        )
        .unwrap();
        request
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_rejects_reserved_storage_bin_backend() {
        let root = unique_test_cache_dir("storage-bin-runtime-guard");
        let error = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(!root.exists());
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_backend_accepts_storage_bin_backend() {
        let root = unique_test_cache_dir("storage-bin-runtime-backend");
        let storage = super::pingora_disk_storage_backend_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::StorageBin,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(1024),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();

        assert_eq!(storage.root(), root.as_path());
        assert_eq!(storage.stats().unwrap().entries, 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn disk_cache_scan_uses_deterministic_hex_shards() {
        let root = unique_test_cache_dir("deterministic-shards");
        std::fs::create_dir_all(root.join("ab")).unwrap();
        std::fs::create_dir_all(root.join("zz")).unwrap();
        let object_name = format!("{}.fhc", "a".repeat(64));
        std::fs::write(root.join("ab").join(&object_name), b"cached").unwrap();
        std::fs::write(root.join("zz").join(&object_name), b"ignored").unwrap();

        let canonical_root = root.canonicalize().unwrap();
        let entries = super::disk_cache_entries(&canonical_root).unwrap();

        assert_eq!(entries.len(), 1);
        assert!(entries[0].path.starts_with(canonical_root.join("ab")));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(feature = "proxy", unix))]
    #[test]
    fn disk_cache_scan_ignores_symlinked_shards() {
        let root = unique_test_cache_dir("symlink-scan-shard");
        let outside = unique_test_cache_dir("symlink-scan-outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("ab")).unwrap();
        let object_name = format!("{}.fhc", "a".repeat(64));
        std::fs::write(outside.join(object_name), b"outside").unwrap();

        let canonical_root = root.canonicalize().unwrap();
        let entries = super::disk_cache_entries(&canonical_root).unwrap();

        assert!(entries.is_empty());

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn disk_cache_temp_cleanup_uses_expected_locations() {
        let root = unique_test_cache_dir("temp-cleanup-locations");
        std::fs::create_dir_all(root.join("tmp")).unwrap();
        std::fs::create_dir_all(root.join("ab")).unwrap();
        std::fs::create_dir_all(root.join("unexpected")).unwrap();
        let root_temp = root.join("tmp/.fluxheim-body-root.tmp");
        let shard_temp = root.join("ab/.fluxheim-object-shard.tmp");
        let unexpected_temp = root.join("unexpected/.fluxheim-body-unexpected.tmp");
        std::fs::write(&root_temp, b"root").unwrap();
        std::fs::write(&shard_temp, b"shard").unwrap();
        std::fs::write(&unexpected_temp, b"unexpected").unwrap();

        let canonical_root = root.canonicalize().unwrap();
        let removed =
            super::cleanup_stale_disk_cache_temp_files(&canonical_root, std::time::Duration::ZERO)
                .unwrap();

        assert_eq!(removed, 2);
        assert!(!root_temp.exists());
        assert!(!shard_temp.exists());
        assert!(unexpected_temp.exists());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_rebuilds_purge_index_from_persistent_objects() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("disk-persistent-index");
        let writer = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "disk-index-key", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let mut meta = pingora_meta("max-age=60");
        meta.response_header_mut()
            .insert_header("Surrogate-Key", "article:1 listing")
            .unwrap();

        let mut miss = block_on(writer.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"disk-body"), true)).unwrap();
        block_on(miss.finish()).unwrap();
        assert_eq!(writer.purge_index.len(), 1);

        let rebuilt = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        assert_eq!(rebuilt.purge_index.len(), 1);
        let result = rebuilt
            .purge_indexed_cache_tag("vhost-a", "article:1", 8)
            .unwrap();
        assert_eq!(
            result,
            super::CacheIndexedPurgeResult {
                matched: 1,
                purged: 1,
                truncated: false,
            }
        );
        assert_eq!(rebuilt.stats().unwrap().entries, 0);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_checkpoint_preserves_shared_root_entries() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("disk-shared-index");
        let vhost = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let route = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let span = pingora::cache::trace::Span::inactive().handle();
        let route_key =
            pingora::cache::CacheKey::new("fluxheim-test", "route-key", "vhost-a:route:assets");
        let vhost_key = pingora::cache::CacheKey::new("fluxheim-test", "vhost-key", "vhost-a");
        let meta = pingora_meta("max-age=60");

        let mut route_miss = block_on(route.get_miss_handler(&route_key, &meta, &span)).unwrap();
        block_on(route_miss.write_body(Bytes::from_static(b"route-body"), true)).unwrap();
        block_on(route_miss.finish()).unwrap();

        let mut vhost_miss = block_on(vhost.get_miss_handler(&vhost_key, &meta, &span)).unwrap();
        block_on(vhost_miss.write_body(Bytes::from_static(b"vhost-body"), true)).unwrap();
        block_on(vhost_miss.finish()).unwrap();

        let rebuilt = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        assert_eq!(rebuilt.purge_index.len(), 2);
        assert_eq!(
            rebuilt
                .purge_indexed_user_tag("vhost-a:route:assets", 8)
                .unwrap(),
            super::CacheIndexedPurgeResult {
                matched: 1,
                purged: 1,
                truncated: false,
            }
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_merges_valid_checkpoint_with_live_shard_scan() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("disk-index-checkpoint");
        let writer = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "checkpoint-key", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");
        let mut miss = block_on(writer.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"indexed"), true)).unwrap();
        block_on(miss.finish()).unwrap();
        writer.write_disk_index_checkpoint().unwrap();
        assert!(super::disk_index_checkpoint_path(writer.root()).exists());

        let rogue = pingora::cache::CacheKey::new("fluxheim-test", "rogue-key", "vhost-a");
        write_rogue_disk_cache_object(writer, &rogue, &meta, b"rogue");
        super::write_disk_index_checkpoint(writer.root(), writer.disk_index.entries()).unwrap();

        let rebuilt = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();

        assert_eq!(rebuilt.stats().unwrap().entries, 2);
        assert!(block_on(rebuilt.lookup(&key, &span)).unwrap().is_some());
        assert!(block_on(rebuilt.lookup(&rogue, &span)).unwrap().is_some());
        assert_eq!(rebuilt.stats().unwrap().entries, 2);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_debounces_checkpoint_after_insert_burst() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("disk-index-checkpoint-debounce");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(8192),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let checkpoint = super::disk_index_checkpoint_path(storage.root());
        std::fs::remove_file(&checkpoint).unwrap();

        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");
        for index in 0..3 {
            let key =
                pingora::cache::CacheKey::new("fluxheim-test", format!("burst-key-{index}"), "v");
            let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }

        let immediate_flags = storage.disk_index_checkpoint_flags();
        assert!(
            checkpoint.exists() || immediate_flags.0 || immediate_flags.1,
            "checkpoint should either be pending or already flushed"
        );

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if checkpoint.exists() && storage.disk_index_checkpoint_flags() == (false, false) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }

        assert!(checkpoint.exists());
        assert_eq!(storage.disk_index_checkpoint_flags(), (false, false));
        let entries = super::read_disk_index_checkpoint(storage.root())
            .unwrap()
            .unwrap();
        assert_eq!(entries.len(), 3);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_indexes_objects_beyond_previous_scan_cap() {
        use pingora::cache::Storage;

        let previous_scan_cap = 8_usize;
        let root = unique_test_cache_dir("disk-start-over-previous-entry-cap");
        let writer = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(65536),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");
        for index in 0..=previous_scan_cap {
            let key = pingora::cache::CacheKey::new(
                "fluxheim-test",
                format!("over-cap-key-{index}"),
                "vhost-a",
            );
            let mut miss = block_on(writer.get_miss_handler(&key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }
        let truncated_checkpoint = writer
            .disk_index
            .entries()
            .into_iter()
            .take(previous_scan_cap)
            .collect();
        super::write_disk_index_checkpoint(writer.root(), truncated_checkpoint).unwrap();

        let rebuilt = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(65536),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();

        assert_eq!(
            rebuilt.stats().unwrap().entries,
            u64::try_from(previous_scan_cap + 1).unwrap()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_enforces_size_budget_after_full_startup_scan() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("disk-start-budget-reconcile");
        let writer = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(65536),
            max_object_bytes: ByteSize::from_bytes(4096),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");
        for index in 0..12 {
            let key = pingora::cache::CacheKey::new(
                "fluxheim-test",
                format!("budget-key-{index}"),
                "vhost-a",
            );
            let mut miss = block_on(writer.get_miss_handler(&key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from(vec![b'x'; 512]), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }

        let rebuilt = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(4096),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();

        assert!(rebuilt.stats().unwrap().size_bytes <= 2048);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_falls_back_when_disk_index_checkpoint_is_corrupt() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("disk-index-corrupt");
        let writer = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "checkpoint-key", "vhost-a");
        let rogue = pingora::cache::CacheKey::new("fluxheim-test", "rogue-key", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");
        let mut miss = block_on(writer.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"indexed"), true)).unwrap();
        block_on(miss.finish()).unwrap();
        write_rogue_disk_cache_object(writer, &rogue, &meta, b"rogue");
        std::fs::write(
            super::disk_index_checkpoint_path(writer.root()),
            b"not-an-index\n",
        )
        .unwrap();

        let rebuilt = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();

        assert_eq!(rebuilt.stats().unwrap().entries, 2);
        assert!(block_on(rebuilt.lookup(&key, &span)).unwrap().is_some());
        assert!(block_on(rebuilt.lookup(&rogue, &span)).unwrap().is_some());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_rebuilds_path_prefix_index_metadata() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("disk-persistent-path-index");
        let writer = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let config = enabled_cache();
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");
        let asset = super::pingora_image_cache_key(
            "fluxheim-image-v1",
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/assets/logo.png",
                query: None,
            },
            "vhost-a",
        )
        .unwrap();
        let nested_asset = super::pingora_image_cache_key(
            "fluxheim-image-v1",
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/assets/icons/menu.png",
                query: None,
            },
            "vhost-a",
        )
        .unwrap();
        let image = super::pingora_image_cache_key(
            "fluxheim-image-v1",
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/img/logo.png",
                query: None,
            },
            "vhost-a",
        )
        .unwrap();

        for key in [&asset, &nested_asset, &image] {
            let mut miss = block_on(writer.get_miss_handler(key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }
        assert_eq!(writer.purge_index.len(), 3);

        let rebuilt = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        assert_eq!(rebuilt.purge_index.len(), 3);
        let result = rebuilt
            .purge_indexed_path_prefix("vhost-a", "/assets/", 8)
            .unwrap();

        assert_eq!(
            result,
            super::CacheIndexedPurgeResult {
                matched: 2,
                purged: 2,
                truncated: false,
            }
        );
        assert!(block_on(rebuilt.lookup(&asset, &span)).unwrap().is_none());
        assert!(
            block_on(rebuilt.lookup(&nested_asset, &span))
                .unwrap()
                .is_none()
        );
        assert!(block_on(rebuilt.lookup(&image, &span)).unwrap().is_some());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_indexed_purge_scans_live_objects_when_index_entry_is_missing() {
        use pingora::cache::Storage;
        use pingora::cache::key::CacheHashKey;

        let root = unique_test_cache_dir("disk-purge-live-scan");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let config = enabled_cache();
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");
        let key = super::pingora_image_cache_key(
            "fluxheim-image-v1",
            &config,
            &CacheRequest {
                method: "GET",
                host: Some("example.test"),
                path: "/assets/live.png",
                query: None,
            },
            "vhost-a",
        )
        .unwrap();

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        block_on(miss.finish()).unwrap();
        assert!(storage.purge_index.remove_combined(&key.combined()));

        let result = storage
            .purge_indexed_path_prefix("vhost-a", "/assets/", 8)
            .unwrap();

        assert_eq!(
            result,
            super::CacheIndexedPurgeResult {
                matched: 1,
                purged: 1,
                truncated: false,
            }
        );
        assert!(block_on(storage.lookup(&key, &span)).unwrap().is_none());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_rebuilds_tag_index_from_v4_objects() {
        let root = unique_test_cache_dir("disk-v4-compat-index");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "legacy-v4-key", "vhost-a");
        let mut meta = pingora_meta("max-age=60");
        meta.response_header_mut()
            .insert_header("Surrogate-Key", "article:legacy")
            .unwrap();
        let (internal_meta, response_header) = meta.serialize().unwrap();
        let store_key = super::PingoraStoreKey::from_cache_key_and_meta(
            &key,
            &meta,
            &super::default_cache_tag_headers_for_storage(),
        );
        let path = storage.path_for_combined_key(&store_key.combined);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        write_v4_disk_cache_object(
            &path,
            &store_key,
            &internal_meta,
            &response_header,
            b"legacy-body",
        );

        let rebuilt = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        assert_eq!(rebuilt.purge_index.len(), 1);
        let result = rebuilt
            .purge_indexed_cache_tag("vhost-a", "article:legacy", 8)
            .unwrap();

        assert_eq!(
            result,
            super::CacheIndexedPurgeResult {
                matched: 1,
                purged: 1,
                truncated: false,
            }
        );
        assert_eq!(rebuilt.stats().unwrap().entries, 0);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_soft_purges_indexed_cache_tag() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("disk-soft-purge");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "disk-soft-key", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let mut meta = pingora_meta("max-age=60");
        meta.response_header_mut()
            .insert_header("Surrogate-Key", "article:1")
            .unwrap();

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"disk-body"), true)).unwrap();
        block_on(miss.finish()).unwrap();
        assert!(
            block_on(storage.lookup(&key, &span))
                .unwrap()
                .unwrap()
                .0
                .is_fresh(std::time::SystemTime::now())
        );

        let result = storage
            .soft_purge_indexed_cache_tag("vhost-a", "article:1", 8)
            .unwrap();

        assert_eq!(
            result,
            super::CacheIndexedPurgeResult {
                matched: 1,
                purged: 1,
                truncated: false,
            }
        );
        let (soft_purged_meta, mut hit) = block_on(storage.lookup(&key, &span)).unwrap().unwrap();
        assert!(!soft_purged_meta.is_fresh(std::time::SystemTime::now()));
        assert_eq!(
            block_on(hit.read_body()).unwrap(),
            Some(Bytes::from_static(b"disk-body"))
        );
        assert_eq!(storage.stats().unwrap().entries, 1);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_purges_indexed_stale_entries() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("disk-stale-purge");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let stale_key = pingora::cache::CacheKey::new("fluxheim-test", "disk-stale", "vhost-a");
        let fresh_key = pingora::cache::CacheKey::new("fluxheim-test", "disk-fresh", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let stale = stale_pingora_meta("max-age=60");
        let fresh = pingora_meta("max-age=60");

        for (key, meta) in [(&stale_key, &stale), (&fresh_key, &fresh)] {
            let mut miss = block_on(storage.get_miss_handler(key, meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }

        let result = storage
            .purge_indexed_stale_user_tag("vhost-a", 8, false)
            .unwrap();

        assert_eq!(
            result,
            super::CacheStalePurgeResult {
                scanned: 2,
                stale: 1,
                purged: 1,
                truncated: false,
            }
        );
        assert!(
            block_on(storage.lookup(&stale_key, &span))
                .unwrap()
                .is_none()
        );
        assert!(
            block_on(storage.lookup(&fresh_key, &span))
                .unwrap()
                .is_some()
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_stale_purge_advances_past_fresh_page() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("disk-stale-purge-advance");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let fresh_first =
            pingora::cache::CacheKey::new("fluxheim-test", "disk-fresh-first", "vhost-a");
        let fresh_second =
            pingora::cache::CacheKey::new("fluxheim-test", "disk-fresh-second", "vhost-a");
        let stale_key =
            pingora::cache::CacheKey::new("fluxheim-test", "disk-stale-third", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let fresh = pingora_meta("max-age=60");
        let stale = stale_pingora_meta("max-age=60");

        for (key, meta) in [
            (&fresh_first, &fresh),
            (&fresh_second, &fresh),
            (&stale_key, &stale),
        ] {
            let mut miss = block_on(storage.get_miss_handler(key, meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }

        let first = storage
            .purge_indexed_stale_user_tag("vhost-a", 1, false)
            .unwrap();
        let second = storage
            .purge_indexed_stale_user_tag("vhost-a", 1, false)
            .unwrap();
        let third = storage
            .purge_indexed_stale_user_tag("vhost-a", 1, false)
            .unwrap();

        assert_eq!(
            first,
            super::CacheStalePurgeResult {
                scanned: 1,
                stale: 0,
                purged: 0,
                truncated: true,
            }
        );
        assert_eq!(
            second,
            super::CacheStalePurgeResult {
                scanned: 1,
                stale: 0,
                purged: 0,
                truncated: true,
            }
        );
        assert_eq!(
            third,
            super::CacheStalePurgeResult {
                scanned: 1,
                stale: 1,
                purged: 1,
                truncated: true,
            }
        );
        assert!(
            block_on(storage.lookup(&stale_key, &span))
                .unwrap()
                .is_none()
        );
        assert!(
            block_on(storage.lookup(&fresh_first, &span))
                .unwrap()
                .is_some()
        );
        assert!(
            block_on(storage.lookup(&fresh_second, &span))
                .unwrap()
                .is_some()
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_dry_runs_indexed_stale_entries() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("disk-stale-purge-dry-run");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let stale_key = pingora::cache::CacheKey::new("fluxheim-test", "disk-stale-dry", "vhost-a");
        let span = pingora::cache::trace::Span::inactive().handle();
        let stale = stale_pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&stale_key, &stale, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        block_on(miss.finish()).unwrap();

        let result = storage
            .purge_indexed_stale_user_tag("vhost-a", 8, true)
            .unwrap();

        assert_eq!(
            result,
            super::CacheStalePurgeResult {
                scanned: 1,
                stale: 1,
                purged: 0,
                truncated: false,
            }
        );
        assert!(
            block_on(storage.lookup(&stale_key, &span))
                .unwrap()
                .is_some()
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_purges_variants_by_primary_key() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("disk-vary-purge");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let base_key = pingora::cache::CacheKey::new("fluxheim-test", "disk-vary-key", "vhost");
        let mut br_key = base_key.clone();
        br_key.set_variance_key([3; 16]);
        let mut gzip_key = base_key.clone();
        gzip_key.set_variance_key([4; 16]);
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        for (key, body) in [(&br_key, b"br".as_slice()), (&gzip_key, b"gzip".as_slice())] {
            let mut miss = block_on(storage.get_miss_handler(key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::copy_from_slice(body), true)).unwrap();
            block_on(miss.finish()).unwrap();
        }

        assert_eq!(storage.stats().unwrap().entries, 2);
        assert!(block_on(storage.lookup(&br_key, &span)).unwrap().is_some());
        assert!(
            block_on(storage.lookup(&gzip_key, &span))
                .unwrap()
                .is_some()
        );
        assert_eq!(storage.purge_index.len(), 2);

        assert!(storage.purge_cache_key(&base_key).unwrap());
        assert!(block_on(storage.lookup(&br_key, &span)).unwrap().is_none());
        assert!(
            block_on(storage.lookup(&gzip_key, &span))
                .unwrap()
                .is_none()
        );
        assert_eq!(storage.stats().unwrap().entries, 0);
        assert!(storage.purge_index.is_empty());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_refuses_oversized_miss_without_storing() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("oversized");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(8),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "disk-oversized-key", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"12345"), false)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"6789"), true)).unwrap();
        let finish = block_on(miss.finish()).unwrap();

        assert!(matches!(
            finish,
            pingora::cache::storage::MissFinishType::Created(0)
        ));
        assert!(block_on(storage.lookup(&key, &span)).unwrap().is_none());
        assert_eq!(storage.stats().unwrap().entries, 0);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_refuses_unbounded_key_metadata() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("oversized-key-metadata");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(32 * 1024),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let user_tag = "v".repeat((super::DISK_CACHE_HEADER_OVERHEAD_LIMIT + 1) as usize);
        let key = pingora::cache::CacheKey::new("fluxheim-test", "disk-key", &user_tag);
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        let finish = block_on(miss.finish()).unwrap();

        assert!(matches!(
            finish,
            pingora::cache::storage::MissFinishType::Created(0)
        ));
        assert_eq!(storage.stats().unwrap().entries, 0);
        assert_eq!(storage.stats().unwrap().activity.store_refusals, 1);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn disk_cache_temp_cleanup_removes_only_stale_fluxheim_temps() {
        let root = unique_test_cache_dir("temp-cleanup");
        let temp_dir = root.join("tmp");
        let shard_dir = root.join("ab");
        std::fs::create_dir_all(&temp_dir).unwrap();
        std::fs::create_dir_all(&shard_dir).unwrap();

        let body_temp = temp_dir.join(".fluxheim-body-test.tmp");
        let object_temp = shard_dir.join(".fluxheim-object-test.tmp");
        let fresh_temp = temp_dir.join(".fluxheim-body-fresh.tmp");
        let unrelated = temp_dir.join("other.tmp");
        for path in [&body_temp, &object_temp, &fresh_temp, &unrelated] {
            std::fs::write(path, b"temp").unwrap();
        }

        assert_eq!(
            super::cleanup_stale_disk_cache_temp_files(
                &root,
                std::time::Duration::from_secs(24 * 60 * 60)
            )
            .unwrap(),
            0
        );
        assert!(fresh_temp.exists());

        assert_eq!(
            super::cleanup_stale_disk_cache_temp_files(&root, std::time::Duration::ZERO).unwrap(),
            3
        );
        assert!(!body_temp.exists());
        assert!(!object_temp.exists());
        assert!(!fresh_temp.exists());
        assert!(unrelated.exists());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_uses_hashed_paths_and_purges() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("paths");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new(
            "fluxheim-test",
            "../unsafe/../../img.png?x=<bad>",
            "vhost",
        );
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        block_on(miss.finish()).unwrap();

        let object_path = storage.path_for_key(&key);
        assert!(object_path.starts_with(&root));
        assert_eq!(object_path.extension(), Some(std::ffi::OsStr::new("fhc")));
        assert!(object_path.exists());
        assert!(
            block_on(storage.purge(
                &key.to_compact(),
                pingora::cache::PurgeType::Invalidation,
                &span
            ))
            .unwrap()
        );
        assert!(!object_path.exists());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(feature = "proxy", unix))]
    #[test]
    fn pingora_disk_storage_refuses_symlinked_shard_writes() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("symlink-shard");
        let outside = unique_test_cache_dir("symlink-shard-outside");
        std::fs::create_dir_all(&outside).unwrap();
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "symlink-write", "vhost");
        let object_path = storage.path_for_key(&key);
        std::os::unix::fs::symlink(&outside, object_path.parent().unwrap()).unwrap();

        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");
        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();

        let Err(_error) = block_on(miss.finish()) else {
            panic!("symlinked disk cache shard write unexpectedly succeeded");
        };
        assert!(!object_path.exists());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(all(feature = "proxy", unix))]
    #[test]
    fn pingora_disk_storage_refuses_symlinked_object_reads() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("symlink-object");
        let outside = unique_test_cache_dir("symlink-object-outside");
        std::fs::create_dir_all(&outside).unwrap();
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "symlink-read", "vhost");
        let object_path = storage.path_for_key(&key);
        std::fs::create_dir_all(object_path.parent().unwrap()).unwrap();
        let outside_file = outside.join("outside.fhc");
        std::fs::write(&outside_file, b"outside").unwrap();
        std::os::unix::fs::symlink(&outside_file, &object_path).unwrap();

        let span = pingora::cache::trace::Span::inactive().handle();
        let Err(_error) = block_on(storage.lookup(&key, &span)) else {
            panic!("symlinked disk cache object read unexpectedly succeeded");
        };

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(all(feature = "proxy", unix))]
    #[test]
    fn pingora_disk_storage_refuses_symlinked_object_writes() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("symlink-object-write");
        let outside = unique_test_cache_dir("symlink-object-write-outside");
        std::fs::create_dir_all(&outside).unwrap();
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "symlink-write-target", "vhost");
        let object_path = storage.path_for_key(&key);
        std::fs::create_dir_all(object_path.parent().unwrap()).unwrap();
        let outside_file = outside.join("outside.fhc");
        std::fs::write(&outside_file, b"outside").unwrap();
        std::os::unix::fs::symlink(&outside_file, &object_path).unwrap();

        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");
        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();

        let Err(_error) = block_on(miss.finish()) else {
            panic!("symlinked disk cache object write unexpectedly succeeded");
        };
        assert_eq!(std::fs::read(&outside_file).unwrap(), b"outside");

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(all(feature = "proxy", unix))]
    #[test]
    fn pingora_disk_storage_refuses_symlinks_inside_root() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("symlink-inside-root");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "inside-symlink", "vhost");
        let object_path = storage.path_for_key(&key);
        let real_shard = root.join("real-shard");
        std::fs::create_dir_all(&real_shard).unwrap();
        std::os::unix::fs::symlink(&real_shard, object_path.parent().unwrap()).unwrap();

        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");
        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();

        let Err(_error) = block_on(miss.finish()) else {
            panic!("symlinked in-root disk cache shard write unexpectedly succeeded");
        };
        let error = storage.purge_cache_key(&key).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(feature = "proxy", unix))]
    #[test]
    fn pingora_disk_storage_refuses_symlinked_root() {
        let root = unique_test_cache_dir("symlink-root");
        let outside = unique_test_cache_dir("symlink-root-outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &root).unwrap();

        let error = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        std::fs::remove_file(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(all(feature = "proxy", unix))]
    #[test]
    fn pingora_disk_storage_refuses_root_below_symlinked_parent() {
        let real_parent = unique_test_cache_dir("symlink-parent-real");
        let linked_parent = unique_test_cache_dir("symlink-parent-link");
        std::fs::create_dir_all(&real_parent).unwrap();
        std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();
        let root = linked_parent.join("cache");

        let error = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!real_parent.join("cache").exists());

        std::fs::remove_file(linked_parent).unwrap();
        std::fs::remove_dir_all(real_parent).unwrap();
    }

    #[cfg(all(feature = "proxy", unix))]
    #[test]
    fn disk_cache_entries_skip_symlinked_shards_and_objects() {
        let root = unique_test_cache_dir("scan-symlinks");
        let shard = root.join("ab");
        let outside = unique_test_cache_dir("scan-symlinks-outside");
        let linked_shard = root.join("cd");
        std::fs::create_dir_all(&shard).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let real_name = format!("{}.fhc", "0".repeat(64));
        let linked_name = format!("{}.fhc", "1".repeat(64));
        let outside_name = format!("{}.fhc", "2".repeat(64));
        std::fs::write(shard.join(&real_name), b"real").unwrap();
        std::fs::write(outside.join(&outside_name), b"outside").unwrap();
        std::os::unix::fs::symlink(outside.join(&outside_name), shard.join(&linked_name)).unwrap();
        std::os::unix::fs::symlink(&outside, &linked_shard).unwrap();

        let entries = super::disk_cache_entries(&root).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].path,
            shard.canonicalize().unwrap().join(real_name)
        );

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn disk_cache_entries_returns_all_safe_objects_over_previous_entry_cap() {
        let previous_scan_cap = 8_usize;
        let root = unique_test_cache_dir("scan-previous-entry-cap");
        let shard = root.join("ab");
        std::fs::create_dir_all(&shard).unwrap();
        for index in 0..=previous_scan_cap {
            std::fs::write(shard.join(format!("{index:064x}.fhc")), b"cached").unwrap();
        }

        let entries = super::disk_cache_entries(&root).unwrap();

        assert_eq!(entries.len(), previous_scan_cap + 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn disk_index_checkpoint_returns_all_safe_entries_over_previous_entry_cap() {
        let previous_scan_cap = 8_usize;
        let root = unique_test_cache_dir("checkpoint-previous-entry-cap");
        let shard = root.join("ab");
        std::fs::create_dir_all(&shard).unwrap();
        let mut checkpoint = String::from(super::DISK_CACHE_INDEX_MAGIC_V1);
        checkpoint.push('\n');
        for index in 0..=previous_scan_cap {
            let file_name = format!("{index:064x}.fhc");
            let path = shard.join(&file_name);
            std::fs::write(&path, b"cached").unwrap();
            checkpoint.push_str(&format!("ab/{file_name}\t6\t0\t0\n"));
        }
        std::fs::write(super::disk_index_checkpoint_path(&root), checkpoint).unwrap();

        let entries = super::read_disk_index_checkpoint(&root).unwrap().unwrap();

        assert_eq!(entries.len(), previous_scan_cap + 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn read_disk_cache_object_refuses_oversized_encoded_file() {
        let root = unique_test_cache_dir("read-oversized");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("oversized.fhc");
        std::fs::write(
            &path,
            vec![b'x'; (super::DISK_CACHE_HEADER_OVERHEAD_LIMIT + 16) as usize],
        )
        .unwrap();

        let error =
            super::read_disk_cache_object(&root, &path, ByteSize::from_bytes(8)).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn encoded_disk_cache_object_parses_as_v5_object() {
        let key = pingora::cache::CacheKey::new("fluxheim-test", "/asset.webp", "vhost");
        let meta = pingora_meta("max-age=60");
        let store_key = super::PingoraStoreKey::from_cache_key_and_meta(
            &key,
            &meta,
            &super::default_cache_tag_headers_for_storage(),
        );
        let (internal_meta, response_header) = meta.serialize().unwrap();

        let encoded = super::encode_disk_cache_object(
            &store_key,
            &internal_meta,
            &response_header,
            b"cache-body",
        )
        .unwrap();
        let object = super::parse_disk_cache_object(&encoded, ByteSize::from_bytes(1024)).unwrap();

        assert_eq!(
            object.combined_key.as_deref(),
            Some(key.combined().as_str())
        );
        assert_eq!(object.primary_key.as_deref(), Some(key.primary().as_str()));
        assert_eq!(object.body.as_ref(), b"cache-body");
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_evicts_oldest_object_to_admit_new_object() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("eviction");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(512),
            max_object_bytes: ByteSize::from_bytes(512),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let first = pingora::cache::CacheKey::new("fluxheim-test", "first", "vhost");
        let second = pingora::cache::CacheKey::new("fluxheim-test", "second", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&first, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from(vec![b'a'; 220]), true)).unwrap();
        block_on(miss.finish()).unwrap();
        assert!(block_on(storage.lookup(&first, &span)).unwrap().is_some());

        std::thread::sleep(std::time::Duration::from_millis(10));

        let mut miss = block_on(storage.get_miss_handler(&second, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from(vec![b'b'; 220]), true)).unwrap();
        block_on(miss.finish()).unwrap();

        assert!(block_on(storage.lookup(&first, &span)).unwrap().is_none());
        assert!(block_on(storage.lookup(&second, &span)).unwrap().is_some());
        assert!(!storage.purge_index.contains_combined(&first.combined()));
        assert!(storage.purge_index.contains_combined(&second.combined()));
        let stats = storage.stats().unwrap();
        assert!(stats.size_bytes <= 512);
        assert_eq!(stats.activity.evictions, 1);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_purge_object_path_prunes_purge_index() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("purge-index-prune");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(1024),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "object", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"cached"), true)).unwrap();
        block_on(miss.finish()).unwrap();
        assert!(storage.purge_index.contains_combined(&key.combined()));

        let path = storage.path_for_key(&key);
        assert!(storage.purge_object_path(path).unwrap());

        assert!(!storage.purge_index.contains_combined(&key.combined()));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_evicts_least_recently_used_index_entry() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("lru-eviction");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(720),
            max_object_bytes: ByteSize::from_bytes(512),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let first = pingora::cache::CacheKey::new("fluxheim-test", "first", "vhost");
        let second = pingora::cache::CacheKey::new("fluxheim-test", "second", "vhost");
        let third = pingora::cache::CacheKey::new("fluxheim-test", "third", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        for (key, byte) in [(&first, b'a'), (&second, b'b')] {
            let mut miss = block_on(storage.get_miss_handler(key, &meta, &span)).unwrap();
            block_on(miss.write_body(Bytes::from(vec![byte; 120]), true)).unwrap();
            block_on(miss.finish()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(storage.stats().unwrap().entries, 2);

        assert!(block_on(storage.lookup(&first, &span)).unwrap().is_some());
        std::thread::sleep(std::time::Duration::from_millis(10));

        let mut miss = block_on(storage.get_miss_handler(&third, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from(vec![b'c'; 120]), true)).unwrap();
        block_on(miss.finish()).unwrap();

        assert!(block_on(storage.lookup(&first, &span)).unwrap().is_some());
        assert!(block_on(storage.lookup(&second, &span)).unwrap().is_none());
        assert!(block_on(storage.lookup(&third, &span)).unwrap().is_some());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_tiered_storage_writes_misses_to_memory_and_disk() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("tiered-write");
        let memory = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(1024),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 2,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let disk = super::pingora_disk_storage_backend_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(512),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let storage = super::pingora_tiered_storage_from_parts(memory, disk);
        let key = pingora::cache::CacheKey::new("fluxheim-test", "tiered-key", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"tiered-body"), true)).unwrap();
        let finish = block_on(miss.finish()).unwrap();

        assert!(matches!(
            finish,
            pingora::cache::storage::MissFinishType::Created(11)
        ));
        assert_eq!(memory.stats().entries, 1);
        assert_eq!(disk.stats().unwrap().entries, 1);
        let (_meta, mut hit) = block_on(storage.lookup(&key, &span)).unwrap().unwrap();
        assert_eq!(
            block_on(hit.read_body()).unwrap(),
            Some(Bytes::from_static(b"tiered-body"))
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_tiered_storage_promotes_disk_hits_to_memory() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("tiered-promote");
        let memory = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(1024),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 2,
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
        });
        let disk = super::pingora_disk_storage_backend_from_plan(super::DiskTierPlan {
            backend: CacheDiskBackend::Filesystem,
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(512),
            cache_tag_headers: super::default_cache_tag_headers_for_storage(),
            storage_bin: CacheDiskStorageBinConfig::default(),
            encryption: CacheDiskEncryptionConfig::default(),
        })
        .unwrap();
        let storage = super::pingora_tiered_storage_from_parts(memory, disk);
        let key = pingora::cache::CacheKey::new("fluxheim-test", "promote-key", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(disk.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"disk-only"), true)).unwrap();
        block_on(miss.finish()).unwrap();
        assert_eq!(memory.stats().entries, 0);

        let (_meta, mut hit) = block_on(storage.lookup(&key, &span)).unwrap().unwrap();

        assert_eq!(
            block_on(hit.read_body()).unwrap(),
            Some(Bytes::from_static(b"disk-only"))
        );
        assert_eq!(memory.stats().entries, 1);
        assert!(block_on(memory.lookup(&key, &span)).unwrap().is_some());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_cache_lock_collapses_concurrent_fetches() {
        use pingora::cache::lock::{LockStatus, Locked};

        let lock = super::pingora_cache_lock(std::time::Duration::from_secs(30));
        let key = pingora::cache::CacheKey::new("fluxheim-test", "collapsed-key", "vhost");

        let writer = lock.lock(&key, false);
        assert!(writer.is_write());
        let reader = lock.lock(&key, false);
        assert!(matches!(reader, Locked::Read(_)));

        if let Locked::Write(permit) = writer {
            lock.release(&key, permit, LockStatus::Done);
        }

        let next_writer = lock.lock(&key, false);
        assert!(next_writer.is_write());
        if let Locked::Write(permit) = next_writer {
            lock.release(&key, permit, LockStatus::Done);
        }
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn cache_object_metadata_reports_stale_serving_state() {
        let mut header = ResponseHeader::build(200, Some(1)).unwrap();
        header
            .insert_header(
                "cache-control",
                "public, max-age=60, stale-while-revalidate=120",
            )
            .unwrap();
        let now = std::time::SystemTime::now();
        let meta = pingora::cache::CacheMeta::new(
            now.checked_sub(std::time::Duration::from_secs(30)).unwrap(),
            now.checked_sub(std::time::Duration::from_secs(90)).unwrap(),
            120,
            0,
            header,
        );
        let (internal_meta, response_header) = meta.serialize().unwrap();
        let object = super::PingoraStoredObject {
            combined_key: None,
            primary_key: None,
            user_tag: Some("vhost".to_owned()),
            index_path: Some("/asset.png".to_owned()),
            cache_tags: Vec::new(),
            internal_meta,
            response_header,
            body: std::sync::Arc::from(&b"body"[..]),
            weight: 0,
        };

        let metadata = super::cache_object_metadata(super::CacheObjectTier::Disk, true, &object)
            .unwrap()
            .unwrap();

        assert!(!metadata.fresh);
        assert_eq!(
            metadata.freshness_state,
            super::CacheObjectFreshnessState::Stale
        );
        assert!(metadata.serve_stale_while_revalidate);
        assert!(!metadata.serve_stale_if_error);
    }

    #[cfg(feature = "proxy")]
    fn pingora_meta(cache_control: &str) -> pingora::cache::CacheMeta {
        let mut header = ResponseHeader::build(200, Some(1)).unwrap();
        header
            .insert_header("cache-control", cache_control)
            .unwrap();
        let now = std::time::SystemTime::now();
        pingora::cache::CacheMeta::new(
            now.checked_add(std::time::Duration::from_secs(60)).unwrap(),
            now,
            0,
            0,
            header,
        )
    }

    #[cfg(feature = "proxy")]
    fn stale_pingora_meta(cache_control: &str) -> pingora::cache::CacheMeta {
        let mut header = ResponseHeader::build(200, Some(1)).unwrap();
        header
            .insert_header("cache-control", cache_control)
            .unwrap();
        let now = std::time::SystemTime::now();
        pingora::cache::CacheMeta::new(
            now.checked_sub(std::time::Duration::from_secs(30)).unwrap(),
            now.checked_sub(std::time::Duration::from_secs(90)).unwrap(),
            0,
            0,
            header,
        )
    }

    #[cfg(feature = "proxy")]
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};

        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[cfg(feature = "proxy")]
    fn unique_test_cache_dir(label: &str) -> PathBuf {
        unique_temp_path(label)
    }

    #[cfg(feature = "proxy")]
    fn write_rogue_disk_cache_object(
        storage: &super::PingoraDiskStorage,
        key: &pingora::cache::CacheKey,
        meta: &pingora::cache::CacheMeta,
        body: &[u8],
    ) {
        let path = storage.path_for_key(key);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let (internal_meta, response_header) = meta.serialize().unwrap();
        let store_key = super::PingoraStoreKey::from_cache_key_and_meta(
            key,
            meta,
            &super::default_cache_tag_headers_for_storage(),
        );
        super::write_disk_cache_object(
            &path,
            None,
            &store_key,
            &internal_meta,
            &response_header,
            body,
        )
        .unwrap();
    }

    #[cfg(feature = "proxy")]
    fn write_v4_disk_cache_object(
        path: &std::path::Path,
        store_key: &super::PingoraStoreKey,
        internal_meta: &[u8],
        response_header: &[u8],
        body: &[u8],
    ) {
        use std::io::Write as _;

        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .unwrap();
        let encoded_cache_tags = super::encode_cache_tags(&store_key.cache_tags);

        file.write_all(super::DISK_CACHE_MAGIC_V4).unwrap();
        writeln!(file, "{}", store_key.combined.len()).unwrap();
        writeln!(file, "{}", store_key.primary.len()).unwrap();
        writeln!(file, "{}", store_key.user_tag.len()).unwrap();
        writeln!(file, "{}", encoded_cache_tags.len()).unwrap();
        writeln!(file, "{}", internal_meta.len()).unwrap();
        writeln!(file, "{}", response_header.len()).unwrap();
        writeln!(file, "{}", body.len()).unwrap();
        file.write_all(store_key.combined.as_bytes()).unwrap();
        file.write_all(store_key.primary.as_bytes()).unwrap();
        file.write_all(store_key.user_tag.as_bytes()).unwrap();
        file.write_all(encoded_cache_tags.as_bytes()).unwrap();
        file.write_all(internal_meta).unwrap();
        file.write_all(response_header).unwrap();
        file.write_all(body).unwrap();
        file.sync_all().unwrap();
    }

    fn cached_image(body: &[u8]) -> CachedImageObject {
        CachedImageObject {
            status: 200,
            headers: vec![CachedHeader {
                name: "content-type".to_owned(),
                value: b"image/png".to_vec(),
            }],
            body: std::sync::Arc::from(body),
            fresh_until_unix_secs: 1,
        }
    }
}

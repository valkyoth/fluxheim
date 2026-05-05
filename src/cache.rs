use std::fmt::Write as _;
#[cfg(feature = "proxy")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

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

use crate::config::{ByteSize, CacheConfig, normalize_host};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheStoragePlan {
    pub memory: Option<MemoryTierPlan>,
    pub disk: Option<DiskTierPlan>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MemoryTierPlan {
    pub max_size_bytes: ByteSize,
    pub max_object_bytes: ByteSize,
    pub object_slots: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DiskTierPlan {
    pub path: PathBuf,
    pub max_size_bytes: ByteSize,
    pub max_object_bytes: ByteSize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheRequest<'a> {
    pub method: &'a str,
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub query: Option<&'a str>,
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
    pub activity: CacheActivityStats,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DiskCacheStats {
    pub entries: u64,
    pub size_bytes: u64,
    pub max_size_bytes: ByteSize,
    pub max_object_bytes: ByteSize,
    pub activity: CacheActivityStats,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TieredCacheStats {
    pub memory: MemoryCacheStats,
    pub disk: DiskCacheStats,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct CacheActivityStats {
    pub hits: u64,
    pub misses: u64,
    pub stores: u64,
    pub store_refusals: u64,
    pub purges: u64,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Default)]
struct CacheActivityCounters {
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    stores: std::sync::atomic::AtomicU64,
    store_refusals: std::sync::atomic::AtomicU64,
    purges: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "proxy")]
impl CacheActivityCounters {
    fn snapshot(&self) -> CacheActivityStats {
        CacheActivityStats {
            hits: self.hits.load(std::sync::atomic::Ordering::Relaxed),
            misses: self.misses.load(std::sync::atomic::Ordering::Relaxed),
            stores: self.stores.load(std::sync::atomic::Ordering::Relaxed),
            store_refusals: self
                .store_refusals
                .load(std::sync::atomic::Ordering::Relaxed),
            purges: self.purges.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    fn reset(&self) {
        self.hits.store(0, std::sync::atomic::Ordering::Relaxed);
        self.misses.store(0, std::sync::atomic::Ordering::Relaxed);
        self.stores.store(0, std::sync::atomic::Ordering::Relaxed);
        self.store_refusals
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.purges.store(0, std::sync::atomic::Ordering::Relaxed);
    }

    fn hit(&self) {
        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn miss(&self) {
        self.misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn store(&self) {
        self.stores
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn store_refusal(&self) {
        self.store_refusals
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn purge(&self) {
        self.purges
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            .field("stats", &self.stats())
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
const DISK_CACHE_MAGIC: &[u8] = b"FLUXHEIM-CACHE-v1\n";

#[cfg(feature = "proxy")]
static DISK_CACHE_TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(feature = "proxy")]
#[derive(Debug)]
pub struct PingoraMemoryStorage {
    inner: moka::sync::Cache<String, PingoraStoredObject>,
    max_size_bytes: ByteSize,
    max_object_bytes: ByteSize,
    activity: CacheActivityCounters,
}

#[cfg(feature = "proxy")]
impl PingoraMemoryStorage {
    pub fn from_plan(plan: MemoryTierPlan) -> Self {
        Self::new(plan.max_size_bytes, plan.max_object_bytes)
    }

    pub fn new(max_size_bytes: ByteSize, max_object_bytes: ByteSize) -> Self {
        let inner = moka::sync::Cache::builder()
            .max_capacity(max_size_bytes.as_u64())
            .weigher(|_key: &String, value: &PingoraStoredObject| value.weight)
            .build();
        Self {
            inner,
            max_size_bytes,
            max_object_bytes,
            activity: CacheActivityCounters::default(),
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
            activity: self.activity.snapshot(),
        }
    }

    pub fn reset_activity(&self) {
        self.activity.reset();
    }

    pub fn purge_cache_key(&self, key: &pingora::cache::CacheKey) -> bool {
        let key = key.combined();
        let existed = self.inner.get(&key).is_some();
        self.inner.invalidate(&key);
        self.inner.run_pending_tasks();
        if existed {
            self.activity.purge();
        }
        existed
    }

    fn lookup_object(&self, key: &pingora::cache::CacheKey) -> Option<PingoraStoredObject> {
        self.inner.get(&key.combined())
    }

    fn put_object(&self, key: String, meta: CacheMeta, body: Arc<[u8]>) -> pingora::Result<usize> {
        let (internal_meta, response_header) = meta.serialize()?;
        Ok(self
            .put_serialized_object(key, internal_meta, response_header, body)?
            .unwrap_or(0))
    }

    fn put_serialized_object(
        &self,
        key: String,
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
        self.inner.insert(
            key,
            PingoraStoredObject {
                internal_meta,
                response_header,
                body,
                weight,
            },
        );
        self.activity.store();
        Ok(Some(body_len))
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug)]
pub struct PingoraDiskStorage {
    root: PathBuf,
    max_size_bytes: ByteSize,
    max_object_bytes: ByteSize,
    activity: CacheActivityCounters,
}

#[cfg(feature = "proxy")]
impl PingoraDiskStorage {
    pub fn from_plan(plan: DiskTierPlan) -> std::io::Result<Self> {
        Self::new(plan.path, plan.max_size_bytes, plan.max_object_bytes)
    }

    pub fn new(
        root: PathBuf,
        max_size_bytes: ByteSize,
        max_object_bytes: ByteSize,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            max_size_bytes,
            max_object_bytes,
            activity: CacheActivityCounters::default(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn stats(&self) -> std::io::Result<DiskCacheStats> {
        let entries = disk_cache_entries(&self.root)?;
        let size_bytes = entries
            .iter()
            .fold(0_u64, |total, entry| total.saturating_add(entry.size));
        Ok(DiskCacheStats {
            entries: entries.len() as u64,
            size_bytes,
            max_size_bytes: self.max_size_bytes,
            max_object_bytes: self.max_object_bytes,
            activity: self.activity.snapshot(),
        })
    }

    pub fn reset_activity(&self) {
        self.activity.reset();
    }

    pub fn purge_cache_key(&self, key: &pingora::cache::CacheKey) -> std::io::Result<bool> {
        match std::fs::remove_file(self.path_for_key(key)) {
            Ok(()) => {
                self.activity.purge();
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn lookup_object(
        &self,
        key: &pingora::cache::CacheKey,
    ) -> pingora::Result<Option<PingoraStoredObject>> {
        let path = self.path_for_key(key);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(cache_io_error("read disk cache object", error)),
        };
        match parse_disk_cache_object(&bytes, self.max_object_bytes) {
            Ok(object) => Ok(Some(object)),
            Err(error) => {
                let _ = std::fs::remove_file(&path);
                Err(cache_io_error("parse disk cache object", error))
            }
        }
    }

    fn put_object(
        &self,
        key: String,
        meta: CacheMeta,
        body: Arc<[u8]>,
    ) -> pingora::Result<Option<usize>> {
        let (internal_meta, response_header) = meta.serialize()?;
        self.put_serialized_object(key, internal_meta, response_header, body)
    }

    fn put_serialized_object(
        &self,
        key: String,
        internal_meta: Vec<u8>,
        response_header: Vec<u8>,
        body: Arc<[u8]>,
    ) -> pingora::Result<Option<usize>> {
        let object_bytes = pingora_object_weight(&internal_meta, &response_header, &body);
        if object_bytes > self.max_object_bytes.as_u64()
            || object_bytes > self.max_size_bytes.as_u64()
        {
            self.activity.store_refusal();
            return Ok(None);
        }

        let path = self.path_for_combined_key(&key);
        if !self
            .evict_until_admissible(&path, object_bytes)
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
        std::fs::create_dir_all(parent)
            .map_err(|error| cache_io_error("create disk cache shard", error))?;
        let tmp_path = self.tmp_path_for(&path);
        let write_result =
            write_disk_cache_object(&tmp_path, &internal_meta, &response_header, &body)
                .and_then(|()| std::fs::rename(&tmp_path, &path));
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&tmp_path);
            self.activity.store_refusal();
            return Err(cache_io_error("write disk cache object", error));
        }
        self.activity.store();
        Ok(Some(body.len()))
    }

    fn evict_until_admissible(&self, path: &Path, object_bytes: u64) -> std::io::Result<bool> {
        let mut entries = disk_cache_entries(&self.root)?;
        let current_size = entries
            .iter()
            .fold(0_u64, |total, entry| total.saturating_add(entry.size));
        let existing_size = entries
            .iter()
            .find(|entry| entry.path == path)
            .map(|entry| entry.size)
            .unwrap_or(0);
        let max_size = self.max_size_bytes.as_u64();
        let projected_size = current_size
            .saturating_sub(existing_size)
            .saturating_add(object_bytes);
        if projected_size <= max_size {
            return Ok(true);
        }

        let mut bytes_to_free = projected_size.saturating_sub(max_size);
        entries.retain(|entry| entry.path != path);
        entries.sort_by(|left, right| {
            left.modified
                .cmp(&right.modified)
                .then_with(|| left.path.cmp(&right.path))
        });

        for entry in entries {
            match std::fs::remove_file(&entry.path) {
                Ok(()) => {
                    bytes_to_free = bytes_to_free.saturating_sub(entry.size);
                    if bytes_to_free == 0 {
                        return Ok(true);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }

        Ok(false)
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

    fn tmp_path_for(&self, path: &Path) -> PathBuf {
        let nonce = DISK_CACHE_TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        path.with_extension(format!("tmp.{}.{}", std::process::id(), nonce))
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug)]
pub struct PingoraTieredStorage {
    memory: &'static PingoraMemoryStorage,
    disk: &'static PingoraDiskStorage,
}

#[cfg(feature = "proxy")]
impl PingoraTieredStorage {
    pub fn new(memory: &'static PingoraMemoryStorage, disk: &'static PingoraDiskStorage) -> Self {
        Self { memory, disk }
    }

    pub fn memory(&self) -> &'static PingoraMemoryStorage {
        self.memory
    }

    pub fn disk(&self) -> &'static PingoraDiskStorage {
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
struct PingoraStoredObject {
    internal_meta: Vec<u8>,
    response_header: Vec<u8>,
    body: Arc<[u8]>,
    weight: u32,
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Eq, PartialEq)]
struct DiskCacheEntry {
    path: PathBuf,
    size: u64,
    modified: std::time::SystemTime,
}

#[cfg(feature = "proxy")]
fn disk_cache_entries(root: &Path) -> std::io::Result<Vec<DiskCacheEntry>> {
    let mut entries = Vec::new();
    for shard in std::fs::read_dir(root)? {
        let shard = shard?;
        if !shard.file_type()?.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(shard.path())? {
            let entry = entry?;
            if !entry.file_type()?.is_file()
                || entry.path().extension() != Some(std::ffi::OsStr::new("fhc"))
            {
                continue;
            }
            let metadata = entry.metadata()?;
            entries.push(DiskCacheEntry {
                path: entry.path(),
                size: metadata.len(),
                modified: metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
            });
        }
    }
    Ok(entries)
}

#[cfg(feature = "proxy")]
pub fn pingora_memory_storage_from_config(
    config: &CacheConfig,
) -> Option<&'static PingoraMemoryStorage> {
    storage_plan(config).memory.map(|plan| {
        Box::leak(Box::new(PingoraMemoryStorage::from_plan(plan))) as &'static PingoraMemoryStorage
    })
}

#[cfg(feature = "proxy")]
pub fn pingora_memory_storage_from_plan(plan: MemoryTierPlan) -> &'static PingoraMemoryStorage {
    Box::leak(Box::new(PingoraMemoryStorage::from_plan(plan)))
}

#[cfg(feature = "proxy")]
pub fn pingora_disk_storage_from_config(
    config: &CacheConfig,
) -> std::io::Result<Option<&'static PingoraDiskStorage>> {
    storage_plan(config)
        .disk
        .map(|plan| {
            PingoraDiskStorage::from_plan(plan)
                .map(|storage| Box::leak(Box::new(storage)) as &'static PingoraDiskStorage)
        })
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
pub fn pingora_tiered_storage_from_parts(
    memory: &'static PingoraMemoryStorage,
    disk: &'static PingoraDiskStorage,
) -> &'static PingoraTieredStorage {
    Box::leak(Box::new(PingoraTieredStorage::new(memory, disk)))
}

#[cfg(feature = "proxy")]
pub fn pingora_cache_lock(age_timeout: std::time::Duration) -> &'static CacheKeyLockImpl {
    Box::leak(CacheLock::new_boxed(age_timeout)) as &'static CacheKeyLockImpl
}

pub fn storage_plan(config: &CacheConfig) -> CacheStoragePlan {
    let memory = config.memory.enabled.then(|| MemoryTierPlan {
        max_size_bytes: config.memory.max_size_bytes,
        max_object_bytes: config.max_object_bytes,
        object_slots: object_slots(config.memory.max_size_bytes, config.max_object_bytes),
    });

    let disk = config
        .disk
        .enabled
        .then(|| {
            config.disk.path.as_ref().map(|path| DiskTierPlan {
                path: path.clone(),
                max_size_bytes: config.disk.max_size_bytes,
                max_object_bytes: config.max_object_bytes,
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
    (internal_meta.len() as u64)
        .saturating_add(response_header.len() as u64)
        .saturating_add(body.len() as u64)
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
            key: key.combined(),
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
        let key = key.combined();
        let Some(mut object) = self.inner.get(&key) else {
            return Ok(false);
        };
        let (internal_meta, response_header) = meta.serialize()?;
        let weight_bytes = pingora_object_weight(&internal_meta, &response_header, &object.body);
        if weight_bytes > self.max_object_bytes.as_u64() {
            self.inner.invalidate(&key);
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
        object.weight = weight;
        self.inner.insert(key, object);
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
        Ok(Box::new(PingoraDiskMissHandler {
            storage: self,
            key: key.combined(),
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
        let path = self.path_for_combined_key(&key.combined());
        match std::fs::remove_file(path) {
            Ok(()) => {
                self.activity.purge();
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(cache_io_error("purge disk cache object", error)),
        }
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
            .put_serialized_object(key.combined(), internal_meta, response_header, object.body)?
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
            self.disk.activity.miss();
            return Ok(None);
        };
        self.disk.activity.hit();
        let meta = CacheMeta::deserialize(&object.internal_meta, &object.response_header)?;
        let _promoted = self.memory.put_serialized_object(
            key.combined(),
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
            key: key.combined(),
            serialized_meta: meta.serialize()?,
            body: Vec::new(),
            max_object_bytes: self
                .memory
                .max_object_bytes
                .as_u64()
                .min(self.disk.max_object_bytes.as_u64()),
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
    key: String,
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
        let created = self
            .storage
            .put_object(self.key, meta, Arc::<[u8]>::from(self.body))?;
        Ok(MissFinishType::Created(created))
    }
}

#[cfg(feature = "proxy")]
struct PingoraDiskMissHandler {
    storage: &'static PingoraDiskStorage,
    key: String,
    serialized_meta: (Vec<u8>, Vec<u8>),
    body: Vec<u8>,
    max_object_bytes: u64,
    exceeded_limit: bool,
}

#[cfg(feature = "proxy")]
#[async_trait]
impl pingora::cache::storage::HandleMiss for PingoraDiskMissHandler {
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
        let Some(created) =
            self.storage
                .put_object(self.key, meta, Arc::<[u8]>::from(self.body))?
        else {
            return Ok(MissFinishType::Created(0));
        };
        Ok(MissFinishType::Created(created))
    }
}

#[cfg(feature = "proxy")]
struct PingoraTieredMissHandler {
    storage: &'static PingoraTieredStorage,
    key: String,
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
            self.key.clone(),
            self.serialized_meta.0.clone(),
            self.serialized_meta.1.clone(),
            Arc::clone(&body),
        )?;
        let disk_created = self.storage.disk.put_serialized_object(
            self.key,
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
    internal_meta: &[u8],
    response_header: &[u8],
    body: &[u8],
) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(DISK_CACHE_MAGIC)?;
    writeln!(file, "{}", internal_meta.len())?;
    writeln!(file, "{}", response_header.len())?;
    writeln!(file, "{}", body.len())?;
    file.write_all(internal_meta)?;
    file.write_all(response_header)?;
    file.write_all(body)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(feature = "proxy")]
fn parse_disk_cache_object(
    bytes: &[u8],
    max_object_bytes: ByteSize,
) -> std::io::Result<PingoraStoredObject> {
    let Some(mut offset) = bytes
        .get(..DISK_CACHE_MAGIC.len())
        .and_then(|prefix| (prefix == DISK_CACHE_MAGIC).then_some(DISK_CACHE_MAGIC.len()))
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid cache object magic",
        ));
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
        .checked_add(internal_meta_len)
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

    let internal_meta_end = offset + internal_meta_len;
    let response_header_end = internal_meta_end + response_header_len;
    let weight = u32::try_from(object_bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "cache object weight exceeds u32",
        )
    })?;
    Ok(PingoraStoredObject {
        internal_meta: bytes[offset..internal_meta_end].to_vec(),
        response_header: bytes[internal_meta_end..response_header_end].to_vec(),
        body: Arc::from(&bytes[response_header_end..][..]),
        weight,
    })
}

#[cfg(feature = "proxy")]
fn parse_disk_cache_len(bytes: &[u8], offset: &mut usize) -> std::io::Result<usize> {
    let Some(relative_newline) = bytes[*offset..].iter().position(|byte| *byte == b'\n') else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "cache object header missing newline",
        ));
    };
    let line_end = *offset + relative_newline;
    let line = std::str::from_utf8(&bytes[*offset..line_end]).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{error}"))
    })?;
    *offset = line_end + 1;
    line.parse::<usize>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{error}")))
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
    append_component(&mut key, "method", request.method);
    append_component(
        &mut key,
        "host",
        &request.host.and_then(normalize_host).unwrap_or_default(),
    );
    append_component(&mut key, "path", request.path);
    append_component(&mut key, "query", request.query.unwrap_or_default());
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
    use bytes::Bytes;

    use super::{
        CacheRequest, CacheStoreError, CachedHeader, CachedImageObject, MemoryImageCache,
        eligible_image_request, image_cache_key, memory_image_cache_from_config, storage_plan,
    };
    use crate::config::{ByteSize, CacheConfig, CacheDiskConfig, CacheMemoryConfig};

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
            },
            ..CacheConfig::default()
        };

        let plan = storage_plan(&config);
        assert_eq!(plan.memory, None);
        assert_eq!(
            plan.disk.unwrap(),
            super::DiskTierPlan {
                path: PathBuf::from("/var/cache/fluxheim/example.test"),
                max_size_bytes: ByteSize::from_bytes(8 * 1024 * 1024 * 1024),
                max_object_bytes: ByteSize::from_bytes(64 * 1024 * 1024),
            }
        );
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
    fn pingora_disk_storage_round_trips_cached_body() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("round-trip");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
        })
        .unwrap();
        let key = pingora::cache::CacheKey::new("fluxheim-test", "disk-key", "vhost");
        let span = pingora::cache::trace::Span::inactive().handle();
        let meta = pingora_meta("max-age=60");

        let mut miss = block_on(storage.get_miss_handler(&key, &meta, &span)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"disk-"), false)).unwrap();
        block_on(miss.write_body(Bytes::from_static(b"body"), true)).unwrap();
        let finish = block_on(miss.finish()).unwrap();
        assert!(matches!(
            finish,
            pingora::cache::storage::MissFinishType::Created(9)
        ));

        let (stored_meta, mut hit) = block_on(storage.lookup(&key, &span)).unwrap().unwrap();
        assert!(stored_meta.is_fresh(std::time::SystemTime::now()));
        assert_eq!(
            block_on(hit.read_body()).unwrap(),
            Some(Bytes::from_static(b"disk-body"))
        );
        assert_eq!(block_on(hit.read_body()).unwrap(), None);
        assert_eq!(storage.stats().unwrap().entries, 1);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_refuses_oversized_miss_without_storing() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("oversized");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(8),
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
    fn pingora_disk_storage_uses_hashed_paths_and_purges() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("paths");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
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

    #[cfg(feature = "proxy")]
    #[test]
    fn pingora_disk_storage_evicts_oldest_object_to_admit_new_object() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("eviction");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(512),
            max_object_bytes: ByteSize::from_bytes(512),
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
        assert!(storage.stats().unwrap().size_bytes <= 512);

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
        });
        let disk = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(512),
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
        });
        let disk = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(512),
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
    fn pingora_meta(cache_control: &str) -> pingora::cache::CacheMeta {
        let mut header = pingora::http::ResponseHeader::build(200, Some(1)).unwrap();
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
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        use std::pin::pin;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn raw_waker() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            fn wake(_: *const ()) {}
            fn wake_by_ref(_: *const ()) {}
            fn drop(_: *const ()) {}

            RawWaker::new(
                std::ptr::null(),
                &RawWakerVTable::new(clone, wake, wake_by_ref, drop),
            )
        }

        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut context = Context::from_waker(&waker);
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
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        std::env::temp_dir().join(format!(
            "fluxheim-cache-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
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

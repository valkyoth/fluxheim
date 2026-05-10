#[cfg(feature = "proxy")]
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
#[cfg(feature = "proxy")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "proxy")]
use std::sync::RwLock;

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

use crate::config::{ByteSize, CacheConfig, CacheKeyPart, normalize_host};

#[cfg(all(feature = "proxy", target_os = "linux"))]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(all(feature = "proxy", target_os = "linux"))]
const O_NOFOLLOW: i32 = 0o400000;

#[cfg(feature = "proxy")]
const DISK_CACHE_HEADER_OVERHEAD_LIMIT: u64 = 128;
#[cfg(feature = "proxy")]
const DISK_CACHE_MAGIC_V1: &[u8] = b"FLUXHEIM-CACHE-v1\n";
#[cfg(feature = "proxy")]
const DISK_CACHE_MAGIC_V2: &[u8] = b"FLUXHEIM-CACHE-v2\n";
#[cfg(feature = "proxy")]
const CACHE_PURGE_INDEX_MAX_ENTRIES: usize = 65_536;

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
    pub purge_index_entries: u64,
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
    pub purge_index_entries: u64,
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
    max_entries: usize,
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
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct CacheIndexedPurgeResult {
    pub matched: usize,
    pub purged: usize,
    pub truncated: bool,
}

#[cfg(feature = "proxy")]
impl CachePurgeIndex {
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(CachePurgeIndexInner::default())),
            max_entries,
        }
    }

    pub fn insert(&self, combined_key: String, primary_key: String, user_tag: String) {
        let path = cache_primary_component(&primary_key, "path");
        self.insert_with_path(combined_key, primary_key, user_tag, path);
    }

    pub fn insert_with_path(
        &self,
        combined_key: String,
        primary_key: String,
        user_tag: String,
        path: Option<String>,
    ) {
        if self.max_entries == 0 {
            return;
        }
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
            },
        );

        while inner.entries.len() > self.max_entries {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            inner.entries.remove(&oldest);
        }
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
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };
        inner
            .order
            .iter()
            .filter_map(|key| inner.entries.get(key))
            .filter(|entry| entry.combined_key.starts_with(prefix))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn entries_for_user_tag(&self, user_tag: &str, limit: usize) -> Vec<CachePurgeIndexEntry> {
        if user_tag.is_empty() || limit == 0 {
            return Vec::new();
        }
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };
        inner
            .order
            .iter()
            .filter_map(|key| inner.entries.get(key))
            .filter(|entry| entry.user_tag == user_tag)
            .take(limit)
            .cloned()
            .collect()
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
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };
        inner
            .order
            .iter()
            .filter_map(|key| inner.entries.get(key))
            .filter(|entry| {
                entry.user_tag == user_tag
                    && entry
                        .path
                        .as_deref()
                        .is_some_and(|path| path.starts_with(path_prefix))
            })
            .take(limit)
            .cloned()
            .collect()
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
        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };
        inner
            .order
            .iter()
            .filter_map(|key| inner.entries.get(key))
            .filter(|entry| {
                entry.user_tag == user_tag
                    && entry
                        .path
                        .as_deref()
                        .is_some_and(|path| cache_path_wildcard_matches(path_pattern, path))
            })
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

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
            purge_index: CachePurgeIndex::new(CACHE_PURGE_INDEX_MAX_ENTRIES),
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
            purge_index_entries: self.purge_index.len() as u64,
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
        let mut entries = self
            .purge_index
            .entries_for_user_tag(user_tag, limit.saturating_add(1));
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

    pub fn purge_indexed_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> CacheIndexedPurgeResult {
        let mut entries = self.purge_index.entries_for_user_tag_path_prefix(
            user_tag,
            path_prefix,
            limit.saturating_add(1),
        );
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

    pub fn purge_indexed_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> CacheIndexedPurgeResult {
        let mut entries = self.purge_index.entries_for_user_tag_path_pattern(
            user_tag,
            path_pattern,
            limit.saturating_add(1),
        );
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

    fn lookup_object(&self, key: &pingora::cache::CacheKey) -> Option<PingoraStoredObject> {
        self.inner.get(&key.combined())
    }

    fn put_object(
        &self,
        store_key: PingoraStoreKey,
        meta: CacheMeta,
        body: Arc<[u8]>,
    ) -> pingora::Result<usize> {
        let (internal_meta, response_header) = meta.serialize()?;
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
                primary_key: Some(store_key.primary.clone()),
                internal_meta,
                response_header,
                body,
                weight,
            },
        );
        self.purge_index.insert_with_path(
            combined_key,
            store_key.primary,
            store_key.user_tag,
            store_key.index_path,
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
        let root = prepare_disk_cache_root(&root)?;
        Ok(Self {
            root,
            purge_index: CachePurgeIndex::new(CACHE_PURGE_INDEX_MAX_ENTRIES),
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
            purge_index_entries: self.purge_index.len() as u64,
            activity: self.activity.snapshot(),
        })
    }

    pub fn reset_activity(&self) {
        self.activity.reset();
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

        for entry in disk_cache_entries(&self.root)? {
            if entry.path == exact_path {
                continue;
            }

            let Some(read_path) = self.safe_existing_object_path(&entry.path)? else {
                continue;
            };
            let object = match read_disk_cache_object(&self.root, &read_path, self.max_object_bytes)
                .and_then(|bytes| parse_disk_cache_object(&bytes, self.max_object_bytes))
            {
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
        let mut entries = self
            .purge_index
            .entries_for_user_tag(user_tag, limit.saturating_add(1));
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

    pub fn purge_indexed_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let mut entries = self.purge_index.entries_for_user_tag_path_prefix(
            user_tag,
            path_prefix,
            limit.saturating_add(1),
        );
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

    pub fn purge_indexed_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
    ) -> std::io::Result<CacheIndexedPurgeResult> {
        let mut entries = self.purge_index.entries_for_user_tag_path_pattern(
            user_tag,
            path_pattern,
            limit.saturating_add(1),
        );
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

    fn purge_object_path(&self, path: PathBuf) -> std::io::Result<bool> {
        match remove_disk_cache_object(&self.root, &path) {
            Ok(true) => {
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
        let path = self.path_for_key(key);
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
        match parse_disk_cache_object(&bytes, self.max_object_bytes) {
            Ok(object) => Ok(Some(object)),
            Err(error) => {
                let _ = remove_disk_cache_object(&self.root, &path);
                Err(cache_io_error("parse disk cache object", error))
            }
        }
    }

    fn put_object(
        &self,
        store_key: PingoraStoreKey,
        meta: CacheMeta,
        body: Arc<[u8]>,
    ) -> pingora::Result<Option<usize>> {
        let (internal_meta, response_header) = meta.serialize()?;
        self.put_serialized_object(store_key, internal_meta, response_header, body)
    }

    fn put_serialized_object(
        &self,
        store_key: PingoraStoreKey,
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

        let path = self.path_for_combined_key(&store_key.combined);
        let combined_key = store_key.combined.clone();
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
        self.ensure_safe_cache_parent(parent)
            .map_err(|error| cache_io_error("create disk cache shard", error))?;
        require_disk_cache_write_destination(&path)
            .map_err(|error| cache_io_error("validate disk cache object destination", error))?;
        self.write_object_atomically(
            &path,
            &store_key.primary,
            &internal_meta,
            &response_header,
            &body,
        )
        .map_err(|error| {
            self.activity.store_refusal();
            cache_io_error("write disk cache object", error)
        })?;
        self.purge_index.insert_with_path(
            combined_key,
            store_key.primary,
            store_key.user_tag,
            store_key.index_path,
        );
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
            match remove_disk_cache_object(&self.root, &entry.path) {
                Ok(true) => {
                    bytes_to_free = bytes_to_free.saturating_sub(entry.size);
                    if bytes_to_free == 0 {
                        return Ok(true);
                    }
                }
                Ok(false) => {}
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

    fn write_object_atomically(
        &self,
        path: &Path,
        primary_key: &str,
        internal_meta: &[u8],
        response_header: &[u8],
        body: &[u8],
    ) -> std::io::Result<()> {
        let mut last_error = None;
        for _ in 0..4 {
            let tmp_path = self.tmp_path_for(path)?;
            let write_result = write_disk_cache_object(
                &tmp_path,
                primary_key,
                internal_meta,
                response_header,
                body,
            )
            .and_then(|()| std::fs::rename(&tmp_path, path));
            match write_result {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = std::fs::remove_file(&tmp_path);
                    last_error = Some(error);
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&tmp_path);
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
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|error| {
            std::io::Error::other(format!("generate cache temp nonce: {error}"))
        })?;
        let mut encoded = String::with_capacity(nonce.len() * 2);
        for byte in nonce {
            let _ = write!(&mut encoded, "{byte:02x}");
        }
        Ok(path.with_extension(format!("tmp.{}.{}", std::process::id(), encoded)))
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

        let metadata = canonical.metadata()?;
        if !metadata.is_file() {
            return Ok(None);
        }

        Ok(Some(canonical))
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

    match std::fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "disk cache root must be a real directory: {}",
                    root.display()
                ),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(root)?;
            let metadata = std::fs::symlink_metadata(root)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "disk cache root must be a real directory: {}",
                        root.display()
                    ),
                ));
            }
        }
        Err(error) => return Err(error),
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

    let mut current = root.to_path_buf();
    for component in relative.components() {
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
struct PingoraStoreKey {
    combined: String,
    primary: String,
    user_tag: String,
    index_path: Option<String>,
}

#[cfg(feature = "proxy")]
impl PingoraStoreKey {
    fn from_cache_key(key: &pingora::cache::CacheKey) -> Self {
        Self {
            combined: key.combined(),
            primary: key.primary(),
            user_tag: key.user_tag.clone(),
            index_path: key
                .primary_key_str()
                .and_then(|primary| cache_primary_component(primary, "path")),
        }
    }
}

#[cfg(feature = "proxy")]
#[derive(Debug, Clone)]
struct PingoraStoredObject {
    primary_key: Option<String>,
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
#[cfg(not(test))]
const MAX_DISK_CACHE_SCAN_ENTRIES: usize = 100_000;

#[cfg(feature = "proxy")]
#[cfg(test)]
const MAX_DISK_CACHE_SCAN_ENTRIES: usize = 8;

#[cfg(feature = "proxy")]
fn disk_cache_entries(root: &Path) -> std::io::Result<Vec<DiskCacheEntry>> {
    let mut entries = Vec::new();
    for shard in std::fs::read_dir(root)? {
        let shard = shard?;
        let Some(shard_path) = safe_cache_shard_entry_path(root, &shard)? else {
            continue;
        };
        for entry in std::fs::read_dir(&shard_path)? {
            let entry = entry?;
            let Some((path, metadata)) = safe_cache_object_entry(root, &shard_path, &entry)? else {
                continue;
            };
            if entries.len() >= MAX_DISK_CACHE_SCAN_ENTRIES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "disk cache scan exceeded {MAX_DISK_CACHE_SCAN_ENTRIES} objects below {}",
                        root.display()
                    ),
                ));
            }
            entries.push(DiskCacheEntry {
                path,
                size: metadata.len(),
                modified: metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
            });
        }
    }
    Ok(entries)
}

#[cfg(feature = "proxy")]
fn safe_cache_shard_entry_path(
    root: &Path,
    entry: &std::fs::DirEntry,
) -> std::io::Result<Option<PathBuf>> {
    let file_type = entry.file_type()?;
    if file_type.is_symlink() || !file_type.is_dir() {
        return Ok(None);
    }

    let file_name = entry.file_name();
    let Some(name) = file_name.to_str() else {
        return Ok(None);
    };
    if name.len() != 2 || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(None);
    }

    let path = root.join(name);
    if cache_path_contains_symlink(root, &path)? {
        return Ok(None);
    }

    let canonical = path.canonicalize()?;
    if canonical.starts_with(root) && canonical.is_dir() {
        Ok(Some(canonical))
    } else {
        Ok(None)
    }
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

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(false);
    }

    match std::fs::remove_file(path) {
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
            store_key: PingoraStoreKey::from_cache_key(key),
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
        object.weight = weight;
        self.purge_index.insert_with_path(
            combined_key.clone(),
            object.primary_key.clone().unwrap_or_else(|| key.primary()),
            key.user_tag.clone(),
            key.primary_key_str()
                .and_then(|primary| cache_primary_component(primary, "path")),
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
        Ok(Box::new(PingoraDiskMissHandler {
            storage: self,
            store_key: PingoraStoreKey::from_cache_key(key),
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
                PingoraStoreKey::from_cache_key(key),
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
        let primary_key = object.primary_key.clone().unwrap_or_else(|| key.primary());
        let _promoted = self.memory.put_serialized_object(
            PingoraStoreKey {
                combined: key.combined(),
                primary: primary_key,
                user_tag: key.user_tag.clone(),
                index_path: key
                    .primary_key_str()
                    .and_then(|primary| cache_primary_component(primary, "path")),
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
            store_key: PingoraStoreKey::from_cache_key(key),
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
                .put_object(self.store_key, meta, Arc::<[u8]>::from(self.body))?
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
    primary_key: &str,
    internal_meta: &[u8],
    response_header: &[u8],
    body: &[u8],
) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW);

    let mut file = options.open(path)?;
    file.write_all(DISK_CACHE_MAGIC_V2)?;
    writeln!(file, "{}", primary_key.len())?;
    writeln!(file, "{}", internal_meta.len())?;
    writeln!(file, "{}", response_header.len())?;
    writeln!(file, "{}", body.len())?;
    file.write_all(primary_key.as_bytes())?;
    file.write_all(internal_meta)?;
    file.write_all(response_header)?;
    file.write_all(body)?;
    file.sync_all()?;
    Ok(())
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

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW);

    let file = options.open(&canonical)?;
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
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "disk cache object destination is unsafe: {}",
                    path.display()
                ),
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "proxy")]
fn parse_disk_cache_object(
    bytes: &[u8],
    max_object_bytes: ByteSize,
) -> std::io::Result<PingoraStoredObject> {
    let (mut offset, has_primary_key) =
        if bytes.get(..DISK_CACHE_MAGIC_V2.len()) == Some(DISK_CACHE_MAGIC_V2) {
            (DISK_CACHE_MAGIC_V2.len(), true)
        } else if bytes.get(..DISK_CACHE_MAGIC_V1.len()) == Some(DISK_CACHE_MAGIC_V1) {
            (DISK_CACHE_MAGIC_V1.len(), false)
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid cache object magic",
            ));
        };

    let primary_key_len = if has_primary_key {
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
        .checked_add(primary_key_len)
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
    let primary_key_end = offset + primary_key_len;
    let internal_meta_end = primary_key_end + internal_meta_len;
    let response_header_end = internal_meta_end + response_header_len;
    let primary_key = if has_primary_key {
        Some(
            std::str::from_utf8(&bytes[offset..primary_key_end])
                .map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{error}"))
                })?
                .to_owned(),
        )
    } else {
        None
    };
    Ok(PingoraStoredObject {
        primary_key,
        internal_meta: bytes[primary_key_end..internal_meta_end].to_vec(),
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
    use crate::config::{ByteSize, CacheConfig, CacheDiskConfig, CacheKeyPart, CacheMemoryConfig};
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
    fn cache_purge_index_bounds_and_matches_entries() {
        let index = super::CachePurgeIndex::new(2);

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

        assert_eq!(index.len(), 2);
        assert!(
            index
                .combined_keys_for_primary("fluxheim-image-v1;path:9:/old/a.js;")
                .is_empty()
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
            vec!["combined:b".to_owned()]
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
        assert_eq!(index.len(), 1);
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
    fn pingora_memory_storage_purges_variants_by_primary_key() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(2048),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 4,
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
    fn pingora_memory_storage_purges_indexed_path_prefix() {
        use pingora::cache::Storage;

        let storage = super::pingora_memory_storage_from_plan(super::MemoryTierPlan {
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(512),
            object_slots: 8,
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
    fn pingora_disk_storage_purges_variants_by_primary_key() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("disk-vary-purge");
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
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

    #[cfg(all(feature = "proxy", unix))]
    #[test]
    fn pingora_disk_storage_refuses_symlinked_shard_writes() {
        use pingora::cache::Storage;

        let root = unique_test_cache_dir("symlink-shard");
        let outside = unique_test_cache_dir("symlink-shard-outside");
        std::fs::create_dir_all(&outside).unwrap();
        let storage = super::pingora_disk_storage_from_plan(super::DiskTierPlan {
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
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
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
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
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
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
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
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
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
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
            path: root.clone(),
            max_size_bytes: ByteSize::from_bytes(4096),
            max_object_bytes: ByteSize::from_bytes(1024),
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
    fn disk_cache_entries_refuses_scan_over_entry_cap() {
        let root = unique_test_cache_dir("scan-entry-cap");
        let shard = root.join("ab");
        std::fs::create_dir_all(&shard).unwrap();
        for index in 0..=super::MAX_DISK_CACHE_SCAN_ENTRIES {
            std::fs::write(shard.join(format!("{index:064x}.fhc")), b"cached").unwrap();
        }

        let error = super::disk_cache_entries(&root).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn read_disk_cache_object_refuses_oversized_encoded_file() {
        let root = unique_test_cache_dir("read-oversized");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("oversized.fhc");
        std::fs::write(&path, vec![b'x'; 256]).unwrap();

        let error =
            super::read_disk_cache_object(&root, &path, ByteSize::from_bytes(8)).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
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

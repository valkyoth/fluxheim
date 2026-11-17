#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

use fluxheim_cache::{
    StorageBinFreeMap, StorageBinIndexEntry, StorageBinLayoutPlan, StorageBinObjectLocation,
    parse_disk_cache_object, read_storage_bin_index, write_storage_bin_index,
};
use sanitization::SecretBytes;

use super::native_http1_cache_disk_path::NativeSafeDiskCachePath;
use super::native_http1_cache_encryption::native_cache_confidential_index_identity;
use super::native_http1_cache_meta::{NativeDiskCacheMeta, native_memory_entry_from_disk_object};
use super::{
    NativeDiskCache, NativeDiskCacheBackend, NativeDiskCacheLocation, NativeDiskCacheRecord,
    NativeDiskCacheState, NativeMemoryCacheVariant,
};

const NATIVE_STORAGE_BIN_INDEX_DEBOUNCE: Duration = Duration::from_secs(1);
const SOFT_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(5);
static SOFT_CHECKPOINT: Mutex<Option<Instant>> = Mutex::new(None);
static NATIVE_STORAGE_BIN_INDEX_SERVICE: OnceLock<
    Result<Arc<NativeStorageBinIndexService>, String>,
> = OnceLock::new();
#[cfg(test)]
static NATIVE_STORAGE_BIN_INDEX_WORKERS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
struct NativeStorageBinIndexService {
    tasks: Arc<Mutex<Vec<Weak<NativeStorageBinIndexTask>>>>,
}

#[derive(Debug)]
pub(super) struct NativeStorageBinIndexFlush {
    task: Arc<NativeStorageBinIndexTask>,
}

#[derive(Debug)]
struct NativeStorageBinIndexTask {
    #[cfg(test)]
    soft_checkpoints: AtomicUsize,
    layout: StorageBinLayoutPlan,
    state: Arc<Mutex<NativeDiskCacheState>>,
    dirty: AtomicBool,
    // The final synchronous flush closes the task while holding this lock.
    flush_lock: Mutex<bool>,
    index_key: Option<Arc<SecretBytes<32>>>,
}

impl NativeStorageBinIndexFlush {
    pub(super) fn start(
        backend: &NativeDiskCacheBackend,
        state: &Arc<Mutex<NativeDiskCacheState>>,
        index_key: Option<Arc<SecretBytes<32>>>,
    ) -> std::io::Result<Option<Self>> {
        let NativeDiskCacheBackend::StorageBin(storage_bin) = backend else {
            return Ok(None);
        };
        let service = native_storage_bin_index_service()?;
        let task = Arc::new(NativeStorageBinIndexTask {
            #[cfg(test)]
            soft_checkpoints: AtomicUsize::new(0),
            layout: storage_bin.layout.clone(),
            state: Arc::clone(state),
            dirty: AtomicBool::new(false),
            flush_lock: Mutex::new(false),
            index_key,
        });
        let entries = task
            .state
            .lock()
            .map_err(|_| std::io::Error::other("cache index state is unavailable"))
            .and_then(|state| {
                native_storage_bin_index_entries(&state, task.index_key.as_deref())
            })?;
        write_storage_bin_index(&task.layout, &entries)?;
        service.register(&task);
        Ok(Some(Self { task }))
    }

    pub(super) fn mark_dirty(&self) {
        self.task.dirty.store(true, Ordering::Release);
    }
}

impl Drop for NativeStorageBinIndexFlush {
    fn drop(&mut self) {
        self.task.flush(true);
    }
}

impl NativeStorageBinIndexService {
    fn start() -> Result<Arc<Self>, String> {
        let tasks = Arc::new(Mutex::new(Vec::<Weak<NativeStorageBinIndexTask>>::new()));
        let worker_tasks = Arc::clone(&tasks);
        let worker = thread::Builder::new()
            .name("fluxheim-cache-index".to_owned())
            .spawn(move || native_storage_bin_index_flush_worker(&worker_tasks))
            .map_err(|error| format!("start process-wide cache index worker: {error}"))?;
        drop(worker);
        #[cfg(test)]
        NATIVE_STORAGE_BIN_INDEX_WORKERS.fetch_add(1, Ordering::AcqRel);
        Ok(Arc::new(Self { tasks }))
    }

    fn register(&self, task: &Arc<NativeStorageBinIndexTask>) {
        let mut tasks = self.tasks.lock().unwrap_or_else(|error| {
            log::error!(
                target: "fluxheim::security",
                "native storage-bin index registry lock poisoned: {error}; aborting"
            );
            fluxheim_common::fatal::abort(
                fluxheim_common::fatal::Reason::StorageBinRegistryPoisoned,
            );
        });
        tasks.retain(|task| task.strong_count() > 0);
        tasks.push(Arc::downgrade(task));
    }
}

#[cfg(test)]
pub(super) fn native_storage_bin_index_worker_count() -> usize {
    NATIVE_STORAGE_BIN_INDEX_WORKERS.load(Ordering::Acquire)
}

impl NativeStorageBinIndexTask {
    fn flush(&self, force: bool) {
        let mut closed = self.flush_lock.lock().unwrap_or_else(|error| {
            log::error!(
                target: "fluxheim::security",
                "native storage-bin index flush lock poisoned: {error}; aborting"
            );
            fluxheim_common::fatal::abort(fluxheim_common::fatal::Reason::StorageBinFlushPoisoned);
        });
        if *closed {
            return;
        }
        if force {
            *closed = true;
        }
        let was_dirty = self.dirty.swap(false, Ordering::AcqRel);
        if !force && !was_dirty {
            return;
        }
        let entries = match self.state.lock() {
            Ok(state) => native_storage_bin_index_entries(&state, self.index_key.as_deref()),
            Err(error) => {
                log::error!(
                    target: "fluxheim::security",
                    "native storage-bin index state lock poisoned: {error}; aborting"
                );
                fluxheim_common::fatal::abort(
                    fluxheim_common::fatal::Reason::StorageBinStatePoisoned,
                );
            }
        };
        if let Err(error) =
            entries.and_then(|entries| write_storage_bin_index(&self.layout, &entries))
        {
            // An oversized snapshot cannot succeed until the index changes.
            if error.kind() != std::io::ErrorKind::InvalidData {
                self.dirty.store(true, Ordering::Release);
            }
            log::warn!(
                target: "fluxheim::native_http1",
                "native storage-bin index write {}: {error}",
                self.layout.root.display()
            );
        }
    }
}

fn native_storage_bin_index_service() -> std::io::Result<Arc<NativeStorageBinIndexService>> {
    match NATIVE_STORAGE_BIN_INDEX_SERVICE.get_or_init(NativeStorageBinIndexService::start) {
        Ok(service) => Ok(Arc::clone(service)),
        Err(error) => Err(std::io::Error::other(error.clone())),
    }
}

pub(crate) fn ensure_native_storage_bin_index_service() -> std::io::Result<()> {
    native_storage_bin_index_service().map(drop)
}

fn native_storage_bin_index_flush_worker(
    registry: &Arc<Mutex<Vec<Weak<NativeStorageBinIndexTask>>>>,
) {
    loop {
        thread::sleep(NATIVE_STORAGE_BIN_INDEX_DEBOUNCE);
        let tasks = {
            let mut registry = registry.lock().unwrap_or_else(|error| {
                log::error!(
                    target: "fluxheim::security",
                    "native storage-bin index registry lock poisoned: {error}; aborting"
                );
                fluxheim_common::fatal::abort(
                    fluxheim_common::fatal::Reason::StorageBinRegistryPoisoned,
                );
            });
            let tasks = registry
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>();
            registry.retain(|task| task.strong_count() > 0);
            tasks
        };
        for task in tasks {
            task.flush(false);
        }
    }
}

fn native_storage_bin_index_entries(
    state: &NativeDiskCacheState,
    index_key: Option<&SecretBytes<32>>,
) -> std::io::Result<Vec<StorageBinIndexEntry>> {
    native_storage_bin_index_entries_with(state, index_key, |_, location| location)
}

fn native_storage_bin_index_entries_with(
    state: &NativeDiskCacheState,
    index_key: Option<&SecretBytes<32>>,
    replace: impl Fn(&str, StorageBinObjectLocation) -> StorageBinObjectLocation,
) -> std::io::Result<Vec<StorageBinIndexEntry>> {
    let mut budget = fluxheim_cache::StorageBinIndexBudget::default();
    let mut entries = Vec::new();
    for (combined_key, record) in &state.objects {
        let NativeDiskCacheLocation::StorageBin(location) = &record.location else {
            continue;
        };
        let location = replace(combined_key, *location);
        let key_bytes = if index_key.is_some() {
            64
        } else {
            combined_key.len()
        };
        budget.charge(key_bytes, location, record.accessed_at)?;
        entries.push(StorageBinIndexEntry {
            combined_key: if let Some(index_key) = index_key {
                native_cache_confidential_index_identity(index_key, combined_key)
            } else {
                combined_key.clone()
            },
            location,
            accessed: record.accessed_at,
        });
    }
    Ok(entries)
}

impl NativeDiskCache {
    pub(super) fn scan_soft_bin(
        &self,
        index: &fluxheim_cache::CachePurgeIndex,
        selector: fluxheim_cache::purge_index::CachePurgeSelector<'_>,
        limit: usize,
    ) -> fluxheim_cache::purge_index::CachePurgeScanResult {
        use fluxheim_cache::purge_index::{
            CachePurgeMode, CachePurgeScanResult, MAX_SOFT_PURGE_BATCH,
        };
        let deferred = || CachePurgeScanResult {
            truncated: true,
            ..Default::default()
        };
        let Ok(mut last) = SOFT_CHECKPOINT.try_lock() else {
            return deferred();
        };
        let now = Instant::now();
        if last.is_some_and(|t| now.saturating_duration_since(t) < SOFT_CHECKPOINT_INTERVAL) {
            return deferred();
        }
        // Denial precedes cursor advancement, body reads and scratch allocation.
        // Retain the process-wide slot through publication or rollback.
        index.scan_batch(
            selector,
            CachePurgeMode::Soft,
            limit.min(MAX_SOFT_PURGE_BATCH),
            |entries| self.soft_purge_bin_group(index, entries.collect(), now, &mut last),
        )
    }

    fn soft_purge_bin_group(
        &self,
        index: &fluxheim_cache::CachePurgeIndex,
        mut entries: Vec<(u64, &fluxheim_cache::CachePurgeIndexEntry)>,
        now: Instant,
        last: &mut Option<Instant>,
    ) -> fluxheim_cache::purge_index::CachePurgeScanResult {
        use super::native_http1_cache_state::native_disk_cache_mutation_lock_stripe as stripe;
        use fluxheim_cache::purge_index::CachePurgeScanResult;
        let mut result = CachePurgeScanResult::default();
        entries.sort_unstable_by_key(|(_, e)| stripe(&e.combined_key));
        let mut guards = Vec::new();
        let mut staged = std::collections::HashMap::new();
        for group in
            entries.chunk_by(|(_, a), (_, b)| stripe(&a.combined_key) == stripe(&b.combined_key))
        {
            let Some((_, first)) = group.first() else {
                continue;
            };
            let Ok(guard) = self.try_lock_key_mutation(&first.combined_key) else {
                result.truncated = true;
                continue;
            };
            guards.push(guard);
            for &(sequence, entry) in group {
                let key = &entry.combined_key;
                if !index.is_current_generation(key, sequence) {
                    continue;
                }
                let Some(record) = self.with_state(|s| s.objects.get(key).cloned()) else {
                    result.truncated = true;
                    continue;
                };
                let NativeDiskCacheLocation::StorageBin(old) = record.location else {
                    result.truncated = true;
                    continue;
                };
                // Encode/write only one body at a time. Retain locations, not buffers.
                match self.encode_soft_purge(entry, &record, now) {
                    Ok(Some(bytes)) => {
                        *last = Some(Instant::now());
                        match self.write_encoded_object(key, &bytes) {
                            Ok(Some(NativeDiskCacheLocation::StorageBin(new))) => {
                                staged.insert(key.as_str(), (old, new));
                            }
                            _ => result.truncated = true,
                        }
                    }
                    Ok(None) => {}
                    Err(_) => result.truncated = true,
                }
            }
        }
        if !staged.is_empty() {
            if self.checkpoint_soft_group(&staged).is_ok() {
                result.purged = staged.len();
                for (old, _) in staged.values() {
                    result.truncated |= self.release_storage_bin_location(*old).is_err();
                }
            } else {
                result.truncated = true;
                self.persist_storage_bin_index();
                for (_, new) in staged.values() {
                    let _ = self.release_storage_bin_location(*new);
                }
            }
        }
        drop(guards);
        result
    }

    fn checkpoint_soft_group(
        &self,
        staged: &std::collections::HashMap<
            &str,
            (StorageBinObjectLocation, StorageBinObjectLocation),
        >,
    ) -> std::io::Result<()> {
        let task = &self
            .index_flush
            .as_ref()
            .ok_or_else(|| std::io::Error::other("missing bin index"))?
            .task;
        let _flush = task
            .flush_lock
            .try_lock()
            .map_err(|_| std::io::Error::other("bin index busy"))?;
        let entries = self.with_state(|state| {
            native_storage_bin_index_entries_with(state, task.index_key.as_deref(), |key, old| {
                staged.get(key).map_or(old, |(_, new)| *new)
            })
        })?;
        #[cfg(test)]
        task.soft_checkpoints.fetch_add(1, Ordering::Relaxed);
        write_storage_bin_index(&task.layout, &entries)?;
        self.with_state_mut(|state| {
            for (key, (_, new)) in staged {
                if let Some(record) = state.objects.get_mut(*key) {
                    record.location = NativeDiskCacheLocation::StorageBin(*new);
                    record.identity = Arc::new(());
                    state.bytes = state
                        .bytes
                        .saturating_sub(record.weight)
                        .saturating_add(new.len);
                    record.weight = new.len;
                }
            }
        });
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn soft_checkpoints(&self) -> usize {
        self.index_flush
            .as_ref()
            .map_or(0, |f| f.task.soft_checkpoints.load(Ordering::Relaxed))
    }

    pub(super) fn allocate_storage_bin_location(
        &self,
        len: u64,
    ) -> std::io::Result<Option<StorageBinObjectLocation>> {
        // The caller may own a key stripe. Allocation must never acquire a
        // second stripe through eviction (including a colliding stripe).
        match &self.backend {
            NativeDiskCacheBackend::StorageBin(storage_bin) => {
                let mut free_map = storage_bin.free_map.lock().map_err(|_| {
                    std::io::Error::other("native storage-bin free map mutex poisoned")
                })?;
                free_map.allocate(len)
            }
            NativeDiskCacheBackend::Filesystem => Ok(None),
        }
    }

    pub(super) fn rebuild_storage_bin_backend(
        &self,
        state: &mut NativeDiskCacheState,
    ) -> std::io::Result<()> {
        let NativeDiskCacheBackend::StorageBin(storage_bin) = &self.backend else {
            return Ok(());
        };
        let mut valid_entries = Vec::new();
        for entry in read_storage_bin_index(&storage_bin.layout)? {
            let bytes = match storage_bin.files.read_object(entry.location) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            if bytes.starts_with(super::NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1) {
                continue;
            }
            let bytes = match self.decrypt_if_needed(&bytes) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let parsed = match parse_disk_cache_object(&bytes, self.max_object_bytes) {
                Ok(parsed) => parsed,
                Err(_) => continue,
            };
            let Some(parsed_combined_key) = parsed.combined_key.as_deref() else {
                continue;
            };
            let expected_index_key = if self.encryption.is_some() {
                self.encryption
                    .as_ref()
                    .map(|encryption| encryption.confidential_index_identity(parsed_combined_key))
                    .unwrap_or_default()
            } else {
                parsed_combined_key.to_owned()
            };
            if expected_index_key != entry.combined_key {
                continue;
            }
            let Some(primary) = parsed.primary_key.clone() else {
                continue;
            };
            let Some(meta) = NativeDiskCacheMeta::decode(&parsed.internal_meta) else {
                continue;
            };
            if native_memory_entry_from_disk_object(&parsed).is_none() {
                continue;
            }
            let combined = parsed_combined_key.to_owned();
            state.bytes = state.bytes.saturating_add(entry.location.len);
            state.insert_object(
                combined.clone(),
                NativeDiskCacheRecord {
                    identity: Arc::new(()),
                    location: NativeDiskCacheLocation::StorageBin(entry.location),
                    weight: entry.location.len,
                    accessed_at: entry.accessed,
                },
            );
            if !meta.vary_fields.is_empty() {
                state
                    .variants
                    .entry(primary.clone())
                    .or_default()
                    .push(NativeMemoryCacheVariant {
                        fields: meta.vary_fields,
                        key: combined.clone(),
                    });
            }
            if let Some(user_tag) = parsed.user_tag {
                state.purge_index.insert_with_path_and_tags(
                    combined,
                    primary,
                    user_tag,
                    parsed.index_path,
                    parsed.cache_tags,
                );
            }
            valid_entries.push(entry);
        }
        let rebuilt = StorageBinFreeMap::from_occupied(&storage_bin.layout, &valid_entries)?;
        let mut free_map = storage_bin
            .free_map
            .lock()
            .map_err(|_| std::io::Error::other("native storage-bin free map mutex poisoned"))?;
        *free_map = rebuilt;
        Ok(())
    }

    pub(super) fn release_storage_bin_location(
        &self,
        location: StorageBinObjectLocation,
    ) -> std::io::Result<()> {
        let NativeDiskCacheBackend::StorageBin(storage_bin) = &self.backend else {
            return Ok(());
        };
        {
            let mut free_map = storage_bin
                .free_map
                .lock()
                .map_err(|_| std::io::Error::other("native storage-bin free map mutex poisoned"))?;
            free_map.release(location)?;
            for bin_id in free_map.reclaim_free_tail_bins() {
                if let Err(error) = storage_bin.files.remove_bin(bin_id) {
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native storage-bin tail reclaim failed for bin {bin_id}: {error}"
                    );
                }
            }
        }
        Ok(())
    }

    pub(super) fn persist_storage_bin_index(&self) {
        if let Some(index_flush) = &self.index_flush {
            index_flush.mark_dirty();
        }
    }

    pub(super) fn purge_legacy_encrypted_storage_bin(&self) -> std::io::Result<()> {
        let NativeDiskCacheBackend::StorageBin(storage_bin) = &self.backend else {
            return Ok(());
        };
        let data_dir = NativeSafeDiskCachePath::from_path(storage_bin.layout.data_dir.clone());
        for path in data_dir.child_paths()? {
            if !path.is_dir() && path.extension().and_then(|value| value.to_str()) == Some("fhbin")
            {
                NativeSafeDiskCachePath::from_path(path).remove_file()?;
            }
        }
        let index_path = fluxheim_cache::storage_bin_index_path(&storage_bin.layout.root);
        match NativeSafeDiskCachePath::from_path(index_path).remove_file() {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }
}

#[cfg(test)]
mod confidential_index_tests {
    use super::*;

    #[test]
    fn invalid_background_snapshot_preserves_index_until_next_change() {
        let root = tempfile::tempdir().unwrap();
        let mut config = fluxheim_config::CacheConfig::default();
        config.disk.enabled = true;
        config.disk.backend = fluxheim_config::CacheDiskBackend::StorageBin;
        config.disk.path = Some(root.path().to_path_buf());
        let cache = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
        let task = &cache.index_flush.as_ref().unwrap().task;
        let record = NativeDiskCacheRecord {
            identity: Arc::new(()),
            location: NativeDiskCacheLocation::StorageBin(StorageBinObjectLocation {
                bin_id: 0,
                offset: 0,
                len: 1,
            }),
            weight: 1,
            accessed_at: std::time::SystemTime::UNIX_EPOCH,
        };
        cache.with_state_mut(|s| s.insert_object("valid".into(), record.clone()));
        cache.persist_storage_bin_index();
        task.flush(false);
        let original = read_storage_bin_index(&task.layout).unwrap();
        assert_eq!(original.len(), 1);
        let oversized = "k".repeat(32 * 1024 + 1);
        cache.with_state_mut(|s| s.insert_object(oversized.clone(), record));
        cache.persist_storage_bin_index();
        task.flush(false);
        assert!(!task.dirty.load(Ordering::Acquire));
        assert_eq!(read_storage_bin_index(&task.layout).unwrap(), original);
        cache.with_state_mut(|s| {
            s.remove_object(&oversized);
            s.remove_object("valid");
        });
        cache.persist_storage_bin_index();
        task.flush(false);
        assert!(read_storage_bin_index(&task.layout).unwrap().is_empty());
    }

    #[test]
    fn final_index_flush_finishes_before_lease_release_and_closes_retained_tasks() {
        let root = tempfile::tempdir().unwrap();
        let mut config = fluxheim_config::CacheConfig::default();
        config.disk.enabled = true;
        config.disk.backend = fluxheim_config::CacheDiskBackend::StorageBin;
        config.disk.path = Some(root.path().to_path_buf());
        let cache = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
        let task = Arc::clone(&cache.index_flush.as_ref().unwrap().task);
        let guard = task.flush_lock.lock().unwrap();
        let (started, ready) = std::sync::mpsc::channel();
        let dropper = std::thread::spawn(move || {
            started.send(()).unwrap();
            drop(cache);
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            super::super::native_http1_cache_backend::acquire_native_storage_bin_lease(root.path())
                .is_err()
        );
        drop(guard);
        dropper.join().unwrap();
        // Parallel subprocess tests can briefly inherit a Unix lease across fork,
        // until exec closes CLOEXEC descriptors. A retained worker must not own it.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match super::super::native_http1_cache_backend::acquire_native_storage_bin_lease(
                root.path(),
            ) {
                Ok(lease) => {
                    drop(lease);
                    break;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::AlreadyExists
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(error) => {
                    panic!("lease was not released after closing the index task: {error}")
                }
            }
        }
        let index = root.path().join(".fluxheim-storage-bin-index-v1");
        std::fs::write(&index, b"new generation").unwrap();
        task.dirty.store(true, Ordering::Release);
        task.flush(false);
        task.flush(true);
        assert_eq!(std::fs::read(index).unwrap(), b"new generation");
    }

    #[test]
    fn encrypted_index_entries_do_not_persist_combined_keys() {
        let mut state = NativeDiskCacheState::default();
        let combined_key = "private.example/account?token=secret";
        state.insert_object(
            combined_key.to_owned(),
            NativeDiskCacheRecord {
                identity: Arc::new(()),
                location: NativeDiskCacheLocation::StorageBin(StorageBinObjectLocation {
                    bin_id: 0,
                    offset: 0,
                    len: 128,
                }),
                weight: 128,
                accessed_at: std::time::SystemTime::UNIX_EPOCH,
            },
        );

        let index_key = SecretBytes::from_array([9_u8; 32]);
        let entries = native_storage_bin_index_entries(&state, Some(&index_key)).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].combined_key.len(), 64);
        assert_ne!(entries[0].combined_key, combined_key);
    }
}

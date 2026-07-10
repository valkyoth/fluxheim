#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread;
use std::time::Duration;

use fluxheim_cache::{
    StorageBinFreeMap, StorageBinIndexEntry, StorageBinLayoutPlan, StorageBinObjectLocation,
    parse_disk_cache_object, read_storage_bin_index, write_storage_bin_index,
};

use super::native_http1_cache_meta::{NativeDiskCacheMeta, native_memory_entry_from_disk_object};
use super::{
    NativeDiskCache, NativeDiskCacheBackend, NativeDiskCacheLocation, NativeDiskCacheRecord,
    NativeDiskCacheState, NativeMemoryCacheVariant,
};

const NATIVE_STORAGE_BIN_INDEX_DEBOUNCE: Duration = Duration::from_secs(1);
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
    layout: StorageBinLayoutPlan,
    state: Arc<Mutex<NativeDiskCacheState>>,
    dirty: AtomicBool,
    flush_lock: Mutex<()>,
}

impl NativeStorageBinIndexFlush {
    pub(super) fn start(
        backend: &NativeDiskCacheBackend,
        state: &Arc<Mutex<NativeDiskCacheState>>,
    ) -> std::io::Result<Option<Self>> {
        let NativeDiskCacheBackend::StorageBin(storage_bin) = backend else {
            return Ok(None);
        };
        let service = native_storage_bin_index_service()?;
        let task = Arc::new(NativeStorageBinIndexTask {
            layout: storage_bin.layout.clone(),
            state: Arc::clone(state),
            dirty: AtomicBool::new(false),
            flush_lock: Mutex::new(()),
        });
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
            std::process::abort();
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
        let _flush = self.flush_lock.lock().unwrap_or_else(|error| {
            log::error!(
                target: "fluxheim::security",
                "native storage-bin index flush lock poisoned: {error}; aborting"
            );
            std::process::abort();
        });
        let was_dirty = self.dirty.swap(false, Ordering::AcqRel);
        if !force && !was_dirty {
            return;
        }
        let entries = match self.state.lock() {
            Ok(state) => native_storage_bin_index_entries(&state),
            Err(error) => {
                log::error!(
                    target: "fluxheim::security",
                    "native storage-bin index state lock poisoned: {error}; aborting"
                );
                std::process::abort();
            }
        };
        if let Err(error) = write_storage_bin_index(&self.layout, &entries) {
            self.dirty.store(true, Ordering::Release);
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
                std::process::abort();
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

fn native_storage_bin_index_entries(state: &NativeDiskCacheState) -> Vec<StorageBinIndexEntry> {
    state
        .objects
        .iter()
        .filter_map(|(combined_key, record)| {
            let NativeDiskCacheLocation::StorageBin(location) = &record.location else {
                return None;
            };
            Some(StorageBinIndexEntry {
                combined_key: combined_key.clone(),
                location: *location,
                accessed: record.accessed_at,
            })
        })
        .collect()
}

impl NativeDiskCache {
    pub(super) fn allocate_storage_bin_location(
        &self,
        len: u64,
    ) -> std::io::Result<Option<StorageBinObjectLocation>> {
        loop {
            let allocation = match &self.backend {
                NativeDiskCacheBackend::StorageBin(storage_bin) => {
                    let mut free_map = storage_bin.free_map.lock().map_err(|_| {
                        std::io::Error::other("native storage-bin free map mutex poisoned")
                    })?;
                    free_map.allocate(len)?
                }
                NativeDiskCacheBackend::Filesystem => return Ok(None),
            };
            if allocation.is_some() {
                return Ok(allocation);
            }
            if !self.evict_oldest()? {
                return Ok(None);
            }
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
            let bytes = match self.decrypt_if_needed(&bytes) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let parsed = match parse_disk_cache_object(&bytes, self.max_object_bytes) {
                Ok(parsed) => parsed,
                Err(_) => continue,
            };
            if parsed.combined_key.as_deref() != Some(entry.combined_key.as_str()) {
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
            let combined = entry.combined_key.clone();
            state.bytes = state.bytes.saturating_add(entry.location.len);
            state.insert_object(
                combined.clone(),
                NativeDiskCacheRecord {
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
}

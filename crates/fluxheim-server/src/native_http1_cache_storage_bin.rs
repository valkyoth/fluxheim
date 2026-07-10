use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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

#[derive(Debug)]
enum NativeStorageBinIndexFlushCommand {
    Dirty,
    Shutdown,
}

#[derive(Debug)]
pub(super) struct NativeStorageBinIndexFlush {
    sender: SyncSender<NativeStorageBinIndexFlushCommand>,
    worker: Option<thread::JoinHandle<()>>,
}

impl NativeStorageBinIndexFlush {
    pub(super) fn start(
        backend: &NativeDiskCacheBackend,
        state: &Arc<Mutex<NativeDiskCacheState>>,
    ) -> Option<Self> {
        let NativeDiskCacheBackend::StorageBin(storage_bin) = backend else {
            return None;
        };
        let layout = storage_bin.layout.clone();
        let state = Arc::clone(state);
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            native_storage_bin_index_flush_worker(receiver, layout, state);
        });
        Some(Self {
            sender,
            worker: Some(worker),
        })
    }

    pub(super) fn mark_dirty(&self) {
        match self
            .sender
            .try_send(NativeStorageBinIndexFlushCommand::Dirty)
        {
            Ok(()) | Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Disconnected(_)) => log::warn!(
                target: "fluxheim::native_http1",
                "native storage-bin index flush worker is unavailable"
            ),
        }
    }
}

impl Drop for NativeStorageBinIndexFlush {
    fn drop(&mut self) {
        let _ = self
            .sender
            .send(NativeStorageBinIndexFlushCommand::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn native_storage_bin_index_flush_worker(
    receiver: Receiver<NativeStorageBinIndexFlushCommand>,
    layout: StorageBinLayoutPlan,
    state: Arc<Mutex<NativeDiskCacheState>>,
) {
    while let Ok(command) = receiver.recv() {
        if matches!(command, NativeStorageBinIndexFlushCommand::Shutdown) {
            return;
        }
        let flush_at = Instant::now() + NATIVE_STORAGE_BIN_INDEX_DEBOUNCE;
        let mut shutdown = false;
        loop {
            let remaining = flush_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match receiver.recv_timeout(remaining) {
                Ok(NativeStorageBinIndexFlushCommand::Dirty) => {}
                Ok(NativeStorageBinIndexFlushCommand::Shutdown) => {
                    shutdown = true;
                    break;
                }
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
            }
        }
        let entries = match state.lock() {
            Ok(state) => native_storage_bin_index_entries(&state),
            Err(error) => {
                log::error!(
                    target: "fluxheim::security",
                    "native storage-bin index state lock poisoned: {error}; aborting"
                );
                std::process::abort();
            }
        };
        if let Err(error) = write_storage_bin_index(&layout, &entries) {
            log::warn!(
                target: "fluxheim::native_http1",
                "native storage-bin index write {}: {error}",
                layout.root.display()
            );
        }
        if shutdown {
            return;
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

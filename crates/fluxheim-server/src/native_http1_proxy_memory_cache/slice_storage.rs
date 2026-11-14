use std::sync::Arc;

use fluxheim_cache::CacheSliceBounds;

use super::NativeProxyMemoryCache;
use crate::native_http1_cache::{
    NativeDiskCacheStoreKey, NativeMemoryCacheEntry, lock_native_memory_cache,
    prune_native_memory_cache, remove_native_memory_cache_entry,
};
use crate::native_http1_proxy_cache_slice::{
    NativeCacheSliceObject, native_slice_object_from_entry,
};

impl NativeProxyMemoryCache {
    pub(super) async fn lookup_cached_slice(
        &self,
        key: &str,
        bounds: CacheSliceBounds,
    ) -> Result<Option<NativeCacheSliceObject>, &'static str> {
        if self.memory_enabled() {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            if let Some(entry) = state.objects.get(key) {
                if let Some(slice) = fresh_slice(entry.clone(), bounds) {
                    return Ok(Some(slice));
                }
                if let Some(entry) = remove_native_memory_cache_entry(&mut state, key) {
                    state.bytes = state.bytes.saturating_sub(entry.weight);
                }
            }
        }
        let Some(disk) = self.disk.as_ref().cloned() else {
            return Ok(None);
        };
        let key = key.to_owned();
        let slice = super::disk::bounded_disk_lookup(move || {
            // The key already includes both the configured variance and slice
            // range. Do not perform complete-object variant lookup/promotion.
            let Some(entry) = disk.lookup_combined(&key)? else {
                return Ok(None);
            };
            let slice = fresh_slice(entry, bounds);
            if slice.is_none() {
                disk.remove_combined(&key);
            }
            Ok(slice)
        })
        .await
        .map_err(|error| error.reason())?;
        if slice.is_some() {
            self.record_activity("disk", "hit");
            self.record_activity_scope("disk", "hit");
        }
        Ok(slice)
    }

    pub(super) async fn store_slice_entry(
        &self,
        primary: &str,
        key: &str,
        path: &str,
        cache_tags: Vec<String>,
        entry: NativeMemoryCacheEntry,
    ) {
        let disk_key = NativeDiskCacheStoreKey {
            combined: key.to_owned(),
            primary: primary.to_owned(),
            user_tag: self.user_tag(),
            index_path: Some(path.to_owned()),
            cache_tags,
            // Predeclared variance is already encoded in the exact slice key.
            vary_fields: Vec::new(),
        };
        if self.memory_enabled() && entry.weight <= self.max_bytes {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            if let Some(previous) = remove_native_memory_cache_entry(&mut state, key) {
                state.bytes = state.bytes.saturating_sub(previous.weight);
            }
            state.purge_index.insert_with_path_and_tags(
                disk_key.combined.clone(),
                disk_key.primary.clone(),
                disk_key.user_tag.clone(),
                disk_key.index_path.clone(),
                disk_key.cache_tags.clone(),
            );
            state.bytes = state.bytes.saturating_add(entry.weight);
            state.objects.insert(key.to_owned(), entry.clone());
            prune_native_memory_cache(&mut state, self.max_bytes);
        }
        if let Some(disk) = &self.disk {
            let disk = Arc::clone(disk);
            let Ok(permit) = crate::blocking_work::try_acquire_request_blocking_work(
                crate::blocking_work::NativeBlockingWorkClass::DiskCache,
            ) else {
                return;
            };
            // Admission is best-effort, as for complete objects. A failed or
            // cancelled store can never publish a partial slice.
            match tokio::task::spawn_blocking(move || {
                let _permit = permit;
                disk.store(disk_key, &entry)
            })
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    log::debug!(target: "fluxheim::native_http1", "slice disk store: {error}")
                }
                Err(error) => {
                    log::debug!(target: "fluxheim::native_http1", "slice disk worker: {error}")
                }
            }
        }
    }
}

fn fresh_slice(
    entry: NativeMemoryCacheEntry,
    expected: CacheSliceBounds,
) -> Option<NativeCacheSliceObject> {
    if entry.status != 206 || entry.expires_at <= std::time::Instant::now() {
        return None;
    }
    let slice = native_slice_object_from_entry(entry)?;
    (slice.total > 0
        && slice.bounds.start == expected.start
        && slice.bounds.end == expected.end.min(slice.total - 1))
    .then_some(slice)
}

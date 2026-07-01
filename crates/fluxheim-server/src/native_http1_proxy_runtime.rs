use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;

use fluxheim_cache::purge_index::{
    CacheIndexedPurgeResult, CachePurgeIndexEntry, CacheStalePurgeResult,
};

use crate::native_http1_cache::{
    NativeDiskCache, NativeDiskCacheStats, NativeMemoryCacheState, lock_native_memory_cache,
    remove_native_memory_cache_entry, remove_native_memory_cache_variants,
};

static NATIVE_MEMORY_CACHE_PURGE_REGISTRY: OnceLock<Mutex<Vec<NativeMemoryCachePurgeHandle>>> =
    OnceLock::new();
static NATIVE_CACHE_STATS_REGISTRY: OnceLock<Mutex<Vec<NativeCacheStatsHandle>>> = OnceLock::new();

#[derive(Clone, Debug)]
struct NativeMemoryCachePurgeHandle {
    vhost: Arc<str>,
    route: Option<Arc<str>>,
    state: Weak<Mutex<NativeMemoryCacheState>>,
}

#[derive(Clone, Debug)]
struct NativeCacheStatsHandle {
    memory_enabled: bool,
    memory_max_bytes: u64,
    memory_state: Weak<Mutex<NativeMemoryCacheState>>,
    disk: Option<Weak<NativeDiskCache>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeCacheRuntimeTotals {
    pub memory_tiers: u64,
    pub memory_entries: u64,
    pub memory_weighted_size_bytes: u64,
    pub memory_max_size_bytes: u64,
    pub memory_purge_index_entries: u64,
    pub disk_tiers: u64,
    pub disk_entries: u64,
    pub disk_size_bytes: u64,
    pub disk_allocated_size_bytes: u64,
    pub disk_free_size_bytes: u64,
    pub disk_free_range_count: u64,
    pub disk_largest_free_range_bytes: u64,
    pub disk_bin_files: u64,
    pub disk_max_size_bytes: u64,
    pub disk_purge_index_entries: u64,
}

pub fn native_cache_runtime_totals() -> NativeCacheRuntimeTotals {
    let Some(registry) = NATIVE_CACHE_STATS_REGISTRY.get() else {
        return NativeCacheRuntimeTotals::default();
    };
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(error) => {
            log::error!(
                target: "fluxheim::security",
                "native cache stats registry mutex poisoned: {error}"
            );
            std::process::abort();
        }
    };
    let mut totals = NativeCacheRuntimeTotals::default();
    registry.retain(|handle| {
        let memory_state = handle.memory_state.upgrade();
        let disk = handle.disk.as_ref().and_then(Weak::upgrade);
        if memory_state.is_none() && disk.is_none() {
            return false;
        }
        if handle.memory_enabled
            && let Some(memory_state) = memory_state
        {
            let state = lock_native_memory_cache(&memory_state, "proxy stats");
            totals.memory_tiers = totals.memory_tiers.saturating_add(1);
            totals.memory_entries = totals
                .memory_entries
                .saturating_add(state.objects.len() as u64);
            totals.memory_weighted_size_bytes = totals
                .memory_weighted_size_bytes
                .saturating_add(state.bytes);
            totals.memory_max_size_bytes = totals
                .memory_max_size_bytes
                .saturating_add(handle.memory_max_bytes);
            totals.memory_purge_index_entries = totals
                .memory_purge_index_entries
                .saturating_add(state.purge_index.len() as u64);
        }
        if let Some(disk) = disk {
            totals.add_disk(disk.stats());
        }
        true
    });
    totals
}

impl NativeCacheRuntimeTotals {
    fn add_disk(&mut self, disk: NativeDiskCacheStats) {
        self.disk_tiers = self.disk_tiers.saturating_add(1);
        self.disk_entries = self.disk_entries.saturating_add(disk.entries);
        self.disk_size_bytes = self.disk_size_bytes.saturating_add(disk.size_bytes);
        self.disk_allocated_size_bytes = self
            .disk_allocated_size_bytes
            .saturating_add(disk.allocated_size_bytes);
        self.disk_free_size_bytes = self
            .disk_free_size_bytes
            .saturating_add(disk.free_size_bytes);
        self.disk_free_range_count = self
            .disk_free_range_count
            .saturating_add(disk.free_range_count);
        self.disk_largest_free_range_bytes = self
            .disk_largest_free_range_bytes
            .max(disk.largest_free_range_bytes);
        self.disk_bin_files = self.disk_bin_files.saturating_add(disk.bin_files);
        self.disk_max_size_bytes = self.disk_max_size_bytes.saturating_add(disk.max_size_bytes);
        self.disk_purge_index_entries = self
            .disk_purge_index_entries
            .saturating_add(disk.purge_index_entries);
    }
}

pub fn purge_native_memory_cache_primary(
    vhost: &str,
    route: Option<&str>,
    primary_key: &str,
    combined_key: &str,
) -> bool {
    let Some(registry) = NATIVE_MEMORY_CACHE_PURGE_REGISTRY.get() else {
        return false;
    };
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(error) => {
            log::error!(
                target: "fluxheim::native_http1",
                "native memory cache purge registry mutex poisoned: {error}"
            );
            std::process::abort();
        }
    };
    let mut purged = false;
    registry.retain(|handle| {
        let Some(state) = handle.state.upgrade() else {
            return false;
        };
        if handle.vhost.as_ref() != vhost || handle.route.as_deref() != route {
            return true;
        }
        let mut state = lock_native_memory_cache(&state, "proxy purge");
        purged |= purge_native_memory_state_primary(&mut state, primary_key, combined_key);
        true
    });
    purged
}

pub fn purge_native_memory_cache_user_tag(
    vhost: &str,
    route: Option<&str>,
    user_tag: &str,
    limit: usize,
    soft: bool,
) -> CacheIndexedPurgeResult {
    purge_native_memory_cache_indexed(vhost, route, |state| {
        let entries = state.purge_index.entries_for_user_tag(user_tag, limit);
        purge_native_memory_indexed_entries(state, entries, soft)
    })
}

pub fn purge_native_memory_cache_path_prefix(
    vhost: &str,
    route: Option<&str>,
    user_tag: &str,
    path_prefix: &str,
    limit: usize,
    soft: bool,
) -> CacheIndexedPurgeResult {
    purge_native_memory_cache_indexed(vhost, route, |state| {
        let entries =
            state
                .purge_index
                .entries_for_user_tag_path_prefix(user_tag, path_prefix, limit);
        purge_native_memory_indexed_entries(state, entries, soft)
    })
}

pub fn purge_native_memory_cache_path_exact(
    vhost: &str,
    route: Option<&str>,
    user_tag: &str,
    path_exact: &str,
    limit: usize,
    soft: bool,
) -> CacheIndexedPurgeResult {
    purge_native_memory_cache_indexed(vhost, route, |state| {
        let entries = state
            .purge_index
            .entries_for_user_tag_path_exact(user_tag, path_exact, limit);
        purge_native_memory_indexed_entries(state, entries, soft)
    })
}

pub fn purge_native_memory_cache_tag(
    vhost: &str,
    route: Option<&str>,
    user_tag: &str,
    cache_tag: &str,
    limit: usize,
    soft: bool,
) -> CacheIndexedPurgeResult {
    purge_native_memory_cache_indexed(vhost, route, |state| {
        let entries = state
            .purge_index
            .entries_for_user_tag_cache_tag(user_tag, cache_tag, limit);
        purge_native_memory_indexed_entries(state, entries, soft)
    })
}

pub fn purge_native_memory_cache_path_pattern(
    vhost: &str,
    route: Option<&str>,
    user_tag: &str,
    path_pattern: &str,
    limit: usize,
    soft: bool,
) -> CacheIndexedPurgeResult {
    purge_native_memory_cache_indexed(vhost, route, |state| {
        let entries =
            state
                .purge_index
                .entries_for_user_tag_path_pattern(user_tag, path_pattern, limit);
        purge_native_memory_indexed_entries(state, entries, soft)
    })
}

pub fn purge_native_memory_cache_stale(
    vhost: &str,
    route: Option<&str>,
    user_tag: &str,
    limit: usize,
    dry_run: bool,
) -> CacheStalePurgeResult {
    purge_native_memory_cache_stale_indexed(vhost, route, |state| {
        let entries = state.purge_index.entries_for_user_tag(user_tag, limit);
        purge_native_memory_stale_entries(state, entries, dry_run)
    })
}

fn purge_native_memory_cache_indexed(
    vhost: &str,
    route: Option<&str>,
    mut purge: impl FnMut(&mut NativeMemoryCacheState) -> CacheIndexedPurgeResult,
) -> CacheIndexedPurgeResult {
    let Some(registry) = NATIVE_MEMORY_CACHE_PURGE_REGISTRY.get() else {
        return CacheIndexedPurgeResult::default();
    };
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(error) => {
            log::error!(
                target: "fluxheim::native_http1",
                "native memory cache purge registry mutex poisoned: {error}"
            );
            std::process::abort();
        }
    };
    let mut result = CacheIndexedPurgeResult::default();
    registry.retain(|handle| {
        let Some(state) = handle.state.upgrade() else {
            return false;
        };
        if handle.vhost.as_ref() != vhost || handle.route.as_deref() != route {
            return true;
        }
        let mut state = lock_native_memory_cache(&state, "proxy purge");
        let scoped = purge(&mut state);
        result.matched = result.matched.saturating_add(scoped.matched);
        result.purged = result.purged.saturating_add(scoped.purged);
        result.truncated |= scoped.truncated;
        true
    });
    result
}

fn purge_native_memory_cache_stale_indexed(
    vhost: &str,
    route: Option<&str>,
    mut purge: impl FnMut(&mut NativeMemoryCacheState) -> CacheStalePurgeResult,
) -> CacheStalePurgeResult {
    let Some(registry) = NATIVE_MEMORY_CACHE_PURGE_REGISTRY.get() else {
        return CacheStalePurgeResult::default();
    };
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(error) => {
            log::error!(
                target: "fluxheim::native_http1",
                "native memory cache purge registry mutex poisoned: {error}"
            );
            std::process::abort();
        }
    };
    let mut result = CacheStalePurgeResult::default();
    registry.retain(|handle| {
        let Some(state) = handle.state.upgrade() else {
            return false;
        };
        if handle.vhost.as_ref() != vhost || handle.route.as_deref() != route {
            return true;
        }
        let mut state = lock_native_memory_cache(&state, "proxy purge");
        let scoped = purge(&mut state);
        result.scanned = result.scanned.saturating_add(scoped.scanned);
        result.stale = result.stale.saturating_add(scoped.stale);
        result.purged = result.purged.saturating_add(scoped.purged);
        result.truncated |= scoped.truncated;
        true
    });
    result
}

fn purge_native_memory_indexed_entries(
    state: &mut NativeMemoryCacheState,
    entries: Vec<CachePurgeIndexEntry>,
    soft: bool,
) -> CacheIndexedPurgeResult {
    let mut purged = 0_usize;
    let now = Instant::now();
    for entry in &entries {
        if soft {
            let Some(object) = state.objects.get_mut(&entry.combined_key) else {
                state.purge_index.remove_combined(&entry.combined_key);
                continue;
            };
            object.expires_at = now;
            purged = purged.saturating_add(1);
            continue;
        }
        if let Some(object) = remove_native_memory_cache_entry(state, &entry.combined_key) {
            state.bytes = state.bytes.saturating_sub(object.weight);
            purged = purged.saturating_add(1);
        } else {
            state.purge_index.remove_combined(&entry.combined_key);
        }
    }
    CacheIndexedPurgeResult {
        matched: entries.len(),
        purged,
        truncated: false,
    }
}

fn purge_native_memory_stale_entries(
    state: &mut NativeMemoryCacheState,
    entries: Vec<CachePurgeIndexEntry>,
    dry_run: bool,
) -> CacheStalePurgeResult {
    let now = Instant::now();
    let mut scanned = 0_usize;
    let mut stale = 0_usize;
    let mut purged = 0_usize;
    for entry in &entries {
        let Some(object) = state.objects.get(&entry.combined_key) else {
            state.purge_index.remove_combined(&entry.combined_key);
            continue;
        };
        scanned = scanned.saturating_add(1);
        if object.expires_at > now {
            continue;
        }
        stale = stale.saturating_add(1);
        if dry_run {
            continue;
        }
        let weight = object.weight;
        if remove_native_memory_cache_entry(state, &entry.combined_key).is_some() {
            state.bytes = state.bytes.saturating_sub(weight);
            purged = purged.saturating_add(1);
        }
    }
    CacheStalePurgeResult {
        scanned,
        stale,
        purged,
        truncated: false,
    }
}

pub(crate) fn register_native_memory_cache_purge_handle(
    vhost: Arc<str>,
    route: Option<Arc<str>>,
    state: &Arc<Mutex<NativeMemoryCacheState>>,
) {
    let registry = NATIVE_MEMORY_CACHE_PURGE_REGISTRY.get_or_init(|| Mutex::new(Vec::new()));
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(error) => {
            log::error!(
                target: "fluxheim::native_http1",
                "native memory cache purge registry mutex poisoned: {error}"
            );
            std::process::abort();
        }
    };
    registry.push(NativeMemoryCachePurgeHandle {
        vhost,
        route,
        state: Arc::downgrade(state),
    });
}

pub(crate) fn register_native_cache_stats_handle(
    memory_enabled: bool,
    memory_max_bytes: u64,
    state: &Arc<Mutex<NativeMemoryCacheState>>,
    disk: Option<&Arc<NativeDiskCache>>,
) {
    let registry = NATIVE_CACHE_STATS_REGISTRY.get_or_init(|| Mutex::new(Vec::new()));
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(error) => {
            log::error!(
                target: "fluxheim::native_http1",
                "native cache stats registry mutex poisoned: {error}"
            );
            std::process::abort();
        }
    };
    registry.push(NativeCacheStatsHandle {
        memory_enabled,
        memory_max_bytes,
        memory_state: Arc::downgrade(state),
        disk: disk.map(Arc::downgrade),
    });
}

fn purge_native_memory_state_primary(
    state: &mut NativeMemoryCacheState,
    primary_key: &str,
    combined_key: &str,
) -> bool {
    let mut purged = false;
    if let Some(entry) = remove_native_memory_cache_entry(state, combined_key) {
        state.bytes = state.bytes.saturating_sub(entry.weight);
        purged = true;
    }
    if primary_key != combined_key
        && let Some(entry) = remove_native_memory_cache_entry(state, primary_key)
    {
        state.bytes = state.bytes.saturating_sub(entry.weight);
        purged = true;
    }
    let removed_variant_bytes = remove_native_memory_cache_variants(state, primary_key);
    if removed_variant_bytes > 0 {
        state.bytes = state.bytes.saturating_sub(removed_variant_bytes);
        purged = true;
    }
    state.filling.remove(primary_key);
    if primary_key != combined_key {
        state.filling.remove(combined_key);
    }
    purged
}

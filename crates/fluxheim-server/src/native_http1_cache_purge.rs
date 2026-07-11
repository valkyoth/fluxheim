use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;

use fluxheim_cache::CacheBackgroundPurgeResult;
use fluxheim_cache::purge_index::{
    CacheIndexedPurgeResult, CachePurgeIndexEntry, CacheStalePurgeResult,
};

use super::{NativeDiskCache, NativeDiskCacheLocation};

static NATIVE_DISK_CACHE_PURGE_REGISTRY: OnceLock<Mutex<Vec<NativeDiskCachePurgeHandle>>> =
    OnceLock::new();

#[cfg(test)]
std::thread_local! {
    static PURGE_REGISTRY_LOCK_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
struct PurgeRegistryLockObservation;

#[cfg(test)]
impl PurgeRegistryLockObservation {
    fn enter() -> Self {
        PURGE_REGISTRY_LOCK_HELD.with(|held| {
            assert!(
                !held.replace(true),
                "nested purge registry lock observation"
            );
        });
        Self
    }
}

#[cfg(test)]
impl Drop for PurgeRegistryLockObservation {
    fn drop(&mut self) {
        PURGE_REGISTRY_LOCK_HELD.with(|held| held.set(false));
    }
}

#[derive(Clone, Debug)]
struct NativeDiskCachePurgeHandle {
    vhost: Arc<str>,
    route: Option<Arc<str>>,
    cache: Weak<NativeDiskCache>,
}

#[derive(Clone, Debug)]
struct NativeDiskCachePurgeTarget {
    vhost: Arc<str>,
    route: Option<Arc<str>>,
    cache: Arc<NativeDiskCache>,
}

impl NativeDiskCache {
    fn purge_primary(&self, primary_key: &str, combined_key: &str) -> bool {
        let mut purged = self.remove_combined(combined_key);
        let variant_keys = self.with_state(|state| {
            state
                .variants
                .get(primary_key)
                .into_iter()
                .flatten()
                .map(|variant| variant.key.clone())
                .collect::<Vec<_>>()
        });
        for variant_key in variant_keys {
            purged |= self.remove_combined(&variant_key);
        }
        purged
    }

    fn purge_user_tag(&self, user_tag: &str, limit: usize, soft: bool) -> CacheIndexedPurgeResult {
        let entries =
            self.with_state(|state| state.purge_index.entries_for_user_tag(user_tag, limit));
        self.purge_indexed_entries(entries, soft)
    }

    fn purge_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        let entries = self.with_state(|state| {
            state
                .purge_index
                .entries_for_user_tag_path_prefix(user_tag, path_prefix, limit)
        });
        self.purge_indexed_entries(entries, soft)
    }

    fn purge_path_exact(
        &self,
        user_tag: &str,
        path_exact: &str,
        limit: usize,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        let entries = self.with_state(|state| {
            state
                .purge_index
                .entries_for_user_tag_path_exact(user_tag, path_exact, limit)
        });
        self.purge_indexed_entries(entries, soft)
    }

    fn purge_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        let entries = self.with_state(|state| {
            state
                .purge_index
                .entries_for_user_tag_cache_tag(user_tag, cache_tag, limit)
        });
        self.purge_indexed_entries(entries, soft)
    }

    fn purge_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        let entries = self.with_state(|state| {
            state
                .purge_index
                .entries_for_user_tag_path_pattern(user_tag, path_pattern, limit)
        });
        self.purge_indexed_entries(entries, soft)
    }

    fn purge_stale(&self, user_tag: &str, limit: usize, dry_run: bool) -> CacheStalePurgeResult {
        let entries =
            self.with_state(|state| state.purge_index.entries_for_user_tag(user_tag, limit));
        self.purge_stale_entries(entries, dry_run)
    }

    fn purge_indexed_entries(
        &self,
        entries: Vec<CachePurgeIndexEntry>,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        let now = Instant::now();
        let mut purged = 0_usize;
        for entry in &entries {
            if soft {
                let Some(record) =
                    self.with_state(|state| state.objects.get(&entry.combined_key).cloned())
                else {
                    self.with_state(|state| {
                        state.purge_index.remove_combined(&entry.combined_key);
                    });
                    continue;
                };
                if matches!(record.location, NativeDiskCacheLocation::StorageBin(_)) {
                    if self.remove_combined(&entry.combined_key) {
                        purged = purged.saturating_add(1);
                    }
                    continue;
                }
                let softened = self.soft_purge_filesystem_record(entry, &record, now);
                if softened {
                    purged = purged.saturating_add(1);
                }
                continue;
            }
            if self.remove_combined(&entry.combined_key) {
                purged = purged.saturating_add(1);
            }
        }
        CacheIndexedPurgeResult {
            matched: entries.len(),
            purged,
            truncated: false,
        }
    }

    fn purge_stale_entries(
        &self,
        entries: Vec<CachePurgeIndexEntry>,
        dry_run: bool,
    ) -> CacheStalePurgeResult {
        let now = Instant::now();
        let mut scanned = 0_usize;
        let mut stale = 0_usize;
        let mut purged = 0_usize;
        for entry in &entries {
            let Some(object) = self.get_combined(&entry.combined_key) else {
                self.with_state(|state| {
                    state.purge_index.remove_combined(&entry.combined_key);
                });
                continue;
            };
            scanned = scanned.saturating_add(1);
            if object.expires_at > now {
                continue;
            }
            stale = stale.saturating_add(1);
            if !dry_run && self.remove_combined(&entry.combined_key) {
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
}

pub(crate) fn register_native_disk_cache_purge_handle(
    vhost: Arc<str>,
    route: Option<Arc<str>>,
    cache: &Arc<NativeDiskCache>,
) {
    let registry = NATIVE_DISK_CACHE_PURGE_REGISTRY.get_or_init(|| Mutex::new(Vec::new()));
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(error) => {
            log::error!(
                target: "fluxheim::native_http1",
                "native disk cache purge registry mutex poisoned: {error}"
            );
            std::process::abort();
        }
    };
    registry.push(NativeDiskCachePurgeHandle {
        vhost,
        route,
        cache: Arc::downgrade(cache),
    });
}

#[cfg(test)]
pub(super) fn native_disk_cache_purge_registry_is_unlocked_for_test() -> bool {
    PURGE_REGISTRY_LOCK_HELD.with(|held| !held.get())
}

pub fn purge_native_disk_cache_primary(
    vhost: &str,
    route: Option<&str>,
    primary_key: &str,
    combined_key: &str,
) -> bool {
    purge_native_disk_cache(vhost, route, |cache| {
        cache.purge_primary(primary_key, combined_key)
    })
}

pub fn purge_native_disk_cache_user_tag(
    vhost: &str,
    route: Option<&str>,
    user_tag: &str,
    limit: usize,
    soft: bool,
) -> CacheIndexedPurgeResult {
    purge_native_disk_cache_indexed(vhost, route, |cache| {
        cache.purge_user_tag(user_tag, limit, soft)
    })
}

pub fn purge_native_disk_cache_path_prefix(
    vhost: &str,
    route: Option<&str>,
    user_tag: &str,
    path_prefix: &str,
    limit: usize,
    soft: bool,
) -> CacheIndexedPurgeResult {
    purge_native_disk_cache_indexed(vhost, route, |cache| {
        cache.purge_path_prefix(user_tag, path_prefix, limit, soft)
    })
}

pub fn purge_native_disk_cache_path_exact(
    vhost: &str,
    route: Option<&str>,
    user_tag: &str,
    path_exact: &str,
    limit: usize,
    soft: bool,
) -> CacheIndexedPurgeResult {
    purge_native_disk_cache_indexed(vhost, route, |cache| {
        cache.purge_path_exact(user_tag, path_exact, limit, soft)
    })
}

pub fn purge_native_disk_cache_tag(
    vhost: &str,
    route: Option<&str>,
    user_tag: &str,
    cache_tag: &str,
    limit: usize,
    soft: bool,
) -> CacheIndexedPurgeResult {
    purge_native_disk_cache_indexed(vhost, route, |cache| {
        cache.purge_cache_tag(user_tag, cache_tag, limit, soft)
    })
}

pub fn purge_native_disk_cache_path_pattern(
    vhost: &str,
    route: Option<&str>,
    user_tag: &str,
    path_pattern: &str,
    limit: usize,
    soft: bool,
) -> CacheIndexedPurgeResult {
    purge_native_disk_cache_indexed(vhost, route, |cache| {
        cache.purge_path_pattern(user_tag, path_pattern, limit, soft)
    })
}

pub fn purge_native_disk_cache_stale(
    vhost: &str,
    route: Option<&str>,
    user_tag: &str,
    limit: usize,
    dry_run: bool,
) -> CacheStalePurgeResult {
    purge_native_disk_cache_stale_indexed(vhost, route, |cache| {
        cache.purge_stale(user_tag, limit, dry_run)
    })
}

pub fn purge_native_disk_cache_stale_all(
    limit: usize,
    batches: usize,
) -> std::io::Result<CacheBackgroundPurgeResult> {
    if limit == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache stale disk purge limit must be greater than zero",
        ));
    }
    if batches == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache stale disk purge batches must be greater than zero",
        ));
    }
    let mut result = CacheBackgroundPurgeResult::default();
    for target in native_disk_cache_purge_targets() {
        result.targets = result.targets.saturating_add(1);
        let user_tag =
            fluxheim_cache::cache_user_tag(target.vhost.as_ref(), target.route.as_deref());
        for _ in 0..batches {
            let batch = target.cache.purge_stale(&user_tag, limit, false);
            result.scanned = result.scanned.saturating_add(batch.scanned);
            result.stale = result.stale.saturating_add(batch.stale);
            result.purged = result.purged.saturating_add(batch.purged);
            result.truncated |= batch.truncated;
            if !batch.truncated {
                break;
            }
        }
    }
    Ok(result)
}

pub(super) fn purge_native_disk_cache(
    vhost: &str,
    route: Option<&str>,
    mut purge: impl FnMut(&NativeDiskCache) -> bool,
) -> bool {
    let mut purged = false;
    for target in native_disk_cache_purge_targets_for(vhost, route) {
        purged |= purge(&target.cache);
    }
    purged
}

fn purge_native_disk_cache_indexed(
    vhost: &str,
    route: Option<&str>,
    mut purge: impl FnMut(&NativeDiskCache) -> CacheIndexedPurgeResult,
) -> CacheIndexedPurgeResult {
    let mut result = CacheIndexedPurgeResult::default();
    for target in native_disk_cache_purge_targets_for(vhost, route) {
        let scoped = purge(&target.cache);
        result.matched = result.matched.saturating_add(scoped.matched);
        result.purged = result.purged.saturating_add(scoped.purged);
        result.truncated |= scoped.truncated;
    }
    result
}

fn purge_native_disk_cache_stale_indexed(
    vhost: &str,
    route: Option<&str>,
    mut purge: impl FnMut(&NativeDiskCache) -> CacheStalePurgeResult,
) -> CacheStalePurgeResult {
    let mut result = CacheStalePurgeResult::default();
    for target in native_disk_cache_purge_targets_for(vhost, route) {
        let scoped = purge(&target.cache);
        result.scanned = result.scanned.saturating_add(scoped.scanned);
        result.stale = result.stale.saturating_add(scoped.stale);
        result.purged = result.purged.saturating_add(scoped.purged);
        result.truncated |= scoped.truncated;
    }
    result
}

fn native_disk_cache_purge_targets_for(
    vhost: &str,
    route: Option<&str>,
) -> Vec<NativeDiskCachePurgeTarget> {
    native_disk_cache_purge_targets()
        .into_iter()
        .filter(|target| target.vhost.as_ref() == vhost && target.route.as_deref() == route)
        .collect()
}

pub(super) fn registered_native_disk_cache(
    vhost: &str,
    route: Option<&str>,
) -> Option<Arc<NativeDiskCache>> {
    native_disk_cache_purge_targets_for(vhost, route)
        .into_iter()
        .next()
        .map(|target| target.cache)
}

fn native_disk_cache_purge_targets() -> Vec<NativeDiskCachePurgeTarget> {
    let Some(registry) = NATIVE_DISK_CACHE_PURGE_REGISTRY.get() else {
        return Vec::new();
    };
    let mut registry = match registry.lock() {
        Ok(registry) => registry,
        Err(error) => {
            log::error!(
                target: "fluxheim::native_http1",
                "native disk cache purge registry mutex poisoned: {error}"
            );
            std::process::abort();
        }
    };
    #[cfg(test)]
    let _lock_observation = PurgeRegistryLockObservation::enter();
    registry.retain(|handle| handle.cache.upgrade().is_some());
    registry
        .iter()
        .filter_map(|handle| {
            let cache = handle.cache.upgrade()?;
            Some(NativeDiskCachePurgeTarget {
                vhost: handle.vhost.clone(),
                route: handle.route.clone(),
                cache,
            })
        })
        .collect()
}

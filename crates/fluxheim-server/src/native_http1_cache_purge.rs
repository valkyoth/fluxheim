use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;

use fluxheim_cache::CacheBackgroundPurgeResult;
use fluxheim_cache::purge_index::{
    CacheIndexedPurgeResult, CachePurgeMode, CachePurgeSelector, CachePurgeVisit,
    CacheStalePurgeResult,
};

use super::{NativeDiskCache, NativeDiskCacheBackend, NativeDiskCacheLocation};

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
        let variant_keys =
            self.with_state(|state| state.purge_index.combined_keys_for_primary(primary_key));
        for variant_key in variant_keys {
            purged |= self.remove_combined(&variant_key);
        }
        purged
    }

    fn purge_user_tag(&self, user_tag: &str, limit: usize, soft: bool) -> CacheIndexedPurgeResult {
        self.purge_indexed_entries(CachePurgeSelector::Scope(user_tag), limit, soft)
    }

    fn purge_path_prefix(
        &self,
        user_tag: &str,
        path_prefix: &str,
        limit: usize,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        self.purge_indexed_entries(
            CachePurgeSelector::Prefix(user_tag, path_prefix),
            limit,
            soft,
        )
    }

    fn purge_path_exact(
        &self,
        user_tag: &str,
        path_exact: &str,
        limit: usize,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        self.purge_indexed_entries(CachePurgeSelector::Exact(user_tag, path_exact), limit, soft)
    }

    fn purge_cache_tag(
        &self,
        user_tag: &str,
        cache_tag: &str,
        limit: usize,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        self.purge_indexed_entries(CachePurgeSelector::Tag(user_tag, cache_tag), limit, soft)
    }

    fn purge_path_pattern(
        &self,
        user_tag: &str,
        path_pattern: &str,
        limit: usize,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        self.purge_indexed_entries(
            CachePurgeSelector::Pattern(user_tag, path_pattern),
            limit,
            soft,
        )
    }

    fn purge_stale(&self, user_tag: &str, limit: usize, dry_run: bool) -> CacheStalePurgeResult {
        self.purge_stale_entries(CachePurgeSelector::Scope(user_tag), limit, dry_run)
    }

    fn purge_indexed_entries(
        &self,
        selector: CachePurgeSelector<'_>,
        limit: usize,
        soft: bool,
    ) -> CacheIndexedPurgeResult {
        let now = Instant::now();
        let index = self.with_state(|state| state.purge_index.clone());
        let mode = if soft {
            CachePurgeMode::Soft
        } else {
            CachePurgeMode::Hard
        };
        let result = if soft && matches!(self.backend, NativeDiskCacheBackend::StorageBin(_)) {
            self.scan_soft_bin(&index, selector, limit)
        } else {
            index.scan(selector, mode, limit, |entry| {
                let Ok(_mutation) = self.try_lock_key_mutation(&entry.combined_key) else {
                    return CachePurgeVisit {
                        retry: true,
                        ..Default::default()
                    };
                };
                if !index.contains_entry(entry) {
                    return CachePurgeVisit {
                        retry: true,
                        ..Default::default()
                    };
                }
                if soft {
                    let Some(record) =
                        self.with_state(|state| state.objects.get(&entry.combined_key).cloned())
                    else {
                        self.with_state(|state| {
                            state.purge_index.remove_combined(&entry.combined_key);
                        });
                        return CachePurgeVisit::default();
                    };
                    let changed = self
                        .encode_soft_purge(entry, &record, now)
                        .and_then(|encoded| {
                            let NativeDiskCacheLocation::Filesystem(path) = &record.location else {
                                return Err(std::io::Error::other("unexpected soft purge backend"));
                            };
                            if let Some(bytes) = encoded {
                                self.write_object_atomically(path, &bytes)?;
                                return Ok(true);
                            }
                            Ok(false)
                        });
                    match changed {
                        Ok(purged) => {
                            return CachePurgeVisit {
                                purged,
                                ..Default::default()
                            };
                        }
                        Err(_) => {
                            return CachePurgeVisit {
                                retry: true,
                                ..Default::default()
                            };
                        }
                    }
                }
                let purged = self.remove_combined_locked(&entry.combined_key);
                let retry = !purged
                    && self.with_state(|state| state.objects.contains_key(&entry.combined_key));
                CachePurgeVisit {
                    purged,
                    retry,
                    ..Default::default()
                }
            })
        };
        CacheIndexedPurgeResult {
            examined: result.examined,
            matched: result.matched,
            purged: result.purged,
            truncated: result.truncated,
        }
    }

    fn purge_stale_entries(
        &self,
        selector: CachePurgeSelector<'_>,
        limit: usize,
        dry_run: bool,
    ) -> CacheStalePurgeResult {
        let now = Instant::now();
        let index = self.with_state(|state| state.purge_index.clone());
        let mode = if dry_run {
            CachePurgeMode::DryRun
        } else {
            CachePurgeMode::Stale
        };
        let mut scanned = 0;
        let result = index.scan(selector, mode, limit, |entry| {
            let expected = self.with_state(|state| state.objects.get(&entry.combined_key).cloned());
            let object = match self.lookup_combined(&entry.combined_key) {
                Ok(Some(object)) => object,
                Err(_) => {
                    return CachePurgeVisit {
                        retry: true,
                        ..Default::default()
                    };
                }
                Ok(None) => {
                    self.with_state(|state| {
                        if !state.objects.contains_key(&entry.combined_key) {
                            state.purge_index.remove_combined(&entry.combined_key);
                        }
                    });
                    return CachePurgeVisit::default();
                }
            };
            scanned += 1;
            if object.expires_at > now {
                return CachePurgeVisit::default();
            }
            let purged = !dry_run
                && expected.as_ref().is_some_and(|record| {
                    self.remove_if_unchanged(&entry.combined_key, record)
                        .unwrap_or(false)
                });
            let retry = !dry_run
                && !purged
                && self.with_state(|state| state.objects.contains_key(&entry.combined_key));
            CachePurgeVisit {
                stale: true,
                purged,
                retry,
            }
        });
        CacheStalePurgeResult {
            examined: result.examined,
            scanned,
            stale: result.stale,
            purged: result.purged,
            truncated: result.truncated,
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
            fluxheim_common::fatal::abort(
                fluxheim_common::fatal::Reason::CachePurgeRegistryPoisoned,
            );
        }
    };
    registry.retain(|entry| entry.cache.strong_count() > 0);
    if registry.iter().any(|entry| {
        entry.vhost == vhost && entry.route == route && entry.cache.ptr_eq(&Arc::downgrade(cache))
    }) {
        return;
    }
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
) -> std::io::Result<bool> {
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
) -> std::io::Result<CacheIndexedPurgeResult> {
    purge_native_disk_cache_indexed(vhost, route, limit, soft, |cache, limit| {
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
) -> std::io::Result<CacheIndexedPurgeResult> {
    purge_native_disk_cache_indexed(vhost, route, limit, soft, |cache, limit| {
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
) -> std::io::Result<CacheIndexedPurgeResult> {
    purge_native_disk_cache_indexed(vhost, route, limit, soft, |cache, limit| {
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
) -> std::io::Result<CacheIndexedPurgeResult> {
    purge_native_disk_cache_indexed(vhost, route, limit, soft, |cache, limit| {
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
) -> std::io::Result<CacheIndexedPurgeResult> {
    purge_native_disk_cache_indexed(vhost, route, limit, soft, |cache, limit| {
        cache.purge_path_pattern(user_tag, path_pattern, limit, soft)
    })
}

pub fn purge_native_disk_cache_stale(
    vhost: &str,
    route: Option<&str>,
    user_tag: &str,
    limit: usize,
    dry_run: bool,
) -> std::io::Result<CacheStalePurgeResult> {
    purge_native_disk_cache_stale_indexed(vhost, route, limit, dry_run, |cache, limit| {
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
    for _ in 0..batches {
        let mut remaining = limit;
        result.truncated = false;
        for target in native_disk_cache_purge_targets() {
            if remaining == 0 {
                result.truncated = true;
                break;
            }
            result.targets = result.targets.saturating_add(1);
            let user_tag =
                fluxheim_cache::cache_user_tag(target.vhost.as_ref(), target.route.as_deref());
            let batch = target.cache.purge_stale(&user_tag, remaining, false);
            target.cache.checkpoint_hard_purge(batch.purged != 0)?;
            remaining = remaining.saturating_sub(batch.examined.max(1));
            result.scanned = result.scanned.saturating_add(batch.scanned);
            result.stale = result.stale.saturating_add(batch.stale);
            result.purged = result.purged.saturating_add(batch.purged);
            result.truncated |= batch.truncated;
        }
        rotate_purge_targets();
        if !result.truncated {
            break;
        }
    }
    Ok(result)
}

pub(super) fn purge_native_disk_cache(
    vhost: &str,
    route: Option<&str>,
    mut purge: impl FnMut(&NativeDiskCache) -> bool,
) -> std::io::Result<bool> {
    let mut purged = false;
    for target in native_disk_cache_purge_targets_for(vhost, route) {
        let changed = purge(&target.cache);
        target.cache.checkpoint_hard_purge(changed)?;
        purged |= changed;
    }
    Ok(purged)
}

fn purge_native_disk_cache_indexed(
    vhost: &str,
    route: Option<&str>,
    mut remaining: usize,
    soft: bool,
    mut purge: impl FnMut(&NativeDiskCache, usize) -> CacheIndexedPurgeResult,
) -> std::io::Result<CacheIndexedPurgeResult> {
    let mut result = CacheIndexedPurgeResult::default();
    for target in native_disk_cache_purge_targets_for(vhost, route) {
        if remaining == 0 {
            result.truncated = true;
            break;
        }
        let scoped = purge(&target.cache, remaining);
        if !soft {
            target.cache.checkpoint_hard_purge(scoped.purged != 0)?;
        }
        remaining = remaining.saturating_sub(scoped.examined.max(1));
        result.examined = result.examined.saturating_add(scoped.examined);
        result.matched = result.matched.saturating_add(scoped.matched);
        result.purged = result.purged.saturating_add(scoped.purged);
        result.truncated |= scoped.truncated;
    }
    rotate_purge_targets();
    Ok(result)
}

fn purge_native_disk_cache_stale_indexed(
    vhost: &str,
    route: Option<&str>,
    mut remaining: usize,
    dry_run: bool,
    mut purge: impl FnMut(&NativeDiskCache, usize) -> CacheStalePurgeResult,
) -> std::io::Result<CacheStalePurgeResult> {
    let mut result = CacheStalePurgeResult::default();
    for target in native_disk_cache_purge_targets_for(vhost, route) {
        if remaining == 0 {
            result.truncated = true;
            break;
        }
        let scoped = purge(&target.cache, remaining);
        if !dry_run {
            target.cache.checkpoint_hard_purge(scoped.purged != 0)?;
        }
        remaining = remaining.saturating_sub(scoped.examined.max(1));
        result.examined = result.examined.saturating_add(scoped.examined);
        result.scanned = result.scanned.saturating_add(scoped.scanned);
        result.stale = result.stale.saturating_add(scoped.stale);
        result.purged = result.purged.saturating_add(scoped.purged);
        result.truncated |= scoped.truncated;
    }
    rotate_purge_targets();
    Ok(result)
}

fn rotate_purge_targets() {
    if let Some(registry) = NATIVE_DISK_CACHE_PURGE_REGISTRY.get()
        && let Ok(mut registry) = registry.lock()
        && !registry.is_empty()
    {
        registry.rotate_left(1);
    }
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
            fluxheim_common::fatal::abort(
                fluxheim_common::fatal::Reason::CachePurgeRegistryPoisoned,
            );
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

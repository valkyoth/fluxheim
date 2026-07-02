use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;

use fluxheim_cache::purge_index::{CacheIndexedPurgeResult, CacheStalePurgeResult};
use fluxheim_cache::{
    CacheBackgroundPurgeResult, CacheObjectFreshnessState, VaryRequestHashField,
    collect_cache_tags, vary_request_hash_material,
};
use fluxheim_config::CacheConfig;

use super::{NativeDiskCache, NativeDiskCacheObjectMetadata, native_instant_to_unix_secs};

static NATIVE_DISK_CACHE_PURGE_REGISTRY: OnceLock<Mutex<Vec<NativeDiskCachePurgeHandle>>> =
    OnceLock::new();

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

pub fn inspect_native_disk_cache_object(
    config: &CacheConfig,
    primary_key: &str,
    request_headers: &[(String, String)],
) -> Option<NativeDiskCacheObjectMetadata> {
    let cache = NativeDiskCache::from_config(config)?;
    let entry = cache.get(primary_key, |fields| {
        native_inspection_vary_cache_key(primary_key, fields, request_headers)
    })?;
    let now = Instant::now();
    let fresh = entry.expires_at > now;
    let serve_stale_while_revalidate = !fresh
        && entry
            .stale_while_revalidate_until
            .is_some_and(|until| until > now);
    let serve_stale_if_error =
        !fresh && entry.stale_if_error_until.is_some_and(|until| until > now);
    let freshness_state = if fresh {
        CacheObjectFreshnessState::Fresh
    } else if serve_stale_while_revalidate || serve_stale_if_error {
        CacheObjectFreshnessState::Stale
    } else {
        CacheObjectFreshnessState::Expired
    };
    let mut header_names = entry
        .headers
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    header_names.sort();
    header_names.dedup();
    let mut cache_tags = Vec::new();
    let mut cache_tags_total_bytes = 0_usize;
    for tag_header in &config.tag_headers {
        for (_, value) in entry
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(tag_header))
        {
            collect_cache_tags(value, &mut cache_tags, &mut cache_tags_total_bytes);
        }
    }
    Some(NativeDiskCacheObjectMetadata {
        status: entry.status,
        fresh,
        freshness_state,
        serve_stale_while_revalidate,
        serve_stale_if_error,
        body_bytes: entry.body.len() as u64,
        weight_bytes: entry.weight,
        created_unix_secs: Some(native_instant_to_unix_secs(entry.stored_at)),
        updated_unix_secs: Some(native_instant_to_unix_secs(entry.stored_at)),
        fresh_until_unix_secs: Some(native_instant_to_unix_secs(entry.expires_at)),
        age_secs: entry.age_secs(),
        fresh_ttl_secs: entry
            .expires_at
            .saturating_duration_since(entry.stored_at)
            .as_secs(),
        stale_while_revalidate_secs: native_stale_window_secs(
            entry.expires_at,
            entry.stale_while_revalidate_until,
        ),
        stale_if_error_secs: native_stale_window_secs(entry.expires_at, entry.stale_if_error_until),
        cache_tags,
        header_names,
        header_values: entry.headers,
    })
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
    NATIVE_DISK_CACHE_PURGE_REGISTRY
        .get()
        .and_then(|registry| registry.try_lock().ok())
        .is_some()
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

fn native_inspection_vary_cache_key(
    base_key: &str,
    fields: &[String],
    request_headers: &[(String, String)],
) -> Option<String> {
    let material = vary_request_hash_material(fields.iter().map(|field| {
        VaryRequestHashField {
            name: field.as_str(),
            values: request_headers
                .iter()
                .filter_map(|(name, value)| {
                    name.eq_ignore_ascii_case(field).then_some(value.as_bytes())
                })
                .collect(),
        }
    }));
    let variance = base64_ng::URL_SAFE_NO_PAD.encode_string(&material).ok()?;
    Some(format!("{base_key};vary:{variance}"))
}

fn native_stale_window_secs(expires_at: Instant, until: Option<Instant>) -> u32 {
    let secs = until
        .map(|until| until.saturating_duration_since(expires_at).as_secs())
        .unwrap_or_default();
    u32::try_from(secs).unwrap_or(u32::MAX)
}

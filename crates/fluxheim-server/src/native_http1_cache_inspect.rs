use std::time::Instant;

use fluxheim_cache::{CacheObjectFreshnessState, collect_cache_tags};
use fluxheim_config::{CacheConfig, CacheDiskBackend};

use crate::native_http1_proxy_cache_headers::native_vary_cache_key_for_headers;

use super::native_http1_cache_purge::registered_native_disk_cache;
use super::{NativeDiskCache, NativeDiskCacheObjectMetadata, native_instant_to_unix_secs};

pub fn inspect_native_disk_cache_object(
    vhost: &str,
    route: Option<&str>,
    config: &CacheConfig,
    primary_key: &str,
    request_headers: &[(String, String)],
) -> Option<NativeDiskCacheObjectMetadata> {
    let cache = registered_native_disk_cache(vhost, route).or_else(|| {
        matches!(config.disk.backend, CacheDiskBackend::Filesystem)
            .then(|| NativeDiskCache::from_config(config))
            .flatten()
            .map(std::sync::Arc::new)
    })?;
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

fn native_inspection_vary_cache_key(
    base_key: &str,
    fields: &[String],
    request_headers: &[(String, String)],
) -> Option<String> {
    native_vary_cache_key_for_headers(base_key, fields, request_headers)
}

fn native_stale_window_secs(expires_at: Instant, until: Option<Instant>) -> u32 {
    let secs = until
        .map(|until| until.saturating_duration_since(expires_at).as_secs())
        .unwrap_or_default();
    u32::try_from(secs).unwrap_or(u32::MAX)
}

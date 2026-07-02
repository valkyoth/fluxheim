use serde_json::{Value, json};

#[cfg(feature = "cache")]
pub(super) fn cache_scope(route: Option<&str>) -> &'static str {
    if route.is_some() { "route" } else { "vhost" }
}

#[cfg(all(feature = "cache", feature = "metrics"))]
pub(super) fn record_cache_purge_metric(
    operation: &str,
    vhost: &str,
    route: Option<&str>,
    mode: &str,
) {
    crate::metrics::record_cache_purge(operation, vhost, route, mode);
}

#[cfg(all(feature = "cache", not(feature = "metrics")))]
pub(super) fn record_cache_purge_metric(
    _operation: &str,
    _vhost: &str,
    _route: Option<&str>,
    _mode: &str,
) {
}

#[cfg(feature = "cache")]
pub(super) fn cache_indexed_purge_mode(soft: bool) -> &'static str {
    if soft { "soft" } else { "normal" }
}

#[cfg(feature = "cache")]
pub(super) fn cache_stale_purge_mode(dry_run: bool) -> &'static str {
    if dry_run { "dry_run" } else { "normal" }
}

#[cfg(feature = "cache")]
pub(super) fn cache_purge_results_json(results: &[fluxheim_cache::CachePurgeResult]) -> Vec<Value> {
    results
        .iter()
        .map(|result| {
            json!({
                "purged": result.purged(),
                "not_purged": result.not_purged(),
                "route": result.route.as_deref(),
                "scope": cache_scope(result.route.as_deref()),
                "host": result.host,
                "method": result.method,
                "path": result.path,
                "query": result.query.as_deref(),
                "cache_key": result.cache_key,
                "memory_purged": result.memory_purged,
                "memory_not_purged": result.memory_not_purged(),
                "disk_purged": result.disk_purged,
                "disk_not_purged": result.disk_not_purged(),
            })
        })
        .collect()
}

#[cfg(feature = "cache")]
pub(super) fn cache_totals_json(totals: &fluxheim_cache::CacheRuntimeTotals) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("vhosts".to_owned(), json!(totals.vhosts));
    object.insert("enabled_vhosts".to_owned(), json!(totals.enabled_vhosts));
    object.insert(
        "enabled_vhost_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(totals.enabled_vhosts, totals.vhosts)),
    );
    object.insert("tiered_vhosts".to_owned(), json!(totals.tiered_vhosts));
    object.insert(
        "tiered_vhost_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(totals.tiered_vhosts, totals.vhosts)),
    );
    object.insert(
        "configured_routes".to_owned(),
        json!(totals.configured_routes),
    );
    object.insert("routes_total".to_owned(), json!(totals.routes_total));
    object.insert(
        "cache_route_coverage_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.routes_total,
            totals.configured_routes
        )),
    );
    object.insert("enabled_routes".to_owned(), json!(totals.enabled_routes));
    object.insert(
        "enabled_route_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(totals.enabled_routes, totals.routes_total)),
    );
    object.insert("tiered_routes".to_owned(), json!(totals.tiered_routes));
    object.insert(
        "tiered_route_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(totals.tiered_routes, totals.routes_total)),
    );
    object.insert(
        "lock_enabled_policies".to_owned(),
        json!(totals.lock_enabled_policies),
    );
    object.insert(
        "lock_enabled_policy_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.lock_enabled_policies,
            totals.enabled_cache_policies()
        )),
    );
    object.insert(
        "origin_protection_enabled_policies".to_owned(),
        json!(totals.origin_protection_enabled_policies),
    );
    object.insert(
        "origin_protection_enabled_policy_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.origin_protection_enabled_policies,
            totals.enabled_cache_policies()
        )),
    );
    object.insert(
        "origin_protection_max_concurrent_fills".to_owned(),
        json!(totals.origin_protection_max_concurrent_fills),
    );
    object.insert(
        "peer_fill_enabled_policies".to_owned(),
        json!(totals.peer_fill_enabled_policies),
    );
    object.insert(
        "peer_fill_enabled_policy_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.peer_fill_enabled_policies,
            totals.enabled_cache_policies()
        )),
    );
    object.insert("peer_fill_peers".to_owned(), json!(totals.peer_fill_peers));
    object.insert(
        "peer_fill_max_concurrent_requests".to_owned(),
        json!(totals.peer_fill_max_concurrent_requests),
    );
    object.insert("memory_tiers".to_owned(), json!(totals.memory_tiers));
    object.insert("memory_entries".to_owned(), json!(totals.memory_entries));
    object.insert(
        "memory_weighted_size_bytes".to_owned(),
        json!(totals.memory_weighted_size_bytes),
    );
    object.insert(
        "memory_average_weighted_size_bytes".to_owned(),
        json!(average_bytes(
            totals.memory_weighted_size_bytes,
            totals.memory_entries
        )),
    );
    object.insert(
        "memory_max_size_bytes".to_owned(),
        json!(totals.memory_max_size_bytes),
    );
    object.insert(
        "memory_fill_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.memory_weighted_size_bytes,
            totals.memory_max_size_bytes
        )),
    );
    object.insert(
        "memory_purge_index_entries".to_owned(),
        json!(totals.memory_purge_index_entries),
    );
    object.insert(
        "memory_purge_index_max_entries".to_owned(),
        json!(totals.memory_purge_index_max_entries),
    );
    object.insert(
        "memory_purge_index_fill_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.memory_purge_index_entries,
            totals.memory_purge_index_max_entries
        )),
    );
    object.insert("disk_tiers".to_owned(), json!(totals.disk_tiers));
    object.insert("disk_entries".to_owned(), json!(totals.disk_entries));
    object.insert("disk_size_bytes".to_owned(), json!(totals.disk_size_bytes));
    object.insert(
        "disk_average_object_size_bytes".to_owned(),
        json!(average_bytes(totals.disk_size_bytes, totals.disk_entries)),
    );
    object.insert(
        "disk_allocated_size_bytes".to_owned(),
        json!(totals.disk_allocated_size_bytes),
    );
    object.insert(
        "disk_free_size_bytes".to_owned(),
        json!(totals.disk_free_size_bytes),
    );
    object.insert(
        "disk_free_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.disk_free_size_bytes,
            totals.disk_allocated_size_bytes
        )),
    );
    object.insert(
        "disk_free_range_count".to_owned(),
        json!(totals.disk_free_range_count),
    );
    object.insert(
        "disk_largest_free_range_bytes".to_owned(),
        json!(totals.disk_largest_free_range_bytes),
    );
    object.insert("disk_bin_files".to_owned(), json!(totals.disk_bin_files));
    object.insert(
        "disk_max_size_bytes".to_owned(),
        json!(totals.disk_max_size_bytes),
    );
    object.insert(
        "disk_fill_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.disk_size_bytes,
            totals.disk_max_size_bytes
        )),
    );
    object.insert(
        "disk_purge_index_entries".to_owned(),
        json!(totals.disk_purge_index_entries),
    );
    object.insert(
        "disk_purge_index_max_entries".to_owned(),
        json!(totals.disk_purge_index_max_entries),
    );
    object.insert(
        "disk_purge_index_fill_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.disk_purge_index_entries,
            totals.disk_purge_index_max_entries
        )),
    );
    object.insert(
        "activity".to_owned(),
        cache_activity_json(&fluxheim_cache::CacheActivityStats {
            hits: totals.hits,
            misses: totals.misses,
            stores: totals.stores,
            store_refusals: totals.store_refusals,
            evictions: totals.evictions,
            purges: totals.purges,
        }),
    );
    Value::Object(object)
}

#[cfg(feature = "cache")]
pub(super) fn cache_vhost_stats_json(vhosts: &[fluxheim_cache::CacheVhostStats]) -> Vec<Value> {
    vhosts
        .iter()
        .map(|vhost| {
            json!({
                "name": vhost.name,
                "enabled": vhost.enabled,
                "tiered": vhost.tiered,
                "lock_enabled": vhost.lock_enabled,
                "lock_wait_timeout_secs": vhost.lock_wait_timeout_secs,
                "origin_protection_enabled": vhost.origin_protection_enabled,
                "origin_protection_max_concurrent_fills": vhost.origin_protection_max_concurrent_fills,
                "peer_fill_enabled": vhost.peer_fill_enabled,
                "peer_fill_peers": vhost.peer_fill_peers,
                "peer_fill_max_concurrent_requests": vhost.peer_fill_max_concurrent_requests,
                "peer_fill_fail_open": vhost.peer_fill_fail_open,
                "storage_tiers": fluxheim_cache::cache_storage_tiers(vhost.memory.is_some(), vhost.disk.is_some()),
                "configured_routes": vhost.configured_routes,
                "routes_total": vhost.routes_total,
                "cache_route_coverage_ratio_per_mille": ratio_per_mille(vhost.routes_total, vhost.configured_routes),
                "enabled_routes": vhost.enabled_routes,
                "enabled_route_ratio_per_mille": ratio_per_mille(vhost.enabled_routes, vhost.routes_total),
                "tiered_routes": vhost.tiered_routes,
                "tiered_route_ratio_per_mille": ratio_per_mille(vhost.tiered_routes, vhost.routes_total),
                "memory": memory_cache_stats_json(vhost.memory.as_ref()),
                "disk": disk_cache_stats_json(vhost.disk.as_ref()),
                "routes": cache_route_stats_json(&vhost.routes),
            })
        })
        .collect()
}

#[cfg(feature = "cache")]
pub(super) fn cache_route_stats_json(routes: &[fluxheim_cache::CacheRouteStats]) -> Vec<Value> {
    routes
        .iter()
        .map(|route| {
            json!({
                "name": route.name,
                "enabled": route.enabled,
                "tiered": route.tiered,
                "lock_enabled": route.lock_enabled,
                "lock_wait_timeout_secs": route.lock_wait_timeout_secs,
                "origin_protection_enabled": route.origin_protection_enabled,
                "origin_protection_max_concurrent_fills": route.origin_protection_max_concurrent_fills,
                "peer_fill_enabled": route.peer_fill_enabled,
                "peer_fill_peers": route.peer_fill_peers,
                "peer_fill_max_concurrent_requests": route.peer_fill_max_concurrent_requests,
                "peer_fill_fail_open": route.peer_fill_fail_open,
                "storage_tiers": fluxheim_cache::cache_storage_tiers(route.memory.is_some(), route.disk.is_some()),
                "memory": memory_cache_stats_json(route.memory.as_ref()),
                "disk": disk_cache_stats_json(route.disk.as_ref()),
            })
        })
        .collect()
}

#[cfg(feature = "cache")]
pub(super) fn memory_cache_stats_json(stats: Option<&fluxheim_cache::MemoryCacheStats>) -> Value {
    let Some(stats) = stats else {
        return Value::Null;
    };

    json!({
        "entries": stats.entries,
        "weighted_size_bytes": stats.weighted_size_bytes,
        "average_weighted_size_bytes": average_bytes(stats.weighted_size_bytes, stats.entries),
        "max_size_bytes": stats.max_size_bytes.as_u64(),
        "fill_ratio_per_mille": ratio_per_mille(stats.weighted_size_bytes, stats.max_size_bytes.as_u64()),
        "max_object_bytes": stats.max_object_bytes.as_u64(),
        "purge_index_entries": stats.purge_index_entries,
        "purge_index_max_entries": stats.purge_index_max_entries,
        "purge_index_fill_ratio_per_mille": ratio_per_mille(stats.purge_index_entries, stats.purge_index_max_entries),
        "activity": cache_activity_json(&stats.activity),
    })
}

#[cfg(feature = "cache")]
pub(super) fn disk_cache_stats_json(stats: Option<&fluxheim_cache::DiskCacheStats>) -> Value {
    let Some(stats) = stats else {
        return Value::Null;
    };

    json!({
        "backend": stats.backend,
        "entries": stats.entries,
        "size_bytes": stats.size_bytes,
        "average_object_size_bytes": average_bytes(stats.size_bytes, stats.entries),
        "allocated_size_bytes": stats.allocated_size_bytes,
        "free_size_bytes": stats.free_size_bytes,
        "free_ratio_per_mille": ratio_per_mille(stats.free_size_bytes, stats.allocated_size_bytes),
        "free_range_count": stats.free_range_count,
        "largest_free_range_bytes": stats.largest_free_range_bytes,
        "bin_files": stats.bin_files,
        "max_size_bytes": stats.max_size_bytes.as_u64(),
        "fill_ratio_per_mille": ratio_per_mille(stats.size_bytes, stats.max_size_bytes.as_u64()),
        "max_object_bytes": stats.max_object_bytes.as_u64(),
        "purge_index_entries": stats.purge_index_entries,
        "purge_index_max_entries": stats.purge_index_max_entries,
        "purge_index_fill_ratio_per_mille": ratio_per_mille(stats.purge_index_entries, stats.purge_index_max_entries),
        "activity": cache_activity_json(&stats.activity),
    })
}

#[cfg(feature = "cache")]
pub(super) fn ratio_per_mille(numerator: u64, denominator: u64) -> u64 {
    fluxheim_cache::cache_ratio_per_mille(numerator, denominator)
}

#[cfg(feature = "cache")]
pub(super) fn ratio_per_mille_usize(numerator: usize, denominator: usize) -> u64 {
    fluxheim_cache::cache_ratio_per_mille_usize(numerator, denominator)
}

#[cfg(feature = "cache")]
pub(super) fn stale_would_purge(dry_run: bool, stale: usize) -> usize {
    fluxheim_cache::cache_stale_would_purge(dry_run, stale)
}

#[cfg(feature = "cache")]
pub(super) fn average_bytes(total_bytes: u64, entries: u64) -> u64 {
    fluxheim_cache::cache_average_bytes(total_bytes, entries)
}

#[cfg(feature = "cache")]
pub(super) fn cache_activity_json(activity: &fluxheim_cache::CacheActivityStats) -> Value {
    let requests = activity.hits.saturating_add(activity.misses);
    let hit_ratio_per_mille = activity
        .hits
        .saturating_mul(1000)
        .checked_div(requests)
        .unwrap_or(0);
    let miss_ratio_per_mille = activity
        .misses
        .saturating_mul(1000)
        .checked_div(requests)
        .unwrap_or(0);
    let store_attempts = activity.stores.saturating_add(activity.store_refusals);
    let store_ratio_per_mille = activity
        .stores
        .saturating_mul(1000)
        .checked_div(store_attempts)
        .unwrap_or(0);
    let store_refusal_ratio_per_mille = activity
        .store_refusals
        .saturating_mul(1000)
        .checked_div(store_attempts)
        .unwrap_or(0);
    let eviction_ratio_per_mille = ratio_per_mille(activity.evictions, activity.stores);
    json!({
        "hits": activity.hits,
        "misses": activity.misses,
        "requests": requests,
        "hit_ratio_per_mille": hit_ratio_per_mille,
        "miss_ratio_per_mille": miss_ratio_per_mille,
        "stores": activity.stores,
        "store_refusals": activity.store_refusals,
        "store_attempts": store_attempts,
        "store_ratio_per_mille": store_ratio_per_mille,
        "store_refusal_ratio_per_mille": store_refusal_ratio_per_mille,
        "evictions": activity.evictions,
        "eviction_ratio_per_mille": eviction_ratio_per_mille,
        "purges": activity.purges,
    })
}

#[cfg(feature = "cache")]
pub(super) fn cache_indexed_purge_json(
    result: &CacheIndexedPurgeBatchResult,
    soft: bool,
    limit: usize,
    batches: usize,
    path_prefix: Option<(&str, &str)>,
    cache_tag: Option<(&str, &str)>,
    path_pattern: Option<(&str, &str)>,
) -> Value {
    let mut body = json!({
        "status": "ok",
        "soft": soft,
        "matched": result.matched(),
        "purged": result.purged(),
        "not_purged": result.not_purged(),
        "purged_ratio_per_mille": ratio_per_mille_usize(result.purged(), result.matched()),
        "not_purged_ratio_per_mille": ratio_per_mille_usize(result.not_purged(), result.matched()),
        "truncated": result.truncated(),
        "repeat_required": result.truncated(),
        "limit": limit,
        "batches": result.batches,
        "batch_limit": batches,
        "batches_exhausted": result.truncated() && result.batches >= batches,
        "vhost": result.vhost,
        "route": result.route.as_deref(),
        "scope": cache_scope(result.route.as_deref()),
        "memory_matched": result.memory_matched,
        "memory_purged": result.memory_purged,
        "memory_not_purged": result.memory_not_purged(),
        "memory_purged_ratio_per_mille": ratio_per_mille_usize(result.memory_purged, result.memory_matched),
        "memory_not_purged_ratio_per_mille": ratio_per_mille_usize(result.memory_not_purged(), result.memory_matched),
        "memory_truncated": result.memory_truncated,
        "disk_matched": result.disk_matched,
        "disk_purged": result.disk_purged,
        "disk_not_purged": result.disk_not_purged(),
        "disk_purged_ratio_per_mille": ratio_per_mille_usize(result.disk_purged, result.disk_matched),
        "disk_not_purged_ratio_per_mille": ratio_per_mille_usize(result.disk_not_purged(), result.disk_matched),
        "disk_truncated": result.disk_truncated,
    });

    if let Some((key, value)) = path_prefix.or(cache_tag).or(path_pattern)
        && let Some(object) = body.as_object_mut()
    {
        object.insert(key.to_owned(), Value::String(value.to_owned()));
    }

    body
}

#[cfg(feature = "cache")]
pub(super) struct CacheIndexedPurgeBatchResult {
    pub(super) result: fluxheim_cache::CacheIndexedPurgeResult,
    pub(super) batches: usize,
}

#[cfg(feature = "cache")]
pub(super) struct CacheStalePurgeBatchResult {
    pub(super) result: fluxheim_cache::CacheStalePurgeResult,
    pub(super) batches: usize,
    pub(super) increase_limit_required: bool,
}

#[cfg(feature = "cache")]
impl std::ops::Deref for CacheIndexedPurgeBatchResult {
    type Target = fluxheim_cache::CacheIndexedPurgeResult;

    fn deref(&self) -> &Self::Target {
        &self.result
    }
}

#[cfg(feature = "cache")]
impl std::ops::Deref for CacheStalePurgeBatchResult {
    type Target = fluxheim_cache::CacheStalePurgeResult;

    fn deref(&self) -> &Self::Target {
        &self.result
    }
}

#[cfg(feature = "cache")]
pub(super) fn repeat_cache_indexed_purge(
    batches: usize,
    mut purge: impl FnMut() -> std::io::Result<fluxheim_cache::CacheIndexedPurgeResult>,
) -> std::io::Result<CacheIndexedPurgeBatchResult> {
    let mut total: Option<fluxheim_cache::CacheIndexedPurgeResult> = None;
    let mut batches_run = 0;
    for _ in 0..batches {
        let result = purge()?;
        batches_run += 1;
        let truncated = result.truncated();
        match &mut total {
            Some(total) => {
                total.memory_matched = total.memory_matched.saturating_add(result.memory_matched);
                total.memory_purged = total.memory_purged.saturating_add(result.memory_purged);
                total.disk_matched = total.disk_matched.saturating_add(result.disk_matched);
                total.disk_purged = total.disk_purged.saturating_add(result.disk_purged);
                total.memory_truncated = result.memory_truncated;
                total.disk_truncated = result.disk_truncated;
            }
            None => total = Some(result),
        }
        if !truncated {
            break;
        }
    }

    total
        .map(|result| CacheIndexedPurgeBatchResult {
            result,
            batches: batches_run,
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cache indexed purge batches must be greater than zero",
            )
        })
}

#[cfg(feature = "cache")]
pub(super) fn repeat_cache_stale_purge(
    batches: usize,
    dry_run: bool,
    mut purge: impl FnMut() -> std::io::Result<fluxheim_cache::CacheStalePurgeResult>,
) -> std::io::Result<CacheStalePurgeBatchResult> {
    let mut total: Option<fluxheim_cache::CacheStalePurgeResult> = None;
    let mut batches_run = 0;
    let mut increase_limit_required = false;

    for _ in 0..batches {
        let result = purge()?;
        batches_run += 1;
        let truncated = result.truncated();
        let purged = result.purged();
        match &mut total {
            Some(total) => {
                total.memory_scanned = total.memory_scanned.saturating_add(result.memory_scanned);
                total.memory_stale = total.memory_stale.saturating_add(result.memory_stale);
                total.memory_purged = total.memory_purged.saturating_add(result.memory_purged);
                total.disk_scanned = total.disk_scanned.saturating_add(result.disk_scanned);
                total.disk_stale = total.disk_stale.saturating_add(result.disk_stale);
                total.disk_purged = total.disk_purged.saturating_add(result.disk_purged);
                total.memory_truncated = result.memory_truncated;
                total.disk_truncated = result.disk_truncated;
            }
            None => total = Some(result),
        }

        if !truncated {
            break;
        }
        if dry_run || purged == 0 {
            increase_limit_required = true;
            break;
        }
    }

    total
        .map(|result| CacheStalePurgeBatchResult {
            result,
            batches: batches_run,
            increase_limit_required,
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cache stale purge batches must be greater than zero",
            )
        })
}

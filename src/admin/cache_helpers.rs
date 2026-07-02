use serde_json::{Value, json};

mod stats_json;
pub(super) use stats_json::*;

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

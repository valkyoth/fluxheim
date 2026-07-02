use super::*;

impl AdminApp {
    #[cfg(feature = "cache")]
    pub(super) fn cache_purge_prefix_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        path_prefix: Option<&str>,
        limit: Option<&str>,
        batches: Option<&str>,
        soft: bool,
    ) -> AdminResponse {
        let Some(vhost) = vhost.map(str::trim).filter(|vhost| !vhost.is_empty()) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "cache path-prefix purge vhost is required",
            );
        };
        let path_prefix = match validated_cache_purge_path_prefix(path_prefix) {
            Ok(path_prefix) => path_prefix,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let limit = match validated_cache_indexed_purge_limit(limit) {
            Ok(limit) => limit,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let batches = match validated_cache_indexed_purge_batches(batches) {
            Ok(batches) => batches,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let route = route.filter(|route| !route.trim().is_empty());

        match repeat_cache_indexed_purge(batches, || {
            self.proxy.purge_indexed_image_cache_path_prefix(
                fluxheim_cache::CacheIndexedPathPrefixPurgeRequest {
                    vhost,
                    route,
                    path_prefix,
                    limit,
                    soft,
                },
            )
        }) {
            Ok(result) => {
                record_cache_purge_metric(
                    "prefix",
                    &result.vhost,
                    result.route.as_deref(),
                    cache_indexed_purge_mode(soft),
                );
                json_response_value(
                    StatusCode::OK,
                    &cache_indexed_purge_json(
                        &result,
                        soft,
                        limit,
                        batches,
                        Some(("path_prefix", path_prefix)),
                        None,
                        None,
                    ),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "cache")]
    pub(super) fn cache_purge_tag_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        cache_tag: Option<&str>,
        limit: Option<&str>,
        batches: Option<&str>,
        soft: bool,
    ) -> AdminResponse {
        let Some(vhost) = vhost.map(str::trim).filter(|vhost| !vhost.is_empty()) else {
            return error_response(StatusCode::BAD_REQUEST, "cache tag purge vhost is required");
        };
        let cache_tag = match validated_cache_purge_tag(cache_tag) {
            Ok(cache_tag) => cache_tag,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let limit = match validated_cache_indexed_purge_limit(limit) {
            Ok(limit) => limit,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let batches = match validated_cache_indexed_purge_batches(batches) {
            Ok(batches) => batches,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let route = route.filter(|route| !route.trim().is_empty());

        match repeat_cache_indexed_purge(batches, || {
            self.proxy
                .purge_indexed_image_cache_tag(fluxheim_cache::CacheIndexedTagPurgeRequest {
                    vhost,
                    route,
                    cache_tag,
                    limit,
                    soft,
                })
        }) {
            Ok(result) => {
                record_cache_purge_metric(
                    "tag",
                    &result.vhost,
                    result.route.as_deref(),
                    cache_indexed_purge_mode(soft),
                );
                json_response_value(
                    StatusCode::OK,
                    &cache_indexed_purge_json(
                        &result,
                        soft,
                        limit,
                        batches,
                        None,
                        Some(("cache_tag", cache_tag)),
                        None,
                    ),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "cache")]
    pub(super) fn cache_purge_stale_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        limit: Option<&str>,
        batches: Option<&str>,
        dry_run: bool,
    ) -> AdminResponse {
        let Some(vhost) = vhost.map(str::trim).filter(|vhost| !vhost.is_empty()) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "cache stale purge vhost is required",
            );
        };
        let limit = match validated_cache_indexed_purge_limit(limit) {
            Ok(limit) => limit,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let batches = match validated_cache_indexed_purge_batches(batches) {
            Ok(batches) => batches,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let route = route.filter(|route| !route.trim().is_empty());

        match repeat_cache_stale_purge(batches, dry_run, || {
            self.proxy
                .purge_stale_image_cache(fluxheim_cache::CacheStalePurgeRequest {
                    vhost,
                    route,
                    limit,
                    dry_run,
                })
        }) {
            Ok(result) => {
                record_cache_purge_metric(
                    "stale",
                    &result.vhost,
                    result.route(),
                    cache_stale_purge_mode(dry_run),
                );
                let repeat_required = result.truncated()
                    && !result.increase_limit_required
                    && result.batches >= batches;
                json_response_value(
                    StatusCode::OK,
                    &json!({
                        "status": "ok",
                        "dry_run": dry_run,
                        "scanned": result.scanned(),
                        "stale": result.stale(),
                        "would_purge": stale_would_purge(dry_run, result.stale()),
                        "purged": result.purged(),
                        "not_purged": result.not_purged(),
                        "purged_ratio_per_mille": ratio_per_mille_usize(result.purged(), result.stale()),
                        "not_purged_ratio_per_mille": ratio_per_mille_usize(result.not_purged(), result.stale()),
                        "truncated": result.truncated(),
                        "repeat_required": repeat_required,
                        "limit": limit,
                        "batches": result.batches,
                        "batch_limit": batches,
                        "batches_exhausted": repeat_required,
                        "increase_limit_required": result.increase_limit_required,
                        "vhost": result.vhost,
                        "route": result.route(),
                        "scope": cache_scope(result.route()),
                        "memory_scanned": result.memory_scanned,
                        "memory_stale": result.memory_stale,
                        "memory_would_purge": stale_would_purge(dry_run, result.memory_stale),
                        "memory_purged": result.memory_purged,
                        "memory_not_purged": result.memory_stale.saturating_sub(result.memory_purged),
                        "memory_truncated": result.memory_truncated,
                        "disk_scanned": result.disk_scanned,
                        "disk_stale": result.disk_stale,
                        "disk_would_purge": stale_would_purge(dry_run, result.disk_stale),
                        "disk_purged": result.disk_purged,
                        "disk_not_purged": result.disk_stale.saturating_sub(result.disk_purged),
                        "disk_truncated": result.disk_truncated,
                    }),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "cache")]
    pub(super) fn cache_purge_wildcard_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        path_pattern: Option<&str>,
        limit: Option<&str>,
        batches: Option<&str>,
        soft: bool,
    ) -> AdminResponse {
        let Some(vhost) = vhost.map(str::trim).filter(|vhost| !vhost.is_empty()) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "cache wildcard purge vhost is required",
            );
        };
        let path_pattern = match validated_cache_purge_path_pattern(path_pattern) {
            Ok(path_pattern) => path_pattern,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let limit = match validated_cache_indexed_purge_limit(limit) {
            Ok(limit) => limit,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let batches = match validated_cache_indexed_purge_batches(batches) {
            Ok(batches) => batches,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let route = route.filter(|route| !route.trim().is_empty());

        match repeat_cache_indexed_purge(batches, || {
            self.proxy.purge_indexed_image_cache_path_pattern(
                fluxheim_cache::CacheIndexedPathPatternPurgeRequest {
                    vhost,
                    route,
                    path_pattern,
                    limit,
                    soft,
                },
            )
        }) {
            Ok(result) => {
                record_cache_purge_metric(
                    "wildcard",
                    &result.vhost,
                    result.route.as_deref(),
                    cache_indexed_purge_mode(soft),
                );
                json_response_value(
                    StatusCode::OK,
                    &cache_indexed_purge_json(
                        &result,
                        soft,
                        limit,
                        batches,
                        None,
                        None,
                        Some(("path_pattern", path_pattern)),
                    ),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }
}

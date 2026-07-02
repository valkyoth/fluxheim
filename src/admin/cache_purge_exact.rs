use super::*;

impl AdminApp {
    #[cfg(feature = "cache")]
    pub(super) fn cache_purge_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        host: Option<&str>,
        method: Option<&str>,
        path: Option<&str>,
        query: Option<&str>,
    ) -> AdminResponse {
        let host = match validated_cache_purge_host(host) {
            Ok(host) => host,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let method = match validated_cache_purge_method(method) {
            Ok(method) => method,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let path = match validated_cache_purge_path(path) {
            Ok(path) => path,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let query = match validated_cache_purge_query(query) {
            Ok(query) => query,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };

        match self
            .proxy
            .purge_image_cache(fluxheim_cache::CachePurgeRequest {
                vhost: vhost.filter(|vhost| !vhost.trim().is_empty()),
                route: route.filter(|route| !route.trim().is_empty()),
                host,
                method,
                path,
                query,
            }) {
            Ok(result) => {
                record_cache_purge_metric(
                    "exact",
                    &result.vhost,
                    result.route.as_deref(),
                    "normal",
                );
                json_response_value(
                    StatusCode::OK,
                    &json!({
                        "status": "ok",
                        "purged": result.purged(),
                        "not_purged": result.not_purged(),
                        "vhost": result.vhost,
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
    pub(super) fn cache_purge_bulk_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        host: Option<&str>,
        method: Option<&str>,
        paths: Vec<&str>,
        query: Option<&str>,
    ) -> AdminResponse {
        let host = match validated_cache_purge_host(host) {
            Ok(host) => host,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let method = match validated_cache_purge_method(method) {
            Ok(method) => method,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let paths = paths
            .into_iter()
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return error_response(
                StatusCode::BAD_REQUEST,
                "at least one cache purge path is required",
            );
        }
        if paths.len() > MAX_CACHE_PURGE_BULK_PATHS {
            return error_response(
                StatusCode::BAD_REQUEST,
                "too many cache purge paths requested",
            );
        }
        for path in &paths {
            if let Err(message) = validate_cache_purge_path_value(path) {
                return error_response(StatusCode::BAD_REQUEST, message);
            }
        }
        let query = match validated_cache_purge_query(query) {
            Ok(query) => query,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };

        match self
            .proxy
            .purge_image_cache_bulk(fluxheim_cache::CacheBulkPurgeRequest {
                vhost: vhost.filter(|vhost| !vhost.trim().is_empty()),
                route: route.filter(|route| !route.trim().is_empty()),
                host,
                method,
                paths,
                query,
            }) {
            Ok(result) => {
                record_cache_purge_metric("bulk", &result.vhost, result.route(), "normal");
                json_response_value(
                    StatusCode::OK,
                    &json!({
                        "status": "ok",
                        "requested": result.requested(),
                        "purged": result.purged(),
                        "not_purged": result.not_purged(),
                        "purged_ratio_per_mille": ratio_per_mille_usize(result.purged(), result.requested()),
                        "not_purged_ratio_per_mille": ratio_per_mille_usize(result.not_purged(), result.requested()),
                        "vhost": result.vhost,
                        "route": result.route(),
                        "scope": cache_scope(result.route()),
                        "memory_purged": result.memory_purged(),
                        "memory_not_purged": result.memory_not_purged(),
                        "memory_purged_ratio_per_mille": ratio_per_mille_usize(result.memory_purged(), result.requested()),
                        "memory_not_purged_ratio_per_mille": ratio_per_mille_usize(result.memory_not_purged(), result.requested()),
                        "disk_purged": result.disk_purged(),
                        "disk_not_purged": result.disk_not_purged(),
                        "disk_purged_ratio_per_mille": ratio_per_mille_usize(result.disk_purged(), result.requested()),
                        "disk_not_purged_ratio_per_mille": ratio_per_mille_usize(result.disk_not_purged(), result.requested()),
                        "results": cache_purge_results_json(&result.results),
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
    pub(super) fn cache_purge_index_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        limit: Option<&str>,
        batches: Option<&str>,
        soft: bool,
    ) -> AdminResponse {
        let Some(vhost) = vhost.map(str::trim).filter(|vhost| !vhost.is_empty()) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "cache indexed purge vhost is required",
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

        match repeat_cache_indexed_purge(batches, || {
            self.proxy
                .purge_indexed_image_cache(fluxheim_cache::CacheIndexedPurgeRequest {
                    vhost,
                    route,
                    limit,
                    soft,
                })
        }) {
            Ok(result) => {
                record_cache_purge_metric(
                    "index",
                    &result.vhost,
                    result.route.as_deref(),
                    cache_indexed_purge_mode(soft),
                );
                json_response_value(
                    StatusCode::OK,
                    &cache_indexed_purge_json(&result, soft, limit, batches, None, None, None),
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

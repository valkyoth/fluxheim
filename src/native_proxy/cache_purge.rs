use std::io;

use fluxheim_cache::{
    CacheBulkPurgeRequest, CacheBulkPurgeResult, CacheIndexedPathPatternPurgeRequest,
    CacheIndexedPathPrefixPurgeRequest, CacheIndexedPurgeRequest, CacheIndexedPurgeResult,
    CacheIndexedTagPurgeRequest, CachePurgeRequest, CachePurgeResult, CacheStalePurgeRequest,
    CacheStalePurgeResult,
};

use super::FluxProxy;

pub(super) struct CacheConfigSelection {
    pub(super) vhost_name: String,
    pub(super) route_name: Option<String>,
    pub(super) cache: crate::config::CacheConfig,
}

impl FluxProxy {
    pub(super) fn cache_config_for_request(
        &self,
        requested_vhost: Option<&str>,
        requested_route: Option<&str>,
        host: &str,
    ) -> io::Result<CacheConfigSelection> {
        let config = self.lock_config("cache config selection")?;
        let vhost = if let Some(vhost_name) = requested_vhost {
            config
                .vhosts
                .iter()
                .find(|vhost| vhost.name == vhost_name)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("vhost not found: {vhost_name}"),
                    )
                })?
        } else {
            config
                .vhosts
                .iter()
                .find(|vhost| super::native_vhost_matches_host(vhost, host))
                .or_else(|| {
                    config
                        .server
                        .default_vhost
                        .as_deref()
                        .and_then(|name| config.vhosts.iter().find(|vhost| vhost.name == name))
                })
                .or_else(|| config.vhosts.first())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no vhost configured"))?
        };
        if let Some(route_name) = requested_route {
            let route = vhost
                .routes
                .iter()
                .find(|route| route.name == route_name)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("route cache not found: {}/{route_name}", vhost.name),
                    )
                })?;
            let cache = route.cache.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("route cache not found: {}/{route_name}", vhost.name),
                )
            })?;
            Ok(CacheConfigSelection {
                vhost_name: vhost.name.clone(),
                route_name: Some(route.name.clone()),
                cache: cache.clone(),
            })
        } else {
            Ok(CacheConfigSelection {
                vhost_name: vhost.name.clone(),
                route_name: None,
                cache: vhost.cache.clone(),
            })
        }
    }

    fn validate_indexed_cache_purge_request(
        &self,
        vhost_name: &str,
        route_name: Option<&str>,
        limit: usize,
    ) -> io::Result<()> {
        if limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache indexed purge limit must be greater than zero",
            ));
        }
        let config = self.lock_config("indexed cache purge validation")?;
        let vhost = config
            .vhosts
            .iter()
            .find(|vhost| vhost.name == vhost_name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("vhost not found: {vhost_name}"),
                )
            })?;
        if let Some(route_name) = route_name {
            let route = vhost
                .routes
                .iter()
                .find(|route| route.name == route_name)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("route cache not found: {}/{route_name}", vhost.name),
                    )
                })?;
            if route.cache.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("route cache not found: {}/{route_name}", vhost.name),
                ));
            }
        }
        Ok(())
    }

    pub fn purge_image_cache(
        &self,
        request: CachePurgeRequest<'_>,
    ) -> io::Result<CachePurgeResult> {
        let selection =
            self.cache_config_for_request(request.vhost, request.route, request.host)?;
        let cache_request = fluxheim_cache::CacheRequest {
            method: request.method,
            host: Some(request.host),
            path: request.path,
            query: request.query,
        };
        let cache_key = fluxheim_cache::image_cache_key(&selection.cache, &cache_request)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    if selection.route_name.is_some() {
                        "request is not eligible for this route cache policy"
                    } else {
                        "request is not eligible for this vhost cache policy"
                    },
                )
            })?;
        let key = cache_key.as_str();
        let memory_purged = fluxheim_server::purge_native_memory_cache_primary(
            &selection.vhost_name,
            selection.route_name.as_deref(),
            key,
            key,
        );
        let disk_purged = fluxheim_server::purge_native_disk_cache_primary(
            &selection.vhost_name,
            selection.route_name.as_deref(),
            key,
            key,
        );
        let mut result = CachePurgeResult {
            vhost: selection.vhost_name.clone(),
            route: selection.route_name.clone(),
            host: request.host.to_owned(),
            method: request.method.to_owned(),
            path: request.path.to_owned(),
            query: request.query.map(str::to_owned),
            cache_key: key.to_owned(),
            memory_purged,
            disk_purged,
        };
        if selection.cache.range.enabled && selection.cache.range.slice.enabled {
            let slice_limit = usize::try_from(selection.cache.range.slice.max_slices)
                .unwrap_or(usize::MAX.saturating_sub(4))
                .saturating_add(4);
            let user_tag = fluxheim_cache::cache_user_tag(&result.vhost, result.route.as_deref());
            let native_memory = fluxheim_server::purge_native_memory_cache_path_exact(
                &result.vhost,
                result.route.as_deref(),
                &user_tag,
                request.path,
                slice_limit,
                false,
            );
            result.memory_purged |= native_memory.purged > 0;
            let native_disk = fluxheim_server::purge_native_disk_cache_path_exact(
                &result.vhost,
                result.route.as_deref(),
                &user_tag,
                request.path,
                slice_limit,
                false,
            );
            result.disk_purged |= native_disk.purged > 0;
        }
        record_native_cache_purge_activity(
            &result.vhost,
            result.route.as_deref(),
            false,
            result.disk_purged,
        );
        Ok(result)
    }

    pub fn purge_image_cache_bulk(
        &self,
        request: CacheBulkPurgeRequest<'_>,
    ) -> io::Result<CacheBulkPurgeResult> {
        if request.paths.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one cache purge path is required",
            ));
        }
        let mut results = Vec::with_capacity(request.paths.len());
        for path in request.paths {
            results.push(self.purge_image_cache(CachePurgeRequest {
                vhost: request.vhost,
                route: request.route,
                host: request.host,
                method: request.method,
                path,
                query: request.query,
            })?);
        }
        let vhost = results
            .first()
            .map(|result| result.vhost.clone())
            .unwrap_or_default();
        Ok(CacheBulkPurgeResult { vhost, results })
    }

    pub fn purge_indexed_image_cache(
        &self,
        request: CacheIndexedPurgeRequest<'_>,
    ) -> io::Result<CacheIndexedPurgeResult> {
        self.validate_indexed_cache_purge_request(request.vhost, request.route, request.limit)?;
        let user_tag = fluxheim_cache::cache_user_tag(request.vhost, request.route);
        let memory = fluxheim_server::purge_native_memory_cache_user_tag(
            request.vhost,
            request.route,
            &user_tag,
            request.limit,
            request.soft,
        );
        let disk = fluxheim_server::purge_native_disk_cache_user_tag(
            request.vhost,
            request.route,
            &user_tag,
            request.limit,
            request.soft,
        );
        Ok(native_indexed_purge_result(
            request.vhost,
            request.route,
            memory,
            disk,
        ))
    }

    pub fn purge_indexed_image_cache_path_prefix(
        &self,
        request: CacheIndexedPathPrefixPurgeRequest<'_>,
    ) -> io::Result<CacheIndexedPurgeResult> {
        self.validate_indexed_cache_purge_request(request.vhost, request.route, request.limit)?;
        if !request.path_prefix.starts_with('/') || request.path_prefix == "/" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache indexed path-prefix purge requires a non-root path prefix",
            ));
        }
        let user_tag = fluxheim_cache::cache_user_tag(request.vhost, request.route);
        let memory = fluxheim_server::purge_native_memory_cache_path_prefix(
            request.vhost,
            request.route,
            &user_tag,
            request.path_prefix,
            request.limit,
            request.soft,
        );
        let disk = fluxheim_server::purge_native_disk_cache_path_prefix(
            request.vhost,
            request.route,
            &user_tag,
            request.path_prefix,
            request.limit,
            request.soft,
        );
        Ok(native_indexed_purge_result(
            request.vhost,
            request.route,
            memory,
            disk,
        ))
    }

    pub fn purge_indexed_image_cache_tag(
        &self,
        request: CacheIndexedTagPurgeRequest<'_>,
    ) -> io::Result<CacheIndexedPurgeResult> {
        self.validate_indexed_cache_purge_request(request.vhost, request.route, request.limit)?;
        if request.cache_tag.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache tag purge requires a non-empty cache tag",
            ));
        }
        let user_tag = fluxheim_cache::cache_user_tag(request.vhost, request.route);
        let memory = fluxheim_server::purge_native_memory_cache_tag(
            request.vhost,
            request.route,
            &user_tag,
            request.cache_tag,
            request.limit,
            request.soft,
        );
        let disk = fluxheim_server::purge_native_disk_cache_tag(
            request.vhost,
            request.route,
            &user_tag,
            request.cache_tag,
            request.limit,
            request.soft,
        );
        Ok(native_indexed_purge_result(
            request.vhost,
            request.route,
            memory,
            disk,
        ))
    }

    pub fn purge_stale_image_cache(
        &self,
        request: CacheStalePurgeRequest<'_>,
    ) -> io::Result<CacheStalePurgeResult> {
        self.validate_indexed_cache_purge_request(request.vhost, request.route, request.limit)?;
        let user_tag = fluxheim_cache::cache_user_tag(request.vhost, request.route);
        let memory = fluxheim_server::purge_native_memory_cache_stale(
            request.vhost,
            request.route,
            &user_tag,
            request.limit,
            request.dry_run,
        );
        let disk = fluxheim_server::purge_native_disk_cache_stale(
            request.vhost,
            request.route,
            &user_tag,
            request.limit,
            request.dry_run,
        );
        Ok(CacheStalePurgeResult {
            vhost: request.vhost.to_owned(),
            route: request.route.map(str::to_owned),
            memory_scanned: memory.scanned,
            memory_stale: memory.stale,
            memory_purged: memory.purged,
            memory_truncated: memory.truncated,
            disk_scanned: disk.scanned,
            disk_stale: disk.stale,
            disk_purged: disk.purged,
            disk_truncated: disk.truncated,
        })
    }

    pub fn purge_indexed_image_cache_path_pattern(
        &self,
        request: CacheIndexedPathPatternPurgeRequest<'_>,
    ) -> io::Result<CacheIndexedPurgeResult> {
        self.validate_indexed_cache_purge_request(request.vhost, request.route, request.limit)?;
        if !request.path_pattern.starts_with('/')
            || !request.path_pattern.contains('*')
            || request
                .path_pattern
                .chars()
                .filter(|character| *character != '*')
                .collect::<String>()
                == "/"
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache indexed wildcard purge requires a non-root absolute path pattern",
            ));
        }
        let user_tag = fluxheim_cache::cache_user_tag(request.vhost, request.route);
        let memory = fluxheim_server::purge_native_memory_cache_path_pattern(
            request.vhost,
            request.route,
            &user_tag,
            request.path_pattern,
            request.limit,
            request.soft,
        );
        let disk = fluxheim_server::purge_native_disk_cache_path_pattern(
            request.vhost,
            request.route,
            &user_tag,
            request.path_pattern,
            request.limit,
            request.soft,
        );
        Ok(native_indexed_purge_result(
            request.vhost,
            request.route,
            memory,
            disk,
        ))
    }
}

fn native_indexed_purge_result(
    vhost: &str,
    route: Option<&str>,
    memory: fluxheim_cache::purge_index::CacheIndexedPurgeResult,
    disk: fluxheim_cache::purge_index::CacheIndexedPurgeResult,
) -> CacheIndexedPurgeResult {
    record_native_cache_purge_activity(vhost, route, memory.purged > 0, disk.purged > 0);
    CacheIndexedPurgeResult {
        vhost: vhost.to_owned(),
        route: route.map(str::to_owned),
        memory_matched: memory.matched,
        memory_purged: memory.purged,
        memory_truncated: memory.truncated,
        disk_matched: disk.matched,
        disk_purged: disk.purged,
        disk_truncated: disk.truncated,
    }
}

fn record_native_cache_purge_activity(
    vhost: &str,
    route: Option<&str>,
    memory_purged: bool,
    disk_purged: bool,
) {
    #[cfg(feature = "metrics")]
    {
        if memory_purged {
            crate::metrics::record_cache_activity("memory", "purge");
            crate::metrics::record_cache_activity_scope(vhost, route, "memory", "purge");
        }
        if disk_purged {
            crate::metrics::record_cache_activity("disk", "purge");
            crate::metrics::record_cache_activity_scope(vhost, route, "disk", "purge");
        }
    }
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (vhost, route, memory_purged, disk_purged);
    }
}

use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(feature = "cache")]
mod cache_stats;
#[cfg(feature = "load-balancer")]
mod load_balancer;

#[cfg(feature = "cache")]
use cache_stats::{
    native_cache_activity_reset_result_from_config, native_cache_runtime_stats_from_config,
    overlay_native_cache_runtime_totals,
};
#[cfg(feature = "cache")]
use fluxheim_cache::{
    CacheActivityResetResult, CacheBulkPurgeRequest, CacheBulkPurgeResult,
    CacheIndexedPathPatternPurgeRequest, CacheIndexedPathPrefixPurgeRequest,
    CacheIndexedPurgeRequest, CacheIndexedPurgeResult, CacheIndexedTagPurgeRequest,
    CacheKeyPreview, CacheKeyPreviewScope, CacheObjectHeaderValue, CacheObjectLookup,
    CacheObjectMetadata, CacheObjectTier, CachePurgeRequest, CachePurgeResult, CacheRuntimeStats,
    CacheStalePurgeRequest, CacheStalePurgeResult,
};

#[derive(Clone)]
pub struct FluxProxy {
    config: Arc<Mutex<crate::config::Config>>,
    #[cfg(feature = "load-balancer")]
    load_balancer_admin_pools: Vec<fluxheim_server::NativeLoadBalancerAdminPool>,
}

#[cfg(feature = "cache")]
struct CacheConfigSelection {
    vhost_name: String,
    route_name: Option<String>,
    cache: crate::config::CacheConfig,
}

impl FluxProxy {
    pub fn from_config(_config: &crate::config::Config) -> io::Result<Self> {
        Ok(Self {
            config: Arc::new(Mutex::new(_config.clone())),
            #[cfg(feature = "load-balancer")]
            load_balancer_admin_pools: Vec::new(),
        })
    }

    pub fn from_config_with_native_load_balancers(
        _config: &crate::config::Config,
        #[cfg(feature = "load-balancer")] load_balancer_admin_pools: Vec<
            fluxheim_server::NativeLoadBalancerAdminPool,
        >,
    ) -> io::Result<Self> {
        Ok(Self {
            config: Arc::new(Mutex::new(_config.clone())),
            #[cfg(feature = "load-balancer")]
            load_balancer_admin_pools,
        })
    }

    pub fn reload_from_config(&self, _config: &crate::config::Config) -> io::Result<()> {
        let mut config = self.lock_config("reload")?;
        *config = _config.clone();
        Ok(())
    }

    fn lock_config(
        &self,
        context: &'static str,
    ) -> io::Result<MutexGuard<'_, crate::config::Config>> {
        self.config.lock().map_err(|_| {
            io::Error::other(format!(
                "native proxy configuration lock poisoned during {context}"
            ))
        })
    }

    fn lock_config_or_abort(&self, context: &'static str) -> MutexGuard<'_, crate::config::Config> {
        self.config.lock().unwrap_or_else(|error| {
            log::error!(
                target: "fluxheim::native_proxy",
                "native proxy configuration mutex poisoned during {context}: {error}"
            );
            std::process::abort();
        })
    }

    pub fn has_health_reporter(&self) -> bool {
        false
    }

    pub fn route_host(&self, host: Option<&str>) -> String {
        let config = self.lock_config_or_abort("route_host");
        let normalized = host
            .and_then(fluxheim_config::config_net::normalize_host)
            .unwrap_or_default();
        config
            .vhosts
            .iter()
            .find(|vhost| {
                vhost
                    .hosts
                    .iter()
                    .filter_map(|host| fluxheim_config::config_net::normalize_host_pattern(host))
                    .any(|candidate| candidate == normalized)
            })
            .or_else(|| {
                config
                    .server
                    .default_vhost
                    .as_deref()
                    .and_then(|name| config.vhosts.iter().find(|vhost| vhost.name == name))
            })
            .or_else(|| config.vhosts.first())
            .map(|vhost| vhost.name.clone())
            .unwrap_or_default()
    }

    #[cfg(feature = "cache")]
    pub fn snapshot(&self) -> NativeProxySnapshot {
        let config = self.lock_config_or_abort("cache snapshot");
        NativeProxySnapshot {
            config: config.clone(),
        }
    }

    #[cfg(feature = "cache")]
    pub fn cache_runtime_stats(&self) -> io::Result<CacheRuntimeStats> {
        let config = self.lock_config("cache runtime stats")?;
        let mut stats = native_cache_runtime_stats_from_config(&config);
        let native = fluxheim_server::native_cache_runtime_totals();
        overlay_native_cache_runtime_totals(&mut stats.totals, &native);
        Ok(stats)
    }

    #[cfg(feature = "cache")]
    pub fn reset_cache_activity(&self) -> CacheActivityResetResult {
        let config = self.lock_config_or_abort("cache activity reset");
        native_cache_activity_reset_result_from_config(&config)
    }

    #[cfg(feature = "cache")]
    fn cache_config_for_request(
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
                .find(|vhost| native_vhost_matches_host(vhost, host))
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

    #[cfg(feature = "cache")]
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

    #[cfg(feature = "cache")]
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

    #[cfg(feature = "cache")]
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

    #[cfg(feature = "cache")]
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

    #[cfg(feature = "cache")]
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

    #[cfg(feature = "cache")]
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

    #[cfg(feature = "cache")]
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

    #[cfg(feature = "cache")]
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

#[cfg(feature = "cache")]
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

#[cfg(feature = "cache")]
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

#[cfg(feature = "cache")]
fn native_cache_object_metadata(
    metadata: fluxheim_server::NativeDiskCacheObjectMetadata,
) -> CacheObjectMetadata {
    CacheObjectMetadata {
        tier: CacheObjectTier::Disk,
        purge_indexed: true,
        status: metadata.status,
        fresh: metadata.fresh,
        freshness_state: metadata.freshness_state,
        serve_stale_while_revalidate: metadata.serve_stale_while_revalidate,
        serve_stale_if_error: metadata.serve_stale_if_error,
        body_bytes: metadata.body_bytes,
        weight_bytes: metadata.weight_bytes,
        created_unix_secs: metadata.created_unix_secs,
        updated_unix_secs: metadata.updated_unix_secs,
        fresh_until_unix_secs: metadata.fresh_until_unix_secs,
        age_secs: metadata.age_secs,
        fresh_ttl_secs: metadata.fresh_ttl_secs,
        stale_while_revalidate_secs: metadata.stale_while_revalidate_secs,
        stale_if_error_secs: metadata.stale_if_error_secs,
        cache_tags: metadata.cache_tags,
        header_names: metadata.header_names,
        header_values: metadata
            .header_values
            .into_iter()
            .map(|(name, value)| CacheObjectHeaderValue { name, value })
            .collect(),
    }
}

#[cfg(feature = "cache")]
fn native_cache_lookup_request_headers(
    request: &crate::http_types::NativeCachePreviewRequest,
) -> Vec<(String, String)> {
    request
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

#[cfg(feature = "cache")]
#[derive(Clone, Debug)]
pub struct NativeProxySnapshot {
    config: crate::config::Config,
}

#[cfg(feature = "cache")]
impl NativeProxySnapshot {
    #[cfg(feature = "cache")]
    pub(crate) fn native_image_cache_key_preview_for_request(
        &self,
        request: &crate::http_types::NativeCachePreviewRequest,
    ) -> CacheKeyPreview {
        let host = request
            .headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let selected = self
            .config
            .vhosts
            .iter()
            .find(|vhost| native_vhost_matches_host(vhost, host))
            .or_else(|| {
                self.config
                    .server
                    .default_vhost
                    .as_deref()
                    .and_then(|name| self.config.vhosts.iter().find(|vhost| vhost.name == name))
            })
            .or_else(|| self.config.vhosts.first());
        let vhost_name = selected
            .map(|vhost| vhost.name.clone())
            .unwrap_or_else(|| host.to_owned());
        let selected_route = selected.and_then(|vhost| {
            native_cache_preview_route(&vhost.routes, request.method.as_str(), request.uri.path())
        });
        let route_cache = selected_route.and_then(|route| route.cache.as_ref());
        let cache_config = route_cache.or_else(|| selected.map(|vhost| &vhost.cache));
        let cache_config = cache_config.unwrap_or(&self.config.cache);
        let memory_tier_enabled = cache_config.memory.enabled;
        let disk_tier_enabled = cache_config.disk.enabled;
        let method_cacheable = cache_config
            .methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(request.method.as_str()));
        let method_temporarily_bypassed =
            fluxheim_cache::cache_method_temporarily_bypassed(request.method.as_str());
        let safe_path = request
            .uri
            .path_and_query()
            .map(|path| fluxheim_common::path_safety::safe_forward_path_and_query(path.as_str()))
            .unwrap_or(false);
        let eligible = selected.is_some()
            && cache_config.enabled
            && !method_temporarily_bypassed
            && method_cacheable
            && safe_path;
        let cache_request = fluxheim_cache::CacheRequest {
            method: request.method.as_str(),
            host: Some(host),
            path: request.uri.path(),
            query: request.uri.query(),
        };
        let key = eligible
            .then(|| fluxheim_cache::image_cache_key(cache_config, &cache_request))
            .flatten();
        let reason = if selected.is_none() {
            Some("no matching vhost".to_owned())
        } else if !cache_config.enabled {
            Some("cache disabled".to_owned())
        } else if method_temporarily_bypassed {
            Some(format!(
                "method {} currently bypasses proxy cache storage",
                request.method
            ))
        } else if !method_cacheable {
            Some(format!("method {} is not cacheable", request.method))
        } else if !safe_path {
            Some("request path is not safe for cache lookup".to_owned())
        } else if key.is_none() {
            Some("path or query is not admitted by selected image cache policy".to_owned())
        } else {
            None
        };
        CacheKeyPreview {
            vhost: vhost_name.clone(),
            route: route_cache.and_then(|_| selected_route.map(|route| route.name.clone())),
            scope: if route_cache.is_some() {
                CacheKeyPreviewScope::Route
            } else {
                CacheKeyPreviewScope::Vhost
            },
            eligible: key.is_some(),
            cache_lock_enabled: cache_config.lock.enabled,
            cache_lock_wait_timeout_secs: cache_config.lock.wait_timeout_secs,
            cache_predictor_enabled: cache_config.predictor.enabled,
            origin_protection_enabled: cache_config.origin_protection.enabled,
            origin_protection_max_concurrent_fills: cache_config
                .origin_protection
                .max_concurrent_fills,
            peer_fill_enabled: cache_config.peer_fill.enabled,
            peer_fill_peer_count: cache_config.peer_fill.peers.len(),
            peer_fill_max_concurrent_requests: cache_config.peer_fill.max_concurrent_requests,
            peer_fill_fail_open: cache_config.peer_fill.fail_open,
            memory_tier_enabled,
            disk_tier_enabled,
            storage_tiers: fluxheim_cache::cache_storage_tiers(
                memory_tier_enabled,
                disk_tier_enabled,
            ),
            reason,
            namespace: key.as_ref().map(|_| "fluxheim-image-v1".to_owned()),
            key_namespace: cache_config.key_namespace.clone(),
            primary_key: key.as_ref().map(|key| key.as_str().to_owned()),
            primary_hash: key.as_ref().map(|key| key.as_str().to_owned()),
            variance_hash: None,
            combined_hash: key.as_ref().map(|key| key.as_str().to_owned()),
            user_tag: key.as_ref().map(|_| {
                route_cache
                    .and_then(|_| {
                        selected_route.map(|route| format!("{vhost_name}:route:{}", route.name))
                    })
                    .unwrap_or(vhost_name)
            }),
        }
    }

    #[cfg(feature = "cache")]
    pub(crate) fn native_image_cache_object_lookup_for_request(
        &self,
        request: &crate::http_types::NativeCachePreviewRequest,
    ) -> io::Result<CacheObjectLookup> {
        let preview = self.native_image_cache_key_preview_for_request(request);
        let mut objects = Vec::new();
        if let Some(primary_key) = preview.primary_key.as_deref()
            && let Some(vhost) = self
                .config
                .vhosts
                .iter()
                .find(|vhost| vhost.name == preview.vhost)
            && let Some(metadata) = fluxheim_server::inspect_native_disk_cache_object(
                &vhost.cache,
                primary_key,
                &native_cache_lookup_request_headers(request),
            )
        {
            objects.push(native_cache_object_metadata(metadata));
        }
        Ok(CacheObjectLookup { preview, objects })
    }
}

#[cfg(feature = "cache")]
fn native_cache_preview_route<'a>(
    routes: &'a [crate::config::RouteConfig],
    method: &str,
    path: &str,
) -> Option<&'a crate::config::RouteConfig> {
    let mut fallback = None;
    let mut best_prefix = None;
    let mut first_regex = None;
    for route in routes {
        if !fluxheim_protocol::route_method_matches(&route.methods, method) {
            continue;
        }
        if route
            .path_exact
            .as_deref()
            .is_some_and(|exact| path == exact)
        {
            return Some(route);
        }
        if let Some(prefix) = route.path_prefix.as_deref()
            && fluxheim_protocol::route_prefix_matches_path(prefix, path)
            && best_prefix
                .map(|best: &crate::config::RouteConfig| {
                    route.path_prefix.as_ref().map_or(0, String::len)
                        > best.path_prefix.as_ref().map_or(0, String::len)
                })
                .unwrap_or(true)
        {
            best_prefix = Some(route);
        }
        if first_regex.is_none()
            && route
                .path_regex
                .as_deref()
                .is_some_and(|pattern| native_route_regex_matches(pattern, path))
        {
            first_regex = Some(route);
        }
        if route.fallback {
            fallback = Some(route);
        }
    }
    best_prefix.or(first_regex).or(fallback)
}

#[cfg(feature = "cache")]
fn native_vhost_matches_host(vhost: &crate::config::VhostConfig, host: &str) -> bool {
    let Some(normalized_host) = fluxheim_config::config_net::normalize_host(host) else {
        return false;
    };
    vhost
        .hosts
        .iter()
        .filter_map(|host| fluxheim_config::config_net::normalize_host_pattern(host))
        .any(|candidate| candidate == normalized_host)
}

#[cfg(feature = "cache")]
fn native_route_regex_matches(pattern: &str, path: &str) -> bool {
    regex::RegexBuilder::new(pattern)
        .size_limit(fluxheim_config::MAX_ROUTE_REGEX_PROGRAM_BYTES)
        .dfa_size_limit(fluxheim_config::MAX_ROUTE_REGEX_PROGRAM_BYTES)
        .build()
        .map(|regex| regex.is_match(path))
        .unwrap_or(false)
}

#[cfg(all(test, feature = "cache"))]
mod tests {
    use super::*;

    fn test_config(toml: &str) -> crate::config::Config {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn route_host_normalizes_candidate_host() {
        let config = test_config(
            r#"
            [server]
            default_vhost = "fallback"

            [[vhosts]]
            name = "fallback"
            hosts = ["fallback.example"]

            [[vhosts]]
            name = "example"
            hosts = ["example.com"]
            "#,
        );
        let proxy = FluxProxy::from_config(&config).unwrap();

        assert_eq!(proxy.route_host(Some("EXAMPLE.COM:80")), "example");
    }

    #[test]
    fn cache_config_for_request_normalizes_host() {
        let config = test_config(
            r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.com"]

            [vhosts.cache]
            enabled = true
            "#,
        );
        let proxy = FluxProxy::from_config(&config).unwrap();

        let selection = proxy
            .cache_config_for_request(None, None, "EXAMPLE.COM:80")
            .unwrap();

        assert_eq!(selection.vhost_name, "example");
        assert_eq!(selection.route_name, None);
    }

    #[test]
    fn reload_updates_route_cache_stats_and_snapshot_config() {
        let initial = test_config(
            r#"
            [server]
            default_vhost = "old"

            [[vhosts]]
            name = "old"
            hosts = ["old.example"]

            [vhosts.cache]
            enabled = true
            "#,
        );
        let reloaded = test_config(
            r#"
            [server]
            default_vhost = "new"

            [[vhosts]]
            name = "new"
            hosts = ["new.example"]

            [vhosts.cache]
            enabled = true
            key_namespace = "new-vhost-cache"

            [[vhosts.routes]]
            name = "images"
            path_regex = "^/images/[0-9]+[.]png$"

            [vhosts.routes.cache]
            enabled = true
            key_namespace = "new-route-cache"
            "#,
        );
        let proxy = FluxProxy::from_config(&initial).unwrap();

        proxy.reload_from_config(&reloaded).unwrap();

        assert_eq!(proxy.route_host(Some("NEW.EXAMPLE:80")), "new");
        let selection = proxy
            .cache_config_for_request(None, None, "NEW.EXAMPLE:80")
            .unwrap();
        assert_eq!(selection.vhost_name, "new");
        assert_eq!(
            selection.cache.key_namespace.as_deref(),
            Some("new-vhost-cache")
        );
        assert!(
            proxy
                .cache_config_for_request(Some("old"), None, "old.example")
                .is_err()
        );

        let stats = proxy.cache_runtime_stats().unwrap();
        assert_eq!(stats.vhosts.len(), 1);
        assert_eq!(stats.vhosts[0].name, "new");
        assert_eq!(stats.vhosts[0].routes[0].name, "images");

        let mut request =
            crate::http_types::NativeCachePreviewRequest::build("GET", b"/images/42.png", None)
                .unwrap();
        request.insert_header("host", "NEW.EXAMPLE:80").unwrap();
        let preview = proxy
            .snapshot()
            .native_image_cache_key_preview_for_request(&request);
        assert_eq!(preview.vhost, "new");
        assert_eq!(preview.route.as_deref(), Some("images"));
    }

    #[test]
    fn cache_key_preview_normalizes_host_and_matches_regex_route() {
        let config = test_config(
            r#"
            [[vhosts]]
            name = "example"
            hosts = ["example.com"]

            [vhosts.cache]
            enabled = true
            key_namespace = "vhost-cache"

            [[vhosts.routes]]
            name = "images"
            path_regex = "^/images/[0-9]+[.]png$"

            [vhosts.routes.cache]
            enabled = true
            key_namespace = "image-route-cache"
            "#,
        );
        let proxy = FluxProxy::from_config(&config).unwrap();
        let mut request =
            crate::http_types::NativeCachePreviewRequest::build("GET", b"/images/42.png", None)
                .unwrap();
        request.insert_header("host", "EXAMPLE.COM:80").unwrap();

        let preview = proxy
            .snapshot()
            .native_image_cache_key_preview_for_request(&request);

        assert_eq!(preview.vhost, "example");
        assert_eq!(preview.route.as_deref(), Some("images"));
        assert_eq!(preview.scope, CacheKeyPreviewScope::Route);
    }
}

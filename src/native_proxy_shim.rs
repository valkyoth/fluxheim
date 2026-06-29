use std::io;
use std::sync::{Arc, Mutex};

#[cfg(feature = "cache")]
pub use crate::cache_api::{
    CacheActivityResetResult, CacheActivityStats, CacheBackgroundPurgeResult,
    CacheBulkPurgeRequest, CacheBulkPurgeResult, CacheIndexedPathPatternPurgeRequest,
    CacheIndexedPathPrefixPurgeRequest, CacheIndexedPurgeRequest, CacheIndexedPurgeResult,
    CacheIndexedTagPurgeRequest, CacheKeyPreview, CacheKeyPreviewScope, CacheObjectHeaderValue,
    CacheObjectLookup, CacheObjectMetadata, CacheObjectTier, CachePurgeRequest, CachePurgeResult,
    CacheRouteStats, CacheRuntimeStats, CacheRuntimeTotals, CacheStalePurgeRequest,
    CacheStalePurgeResult, CacheVhostStats, DiskCacheStats, MemoryCacheStats,
};

#[derive(Clone)]
pub struct FluxProxy {
    #[cfg(any(feature = "cache", feature = "load-balancer"))]
    config: crate::config::Config,
    live_config: Arc<Mutex<crate::config::Config>>,
    #[cfg(feature = "load-balancer")]
    load_balancer_admin_pools: Vec<fluxheim_server::NativeLoadBalancerAdminPool>,
}

impl FluxProxy {
    pub fn from_config(_config: &crate::config::Config) -> io::Result<Self> {
        Ok(Self {
            #[cfg(any(feature = "cache", feature = "load-balancer"))]
            config: _config.clone(),
            live_config: Arc::new(Mutex::new(_config.clone())),
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
            #[cfg(any(feature = "cache", feature = "load-balancer"))]
            config: _config.clone(),
            live_config: Arc::new(Mutex::new(_config.clone())),
            #[cfg(feature = "load-balancer")]
            load_balancer_admin_pools,
        })
    }

    pub fn reload_from_config(&self, _config: &crate::config::Config) -> io::Result<()> {
        let mut live_config = self.live_config.lock().map_err(|_| {
            io::Error::other("native proxy live configuration lock poisoned during reload")
        })?;
        *live_config = _config.clone();
        Ok(())
    }

    pub fn has_health_reporter(&self) -> bool {
        false
    }

    pub fn route_host(&self, host: Option<&str>) -> String {
        let config = self.live_config.lock().unwrap_or_else(|error| {
            log::error!(
                target: "fluxheim::native_proxy",
                "native proxy live configuration mutex poisoned in route_host: {error}"
            );
            std::process::abort();
        });
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

    #[cfg(feature = "load-balancer")]
    fn native_load_balancer_pool(
        &self,
        vhost: &str,
        route: Option<&str>,
    ) -> io::Result<(
        String,
        Option<String>,
        &fluxheim_load_balancer::UpstreamLoadBalancer,
    )> {
        let vhost = vhost.trim();
        if vhost.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "load balancer vhost is required",
            ));
        }
        let route = route.map(str::trim).filter(|route| !route.is_empty());
        self.load_balancer_admin_pools
            .iter()
            .find(|pool| pool.vhost.as_ref() == vhost && pool.route.as_deref() == route)
            .map(|pool| {
                (
                    pool.vhost.to_string(),
                    pool.route.as_ref().map(ToString::to_string),
                    &pool.load_balancer,
                )
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    if route.is_some() {
                        "load balancer route has no configured pool"
                    } else {
                        "load balancer vhost has no configured pool"
                    },
                )
            })
    }

    #[cfg(feature = "cache")]
    pub fn snapshot(&self) -> NativeProxySnapshot {
        NativeProxySnapshot {
            config: self.config.clone(),
        }
    }

    #[cfg(feature = "load-balancer")]
    pub fn load_balancer_runtime_stats(&self) -> LoadBalancerRuntimeStats {
        let mut vhosts = Vec::new();
        for vhost in &self.config.vhosts {
            let pool = self
                .native_load_balancer_pool(&vhost.name, None)
                .ok()
                .map(|(_, _, pool)| pool.runtime_stats());
            let routes = self
                .load_balancer_admin_pools
                .iter()
                .filter(|pool| pool.vhost.as_ref() == vhost.name)
                .filter_map(|pool| {
                    let route = pool.route.as_ref()?;
                    Some(LoadBalancerRouteRuntimeStats {
                        name: route.to_string(),
                        pool: pool.load_balancer.runtime_stats(),
                    })
                })
                .collect::<Vec<_>>();
            if pool.is_some() || !routes.is_empty() {
                vhosts.push(LoadBalancerVhostRuntimeStats {
                    name: vhost.name.clone(),
                    pool,
                    routes,
                });
            }
        }
        for pool in &self.load_balancer_admin_pools {
            if self
                .config
                .vhosts
                .iter()
                .any(|vhost| vhost.name == pool.vhost.as_ref())
            {
                continue;
            }
            vhosts.push(LoadBalancerVhostRuntimeStats {
                name: pool.vhost.to_string(),
                pool: pool
                    .route
                    .is_none()
                    .then(|| pool.load_balancer.runtime_stats()),
                routes: pool
                    .route
                    .as_ref()
                    .map(|route| {
                        vec![LoadBalancerRouteRuntimeStats {
                            name: route.to_string(),
                            pool: pool.load_balancer.runtime_stats(),
                        }]
                    })
                    .unwrap_or_default(),
            });
        }
        LoadBalancerRuntimeStats { vhosts }
    }

    #[cfg(feature = "load-balancer")]
    pub fn set_load_balancer_member_state(
        &self,
        request: LoadBalancerMemberStateRequest<'_>,
    ) -> io::Result<LoadBalancerMemberStateResult> {
        let member = native_load_balancer_member(request.member)?;
        let (vhost, route, pool) = self.native_load_balancer_pool(request.vhost, request.route)?;
        let mutation = pool.set_runtime_backend_state(member, request.state)?;
        Ok(LoadBalancerMemberStateResult {
            vhost,
            route,
            member: mutation.member,
            state: mutation.state,
            persistent: mutation.persistent,
            #[cfg(not(feature = "privacy-mode"))]
            address: mutation.address,
            alias: mutation.alias,
        })
    }

    #[cfg(feature = "load-balancer")]
    pub fn set_load_balancer_member_weight(
        &self,
        request: LoadBalancerMemberWeightRequest<'_>,
    ) -> io::Result<LoadBalancerMemberWeightResult> {
        let member = native_load_balancer_member(request.member)?;
        let (vhost, route, pool) = self.native_load_balancer_pool(request.vhost, request.route)?;
        let mutation = pool.set_runtime_backend_weight(member, request.weight)?;
        Ok(LoadBalancerMemberWeightResult {
            vhost,
            route,
            member: mutation.member,
            configured_weight: mutation.configured_weight,
            effective_weight: mutation.effective_weight,
            runtime_weight_override: mutation.runtime_weight_override,
            persistent: mutation.persistent,
            #[cfg(not(feature = "privacy-mode"))]
            address: mutation.address,
            alias: mutation.alias,
        })
    }

    #[cfg(feature = "load-balancer")]
    pub fn add_load_balancer_member(
        &self,
        request: LoadBalancerMemberAddRequest<'_>,
    ) -> io::Result<LoadBalancerMemberSetMutationResult> {
        let (vhost, route, pool) = self.native_load_balancer_pool(request.vhost, request.route)?;
        let mutation = pool.add_runtime_backend_member(request.member, request.weight)?;
        Ok(native_load_balancer_set_mutation_result(
            vhost, route, mutation,
        ))
    }

    #[cfg(feature = "load-balancer")]
    pub fn remove_load_balancer_member(
        &self,
        request: LoadBalancerMemberRemoveRequest<'_>,
    ) -> io::Result<LoadBalancerMemberSetMutationResult> {
        let member = native_load_balancer_member(request.member)?;
        let (vhost, route, pool) = self.native_load_balancer_pool(request.vhost, request.route)?;
        let mutation = pool.remove_runtime_backend_member(member)?;
        Ok(native_load_balancer_set_mutation_result(
            vhost, route, mutation,
        ))
    }

    #[cfg(feature = "load-balancer")]
    pub fn update_load_balancer_member(
        &self,
        request: LoadBalancerMemberUpdateRequest<'_>,
    ) -> io::Result<LoadBalancerMemberSetMutationResult> {
        let member = native_load_balancer_member(request.member)?;
        let (vhost, route, pool) = self.native_load_balancer_pool(request.vhost, request.route)?;
        let mutation =
            pool.update_runtime_backend_member(member, request.updated_member, request.weight)?;
        Ok(native_load_balancer_set_mutation_result(
            vhost, route, mutation,
        ))
    }

    #[cfg(feature = "load-balancer")]
    pub fn clear_load_balancer_persistence(
        &self,
        request: LoadBalancerPersistenceClearRequest<'_>,
    ) -> io::Result<LoadBalancerPersistenceClearResult> {
        let (vhost, route, pool) = self.native_load_balancer_pool(request.vhost, request.route)?;
        let cleared_entries = pool.clear_persistence();
        Ok(LoadBalancerPersistenceClearResult {
            vhost,
            route,
            cleared_entries,
            persistent: pool.runtime_state_persistent(),
        })
    }

    #[cfg(feature = "cache")]
    pub fn cache_runtime_stats(&self) -> io::Result<CacheRuntimeStats> {
        let mut stats = native_cache_runtime_stats_from_config(&self.config);
        let native = fluxheim_server::native_cache_runtime_totals();
        overlay_native_cache_runtime_totals(&mut stats.totals, &native);
        Ok(stats)
    }

    #[cfg(feature = "cache")]
    pub fn reset_cache_activity(&self) -> CacheActivityResetResult {
        native_cache_activity_reset_result_from_config(&self.config)
    }

    #[cfg(feature = "cache")]
    fn cache_config_for_request<'a>(
        &'a self,
        requested_vhost: Option<&str>,
        requested_route: Option<&str>,
        host: &str,
    ) -> io::Result<(
        &'a crate::config::VhostConfig,
        Option<String>,
        &'a crate::config::CacheConfig,
    )> {
        let vhost = if let Some(vhost_name) = requested_vhost {
            self.config
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
            self.config
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
                .or_else(|| self.config.vhosts.first())
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
            Ok((vhost, Some(route.name.clone()), cache))
        } else {
            Ok((vhost, None, &vhost.cache))
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
        let vhost = self
            .config
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
        let (vhost, route_name, cache_config) =
            self.cache_config_for_request(request.vhost, request.route, request.host)?;
        let cache_request = fluxheim_cache::CacheRequest {
            method: request.method,
            host: Some(request.host),
            path: request.path,
            query: request.query,
        };
        let cache_key =
            fluxheim_cache::image_cache_key(cache_config, &cache_request).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    if route_name.is_some() {
                        "request is not eligible for this route cache policy"
                    } else {
                        "request is not eligible for this vhost cache policy"
                    },
                )
            })?;
        let key = cache_key.as_str();
        let memory_purged = fluxheim_server::purge_native_memory_cache_primary(
            &vhost.name,
            route_name.as_deref(),
            key,
            key,
        );
        let disk_purged = fluxheim_server::purge_native_disk_cache_primary(
            &vhost.name,
            route_name.as_deref(),
            key,
            key,
        );
        let mut result = CachePurgeResult {
            vhost: vhost.name.clone(),
            route: route_name,
            host: request.host.to_owned(),
            method: request.method.to_owned(),
            path: request.path.to_owned(),
            query: request.query.map(str::to_owned),
            cache_key: key.to_owned(),
            memory_purged,
            disk_purged,
        };
        if cache_config.range.enabled && cache_config.range.slice.enabled {
            let slice_limit = usize::try_from(cache_config.range.slice.max_slices)
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
    request: &crate::http_types::PingoraRequestHeader,
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

#[cfg(feature = "load-balancer")]
fn native_load_balancer_member(member: &str) -> io::Result<&str> {
    let member = member.trim();
    if member.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "load balancer member is required",
        ));
    }
    Ok(member)
}

#[cfg(feature = "load-balancer")]
fn native_load_balancer_set_mutation_result(
    vhost: String,
    route: Option<String>,
    mutation: fluxheim_load_balancer::LoadBalancerRuntimeBackendSetMutation,
) -> LoadBalancerMemberSetMutationResult {
    LoadBalancerMemberSetMutationResult {
        vhost,
        route,
        member: mutation.member,
        operation: mutation.operation,
        configured_weight: mutation.configured_weight,
        backend_count: mutation.backend_count,
        persistent: mutation.persistent,
        #[cfg(not(feature = "privacy-mode"))]
        address: mutation.address,
        #[cfg(not(feature = "privacy-mode"))]
        previous_address: mutation.previous_address,
        alias: mutation.alias,
    }
}

#[cfg(feature = "cache")]
fn native_cache_runtime_stats_from_config(config: &crate::config::Config) -> CacheRuntimeStats {
    let mut totals = CacheRuntimeTotals {
        vhosts: config.vhosts.len() as u64,
        ..CacheRuntimeTotals::default()
    };
    let mut vhosts = Vec::with_capacity(config.vhosts.len());

    for vhost in &config.vhosts {
        let configured_routes = vhost.routes.len() as u64;
        totals.configured_routes = totals.configured_routes.saturating_add(configured_routes);
        let memory = native_memory_cache_stats(&vhost.cache);
        let disk = native_disk_cache_stats(&vhost.cache);
        let storage = memory.is_some() || disk.is_some();
        let tiered = memory.is_some() && disk.is_some();
        if vhost.cache.enabled {
            totals.enabled_vhosts = totals.enabled_vhosts.saturating_add(1);
        }
        if tiered {
            totals.tiered_vhosts = totals.tiered_vhosts.saturating_add(1);
        }
        if storage && vhost.cache.lock.enabled {
            totals.lock_enabled_policies = totals.lock_enabled_policies.saturating_add(1);
        }
        native_accumulate_origin_protection_stats(&mut totals, &vhost.cache);
        native_accumulate_peer_fill_stats(&mut totals, &vhost.cache);
        native_accumulate_cache_stats(&mut totals, memory.as_ref(), disk.as_ref());

        let mut routes = Vec::new();
        let mut enabled_routes = 0_u64;
        let mut tiered_routes = 0_u64;
        for route in &vhost.routes {
            let Some(cache) = &route.cache else {
                continue;
            };
            totals.routes_total = totals.routes_total.saturating_add(1);
            let route_memory = native_memory_cache_stats(cache);
            let route_disk = native_disk_cache_stats(cache);
            let route_storage = route_memory.is_some() || route_disk.is_some();
            let route_tiered = route_memory.is_some() && route_disk.is_some();
            if cache.enabled {
                totals.enabled_routes = totals.enabled_routes.saturating_add(1);
                enabled_routes = enabled_routes.saturating_add(1);
            }
            if route_tiered {
                totals.tiered_routes = totals.tiered_routes.saturating_add(1);
                tiered_routes = tiered_routes.saturating_add(1);
            }
            if route_storage && cache.lock.enabled {
                totals.lock_enabled_policies = totals.lock_enabled_policies.saturating_add(1);
            }
            native_accumulate_origin_protection_stats(&mut totals, cache);
            native_accumulate_peer_fill_stats(&mut totals, cache);
            native_accumulate_cache_stats(&mut totals, route_memory.as_ref(), route_disk.as_ref());
            routes.push(CacheRouteStats {
                name: route.name.clone(),
                enabled: cache.enabled,
                tiered: route_tiered,
                lock_enabled: route_storage && cache.lock.enabled,
                lock_wait_timeout_secs: cache.lock.wait_timeout_secs,
                origin_protection_enabled: cache.origin_protection.enabled,
                origin_protection_max_concurrent_fills: cache
                    .origin_protection
                    .max_concurrent_fills,
                peer_fill_enabled: cache.peer_fill.enabled,
                peer_fill_peers: cache.peer_fill.peers.len(),
                peer_fill_max_concurrent_requests: cache.peer_fill.max_concurrent_requests,
                peer_fill_fail_open: cache.peer_fill.fail_open,
                memory: route_memory,
                disk: route_disk,
            });
        }

        vhosts.push(CacheVhostStats {
            name: vhost.name.clone(),
            enabled: vhost.cache.enabled,
            tiered,
            lock_enabled: storage && vhost.cache.lock.enabled,
            lock_wait_timeout_secs: vhost.cache.lock.wait_timeout_secs,
            origin_protection_enabled: vhost.cache.origin_protection.enabled,
            origin_protection_max_concurrent_fills: vhost
                .cache
                .origin_protection
                .max_concurrent_fills,
            peer_fill_enabled: vhost.cache.peer_fill.enabled,
            peer_fill_peers: vhost.cache.peer_fill.peers.len(),
            peer_fill_max_concurrent_requests: vhost.cache.peer_fill.max_concurrent_requests,
            peer_fill_fail_open: vhost.cache.peer_fill.fail_open,
            configured_routes,
            routes_total: routes.len() as u64,
            enabled_routes,
            tiered_routes,
            memory,
            disk,
            routes,
        });
    }

    CacheRuntimeStats { totals, vhosts }
}

#[cfg(feature = "cache")]
fn native_cache_activity_reset_result_from_config(
    config: &crate::config::Config,
) -> CacheActivityResetResult {
    let stats = native_cache_runtime_stats_from_config(config);
    CacheActivityResetResult {
        vhosts: stats.totals.vhosts,
        enabled_vhosts: stats.totals.enabled_vhosts,
        configured_routes: stats.totals.configured_routes,
        routes_total: stats.totals.routes_total,
        enabled_routes: stats.totals.enabled_routes,
        memory_tiers: stats.totals.memory_tiers,
        disk_tiers: stats.totals.disk_tiers,
        tiered_vhosts: stats.totals.tiered_vhosts,
        tiered_routes: stats.totals.tiered_routes,
    }
}

#[cfg(feature = "cache")]
fn native_memory_cache_stats(cache: &crate::config::CacheConfig) -> Option<MemoryCacheStats> {
    (cache.enabled && cache.memory.enabled).then_some(MemoryCacheStats {
        entries: 0,
        weighted_size_bytes: 0,
        max_size_bytes: cache.memory.max_size_bytes,
        max_object_bytes: cache.max_object_bytes,
        purge_index_entries: 0,
        purge_index_max_entries: u64::MAX,
        activity: CacheActivityStats::default(),
    })
}

#[cfg(feature = "cache")]
fn native_disk_cache_stats(cache: &crate::config::CacheConfig) -> Option<DiskCacheStats> {
    (cache.enabled && cache.disk.enabled).then_some(DiskCacheStats {
        backend: match cache.disk.backend {
            crate::config::CacheDiskBackend::Filesystem => "filesystem",
            crate::config::CacheDiskBackend::StorageBin => "storage-bin",
        },
        entries: 0,
        size_bytes: 0,
        allocated_size_bytes: 0,
        free_size_bytes: 0,
        free_range_count: 0,
        largest_free_range_bytes: 0,
        bin_files: 0,
        max_size_bytes: cache.disk.max_size_bytes,
        max_object_bytes: cache.max_object_bytes,
        purge_index_entries: 0,
        purge_index_max_entries: u64::MAX,
        activity: CacheActivityStats::default(),
    })
}

#[cfg(feature = "cache")]
fn native_accumulate_cache_stats(
    totals: &mut CacheRuntimeTotals,
    memory: Option<&MemoryCacheStats>,
    disk: Option<&DiskCacheStats>,
) {
    if let Some(memory) = memory {
        totals.memory_tiers = totals.memory_tiers.saturating_add(1);
        totals.memory_entries = totals.memory_entries.saturating_add(memory.entries);
        totals.memory_weighted_size_bytes = totals
            .memory_weighted_size_bytes
            .saturating_add(memory.weighted_size_bytes);
        totals.memory_max_size_bytes = totals
            .memory_max_size_bytes
            .saturating_add(memory.max_size_bytes.as_u64());
        totals.memory_purge_index_entries = totals
            .memory_purge_index_entries
            .saturating_add(memory.purge_index_entries);
        totals.memory_purge_index_max_entries = totals
            .memory_purge_index_max_entries
            .saturating_add(memory.purge_index_max_entries);
    }
    if let Some(disk) = disk {
        totals.disk_tiers = totals.disk_tiers.saturating_add(1);
        totals.disk_entries = totals.disk_entries.saturating_add(disk.entries);
        totals.disk_size_bytes = totals.disk_size_bytes.saturating_add(disk.size_bytes);
        totals.disk_allocated_size_bytes = totals
            .disk_allocated_size_bytes
            .saturating_add(disk.allocated_size_bytes);
        totals.disk_free_size_bytes = totals
            .disk_free_size_bytes
            .saturating_add(disk.free_size_bytes);
        totals.disk_free_range_count = totals
            .disk_free_range_count
            .saturating_add(disk.free_range_count);
        totals.disk_largest_free_range_bytes = totals
            .disk_largest_free_range_bytes
            .max(disk.largest_free_range_bytes);
        totals.disk_bin_files = totals.disk_bin_files.saturating_add(disk.bin_files);
        totals.disk_max_size_bytes = totals
            .disk_max_size_bytes
            .saturating_add(disk.max_size_bytes.as_u64());
        totals.disk_purge_index_entries = totals
            .disk_purge_index_entries
            .saturating_add(disk.purge_index_entries);
        totals.disk_purge_index_max_entries = totals
            .disk_purge_index_max_entries
            .saturating_add(disk.purge_index_max_entries);
    }
}

#[cfg(feature = "cache")]
fn native_accumulate_peer_fill_stats(
    totals: &mut CacheRuntimeTotals,
    cache: &crate::config::CacheConfig,
) {
    if !cache.peer_fill.enabled {
        return;
    }
    totals.peer_fill_enabled_policies = totals.peer_fill_enabled_policies.saturating_add(1);
    totals.peer_fill_peers = totals
        .peer_fill_peers
        .saturating_add(cache.peer_fill.peers.len() as u64);
    totals.peer_fill_max_concurrent_requests = totals
        .peer_fill_max_concurrent_requests
        .max(cache.peer_fill.max_concurrent_requests as u64);
}

#[cfg(feature = "cache")]
fn native_accumulate_origin_protection_stats(
    totals: &mut CacheRuntimeTotals,
    cache: &crate::config::CacheConfig,
) {
    if !cache.origin_protection.enabled {
        return;
    }
    totals.origin_protection_enabled_policies =
        totals.origin_protection_enabled_policies.saturating_add(1);
    totals.origin_protection_max_concurrent_fills = totals
        .origin_protection_max_concurrent_fills
        .max(cache.origin_protection.max_concurrent_fills as u64);
}

#[cfg(feature = "cache")]
fn overlay_native_cache_runtime_totals(
    totals: &mut CacheRuntimeTotals,
    native: &fluxheim_server::NativeCacheRuntimeTotals,
) {
    totals.memory_entries = native.memory_entries;
    totals.memory_weighted_size_bytes = native.memory_weighted_size_bytes;
    totals.memory_purge_index_entries = native.memory_purge_index_entries;
    totals.disk_entries = native.disk_entries;
    totals.disk_size_bytes = native.disk_size_bytes;
    totals.disk_allocated_size_bytes = native.disk_allocated_size_bytes;
    totals.disk_free_size_bytes = native.disk_free_size_bytes;
    totals.disk_free_range_count = native.disk_free_range_count;
    totals.disk_largest_free_range_bytes = native.disk_largest_free_range_bytes;
    totals.disk_bin_files = native.disk_bin_files;
    totals.disk_purge_index_entries = native.disk_purge_index_entries;
}

#[cfg(feature = "cache")]
#[derive(Clone, Debug)]
pub struct NativeProxySnapshot {
    config: crate::config::Config,
}

#[cfg(feature = "cache")]
impl NativeProxySnapshot {
    #[cfg(feature = "cache")]
    pub(crate) fn pingora_image_cache_key_preview_for_request_header(
        &self,
        request: &crate::http_types::PingoraRequestHeader,
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
    pub(crate) fn pingora_image_cache_object_lookup_for_request_header(
        &self,
        request: &crate::http_types::PingoraRequestHeader,
    ) -> io::Result<CacheObjectLookup> {
        let preview = self.pingora_image_cache_key_preview_for_request_header(request);
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

        assert_eq!(proxy.route_host(Some("EXAMPLE.COM")), "example");
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

        let (vhost, route, _cache) = proxy
            .cache_config_for_request(None, None, "EXAMPLE.COM")
            .unwrap();

        assert_eq!(vhost.name, "example");
        assert_eq!(route, None);
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
            crate::http_types::PingoraRequestHeader::build("GET", b"/images/42.png", None).unwrap();
        request.insert_header("host", "EXAMPLE.COM").unwrap();

        let preview = proxy
            .snapshot()
            .pingora_image_cache_key_preview_for_request_header(&request);

        assert_eq!(preview.vhost, "example");
        assert_eq!(preview.route.as_deref(), Some("images"));
        assert_eq!(preview.scope, CacheKeyPreviewScope::Route);
    }
}

#[cfg(feature = "load-balancer")]
#[derive(Clone, Debug, serde::Serialize)]
pub struct LoadBalancerRuntimeStats {
    pub vhosts: Vec<LoadBalancerVhostRuntimeStats>,
}

#[cfg(feature = "load-balancer")]
#[derive(Clone, Debug, serde::Serialize)]
pub struct LoadBalancerVhostRuntimeStats {
    pub name: String,
    pub pool: Option<fluxheim_load_balancer::LoadBalancerPoolRuntimeStats>,
    pub routes: Vec<LoadBalancerRouteRuntimeStats>,
}

#[cfg(feature = "load-balancer")]
#[derive(Clone, Debug, serde::Serialize)]
pub struct LoadBalancerRouteRuntimeStats {
    pub name: String,
    pub pool: fluxheim_load_balancer::LoadBalancerPoolRuntimeStats,
}

#[cfg(feature = "load-balancer")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadBalancerMemberStateRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub member: &'a str,
    pub state: crate::load_balancer::LoadBalancerRuntimeBackendState,
}

#[cfg(feature = "load-balancer")]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct LoadBalancerMemberStateResult {
    pub vhost: String,
    pub route: Option<String>,
    pub member: String,
    pub state: crate::load_balancer::LoadBalancerRuntimeBackendState,
    pub persistent: bool,
    #[cfg(not(feature = "privacy-mode"))]
    pub address: String,
    pub alias: Option<String>,
}

#[cfg(feature = "load-balancer")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadBalancerMemberWeightRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub member: &'a str,
    pub weight: Option<usize>,
}

#[cfg(feature = "load-balancer")]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct LoadBalancerMemberWeightResult {
    pub vhost: String,
    pub route: Option<String>,
    pub member: String,
    pub configured_weight: usize,
    pub effective_weight: usize,
    pub runtime_weight_override: Option<usize>,
    pub persistent: bool,
    #[cfg(not(feature = "privacy-mode"))]
    pub address: String,
    pub alias: Option<String>,
}

#[cfg(feature = "load-balancer")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadBalancerMemberAddRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub member: &'a str,
    pub weight: usize,
}

#[cfg(feature = "load-balancer")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadBalancerMemberRemoveRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub member: &'a str,
}

#[cfg(feature = "load-balancer")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadBalancerMemberUpdateRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub member: &'a str,
    pub updated_member: Option<&'a str>,
    pub weight: Option<usize>,
}

#[cfg(feature = "load-balancer")]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct LoadBalancerMemberSetMutationResult {
    pub vhost: String,
    pub route: Option<String>,
    pub member: String,
    pub operation: crate::load_balancer::LoadBalancerRuntimeBackendSetOperation,
    pub configured_weight: usize,
    pub backend_count: usize,
    pub persistent: bool,
    #[cfg(not(feature = "privacy-mode"))]
    pub address: String,
    #[cfg(not(feature = "privacy-mode"))]
    pub previous_address: Option<String>,
    pub alias: Option<String>,
}

#[cfg(feature = "load-balancer")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadBalancerPersistenceClearRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
}

#[cfg(feature = "load-balancer")]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct LoadBalancerPersistenceClearResult {
    pub vhost: String,
    pub route: Option<String>,
    pub cleared_entries: usize,
    pub persistent: bool,
}

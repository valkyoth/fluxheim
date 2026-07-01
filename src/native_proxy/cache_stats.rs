use fluxheim_cache::{
    CacheActivityResetResult, CacheActivityStats, CacheRouteStats, CacheRuntimeStats,
    CacheRuntimeTotals, CacheVhostStats, DiskCacheStats, MemoryCacheStats,
};

pub(super) fn native_cache_runtime_stats_from_config(
    config: &crate::config::Config,
) -> CacheRuntimeStats {
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

pub(super) fn native_cache_activity_reset_result_from_config(
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

pub(super) fn overlay_native_cache_runtime_totals(
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

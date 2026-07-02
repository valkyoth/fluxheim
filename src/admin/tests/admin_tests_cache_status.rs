use super::*;

#[cfg(feature = "cache")]
#[test]
fn cache_activity_json_reports_request_count_and_hit_ratio() {
    let body = super::super::cache_activity_json(&fluxheim_cache::CacheActivityStats {
        hits: 7,
        misses: 3,
        stores: 4,
        store_refusals: 2,
        evictions: 5,
        purges: 1,
    });

    assert_eq!(
        body,
        serde_json::json!({
            "hits": 7,
            "misses": 3,
            "requests": 10,
            "hit_ratio_per_mille": 700,
            "miss_ratio_per_mille": 300,
            "stores": 4,
            "store_refusals": 2,
            "store_attempts": 6,
            "store_ratio_per_mille": 666,
            "store_refusal_ratio_per_mille": 333,
            "evictions": 5,
            "eviction_ratio_per_mille": 1250,
            "purges": 1,
        })
    );
}

#[cfg(feature = "cache")]
#[test]
fn cache_ratio_per_mille_handles_empty_and_full_capacity() {
    assert_eq!(super::super::ratio_per_mille(0, 0), 0);
    assert_eq!(super::super::ratio_per_mille(0, 1024), 0);
    assert_eq!(super::super::ratio_per_mille(512, 2048), 250);
    assert_eq!(super::super::ratio_per_mille(2048, 2048), 1000);
    assert_eq!(super::super::ratio_per_mille(4096, 2048), 2000);
}

#[cfg(feature = "cache")]
#[test]
fn cache_ratio_per_mille_usize_handles_empty_and_full_capacity() {
    assert_eq!(super::super::ratio_per_mille_usize(0, 0), 0);
    assert_eq!(super::super::ratio_per_mille_usize(0, 1024), 0);
    assert_eq!(super::super::ratio_per_mille_usize(512, 2048), 250);
    assert_eq!(super::super::ratio_per_mille_usize(2048, 2048), 1000);
    assert_eq!(super::super::ratio_per_mille_usize(4096, 2048), 2000);
}

#[cfg(feature = "cache")]
#[test]
fn stale_purge_batching_repeats_while_progressing() {
    let mut calls = 0;
    let result = super::super::repeat_cache_stale_purge(4, false, || {
        calls += 1;
        Ok(fluxheim_cache::CacheStalePurgeResult {
            vhost: "cached".to_owned(),
            route: None,
            memory_scanned: 1,
            memory_stale: 1,
            memory_purged: 1,
            memory_truncated: calls == 1,
            disk_scanned: 0,
            disk_stale: 0,
            disk_purged: 0,
            disk_truncated: false,
        })
    })
    .unwrap();

    assert_eq!(calls, 2);
    assert_eq!(result.batches, 2);
    assert_eq!(result.scanned(), 2);
    assert_eq!(result.stale(), 2);
    assert_eq!(result.purged(), 2);
    assert!(!result.truncated());
    assert!(!result.increase_limit_required);
}

#[cfg(feature = "cache")]
#[test]
fn stale_purge_batching_does_not_repeat_dry_runs() {
    let mut calls = 0;
    let result = super::super::repeat_cache_stale_purge(4, true, || {
        calls += 1;
        Ok(fluxheim_cache::CacheStalePurgeResult {
            vhost: "cached".to_owned(),
            route: None,
            memory_scanned: 1,
            memory_stale: 1,
            memory_purged: 0,
            memory_truncated: true,
            disk_scanned: 0,
            disk_stale: 0,
            disk_purged: 0,
            disk_truncated: false,
        })
    })
    .unwrap();

    assert_eq!(calls, 1);
    assert_eq!(result.batches, 1);
    assert_eq!(result.scanned(), 1);
    assert_eq!(result.stale(), 1);
    assert_eq!(result.purged(), 0);
    assert!(result.truncated());
    assert!(result.increase_limit_required);
}

#[cfg(feature = "cache")]
#[test]
fn cache_average_bytes_handles_empty_and_partial_capacity() {
    assert_eq!(super::super::average_bytes(0, 0), 0);
    assert_eq!(super::super::average_bytes(0, 8), 0);
    assert_eq!(super::super::average_bytes(1024, 4), 256);
    assert_eq!(super::super::average_bytes(1025, 4), 256);
}

#[cfg(feature = "cache")]
#[test]
fn cache_status_endpoint_reports_vhost_cache_tiers() {
    let cache_path = unique_temp_path("admin-cache-status");
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "cached".to_owned(),
            hosts: vec!["cached.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig {
                enabled: true,
                memory: crate::config::CacheMemoryConfig {
                    enabled: true,
                    max_size_bytes: ByteSize::from_bytes(2048),
                },
                disk: crate::config::CacheDiskConfig {
                    enabled: true,
                    path: Some(cache_path.clone()),
                    max_size_bytes: ByteSize::from_bytes(4096),
                    ..crate::config::CacheDiskConfig::default()
                },
                peer_fill: crate::config::CachePeerFillConfig {
                    enabled: true,
                    peers: vec![crate::config::CachePeerConfig {
                        name: "cache-peer".to_owned(),
                        base_url: "https://cache-peer.example:8443".to_owned(),
                    }],
                    max_concurrent_requests: 128,
                    ..crate::config::CachePeerFillConfig::default()
                },
                origin_protection: crate::config::CacheOriginProtectionConfig {
                    enabled: true,
                    max_concurrent_fills: 16,
                },
                max_object_bytes: ByteSize::from_bytes(512),
                ..CacheConfig::default()
            },
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: vec![cached_assets_route(), uncached_api_route()],
        }],
        ..Config::default()
    };
    let app = app_with_config(config);

    let unauthorized = app.handle("GET", "/_fluxheim/cache/status", None, &HeaderMap::new());
    assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);

    let response = app.handle("GET", "/_fluxheim/cache/status", None, &auth_headers());

    assert_eq!(response.status, StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["status"], "ok");
    let totals = &body["totals"];
    assert_eq!(totals["vhosts"], 1);
    assert_eq!(totals["enabled_vhosts"], 1);
    assert_eq!(totals["enabled_vhost_ratio_per_mille"], 1000);
    assert_eq!(totals["tiered_vhosts"], 1);
    assert_eq!(totals["tiered_vhost_ratio_per_mille"], 1000);
    assert_eq!(totals["configured_routes"], 2);
    assert_eq!(totals["routes_total"], 1);
    assert_eq!(totals["cache_route_coverage_ratio_per_mille"], 500);
    assert_eq!(totals["enabled_routes"], 1);
    assert_eq!(totals["enabled_route_ratio_per_mille"], 1000);
    assert_eq!(totals["tiered_routes"], 0);
    assert_eq!(totals["tiered_route_ratio_per_mille"], 0);
    assert_eq!(totals["lock_enabled_policies"], 2);
    assert_eq!(totals["lock_enabled_policy_ratio_per_mille"], 1000);
    assert_eq!(totals["origin_protection_enabled_policies"], 1);
    assert_eq!(
        totals["origin_protection_enabled_policy_ratio_per_mille"],
        500
    );
    assert_eq!(totals["origin_protection_max_concurrent_fills"], 16);
    assert_eq!(totals["peer_fill_enabled_policies"], 1);
    assert_eq!(totals["peer_fill_enabled_policy_ratio_per_mille"], 500);
    assert_eq!(totals["peer_fill_peers"], 1);
    assert_eq!(totals["peer_fill_max_concurrent_requests"], 128);
    assert_eq!(totals["memory_tiers"], 2);
    assert_eq!(totals["memory_entries"], 0);
    assert_eq!(totals["memory_average_weighted_size_bytes"], 0);
    assert_eq!(totals["memory_fill_ratio_per_mille"], 0);
    assert_eq!(totals["memory_purge_index_entries"], 0);
    assert_eq!(
        totals["memory_purge_index_max_entries"],
        serde_json::json!(u64::MAX)
    );
    assert_eq!(totals["memory_purge_index_fill_ratio_per_mille"], 0);
    assert_eq!(totals["disk_tiers"], 1);
    assert_eq!(totals["disk_entries"], 0);
    assert_eq!(totals["disk_average_object_size_bytes"], 0);
    assert_eq!(totals["disk_fill_ratio_per_mille"], 0);
    assert_eq!(totals["disk_purge_index_entries"], 0);
    assert_eq!(
        totals["disk_purge_index_max_entries"],
        serde_json::json!(u64::MAX)
    );
    assert_eq!(totals["disk_purge_index_fill_ratio_per_mille"], 0);
    assert_eq!(totals["activity"]["requests"], 0);
    assert_eq!(totals["activity"]["hit_ratio_per_mille"], 0);

    let vhost = &body["vhosts"][0];
    assert_eq!(vhost["name"], "cached");
    assert_eq!(vhost["enabled"], true);
    assert_eq!(vhost["tiered"], true);
    assert_eq!(vhost["lock_enabled"], true);
    assert_eq!(vhost["lock_wait_timeout_secs"], 30);
    assert_eq!(vhost["origin_protection_enabled"], true);
    assert_eq!(vhost["origin_protection_max_concurrent_fills"], 16);
    assert_eq!(vhost["peer_fill_enabled"], true);
    assert_eq!(vhost["peer_fill_peers"], 1);
    assert_eq!(vhost["peer_fill_max_concurrent_requests"], 128);
    assert_eq!(vhost["peer_fill_fail_open"], true);
    assert_eq!(vhost["storage_tiers"], 2);
    assert_eq!(vhost["configured_routes"], 2);
    assert_eq!(vhost["routes_total"], 1);
    assert_eq!(vhost["cache_route_coverage_ratio_per_mille"], 500);
    assert_eq!(vhost["enabled_routes"], 1);
    assert_eq!(vhost["enabled_route_ratio_per_mille"], 1000);
    assert_eq!(vhost["tiered_routes"], 0);
    assert_eq!(vhost["tiered_route_ratio_per_mille"], 0);
    assert_eq!(vhost["memory"]["entries"], 0);
    assert_eq!(vhost["memory"]["average_weighted_size_bytes"], 0);
    assert_eq!(vhost["memory"]["fill_ratio_per_mille"], 0);
    assert_eq!(vhost["memory"]["purge_index_entries"], 0);
    assert_eq!(
        vhost["memory"]["purge_index_max_entries"],
        serde_json::json!(u64::MAX)
    );
    assert_eq!(vhost["memory"]["purge_index_fill_ratio_per_mille"], 0);
    assert_eq!(vhost["disk"]["backend"], "filesystem");
    assert_eq!(vhost["disk"]["entries"], 0);
    assert_eq!(vhost["disk"]["average_object_size_bytes"], 0);
    assert_eq!(vhost["disk"]["allocated_size_bytes"], 0);
    assert_eq!(vhost["disk"]["free_size_bytes"], 0);
    assert_eq!(vhost["disk"]["free_ratio_per_mille"], 0);
    assert_eq!(vhost["disk"]["free_range_count"], 0);
    assert_eq!(vhost["disk"]["largest_free_range_bytes"], 0);
    assert_eq!(vhost["disk"]["bin_files"], 0);
    let route = &vhost["routes"][0];
    assert_eq!(route["name"], "assets");
    assert_eq!(route["enabled"], true);
    assert_eq!(route["tiered"], false);
    assert_eq!(route["lock_enabled"], true);
    assert_eq!(route["lock_wait_timeout_secs"], 30);
    assert_eq!(route["origin_protection_enabled"], false);
    assert_eq!(route["origin_protection_max_concurrent_fills"], 32);
    assert_eq!(route["peer_fill_enabled"], false);
    assert_eq!(route["peer_fill_peers"], 0);
    assert_eq!(route["peer_fill_max_concurrent_requests"], 64);
    assert_eq!(route["peer_fill_fail_open"], true);
    assert_eq!(route["storage_tiers"], 1);

    let _ = std::fs::remove_dir_all(cache_path);
}

#[cfg(feature = "cache")]
#[test]
fn cache_status_endpoint_reports_route_tiered_cache() {
    let cache_path = unique_temp_path("admin-cache-status-route-tiered");
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "cached".to_owned(),
            hosts: vec!["cached.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: vec![cached_tiered_route(&cache_path)],
        }],
        ..Config::default()
    };
    let app = app_with_config(config);

    let response = app.handle("GET", "/_fluxheim/cache/status", None, &auth_headers());

    assert_eq!(response.status, StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    let totals = &body["totals"];
    assert_eq!(totals["vhosts"], 1);
    assert_eq!(totals["enabled_vhosts"], 0);
    assert_eq!(totals["tiered_vhosts"], 0);
    assert_eq!(totals["configured_routes"], 1);
    assert_eq!(totals["routes_total"], 1);
    assert_eq!(totals["cache_route_coverage_ratio_per_mille"], 1000);
    assert_eq!(totals["enabled_routes"], 1);
    assert_eq!(totals["enabled_route_ratio_per_mille"], 1000);
    assert_eq!(totals["tiered_routes"], 1);
    assert_eq!(totals["tiered_route_ratio_per_mille"], 1000);
    assert_eq!(totals["lock_enabled_policies"], 1);
    assert_eq!(totals["lock_enabled_policy_ratio_per_mille"], 1000);
    assert_eq!(totals["peer_fill_enabled_policies"], 0);
    assert_eq!(totals["peer_fill_enabled_policy_ratio_per_mille"], 0);
    assert_eq!(totals["memory_tiers"], 1);
    assert_eq!(totals["disk_tiers"], 1);

    let vhost = &body["vhosts"][0];
    assert_eq!(vhost["name"], "cached");
    assert_eq!(vhost["enabled"], false);
    assert_eq!(vhost["tiered"], false);
    assert_eq!(vhost["lock_enabled"], false);
    assert_eq!(vhost["lock_wait_timeout_secs"], 30);
    assert_eq!(vhost["peer_fill_enabled"], false);
    assert_eq!(vhost["peer_fill_peers"], 0);
    assert_eq!(vhost["peer_fill_max_concurrent_requests"], 64);
    assert_eq!(vhost["peer_fill_fail_open"], true);
    let route = &vhost["routes"][0];
    assert_eq!(route["name"], "media");
    assert_eq!(route["enabled"], true);
    assert_eq!(route["tiered"], true);
    assert_eq!(route["lock_enabled"], true);
    assert_eq!(route["storage_tiers"], 2);
    assert_eq!(route["memory"]["entries"], 0);
    assert_eq!(route["disk"]["backend"], "filesystem");
    assert_eq!(route["disk"]["entries"], 0);

    let _ = std::fs::remove_dir_all(cache_path);
}

#[cfg(feature = "cache")]
#[test]
fn cache_activity_reset_endpoint_requires_auth_and_reports_tiers() {
    let cache_path = unique_temp_path("admin-cache-reset");
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "cached".to_owned(),
            hosts: vec!["cached.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig {
                enabled: true,
                memory: crate::config::CacheMemoryConfig {
                    enabled: true,
                    max_size_bytes: ByteSize::from_bytes(2048),
                },
                disk: crate::config::CacheDiskConfig {
                    enabled: true,
                    path: Some(cache_path.clone()),
                    max_size_bytes: ByteSize::from_bytes(4096),
                    ..crate::config::CacheDiskConfig::default()
                },
                max_object_bytes: ByteSize::from_bytes(512),
                ..CacheConfig::default()
            },
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: vec![cached_assets_route(), uncached_api_route()],
        }],
        ..Config::default()
    };
    let app = app_with_config(config);

    let unauthorized = app.handle(
        "POST",
        "/_fluxheim/cache/activity/reset",
        None,
        &HeaderMap::new(),
    );
    assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);

    let response = app.handle(
        "POST",
        "/_fluxheim/cache/activity/reset",
        None,
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""status":"ok""#));
    assert!(body.contains(r#""vhosts":1"#));
    assert!(body.contains(r#""enabled_vhosts":1"#));
    assert!(body.contains(r#""enabled_vhost_ratio_per_mille":1000"#));
    assert!(body.contains(r#""tiered_vhosts":1"#));
    assert!(body.contains(r#""tiered_vhost_ratio_per_mille":1000"#));
    assert!(body.contains(r#""configured_routes":2"#));
    assert!(body.contains(r#""routes_total":1"#));
    assert!(body.contains(r#""cache_route_coverage_ratio_per_mille":500"#));
    assert!(body.contains(r#""enabled_routes":1"#));
    assert!(body.contains(r#""enabled_route_ratio_per_mille":1000"#));
    assert!(body.contains(r#""tiered_routes":0"#));
    assert!(body.contains(r#""tiered_route_ratio_per_mille":0"#));
    assert!(body.contains(r#""memory_tiers":2"#));
    assert!(body.contains(r#""disk_tiers":1"#));

    let _ = std::fs::remove_dir_all(cache_path);
}

#[cfg(feature = "cache")]
#[test]
fn cache_activity_reset_endpoint_reports_route_tiered_cache() {
    let cache_path = unique_temp_path("admin-cache-reset-route-tiered");
    let config = Config {
        vhosts: vec![VhostConfig {
            name: "cached".to_owned(),
            hosts: vec!["cached.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: vec![cached_tiered_route(&cache_path)],
        }],
        ..Config::default()
    };
    let app = app_with_config(config);

    let response = app.handle(
        "POST",
        "/_fluxheim/cache/activity/reset",
        None,
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""status":"ok""#));
    assert!(body.contains(r#""vhosts":1"#));
    assert!(body.contains(r#""enabled_vhosts":0"#));
    assert!(body.contains(r#""enabled_vhost_ratio_per_mille":0"#));
    assert!(body.contains(r#""tiered_vhosts":0"#));
    assert!(body.contains(r#""tiered_vhost_ratio_per_mille":0"#));
    assert!(body.contains(r#""configured_routes":1"#));
    assert!(body.contains(r#""routes_total":1"#));
    assert!(body.contains(r#""cache_route_coverage_ratio_per_mille":1000"#));
    assert!(body.contains(r#""enabled_routes":1"#));
    assert!(body.contains(r#""enabled_route_ratio_per_mille":1000"#));
    assert!(body.contains(r#""tiered_routes":1"#));
    assert!(body.contains(r#""tiered_route_ratio_per_mille":1000"#));
    assert!(body.contains(r#""memory_tiers":1"#));
    assert!(body.contains(r#""disk_tiers":1"#));

    let _ = std::fs::remove_dir_all(cache_path);
}

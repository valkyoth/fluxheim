use std::time::Duration;

use crate::{
    DownstreamHttp1Policy, NativeHttp1Handler, NativeHttp1HostRouter, NativeHttp1ReloadableRouter,
    NativeHttp1Response, NativeRequestBodyBudget,
};

use super::{
    native_proxy_storage_bin_cache_config, route_test_request, upstream_raw_response_sequence,
};

const ORIGIN_RESPONSE: &str = "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=120\r\ncontent-length: 4\r\n\r\nbody";

fn config(root: &std::path::Path, upstream: std::net::SocketAddr) -> fluxheim_config::Config {
    let mut config = fluxheim_config::Config::default();
    config.proxy.upstream = Some(upstream.to_string());
    config.proxy.upstream_tls = false;
    config.cache = native_proxy_storage_bin_cache_config(root.to_path_buf());
    config
}

async fn get(handler: &(impl NativeHttp1Handler + ?Sized)) -> NativeHttp1Response {
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        handler.handle(route_test_request("/asset.png")),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"body");
    response
}

fn cache_status(response: &NativeHttp1Response) -> Option<&str> {
    response.headers().iter().find_map(|(name, value)| {
        name.eq_ignore_ascii_case("x-cache-status")
            .then_some(value.as_str())
    })
}

#[tokio::test]
async fn named_scope_reload_and_late_failure_preserve_disk_and_release_cancelled_pins() {
    for route_scope in [false, true] {
        for backend in [
            fluxheim_config::CacheDiskBackend::Filesystem,
            fluxheim_config::CacheDiskBackend::StorageBin,
        ] {
            let root = tempfile::tempdir().unwrap();
            let origin = upstream_raw_response_sequence(&[("/asset.png", ORIGIN_RESPONSE)]).await;
            let mut baseline = config(&root.path().canonicalize().unwrap(), origin);
            baseline.cache.disk.backend = backend;
            let mut vhost = super::native_route_proxy_test_vhost();
            if route_scope {
                let mut route = super::native_route_proxy_test_route();
                route.path_exact = Some("/asset.png".into());
                route.redirect = None;
                route.proxy = Some(baseline.proxy.clone());
                route.cache = Some(baseline.cache.clone());
                vhost.routes.push(route);
            } else {
                vhost.proxy = baseline.proxy.clone();
                vhost.cache = baseline.cache.clone();
            }
            baseline.vhosts.push(vhost);
            let initial =
                NativeHttp1HostRouter::from_config(&baseline, DownstreamHttp1Policy::default(), 0)
                    .unwrap();
            let (router, reloader) = NativeHttp1ReloadableRouter::new(
                initial,
                DownstreamHttp1Policy::default(),
                0,
                false,
                NativeRequestBodyBudget::new(1024 * 1024),
            );
            assert_eq!(cache_status(&get(&router).await), Some("MISS"));
            reloader.reload_from_config(&baseline).unwrap();
            let mut invalid = baseline.clone();
            invalid.server.default_vhost = Some("missing".into());
            assert!(reloader.reload_from_config(&invalid).is_err());
            assert_eq!(cache_status(&get(&router).await), Some("HIT"));
            let pin = router.pin_request_handler().unwrap();
            let (started, ready) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let _pin = pin;
                started.send(()).unwrap();
                std::future::pending::<()>().await;
            });
            ready.await.unwrap();
            drop(reloader);
            drop(router);
            if backend == fluxheim_config::CacheDiskBackend::StorageBin {
                assert!(
                    crate::native_http1_cache::NativeDiskCache::try_from_config(&baseline.cache)
                        .is_err()
                );
            }
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            let restarted =
                NativeHttp1HostRouter::from_config(&baseline, DownstreamHttp1Policy::default(), 0)
                    .unwrap();
            assert_eq!(cache_status(&get(&restarted).await), Some("HIT"));
        }
    }
}

#[tokio::test]
async fn disk_reload_reuses_allocator_preserves_pins_and_rejects_incompatible_candidates() {
    for backend in [
        fluxheim_config::CacheDiskBackend::Filesystem,
        fluxheim_config::CacheDiskBackend::StorageBin,
    ] {
        for memory in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let upstream = upstream_raw_response_sequence(&[("/asset.png", ORIGIN_RESPONSE)]).await;
            let mut baseline = config(&root.path().canonicalize().unwrap(), upstream);
            baseline.cache.disk.backend = backend;
            baseline.cache.memory.enabled = memory;
            let handler =
                NativeHttp1HostRouter::from_config(&baseline, DownstreamHttp1Policy::default(), 0)
                    .unwrap();
            let (router, reloader) = NativeHttp1ReloadableRouter::new(
                handler,
                DownstreamHttp1Policy::default(),
                0,
                false,
                NativeRequestBodyBudget::new(1024 * 1024),
            );
            assert_eq!(cache_status(&get(&router).await), Some("MISS"));
            assert_eq!(cache_status(&get(&router).await), Some("HIT"));
            let pinned = router.pin_request_handler().unwrap();
            let mut candidate = baseline.clone();
            candidate.cache.status_reason_header = Some("x-new-cache-reason".to_owned());
            assert_eq!(
                fluxheim_config::reload::classify_reload(&baseline, &candidate),
                fluxheim_config::reload::ReloadImpact::Snapshot
            );
            reloader.reload_from_config(&candidate).unwrap();
            assert_eq!(cache_status(&get(&router).await), Some("HIT"));
            assert_eq!(cache_status(&get(pinned.as_ref()).await), Some("HIT"));
            let mut incompatible = candidate.clone();
            incompatible.cache.disk.max_size_bytes =
                fluxheim_config::ByteSize::from_bytes(2 * 1024 * 1024);
            assert!(reloader.reload_from_config(&incompatible).is_err());
            assert_eq!(cache_status(&get(&router).await), Some("HIT"));
            // Rollback reuses the same disk state instead of opening another allocator.
            reloader.reload_from_config(&baseline).unwrap();
            assert_eq!(cache_status(&get(&router).await), Some("HIT"));
            drop(reloader);
            drop(router);
            assert_eq!(cache_status(&get(pinned.as_ref()).await), Some("HIT"));
            drop(pinned);
            let restarted =
                NativeHttp1HostRouter::from_config(&candidate, DownstreamHttp1Policy::default(), 0)
                    .unwrap();
            assert_eq!(cache_status(&get(&restarted).await), Some("HIT"));
        }
    }
}

#[tokio::test]
async fn manifest_mismatch_rejects_disk_only_and_tiered_router_without_rewriting_layout() {
    for memory in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let upstream = upstream_raw_response_sequence(&[("/asset.png", ORIGIN_RESPONSE)]).await;
        let mut baseline = config(&root.path().canonicalize().unwrap(), upstream);
        baseline.cache.memory.enabled = memory;
        let handler =
            NativeHttp1HostRouter::from_config(&baseline, DownstreamHttp1Policy::default(), 0)
                .unwrap();
        drop(handler);
        let manifest_path = root.path().join(".fluxheim-storage-bin-v1");
        let manifest = std::fs::read(&manifest_path).unwrap();
        let mut candidate = baseline;
        candidate.cache.disk.storage_bin.max_open_bins += 1;
        assert!(
            NativeHttp1HostRouter::from_config(&candidate, DownstreamHttp1Policy::default(), 0)
                .is_err()
        );
        assert_eq!(std::fs::read(manifest_path).unwrap(), manifest);
    }
}

#[test]
fn missing_encryption_key_and_unusable_roots_reject_all_required_disk_tiers() {
    for backend in [
        fluxheim_config::CacheDiskBackend::Filesystem,
        fluxheim_config::CacheDiskBackend::StorageBin,
    ] {
        for memory in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let root = root.path().canonicalize().unwrap();
            let mut candidate = config(&root.join("cache"), "127.0.0.1:9".parse().unwrap());
            candidate.cache.disk.backend = backend;
            candidate.cache.memory.enabled = memory;
            candidate.cache.disk.encryption.enabled = true;
            candidate.cache.disk.encryption.key_file = Some(root.join("missing.key"));
            assert!(
                NativeHttp1HostRouter::from_config(&candidate, DownstreamHttp1Policy::default(), 0)
                    .is_err()
            );
            candidate.cache.disk.encryption.enabled = false;
            let blocked = root.join("not-a-directory");
            std::fs::write(&blocked, b"untouched").unwrap();
            candidate.cache.disk.path = Some(blocked.clone());
            assert!(
                NativeHttp1HostRouter::from_config(&candidate, DownstreamHttp1Policy::default(), 0)
                    .is_err()
            );
            assert_eq!(std::fs::read(blocked).unwrap(), b"untouched");
        }
    }
}

#[test]
fn corrupt_bin_index_and_external_allocator_reject_router_initialization() {
    for memory in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut candidate = config(
            &root.path().canonicalize().unwrap(),
            "127.0.0.1:9".parse().unwrap(),
        );
        candidate.cache.memory.enabled = memory;
        let independent =
            crate::native_http1_cache::NativeDiskCache::try_from_config(&candidate.cache)
                .unwrap()
                .unwrap();
        assert!(
            NativeHttp1HostRouter::from_config(&candidate, DownstreamHttp1Policy::default(), 0)
                .is_err()
        );
        drop(independent);
        let index = root.path().join(".fluxheim-storage-bin-index-v1");
        std::fs::write(&index, b"invalid index; must not be overwritten").unwrap();
        assert!(
            NativeHttp1HostRouter::from_config(&candidate, DownstreamHttp1Policy::default(), 0)
                .is_err()
        );
        assert_eq!(
            std::fs::read(index).unwrap(),
            b"invalid index; must not be overwritten"
        );
    }
}

#[tokio::test]
async fn encrypted_reload_requires_restart_and_preserves_active_cache_and_key_state() {
    for backend in [
        fluxheim_config::CacheDiskBackend::Filesystem,
        fluxheim_config::CacheDiskBackend::StorageBin,
    ] {
        for memory in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().canonicalize().unwrap();
            let key = path.join("key");
            super::write_native_proxy_cache_secret(
                &key,
                b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            );
            let upstream = upstream_raw_response_sequence(&[("/asset.png", ORIGIN_RESPONSE)]).await;
            let mut baseline = config(&path.join("cache"), upstream);
            baseline.cache.disk.backend = backend;
            baseline.cache.memory.enabled = memory;
            baseline.cache.disk.encryption.enabled = true;
            baseline.cache.disk.encryption.key_file = Some(key);
            let initial =
                NativeHttp1HostRouter::from_config(&baseline, DownstreamHttp1Policy::default(), 0)
                    .unwrap();
            let (router, reloader) = NativeHttp1ReloadableRouter::new(
                initial,
                DownstreamHttp1Policy::default(),
                0,
                false,
                NativeRequestBodyBudget::new(1024 * 1024),
            );
            assert_eq!(cache_status(&get(&router).await), Some("MISS"));
            let key_state = path.join("cache/.fluxheim-encryption-key-v1");
            let before = std::fs::read(&key_state).unwrap();
            for candidate in [baseline.clone(), {
                let mut changed = baseline.clone();
                changed.cache.disk.encryption.enabled = false;
                changed
            }] {
                assert!(reloader.reload_from_config(&candidate).is_err());
                assert_eq!(cache_status(&get(&router).await), Some("HIT"));
                assert_eq!(std::fs::read(&key_state).unwrap(), before);
            }
            drop(reloader);
            drop(router);
            let restarted =
                NativeHttp1HostRouter::from_config(&baseline, DownstreamHttp1Policy::default(), 0)
                    .unwrap();
            assert_eq!(cache_status(&get(&restarted).await), Some("HIT"));
        }
    }
}

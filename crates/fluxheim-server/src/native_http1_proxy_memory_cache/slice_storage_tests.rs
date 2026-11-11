use super::*;
use crate::native_http1_cache::{lock_native_memory_cache, purge_native_disk_cache_primary};
use crate::native_http1_proxy_runtime::purge_native_memory_cache_primary;
use fluxheim_config::{ByteSize, CacheConfig, CacheDiskBackend};

#[path = "slice_recovery_tests.rs"]
mod recovery;

fn config(
    root: &std::path::Path,
    backend: CacheDiskBackend,
    memory: bool,
    encrypted: bool,
) -> CacheConfig {
    let mut config = CacheConfig {
        enabled: true,
        ..Default::default()
    };
    config.memory.enabled = memory;
    config.disk.enabled = true;
    config.disk.backend = backend;
    config.disk.path = Some(root.join("objects"));
    config.disk.max_size_bytes = ByteSize::from_bytes(65536);
    config.disk.storage_bin.bin_size_bytes = ByteSize::from_bytes(65536);
    config.range.enabled = true;
    config.range.slice.enabled = true;
    config.range.slice.size_bytes = ByteSize::from_bytes(4);
    config.vary_request_headers = vec!["accept-language".to_owned()];
    if encrypted {
        use std::io::Write;
        let path = root.join("key");
        #[cfg(windows)]
        fluxheim_config::fs_trust::create_private_directory_all(root).unwrap();
        #[cfg(windows)]
        let mut file = fluxheim_config::fs_trust::open_or_create_confidential_file(&path).unwrap();
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap()
        };
        file.write_all(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n")
            .unwrap();
        config.disk.encryption.enabled = true;
        config.disk.encryption.key_file = Some(path);
    }
    config
}

fn request(language: &str) -> NativeHttp1Request {
    NativeHttp1Request {
        method: "GET".to_owned(),
        target: "/asset.png".to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![
            ("host".into(), "slice.test".into()),
            ("accept-language".into(), language.into()),
            ("range".into(), "bytes=0-3".into()),
        ],
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        body: crate::NativeHttp1RequestBody::empty(),
        trailers: Vec::new(),
    }
}

fn response(body: &[u8], range: &str, etag: &str) -> NativeHttp1Response {
    NativeHttp1Response::new(206, "Partial Content", body.to_vec())
        .with_header("content-length", body.len().to_string())
        .with_header("content-range", range)
        .with_header("etag", etag)
        .with_header("content-type", "image/png")
        .with_header("cache-control", "max-age=120")
        .with_header("vary", "Accept-Language")
}

fn keys(cache: &NativeProxyMemoryCache, request: &NativeHttp1Request) -> (String, String) {
    let primary = cache.key_with_components(request, &[]).unwrap();
    let base =
        native_vary_cache_key(&primary, &cache.config.vary_request_headers, request).unwrap();
    (
        primary,
        native_slice_cache_key(&base, bounds().range_request()),
    )
}

fn bounds() -> CacheSliceBounds {
    CacheSliceBounds { start: 0, end: 3 }
}

#[tokio::test]
async fn slice_scoped_purge_preserves_other_paths_and_complete_object_variants() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path(), backend, true, false);
        let scope = root.path().display().to_string();
        let cache =
            NativeProxyMemoryCache::from_config_with_metrics(&config, &scope, None).unwrap();
        let mut full_request = request("en");
        full_request.headers.retain(|(name, _)| name != "range");
        let (primary, _) = keys(&cache, &full_request);
        let full = NativeHttp1Response::new(200, "OK", b"fullbody".to_vec())
            .with_header("cache-control", "max-age=120")
            .with_header("vary", "Accept-Language")
            .with_header("content-type", "image/png");
        cache.store(&primary, &full_request, &full).await.unwrap();
        for path in ["/asset.png", "/other.png"] {
            let mut request = request("en");
            request.target = path.to_owned();
            let (primary, key) = keys(&cache, &request);
            cache
                .store_origin_slice(
                    &primary,
                    &key,
                    &request,
                    bounds(),
                    &response(b"abcd", "bytes 0-3/8", "\"v1\""),
                )
                .await
                .unwrap();
        }
        // Slice admission must not remove the complete-object variant map.
        assert_eq!(
            &*cache
                .get(&primary, &full_request)
                .await
                .unwrap()
                .unwrap()
                .body,
            b"fullbody"
        );
        drop(cache);
        let cache =
            NativeProxyMemoryCache::from_config_with_metrics(&config, &scope, None).unwrap();
        assert_eq!(
            &*cache
                .get(&primary, &full_request)
                .await
                .unwrap()
                .unwrap()
                .body,
            b"fullbody"
        );
        let purged = crate::purge_native_disk_cache_path_exact(
            &scope,
            None,
            &scope,
            "/asset.png",
            100,
            false,
        );
        assert_eq!(purged.purged, 2);
        crate::purge_native_memory_cache_primary(&scope, None, &primary, &primary);
        let (_, key) = keys(&cache, &request("en"));
        assert!(
            cache
                .lookup_cached_slice(&key, bounds())
                .await
                .unwrap()
                .is_none()
        );
        let mut other = request("en");
        other.target = "/other.png".into();
        let (_, key) = keys(&cache, &other);
        assert!(
            cache
                .lookup_cached_slice(&key, bounds())
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 1);
    }
}

#[tokio::test]
async fn slice_disk_eviction_respects_weight_and_memory_purge_removes_slices() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let root = tempfile::tempdir().unwrap();
        let config = config(root.path(), backend, true, false);
        let scope = root.path().display().to_string();
        let cache =
            NativeProxyMemoryCache::from_config_with_metrics(&config, &scope, None).unwrap();
        let req = request("en");
        let (primary, key) = keys(&cache, &req);
        cache
            .store_origin_slice(
                &primary,
                &key,
                &req,
                bounds(),
                &response(b"abcd", "bytes 0-3/8", "\"v1\""),
            )
            .await
            .unwrap();
        let weight = cache.disk.as_ref().unwrap().stats().size_bytes;
        assert!(purge_native_memory_cache_primary(
            &scope, None, &primary, &primary
        ));
        assert!(
            lock_native_memory_cache(&cache.state, "test")
                .objects
                .is_empty()
        );
        assert_eq!(lock_native_memory_cache(&cache.state, "test").bytes, 0);
        drop(cache);
        let mut limited = config.clone();
        limited.disk.path = Some(root.path().join("eviction"));
        limited.disk.max_size_bytes = ByteSize::from_bytes(weight + weight / 2);
        limited.memory.enabled = false;
        let cache = NativeProxyMemoryCache::from_config(&limited).unwrap();
        for lang in ["en", "sv"] {
            let req = request(lang);
            let (primary, key) = keys(&cache, &req);
            cache
                .store_origin_slice(
                    &primary,
                    &key,
                    &req,
                    bounds(),
                    &response(b"abcd", "bytes 0-3/8", "\"v1\""),
                )
                .await
                .unwrap();
        }
        assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 1);
        assert!(
            cache.disk.as_ref().unwrap().stats().size_bytes <= limited.disk.max_size_bytes.as_u64()
        );
        assert!(
            cache
                .lookup_cached_slice(&key, bounds())
                .await
                .unwrap()
                .is_none()
        );
        let (_, newest) = keys(&cache, &request("sv"));
        assert!(
            cache
                .lookup_cached_slice(&newest, bounds())
                .await
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test]
async fn slices_recover_all_tiers_encryption_variants_and_exact_purge() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        for memory in [false, true] {
            for encrypted in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let config = config(root.path(), backend, memory, encrypted);
                let scope = root.path().display().to_string();
                let cache = NativeProxyMemoryCache::from_config_with_metrics(&config, &scope, None)
                    .unwrap();
                for (lang, body) in [("en", b"abcd"), ("sv", b"wxyz")] {
                    let request = request(lang);
                    let (primary, key) = keys(&cache, &request);
                    cache
                        .store_origin_slice(
                            &primary,
                            &key,
                            &request,
                            bounds(),
                            &response(body, "bytes 0-3/8", "\"v1\""),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        &*cache
                            .lookup_cached_slice(&key, bounds())
                            .await
                            .unwrap()
                            .unwrap()
                            .entry
                            .body,
                        body
                    );
                }
                assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 2);
                {
                    let state = lock_native_memory_cache(&cache.state, "test");
                    assert_eq!(state.objects.len(), if memory { 2 } else { 0 });
                    assert_eq!(state.purge_index.len(), if memory { 2 } else { 0 });
                    if !memory {
                        assert_eq!(state.bytes, 0);
                    }
                }
                drop(cache);
                let cache = NativeProxyMemoryCache::from_config_with_metrics(&config, &scope, None)
                    .unwrap();
                for (lang, body) in [("en", b"abcd"), ("sv", b"wxyz")] {
                    let (_, key) = keys(&cache, &request(lang));
                    assert_eq!(
                        &*cache
                            .lookup_cached_slice(&key, bounds())
                            .await
                            .unwrap()
                            .unwrap()
                            .entry
                            .body,
                        body
                    );
                }
                let (primary, _) = keys(&cache, &request("en"));
                assert!(
                    cache.get(&primary, &request("en")).await.unwrap().is_none(),
                    "slices must not be complete objects"
                );
                assert!(purge_native_disk_cache_primary(
                    &scope, None, &primary, &primary
                ));
                purge_native_memory_cache_primary(&scope, None, &primary, &primary);
                for lang in ["en", "sv"] {
                    let (_, key) = keys(&cache, &request(lang));
                    assert!(
                        cache
                            .lookup_cached_slice(&key, bounds())
                            .await
                            .unwrap()
                            .is_none()
                    );
                }
                assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 0);
                assert_eq!(cache.disk.as_ref().unwrap().stats().size_bytes, 0);
            }
        }
    }
}

#[tokio::test]
async fn slices_reject_invalid_partial_bodies_and_respect_capacity() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let root = tempfile::tempdir().unwrap();
        let mut config = config(root.path(), backend, false, false);
        let cache = NativeProxyMemoryCache::from_config(&config).unwrap();
        let request = request("en");
        let (primary, key) = keys(&cache, &request);
        for invalid in [
            response(b"abc", "bytes 0-3/8", "\"v1\""),
            response(b"abcde", "bytes 0-4/8", "\"v1\""),
            response(b"abcd", "bytes 4-7/8", "\"v1\""),
            response(b"abcd", "bytes 0-3/8", "\"v1\"").with_header("content-encoding", "gzip"),
            NativeHttp1Response::new(500, "Error", b"abcd".to_vec()),
        ] {
            assert!(
                cache
                    .store_origin_slice(&primary, &key, &request, bounds(), &invalid)
                    .await
                    .is_none()
            );
            assert!(
                cache
                    .lookup_cached_slice(&key, bounds())
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 0);
        drop(cache);
        config.disk.max_size_bytes = ByteSize::from_bytes(1);
        config.disk.path = Some(root.path().join("limited"));
        let cache = NativeProxyMemoryCache::from_config(&config).unwrap();
        cache
            .store_origin_slice(
                &primary,
                &key,
                &request,
                bounds(),
                &response(b"abcd", "bytes 0-3/8", "\"v1\""),
            )
            .await
            .unwrap();
        assert!(
            cache
                .lookup_cached_slice(&key, bounds())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 0);
        assert!(
            lock_native_memory_cache(&cache.state, "test")
                .objects
                .is_empty()
        );
    }
}

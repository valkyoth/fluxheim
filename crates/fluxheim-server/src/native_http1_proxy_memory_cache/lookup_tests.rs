use super::*;
use crate::native_http1_cache::{NativeDiskCacheStoreKey, native_cache_body_sha256};
use fluxheim_config::{ByteSize, CacheConfig, CacheDiskBackend};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn disk_lookup_classifies_each_entry_with_one_read_including_variants() {
    let request = NativeHttp1Request {
        method: "GET".into(),
        target: "/asset.png".into(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![
            ("host".into(), "cache.test".into()),
            ("accept-language".into(), "en".into()),
        ],
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        body: crate::NativeHttp1RequestBody::empty(),
        trailers: Vec::new(),
    };
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        for vary in [false, true] {
            for kind in ["missing", "fresh", "swr", "revalidate", "expired"] {
                let root = tempfile::tempdir().unwrap();
                let mut config = CacheConfig {
                    enabled: true,
                    ..Default::default()
                };
                config.memory.enabled = false;
                config.disk.enabled = true;
                config.disk.path = Some(root.path().join("cache"));
                config.disk.backend = backend;
                config.disk.max_size_bytes = ByteSize::from_bytes(65536);
                config.disk.storage_bin.bin_size_bytes = ByteSize::from_bytes(65536);
                let cache = NativeProxyMemoryCache::from_config(&config).unwrap();
                let key = cache.key_with_components(&request, &[]).unwrap();
                let disk = cache.disk.as_ref().unwrap();
                if kind != "missing" {
                    let now = Instant::now();
                    let fields = if vary {
                        vec!["accept-language".to_owned()]
                    } else {
                        Vec::new()
                    };
                    let combined = if vary {
                        native_vary_cache_key(&key, &fields, &request).unwrap()
                    } else {
                        key.clone()
                    };
                    let entry = NativeMemoryCacheEntry {
                        status: 200,
                        reason: "OK".into(),
                        headers: if kind == "revalidate" {
                            vec![("etag".into(), "\"v1\"".into())]
                        } else {
                            Vec::new()
                        },
                        content_length: Some(4),
                        body: Arc::from(&b"body"[..]),
                        body_sha256: Arc::new(native_cache_body_sha256(b"body")),
                        stored_at: now - Duration::from_secs(2),
                        expires_at: if kind == "fresh" {
                            now + Duration::from_secs(60)
                        } else {
                            now - Duration::from_secs(1)
                        },
                        stale_while_revalidate_until: (kind == "swr")
                            .then_some(now + Duration::from_secs(60)),
                        stale_if_error_until: (kind == "revalidate")
                            .then_some(now + Duration::from_secs(60)),
                        stale_reuse_forbidden: false,
                        weight: 100,
                    };
                    disk.store(
                        NativeDiskCacheStoreKey {
                            combined,
                            primary: key,
                            user_tag: "cache.test".into(),
                            index_path: Some("/asset.png".into()),
                            cache_tags: Vec::new(),
                            vary_fields: fields,
                        },
                        &entry,
                    )
                    .unwrap();
                }
                let before = disk.with_state(|state| state.lookup_attempts);
                let result = cache.lookup_with_key_components(&request, &[]).await;
                assert_eq!(
                    disk.with_state(|state| state.lookup_attempts) - before,
                    1,
                    "{kind} {backend:?} vary={vary}"
                );
                assert!(
                    match kind {
                        "fresh" => matches!(result, NativeProxyCacheLookup::Hit { .. }),
                        "swr" =>
                            matches!(result, NativeProxyCacheLookup::StaleWhileRevalidate { .. }),
                        "revalidate" => matches!(result, NativeProxyCacheLookup::Revalidate { .. }),
                        _ => matches!(result, NativeProxyCacheLookup::Miss { .. }),
                    },
                    "{kind}: {result:?}"
                );
            }
        }
    }
}

use tokio::net::TcpListener;

use crate::NativeHttp1RouteProxy;

use super::{
    downstream_get, downstream_request, native_proxy_disk_cache_config,
    native_proxy_tiered_cache_config, proxy_for, response_header, route_proxy_listener,
    upstream_cacheable_once_with_max_age,
};

const DISK_CACHE_SATURATION_CHILD: &str = "FLUXHEIM_DISK_CACHE_SATURATION_CHILD";

#[tokio::test]
async fn disk_cache_saturation_child_process() {
    if std::env::var_os(DISK_CACHE_SATURATION_CHILD).is_none() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let cache = native_proxy_disk_cache_config(root.path().to_path_buf());
    let unavailable_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_origin = unavailable_listener.local_addr().unwrap();
    drop(unavailable_listener);
    let proxy = proxy_for(unavailable_origin)
        .with_proxy_cache_config(&cache)
        .unwrap();
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;
    let permits = crate::blocking_work::exhaust_disk_cache_blocking_work_for_test();

    let response = downstream_get(listener, "/asset.png").await;

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.ends_with("cache temporarily unavailable\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    let mut slice_config = cache.clone();
    let slice_root = tempfile::tempdir().unwrap();
    slice_config.disk.path = Some(slice_root.path().to_path_buf());
    slice_config.range.enabled = true;
    slice_config.range.slice.enabled = true;
    slice_config.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(4);
    let slice_listener = route_proxy_listener(NativeHttp1RouteProxy::new(
        Vec::new(),
        Some(
            proxy_for(unavailable_origin)
                .with_proxy_cache_config(&slice_config)
                .unwrap(),
        ),
    ))
    .await;
    let response = downstream_request(slice_listener, "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=0-3\r\nConnection: close\r\n\r\n").await;
    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert_eq!(
        response_header(&response, "x-cache-reason").as_deref(),
        Some("disk-cache-saturated")
    );
    drop(permits);

    let stale_root = tempfile::tempdir().unwrap();
    let upstream = upstream_cacheable_once_with_max_age("stale-memory", 1).await;
    let mut stale_cache = native_proxy_tiered_cache_config(stale_root.path().to_path_buf());
    stale_cache.stale_while_revalidate_secs = Some(60);
    let stale_proxy = proxy_for(upstream)
        .with_proxy_cache_config(&stale_cache)
        .unwrap();
    let stale_listener =
        route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(stale_proxy))).await;
    let first = downstream_get(stale_listener, "/asset.png").await;
    assert!(first.ends_with("stale-memory"));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let _permits = crate::blocking_work::exhaust_disk_cache_blocking_work_for_test();

    let stale = downstream_get(stale_listener, "/asset.png").await;

    assert!(stale.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(stale.ends_with("stale-memory"));
    assert_eq!(
        response_header(&stale, "x-cache-status").as_deref(),
        Some("STALE-UPDATING")
    );
}

#[test]
fn disk_cache_saturation_fails_closed_without_origin_contact() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(
            "native_http1_route_proxy_tests::cache_saturation_tests::disk_cache_saturation_child_process",
        )
        .arg("--nocapture")
        .env(DISK_CACHE_SATURATION_CHILD, "1")
        .status()
        .unwrap();

    assert!(status.success());
}

#[tokio::test]
async fn disk_cache_key_contention_child_process() {
    if std::env::var_os("FLUXHEIM_CACHE_KEY_CONTENTION_CHILD").is_none() {
        return;
    }
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    for bins in [false, true] {
        for sliced in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let mut config = if bins {
                super::native_proxy_storage_bin_cache_config(root.path().to_path_buf())
            } else {
                native_proxy_disk_cache_config(root.path().to_path_buf())
            };
            config.disk.storage_bin.max_open_bins = 1;
            config.range.enabled = sliced;
            config.range.slice.enabled = sliced;
            config.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(4);
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = origin.local_addr().unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&calls);
            let origin_task = tokio::spawn(async move {
                loop {
                    let (mut stream, _) = origin.accept().await.unwrap();
                    counter.fetch_add(1, Ordering::SeqCst);
                    let mut bytes = vec![0; 8192];
                    let mut used = 0;
                    while !bytes[..used].windows(4).any(|part| part == b"\r\n\r\n") {
                        assert!(used < bytes.len());
                        let received = stream.read(&mut bytes[used..]).await.unwrap();
                        assert_ne!(received, 0);
                        used += received;
                    }
                    let response = if sliced {
                        "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-3/4\r\nETag: \"stable\"\r\nContent-Length: 4\r\nContent-Type: image/png\r\nCache-Control: max-age=120\r\nConnection: close\r\n\r\ndata"
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Type: image/png\r\nCache-Control: max-age=120\r\nConnection: close\r\n\r\ndata"
                    };
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            });
            let proxy = proxy_for(address).with_proxy_cache_config(&config).unwrap();
            let cache = proxy.cache.as_ref().unwrap();
            let disk = Arc::clone(cache.disk.as_ref().unwrap());
            let primary = fluxheim_cache::image_cache_key(
                &cache.config,
                &fluxheim_cache::CacheRequest {
                    method: "GET",
                    host: Some("route.test"),
                    path: "/asset.png",
                    query: None,
                },
            )
            .unwrap()
            .as_str()
            .to_owned();
            let key = if sliced {
                crate::native_http1_proxy_cache_slice::native_slice_cache_key(
                    &primary,
                    fluxheim_cache::CacheSliceBounds { start: 0, end: 3 }.range_request(),
                )
            } else {
                primary
            };
            let listener =
                route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;
            let request = if sliced {
                "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=0-3\r\nConnection: close\r\n\r\n"
            } else {
                "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nConnection: close\r\n\r\n"
            };
            assert!(
                downstream_request(listener, request)
                    .await
                    .ends_with("data")
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let writer = std::thread::spawn(move || {
                let _guard = disk.lock_key_mutation(&key);
                ready_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(15)).unwrap();
            });
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let mut requests = tokio::task::JoinSet::new();
            for _ in 0..32 {
                requests.spawn(async move { downstream_request(listener, request).await });
            }
            while let Some(response) = requests.join_next().await {
                let response = response.unwrap();
                assert!(
                    response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
                    "{response}"
                );
                assert_eq!(
                    response_header(&response, "x-cache-reason").as_deref(),
                    Some("disk-cache-saturated")
                );
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1, "contention reached origin");
            release_tx.send(()).unwrap();
            writer.join().unwrap();
            assert!(
                downstream_request(listener, request)
                    .await
                    .ends_with("data")
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "cached object was discarded"
            );
            origin_task.abort();
            let _ = origin_task.await;
        }
    }
}

#[test]
fn disk_cache_key_contention_returns_503_without_origin_contact() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_http1_route_proxy_tests::cache_saturation_tests::disk_cache_key_contention_child_process", "--nocapture"])
        .env("FLUXHEIM_CACHE_KEY_CONTENTION_CHILD", "1")
        .status().unwrap();
    assert!(status.success());
}

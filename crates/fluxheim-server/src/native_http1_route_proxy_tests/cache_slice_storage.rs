use super::*;
use fluxheim_config::{ByteSize, CacheDiskBackend};

#[path = "cache_slice_validators.rs"]
mod validators;

fn policy(root: &std::path::Path, backend: CacheDiskBackend) -> fluxheim_config::CacheConfig {
    let mut cache = native_proxy_disk_cache_config(root.to_path_buf());
    cache.disk.backend = backend;
    cache.disk.storage_bin.bin_size_bytes = ByteSize::from_bytes(65536);
    cache.range.enabled = true;
    cache.range.slice.enabled = true;
    cache.range.slice.size_bytes = ByteSize::from_bytes(4);
    cache.lock.enabled = true;
    cache
}

#[test]
fn slice_disk_concurrent_fills_collapse_without_retained_memory() {
    // This test deliberately occupies the whole process-wide disk budget.
    // Keep unrelated parallel tests outside that budget, not outside the assertion.
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("native_http1_route_proxy_tests::cache_slice_storage::slice_disk_concurrent_fills_child")
        .env("FLUXHEIM_SLICE_CONCURRENCY_CHILD", "1")
        .status().unwrap();
    assert!(status.success());
}

#[tokio::test]
async fn slice_disk_concurrent_fills_child() {
    if std::env::var_os("FLUXHEIM_SLICE_CONCURRENCY_CHILD").is_none() {
        return;
    }
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let root = tempfile::tempdir().unwrap();
        let (origin, calls) = upstream_counted_delayed_slice(Duration::from_millis(100)).await;
        let proxy = proxy_for(origin)
            .with_proxy_cache_config(&policy(root.path(), backend))
            .unwrap();
        let cache = proxy.cache.clone().unwrap();
        let (listener, shutdown, task) =
            route_proxy_listener_with_shutdown(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy)))
                .await;
        let mut requests = tokio::task::JoinSet::new();
        for _ in 0..32 {
            requests.spawn(async move { downstream_request(listener, "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=0-3\r\nConnection: close\r\n\r\n").await });
        }
        while let Some(response) = requests.join_next().await {
            let response = response.unwrap();
            assert!(response.starts_with("HTTP/1.1 206"), "{response}");
            assert!(response.ends_with("0123"), "{response}");
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::Acquire), 1);
        assert!(
            crate::native_http1_cache::lock_native_memory_cache(&cache.state, "test")
                .objects
                .is_empty()
        );
        assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 1);
        shutdown.send(()).unwrap();
        task.await.unwrap();
    }
}

#[tokio::test]
async fn slice_disk_cancelled_fill_releases_lock_and_stores_only_complete_response() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let root = tempfile::tempdir().unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let (started, observed) = tokio::sync::oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let (mut first, _) = origin.accept().await.unwrap();
            let mut byte = [0; 1];
            assert_eq!(first.read(&mut byte).await.unwrap(), 1);
            started.send(()).unwrap();
            // The cancelled client closes before a response is published.
            let mut discarded = Vec::new();
            first.take(8192).read_to_end(&mut discarded).await.unwrap();
            let (mut second, _) = origin.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert_eq!(second.read(&mut byte).await.unwrap(), 1);
                request.push(byte[0]);
                assert!(request.len() < 8192);
            }
            second.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Type: image/png\r\nContent-Length: 4\r\nContent-Range: bytes 0-3/8\r\nETag: \"v1\"\r\nCache-Control: max-age=120\r\nConnection: close\r\n\r\n0123").await.unwrap();
        });
        let proxy = proxy_for(address)
            .with_proxy_cache_config(&policy(root.path(), backend))
            .unwrap();
        let mut request = route_test_request("/asset.png");
        request.headers.push(("range".into(), "bytes=0-3".into()));
        let task_proxy = proxy.clone();
        let task_request = request.metadata_snapshot();
        let pending = tokio::spawn(async move {
            task_proxy
                .cache
                .as_ref()
                .unwrap()
                .slice_response(
                    &task_request,
                    &task_proxy,
                    #[cfg(feature = "wasm")]
                    &[],
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), observed)
            .await
            .unwrap()
            .unwrap();
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        let cache = proxy.cache.as_ref().unwrap();
        assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 0);
        assert!(
            crate::native_http1_cache::lock_native_memory_cache(&cache.state, "test")
                .filling
                .is_empty()
        );
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            cache.slice_response(
                &request,
                &proxy,
                #[cfg(feature = "wasm")]
                &[],
            ),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(result.response.body(), b"0123");
        assert!(result.filled);
        assert_eq!(cache.disk.as_ref().unwrap().stats().entries, 1);
        let hit = cache
            .slice_response(
                &request,
                &proxy,
                #[cfg(feature = "wasm")]
                &[],
            )
            .await
            .unwrap()
            .unwrap();
        assert!(!hit.filled);
        assert_eq!(hit.response.body(), b"0123");
        tokio::time::timeout(Duration::from_secs(5), origin_task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn slice_disk_validator_change_never_composes_mixed_representations() {
    for backend in [CacheDiskBackend::Filesystem, CacheDiskBackend::StorageBin] {
        let root = tempfile::tempdir().unwrap();
        let origin = upstream_slice_response_sequence(&[
            ("/asset.png", "bytes=0-3", "HTTP/1.1 206 Partial Content\r\nContent-Type: image/png\r\nCache-Control: max-age=120\r\nETag: \"old\"\r\nContent-Range: bytes 0-3/8\r\nContent-Length: 4\r\n\r\n0123"),
            ("/asset.png", "bytes=4-7", "HTTP/1.1 206 Partial Content\r\nContent-Type: image/png\r\nCache-Control: max-age=120\r\nETag: \"new\"\r\nContent-Range: bytes 4-7/8\r\nContent-Length: 4\r\n\r\nefgh"),
            ("/asset.png", "bytes=2-5", "HTTP/1.1 206 Partial Content\r\nContent-Type: image/png\r\nCache-Control: no-store\r\nETag: \"new\"\r\nContent-Range: bytes 2-5/8\r\nContent-Length: 4\r\n\r\ncdef"),
        ]).await;
        let cache = policy(root.path(), backend);
        let (listener, shutdown, task) =
            route_proxy_listener_with_shutdown(NativeHttp1RouteProxy::new(
                Vec::new(),
                Some(proxy_for(origin).with_proxy_cache_config(&cache).unwrap()),
            ))
            .await;
        let response = downstream_request(listener, "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Encoding: identity\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 206"), "{response}");
        assert!(
            response.ends_with("cdef"),
            "must not compose 23ef: {response}"
        );
        assert_ne!(
            response_header(&response, "x-cache-reason").as_deref(),
            Some("slice")
        );
        shutdown.send(()).unwrap();
        task.await.unwrap();
    }
}

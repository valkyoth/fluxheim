use super::*;

#[tokio::test]
async fn slice_unproven_representation_falls_back_without_composing_after_restart() {
    for backend in [
        None,
        Some(CacheDiskBackend::Filesystem),
        Some(CacheDiskBackend::StorageBin),
    ] {
        for validator in [
            "",
            "ETag: W/\"old\"\r\n",
            "Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\n",
            "ETag: \"old\"\r\nETag: \"old\"\r\n",
        ] {
            let root = tempfile::tempdir().unwrap();
            let mut config = policy(root.path(), backend.unwrap_or(CacheDiskBackend::Filesystem));
            config.disk.enabled = backend.is_some();
            config.memory.enabled = backend.is_none();
            let first = "HTTP/1.1 206 Partial Content\r\nContent-Type: image/png\r\nCache-Control: max-age=120\r\nETag: \"old\"\r\nContent-Range: bytes 0-3/8\r\nContent-Length: 4\r\n\r\n0123";
            let unproven = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Type: image/png\r\nCache-Control: max-age=120\r\n{validator}Content-Range: bytes 4-7/8\r\nContent-Length: 4\r\n\r\nefgh"
            );
            let fallback = "HTTP/1.1 206 Partial Content\r\nContent-Type: image/png\r\nCache-Control: no-store\r\nContent-Range: bytes 2-5/8\r\nContent-Length: 4\r\n\r\ncdef";
            let mut sequence = vec![
                ("/asset.png", "bytes=0-3", first),
                ("/asset.png", "bytes=4-7", unproven.as_str()),
                ("/asset.png", "bytes=2-5", fallback),
            ];
            if backend.is_none() {
                sequence.push(("/asset.png", "bytes=0-3", first));
            }
            sequence.extend([
                ("/asset.png", "bytes=4-7", unproven.as_str()),
                ("/asset.png", "bytes=2-5", fallback),
            ]);
            let origin = upstream_slice_response_sequence(&sequence).await;
            for _ in 0..2 {
                let proxy = proxy_for(origin).with_proxy_cache_config(&config);
                let (listener, shutdown, task) = route_proxy_listener_with_shutdown(
                    NativeHttp1RouteProxy::new(Vec::new(), Some(proxy)),
                )
                .await;
                let response = downstream_request(listener, "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Encoding: identity\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n").await;
                assert!(response.starts_with("HTTP/1.1 206"), "{response}");
                assert!(
                    response.ends_with("cdef"),
                    "must never compose 23ef: {response}"
                );
                assert!(
                    !response_header(&response, "x-cache-reason")
                        .is_some_and(|reason| reason == "slice" || reason == "slice-fill")
                );
                shutdown.send(()).unwrap();
                task.await.unwrap();
            }
        }
    }
}

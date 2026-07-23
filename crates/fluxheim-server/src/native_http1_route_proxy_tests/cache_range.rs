use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::NativeHttp1RouteProxy;

use super::{
    downstream_get, downstream_request, native_proxy_memory_cache_config, proxy_for,
    response_header, route_proxy_listener, upstream_cacheable_once, upstream_counted_delayed_slice,
    upstream_raw_response_sequence, upstream_slice_response_sequence,
};

#[tokio::test]
async fn native_route_proxy_serves_bounded_range_from_memory_cache_hit() {
    let upstream = upstream_cacheable_once("0123456789").await;
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let range = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(range.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(range.ends_with("2345"));
    assert_eq!(
        response_header(&range, "content-range").as_deref(),
        Some("bytes 2-5/10")
    );
    assert_eq!(
        response_header(&range, "content-length").as_deref(),
        Some("4")
    );
    assert_eq!(
        response_header(&range, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_serves_range_not_satisfiable_from_memory_cache_hit() {
    let upstream = upstream_cacheable_once("0123456789").await;
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let range = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=20-29\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(range.starts_with("HTTP/1.1 416 Range Not Satisfiable\r\n"));
    assert!(range.ends_with("\r\n\r\n"));
    assert_eq!(
        response_header(&range, "content-range").as_deref(),
        Some("bytes */10")
    );
    assert_eq!(
        response_header(&range, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_bypasses_cache_fill_on_range_miss() {
    let upstream = upstream_raw_response_sequence(&[
        (
            "/asset.png",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-range: bytes 0-3/10\r\ncontent-length: 4\r\n\r\nrang",
        ),
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-length: 9\r\n\r\nfull-body",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let range = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=0-3\r\nConnection: close\r\n\r\n",
    )
    .await;
    let full = downstream_get(listener, "/asset.png").await;

    assert!(range.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(range.ends_with("rang"));
    assert_eq!(
        response_header(&range, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&range, "x-cache-reason").as_deref(),
        Some("range-miss")
    );
    assert!(full.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(full.ends_with("full-body"));
    assert_eq!(
        response_header(&full, "x-cache-status").as_deref(),
        Some("MISS")
    );
}

#[tokio::test]
async fn native_route_proxy_slice_cache_fills_and_composes_memory_range() {
    let upstream = upstream_slice_response_sequence(&[
        (
            "/asset.png",
            "bytes=0-3",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\netag: \"slice-v1\"\r\ncontent-range: bytes 0-3/10\r\ncontent-length: 4\r\n\r\n0123",
        ),
        (
            "/asset.png",
            "bytes=4-7",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\netag: \"slice-v1\"\r\ncontent-range: bytes 4-7/10\r\ncontent-length: 4\r\n\r\n4567",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    cache.range.slice.enabled = true;
    cache.range.slice.fill_missing = true;
    cache.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(4);
    cache.range.slice.max_slices = 4;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    )
    .await;
    let second = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(first.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(first.ends_with("2345"));
    assert_eq!(
        response_header(&first, "content-range").as_deref(),
        Some("bytes 2-5/10")
    );
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&first, "x-cache-reason").as_deref(),
        Some("slice-fill")
    );
    assert!(second.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(second.ends_with("2345"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
    assert_eq!(
        response_header(&second, "x-cache-reason").as_deref(),
        Some("slice")
    );
}

#[tokio::test]
async fn native_route_proxy_slice_cache_collapses_concurrent_same_slice_fills() {
    const REQUESTS: usize = 32;

    let (upstream, upstream_requests) =
        upstream_counted_delayed_slice(Duration::from_millis(100)).await;
    let mut cache = native_proxy_memory_cache_config();
    cache.lock.enabled = true;
    cache.lock.wait_timeout_secs = 5;
    cache.range.enabled = true;
    cache.range.slice.enabled = true;
    cache.range.slice.fill_missing = true;
    cache.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(4);
    cache.range.slice.max_slices = 4;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;
    let barrier = Arc::new(tokio::sync::Barrier::new(REQUESTS + 1));
    let mut requests = Vec::with_capacity(REQUESTS);
    for _ in 0..REQUESTS {
        let barrier = barrier.clone();
        requests.push(tokio::spawn(async move {
            barrier.wait().await;
            downstream_request(
                listener,
                "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=0-3\r\nConnection: close\r\n\r\n",
            )
            .await
        }));
    }

    barrier.wait().await;
    for request in requests {
        let response = request.await.unwrap();
        assert!(response.starts_with("HTTP/1.1 206 Partial Content\r\n"));
        assert!(response.ends_with("0123"));
    }
    assert_eq!(upstream_requests.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn native_route_proxy_slice_cache_lock_wait_timeout_fails_closed() {
    let (upstream, upstream_requests) =
        upstream_counted_delayed_slice(Duration::from_millis(1_500)).await;
    let mut cache = native_proxy_memory_cache_config();
    cache.lock.enabled = true;
    cache.lock.wait_timeout_secs = 1;
    cache.range.enabled = true;
    cache.range.slice.enabled = true;
    cache.range.slice.fill_missing = true;
    cache.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(4);
    cache.range.slice.max_slices = 4;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = tokio::spawn(async move {
        downstream_request(
            listener,
            "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=0-3\r\nConnection: close\r\n\r\n",
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while upstream_requests.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let second = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=0-3\r\nConnection: close\r\n\r\n",
    )
    .await;
    let first = first.await.unwrap();

    assert!(first.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(
        second.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "unexpected second response: {second:?}"
    );
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&second, "x-cache-reason").as_deref(),
        Some("lock-wait-timeout")
    );
    assert_eq!(
        response_header(&second, "retry-after").as_deref(),
        Some("1")
    );
    assert_eq!(upstream_requests.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn native_route_proxy_slice_cache_isolates_configured_vary_headers() {
    let upstream = upstream_slice_response_sequence(&[
        (
            "/asset.png",
            "bytes=0-3",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\netag: \"english-v1\"\r\ncontent-range: bytes 0-3/10\r\ncontent-length: 4\r\n\r\nE012",
        ),
        (
            "/asset.png",
            "bytes=4-7",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\netag: \"english-v1\"\r\ncontent-range: bytes 4-7/10\r\ncontent-length: 4\r\n\r\n3456",
        ),
        (
            "/asset.png",
            "bytes=0-3",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\netag: \"swedish-v1\"\r\ncontent-range: bytes 0-3/10\r\ncontent-length: 4\r\n\r\nSABC",
        ),
        (
            "/asset.png",
            "bytes=4-7",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\netag: \"swedish-v1\"\r\ncontent-range: bytes 4-7/10\r\ncontent-length: 4\r\n\r\nDEFG",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    cache.range.slice.enabled = true;
    cache.range.slice.fill_missing = true;
    cache.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(4);
    cache.range.slice.max_slices = 4;
    cache.vary_request_headers = vec!["accept-language".to_owned()];
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let english = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: en\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    )
    .await;
    let swedish = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: sv\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    )
    .await;
    let english_hit = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: en\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(
        english.ends_with("1234"),
        "unexpected English slice: {english:?}"
    );
    assert!(
        swedish.ends_with("BCDE"),
        "unexpected Swedish slice: {swedish:?}"
    );
    assert!(english_hit.ends_with("1234"));
    assert_eq!(
        response_header(&english, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&swedish, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&english_hit, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_slice_cache_composes_multipart_memory_response() {
    let upstream = upstream_slice_response_sequence(&[
        (
            "/asset.png",
            "bytes=0-3",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\nlast-modified: Wed, 21 Oct 2015 07:28:00 GMT\r\ncontent-range: bytes 0-3/10\r\ncontent-length: 4\r\n\r\n0123",
        ),
        (
            "/asset.png",
            "bytes=4-7",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\nlast-modified: Wed, 21 Oct 2015 07:28:00 GMT\r\ncontent-range: bytes 4-7/10\r\ncontent-length: 4\r\n\r\n4567",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    cache.range.slice.enabled = true;
    cache.range.slice.fill_missing = true;
    cache.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(4);
    cache.range.slice.max_slices = 4;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let response = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=0-1,6-7\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(
        response_header(&response, "content-type")
            .as_deref()
            .is_some_and(|value| value.starts_with("multipart/byteranges; boundary=fluxheim-"))
    );
    assert!(response.contains("Content-Range: bytes 0-1/10\r\n\r\n01"));
    assert!(response.contains("Content-Range: bytes 6-7/10\r\n\r\n67"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&response, "x-cache-reason").as_deref(),
        Some("slice-fill")
    );
}

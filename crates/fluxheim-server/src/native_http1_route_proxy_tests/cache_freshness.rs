use std::time::Duration;

use crate::NativeHttp1RouteProxy;

use super::{
    downstream_get, native_proxy_memory_cache_config, proxy_for, response_header,
    route_proxy_listener, upstream_cacheable_once_with_max_age, upstream_cacheable_sequence,
    upstream_raw_response_sequence,
};

#[tokio::test]
async fn native_route_proxy_min_uses_delays_memory_cache_admission() {
    let upstream = upstream_cacheable_sequence(&[
        ("/asset.png", "first-cacheable"),
        ("/asset.png", "second-cacheable"),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.min_uses = 2;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let second = downstream_get(listener, "/asset.png").await;
    let third = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("first-cacheable"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&first, "x-cache-reason").as_deref(),
        Some("cache-min-uses")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("second-cacheable"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(third.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(third.ends_with("second-cacheable"));
    assert_eq!(
        response_header(&third, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_predictor_passes_repeated_uncacheable_memory_response() {
    let upstream = upstream_raw_response_sequence(&[
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: no-store\r\ncontent-length: 17\r\n\r\nuncacheable-first",
        ),
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: no-store\r\ncontent-length: 18\r\n\r\nuncacheable-second",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.predictor.enabled = true;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let second = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("uncacheable-first"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&first, "x-cache-reason").as_deref(),
        Some("cache-control-no-store")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("uncacheable-second"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&second, "x-cache-reason").as_deref(),
        Some("cache-pass")
    );
}

#[tokio::test]
async fn native_route_proxy_serves_stale_while_revalidating_memory_cache() {
    let upstream = upstream_raw_response_sequence(&[
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=1\r\ncontent-length: 9\r\n\r\nstale-one",
        ),
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-length: 9\r\n\r\nfresh-two",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.stale_while_revalidate_secs = Some(60);
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let stale = downstream_get(listener, "/asset.png").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let refreshed = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("stale-one"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(stale.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(stale.ends_with("stale-one"));
    assert_eq!(
        response_header(&stale, "x-cache-status").as_deref(),
        Some("STALE-UPDATING")
    );
    assert_eq!(
        response_header(&stale, "x-cache-reason").as_deref(),
        Some("stale-while-revalidate")
    );
    assert!(refreshed.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(refreshed.ends_with("fresh-two"));
    assert_eq!(
        response_header(&refreshed, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_serves_stale_proxy_response_on_upstream_error() {
    let upstream = upstream_cacheable_once_with_max_age("stale-origin", 1).await;
    let mut cache = native_proxy_memory_cache_config();
    cache.stale_if_error_secs = Some(60);
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("stale-origin"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("stale-origin"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("STALE")
    );
    assert_eq!(
        response_header(&second, "x-cache-reason").as_deref(),
        Some("upstream-error")
    );
    assert!(
        response_header(&second, "age")
            .and_then(|age| age.parse::<u64>().ok())
            .is_some_and(|age| age >= 1),
        "response: {second:?}"
    );
}

#[tokio::test]
async fn native_route_proxy_serves_stale_proxy_response_on_upstream_status() {
    let upstream = upstream_raw_response_sequence(&[
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=1\r\ncontent-length: 12\r\n\r\nstatus-stale",
        ),
        (
            "/asset.png",
            "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 14\r\n\r\norigin-failure",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.stale_if_error_secs = Some(60);
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("status-stale"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("status-stale"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("STALE")
    );
    assert_eq!(
        response_header(&second, "x-cache-reason").as_deref(),
        Some("upstream-status")
    );
}

use std::time::Duration;

use tokio::net::TcpListener;

use crate::NativeHttp1RouteProxy;

use super::{
    downstream_get, downstream_request, native_proxy_memory_cache_config, proxy_for,
    response_header, response_header_values, route_proxy_listener,
    upstream_cacheable_once_with_hop_header, upstream_cacheable_sequence,
    upstream_delayed_cacheable_once, upstream_raw_response_sequence, upstream_response,
    upstream_vary_sequence,
};

#[tokio::test]
async fn native_route_proxy_never_forwards_or_caches_connection_nominated_headers() {
    let upstream = upstream_cacheable_once_with_hop_header("cache-safe").await;
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let miss = downstream_get(listener, "/asset.png").await;
    let hit = downstream_get(listener, "/asset.png").await;

    assert_eq!(
        response_header(&miss, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&hit, "x-cache-status").as_deref(),
        Some("HIT")
    );
    for response in [&miss, &hit] {
        assert!(response_header(response, "proxy-connection").is_none());
        assert!(response_header(response, "x-internal-session").is_none());
    }
}

#[tokio::test]
async fn native_route_proxy_origin_protection_limits_concurrent_cache_fills() {
    let (upstream, accepted) =
        upstream_delayed_cacheable_once("slow-origin", Duration::from_millis(200)).await;
    let mut cache = native_proxy_memory_cache_config();
    cache.lock.enabled = false;
    cache.origin_protection.enabled = true;
    cache.origin_protection.max_concurrent_fills = 1;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = tokio::spawn(async move { downstream_get(listener, "/asset.png").await });
    accepted.await.unwrap();
    let second = downstream_get(listener, "/asset.png").await;
    let first = first.await.unwrap();

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("slow-origin"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(second.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&second, "x-cache-reason").as_deref(),
        Some("origin-protected")
    );
}

#[tokio::test]
async fn native_route_proxy_cache_lock_collapses_concurrent_memory_fills() {
    let (upstream, accepted) =
        upstream_delayed_cacheable_once("collapsed-fill", Duration::from_millis(150)).await;
    let mut cache = native_proxy_memory_cache_config();
    cache.lock.enabled = true;
    cache.lock.wait_timeout_secs = 5;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = tokio::spawn(async move { downstream_get(listener, "/asset.png").await });
    accepted.await.unwrap();
    let second = downstream_get(listener, "/asset.png").await;
    let first = first.await.unwrap();

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("collapsed-fill"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("collapsed-fill"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_does_not_cache_authorized_proxy_response() {
    let upstream = upstream_cacheable_sequence(&[
        ("/tenant.png", "authorized-origin"),
        ("/tenant.png", "public-origin"),
    ])
    .await;
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let authorized = downstream_request(
        listener,
        "GET /tenant.png HTTP/1.1\r\nHost: route.test\r\nAuthorization: Bearer token-a\r\nConnection: close\r\n\r\n",
    )
    .await;
    let public = downstream_get(listener, "/tenant.png").await;

    assert!(authorized.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(authorized.ends_with("authorized-origin"));
    assert_eq!(
        response_header(&authorized, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&authorized, "x-cache-reason").as_deref(),
        Some("request-authorization")
    );
    assert!(public.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(public.ends_with("public-origin"));
    assert_eq!(
        response_header(&public, "x-cache-status").as_deref(),
        Some("MISS")
    );
}

#[tokio::test]
async fn native_route_proxy_does_not_cache_proxy_authorized_response() {
    let upstream = upstream_cacheable_sequence(&[
        ("/tenant.png", "proxy-authorized-origin"),
        ("/tenant.png", "public-origin"),
    ])
    .await;
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let authorized = downstream_request(
        listener,
        "GET /tenant.png HTTP/1.1\r\nHost: route.test\r\nProxy-Authorization: Basic secret\r\nConnection: close\r\n\r\n",
    )
    .await;
    let public = downstream_get(listener, "/tenant.png").await;

    assert!(authorized.ends_with("proxy-authorized-origin"));
    assert_eq!(
        response_header(&authorized, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&authorized, "x-cache-reason").as_deref(),
        Some("request-proxy-authorization")
    );
    assert!(public.ends_with("public-origin"));
    assert_eq!(
        response_header(&public, "x-cache-status").as_deref(),
        Some("MISS")
    );
}

#[tokio::test]
async fn native_route_proxy_does_not_cache_malformed_freshness() {
    let upstream = upstream_raw_response_sequence(&[
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60, max-age=120\r\ncontent-length: 9\r\n\r\nambiguous",
        ),
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-length: 12\r\n\r\nvalid-origin",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.default_status_ttl_secs = Some(300);
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let malformed = downstream_get(listener, "/asset.png").await;
    let valid = downstream_get(listener, "/asset.png").await;

    assert!(malformed.ends_with("ambiguous"));
    assert_eq!(
        response_header(&malformed, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&malformed, "x-cache-reason").as_deref(),
        Some("cache-control-invalid")
    );
    assert!(valid.ends_with("valid-origin"));
    assert_eq!(
        response_header(&valid, "x-cache-status").as_deref(),
        Some("MISS")
    );
}

#[tokio::test]
async fn native_route_proxy_applies_cache_bypass_status_to_upstream_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unused_upstream = listener.local_addr().unwrap();
    drop(listener);
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(unused_upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let response = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&response, "x-cache-reason").as_deref(),
        Some("request-no-store")
    );
}

#[tokio::test]
async fn native_route_proxy_replaces_upstream_age_on_cache_hit() {
    let upstream = upstream_response(
        "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\nage: 5\r\ncontent-length: 10\r\n\r\norigin-age",
    )
    .await;
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let second = downstream_get(listener, "/asset.png").await;

    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
    let age_values = response_header_values(&second, "age");
    assert_eq!(age_values.len(), 1, "response: {second:?}");
}

#[tokio::test]
async fn native_route_proxy_respects_origin_vary_header_in_memory_cache() {
    let upstream = upstream_vary_sequence(&[
        ("/asset.png", "en", "accept-language", "hello"),
        ("/asset.png", "sv", "accept-language", "hej"),
    ])
    .await;
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let english = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: en\r\nConnection: close\r\n\r\n",
    )
    .await;
    let swedish = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: sv\r\nConnection: close\r\n\r\n",
    )
    .await;
    let english_hit = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: en\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(english.ends_with("hello"));
    assert_eq!(
        response_header(&english, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(swedish.ends_with("hej"));
    assert_eq!(
        response_header(&swedish, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(english_hit.ends_with("hello"));
    assert_eq!(
        response_header(&english_hit, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_configured_vary_headers_isolate_memory_cache() {
    let upstream = upstream_cacheable_sequence(&[
        ("/asset.png", "configured-english"),
        ("/asset.png", "configured-swedish"),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.vary_request_headers = vec!["accept-language".to_owned()];
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let english = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: en\r\nConnection: close\r\n\r\n",
    )
    .await;
    let swedish = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: sv\r\nConnection: close\r\n\r\n",
    )
    .await;
    let english_hit = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: en\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(english.ends_with("configured-english"));
    assert_eq!(
        response_header(&english, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(swedish.ends_with("configured-swedish"));
    assert_eq!(
        response_header(&swedish, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(english_hit.ends_with("configured-english"));
    assert_eq!(
        response_header(&english_hit, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

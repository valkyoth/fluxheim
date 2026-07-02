use tokio::net::TcpListener;

use crate::NativeHttp1RouteProxy;

use super::{
    downstream_get, downstream_request, native_proxy_memory_cache_config, peer_fill_cacheable_once,
    peer_fill_response_once, proxy_for, response_header, route_proxy_listener,
};

#[tokio::test]
async fn native_route_proxy_peer_fills_and_stores_memory_cache_response() {
    let peer = peer_fill_cacheable_once("peer-object").await;
    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let mut cache = native_proxy_memory_cache_config();
    cache.peer_fill.enabled = true;
    cache.peer_fill.allow_insecure_http = true;
    cache.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
        name: "local-peer".to_owned(),
        base_url: format!("http://{peer}"),
    }];
    let proxy = proxy_for(origin).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let second = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("peer-object"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("PEER-HIT")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("peer-object"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_client_peer_fill_marker_does_not_skip_peer_fill() {
    let peer = peer_fill_cacheable_once("peer-object").await;
    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let mut cache = native_proxy_memory_cache_config();
    cache.peer_fill.enabled = true;
    cache.peer_fill.allow_insecure_http = true;
    cache.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
        name: "local-peer".to_owned(),
        base_url: format!("http://{peer}"),
    }];
    let proxy = proxy_for(origin).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let response = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nX-Fluxheim-Peer-Fill: 1\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("peer-object"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("PEER-HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_only_if_cached_miss_does_not_contact_origin() {
    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(origin).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let response = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nCache-Control: only-if-cached\r\nX-Fluxheim-Peer-Fill: 1\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&response, "x-cache-reason").as_deref(),
        Some("only-if-cached-miss")
    );
}

#[tokio::test]
async fn native_route_proxy_peer_fill_subtracts_upstream_age_before_admission() {
    let peer = peer_fill_response_once(
        "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=2\r\nage: 2\r\ncontent-length: 10\r\n\r\nstale-peer",
    )
    .await;
    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let mut cache = native_proxy_memory_cache_config();
    cache.peer_fill.enabled = true;
    cache.peer_fill.allow_insecure_http = true;
    cache.peer_fill.fail_open = false;
    cache.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
        name: "local-peer".to_owned(),
        base_url: format!("http://{peer}"),
    }];
    let proxy = proxy_for(origin).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let response = downstream_get(listener, "/asset.png").await;

    assert!(response.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&response, "x-cache-reason").as_deref(),
        Some("peer-fill-miss")
    );
}

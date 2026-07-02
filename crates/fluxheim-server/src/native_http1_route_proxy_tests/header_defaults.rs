use crate::{NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute};

#[cfg(not(feature = "privacy-mode"))]
use crate::DownstreamHttp1Policy;

#[cfg(not(feature = "privacy-mode"))]
use super::upstream_expect_header;
#[cfg(feature = "privacy-mode")]
use super::upstream_expect_headers_absent;
use super::{downstream_request, proxy_for, route_proxy_listener};

#[cfg(not(feature = "privacy-mode"))]
#[tokio::test]
async fn native_route_proxy_vhost_fallback_applies_merged_header_policy() {
    let upstream = upstream_expect_header(
        "/fallback",
        "x-forwarded-for",
        "127.0.0.1",
        "cf-connecting-ip",
    )
    .await;
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
        acme_challenge: Default::default(),
        redirect: Default::default(),
        proxy: fluxheim_config::ProxyConfig {
            upstreams: vec![upstream.to_string()],
            ..Default::default()
        },
        cache: Default::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: Vec::new(),
    };
    let route_proxy = NativeHttp1RouteProxy::from_vhost_config(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = route_proxy_listener(route_proxy).await;

    let response = downstream_request(
        proxy,
        "GET /fallback HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 203.0.113.9\r\n\
         CF-Connecting-IP: 203.0.113.10\r\n\
         Connection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("headers"));
}

#[cfg(not(feature = "privacy-mode"))]
#[tokio::test]
async fn native_route_proxy_default_constructor_applies_safe_request_headers() {
    let upstream =
        upstream_expect_header("/safe", "x-forwarded-for", "127.0.0.1", "cf-connecting-ip").await;
    let route = NativeHttp1RouteProxyRoute::exact("/safe", Vec::new(), proxy_for(upstream));
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /safe HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 203.0.113.9\r\n\
         CF-Connecting-IP: 203.0.113.10\r\n\
         Connection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("headers"));
}

#[cfg(feature = "privacy-mode")]
#[tokio::test]
async fn native_route_proxy_privacy_mode_strips_spoofable_headers_after_mutation() {
    let upstream = upstream_expect_headers_absent(
        "/privacy",
        &["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"],
    )
    .await;
    let mut overlay = fluxheim_config::RequestHeaderPolicyOverlayConfig::default();
    overlay
        .set
        .insert("x-forwarded-for".to_owned(), "203.0.113.77".to_owned());
    let route = NativeHttp1RouteProxyRoute::exact("/privacy", Vec::new(), proxy_for(upstream))
        .with_request_header_policy(&overlay);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /privacy HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 203.0.113.9\r\n\
         X-Forwarded-Host: admin.internal\r\n\
         X-Forwarded-Proto: https\r\n\
         Connection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("headers"));
}

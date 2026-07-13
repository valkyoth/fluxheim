use std::time::Duration;

use crate::{DownstreamHttp1Policy, NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute};

use super::{
    downstream_get, proxy_for, route_proxy_listener, upstream_expect_path, upstream_hold_response,
};

#[tokio::test]
async fn native_route_proxy_vhost_concurrency_rejects_second_request() {
    let (upstream, observed, release) = upstream_hold_response("/slow", "released").await;
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: fluxheim_config::ConcurrencyLimitConfig {
            enabled: true,
            max_in_flight: 1,
            status: 429,
            ..Default::default()
        },
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
    let first = tokio::spawn(async move { downstream_get(proxy, "/slow").await });
    observed.await.unwrap();

    let rejected = downstream_get(proxy, "/slow").await;
    release.send(()).unwrap();
    let first = first.await.unwrap();

    assert!(rejected.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
    assert!(rejected.contains("retry-after: 1\r\n"));
    assert!(rejected.ends_with("too many requests\n"));
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("released"));
}

#[tokio::test]
async fn native_route_proxy_route_concurrency_rejects_second_request() {
    let (upstream, observed, release) = upstream_hold_response("/slow", "released").await;
    let route_config = fluxheim_config::RouteConfig {
        name: "slow".to_owned(),
        path_exact: Some("/slow".to_owned()),
        path_prefix: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: fluxheim_config::ConcurrencyLimitConfig {
            enabled: true,
            max_in_flight: 1,
            status: 429,
            ..Default::default()
        },
        grpc: Default::default(),
        redirect: None,
        proxy: Some(fluxheim_config::ProxyConfig {
            upstreams: vec![upstream.to_string()],
            ..Default::default()
        }),
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };
    let route =
        NativeHttp1RouteProxyRoute::from_config(&route_config, Some(proxy_for(upstream))).unwrap();
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;
    let first = tokio::spawn(async move { downstream_get(proxy, "/slow").await });
    observed.await.unwrap();

    let rejected = downstream_get(proxy, "/slow").await;
    release.send(()).unwrap();
    let first = first.await.unwrap();

    assert!(rejected.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
    assert!(rejected.contains("retry-after: 1\r\n"));
    assert!(rejected.ends_with("too many requests\n"));
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("released"));
}

#[tokio::test]
async fn native_route_proxy_vhost_rate_limit_rejects_second_request() {
    let upstream = upstream_expect_path("/limited", "first").await;
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: fluxheim_config::RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst: 1,
            status: 429,
            ..Default::default()
        },
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

    let first = downstream_get(proxy, "/limited").await;
    let second = downstream_get(proxy, "/limited").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("first"));
    assert!(second.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
    assert!(second.contains("retry-after: 1\r\n"));
    assert!(second.ends_with("rate limited\n"));
}

#[tokio::test]
async fn native_route_proxy_route_rate_limit_rejects_second_request() {
    let upstream = upstream_expect_path("/limited", "first").await;
    let route_config = fluxheim_config::RouteConfig {
        name: "limited".to_owned(),
        path_exact: Some("/limited".to_owned()),
        path_prefix: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: fluxheim_config::RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst: 1,
            status: 429,
            ..Default::default()
        },
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: None,
        proxy: Some(fluxheim_config::ProxyConfig {
            upstreams: vec![upstream.to_string()],
            ..Default::default()
        }),
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };
    let route =
        NativeHttp1RouteProxyRoute::from_config(&route_config, Some(proxy_for(upstream))).unwrap();
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let first = downstream_get(proxy, "/limited").await;
    let second = downstream_get(proxy, "/limited").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("first"));
    assert!(second.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
    assert!(second.contains("retry-after: 1\r\n"));
    assert!(second.ends_with("rate limited\n"));
}

#[tokio::test]
async fn native_route_proxy_rate_limit_delay_consumes_concurrency() {
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: fluxheim_config::RateLimitConfig {
            enabled: true,
            requests_per_second: 10,
            burst: 1,
            status: 429,
            mode: fluxheim_config::RateLimitMode::Delay,
            max_delay_ms: 500,
            ..Default::default()
        },
        concurrency: fluxheim_config::ConcurrencyLimitConfig {
            enabled: true,
            max_in_flight: 1,
            max_queue: 0,
            queue_timeout_ms: 0,
            status: 503,
        },
        tls: Default::default(),
        acme_challenge: Default::default(),
        redirect: fluxheim_config::VhostRedirectConfig {
            enabled: true,
            to: Some("https://target.example{uri}".to_owned()),
            status: 308,
        },
        proxy: Default::default(),
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

    let first = downstream_get(proxy, "/delayed").await;
    assert!(first.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"));

    let delayed = tokio::spawn(async move { downstream_get(proxy, "/delayed").await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let rejected_by_concurrency = downstream_get(proxy, "/delayed").await;
    let delayed = delayed.await.unwrap();

    assert!(rejected_by_concurrency.starts_with("HTTP/1.1 503 Too Many Requests\r\n"));
    assert!(rejected_by_concurrency.contains("retry-after: 1\r\n"));
    assert!(rejected_by_concurrency.ends_with("too many requests\n"));
    assert!(delayed.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"));
}

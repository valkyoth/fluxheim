use crate::{NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute};

use super::{downstream_get, proxy_for, route_proxy_listener, upstream_expect_path};

#[tokio::test]
async fn native_route_proxy_rewrites_prefix_before_forwarding() {
    let upstream = upstream_expect_path("/internal/v1/items?id=7", "rewritten").await;
    let route = NativeHttp1RouteProxyRoute::prefix("/api/", Vec::new(), proxy_for(upstream))
        .with_strip_prefix("/api/")
        .with_rewrite_prefix("/internal/v1/");
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/api/items?id=7").await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("rewritten"));
}

#[tokio::test]
async fn native_route_proxy_rewrite_template_uses_regex_captures() {
    let upstream = upstream_expect_path("/internal/v2/users?id=7", "regex").await;
    let route_config = fluxheim_config::RouteConfig {
        name: "api".to_owned(),
        path_exact: None,
        path_prefix: None,
        path_regex: Some(r"^/api/v(?P<version>[0-9]+)/(?P<rest>.*)$".to_owned()),
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: Some("/internal/v{route.regex.version}/{route.regex.rest}".to_owned()),
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
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

    let response = downstream_get(proxy, "/api/v2/users?id=7").await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("regex"));
}

#[tokio::test]
async fn native_route_proxy_rewrite_template_rejects_capture_slashes() {
    let upstream = upstream_expect_path("/never", "unexpected").await;
    let route_config = fluxheim_config::RouteConfig {
        name: "api".to_owned(),
        path_exact: None,
        path_prefix: None,
        path_regex: Some(r"^/api/(?P<rest>.*)$".to_owned()),
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: Some("/internal/{route.regex.rest}".to_owned()),
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
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

    let response = downstream_get(proxy, "/api/team/users").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
}

#[tokio::test]
async fn native_route_proxy_rewrite_template_rejects_unsafe_regex_capture_path() {
    let upstream = upstream_expect_path("/never", "unexpected").await;
    let route_config = fluxheim_config::RouteConfig {
        name: "api".to_owned(),
        path_exact: None,
        path_prefix: None,
        path_regex: Some(r"^/api/v(?P<version>[0-9]+)/(?P<rest>.*)$".to_owned()),
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: Some("/internal/v{route.regex.version}/{route.regex.rest}".to_owned()),
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
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

    let response = downstream_get(proxy, "/api/v2/../admin").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
}

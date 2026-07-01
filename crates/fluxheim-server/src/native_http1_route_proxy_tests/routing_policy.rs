use std::time::Duration;

use fluxheim_config::GrpcRouteConfig;

use crate::{
    NativeHttp1Handler, NativeHttp1Proxy, NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute,
    NativeHttp1Upstream,
};

use super::{
    downstream_get, downstream_request, proxy_for, response_header, route_proxy_listener,
    route_test_request, upstream_expect_method_path, upstream_expect_path,
};

#[tokio::test]
async fn native_route_proxy_prefers_longest_matching_prefix() {
    let api = upstream_expect_path("/api/users", "api").await;
    let admin = upstream_expect_path("/admin/users", "admin").await;
    let routes = vec![
        NativeHttp1RouteProxyRoute::prefix("/api/", Vec::new(), proxy_for(api)),
        NativeHttp1RouteProxyRoute::prefix("/api/admin/", Vec::new(), proxy_for(admin))
            .with_strip_prefix("/api/admin/")
            .with_rewrite_prefix("/admin/"),
    ];
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(routes, None)).await;

    let response = downstream_get(proxy, "/api/admin/users").await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("admin"));
}

#[tokio::test]
async fn native_route_proxy_uses_fallback_when_method_does_not_match() {
    let fallback = upstream_expect_path("/submit", "fallback").await;
    let route = NativeHttp1RouteProxyRoute::exact(
        "/submit",
        vec!["POST".to_owned()],
        proxy_for(upstream_expect_path("/submit", "post").await),
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(
        vec![route],
        Some(proxy_for(fallback)),
    ))
    .await;

    let response = downstream_get(proxy, "/submit").await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("fallback"));
}

#[test]
fn native_route_proxy_selects_route_request_body_timeout() {
    let route_upstream = "127.0.0.1:3000".parse().unwrap();
    let fallback_upstream = "127.0.0.1:3001".parse().unwrap();
    let route = NativeHttp1RouteProxyRoute::prefix(
        "/api/",
        Vec::new(),
        proxy_for(route_upstream).with_request_body_timeout(Some(Duration::from_secs(4))),
    );
    let proxy = NativeHttp1RouteProxy::new(vec![route], Some(proxy_for(fallback_upstream)));

    assert_eq!(
        proxy.request_body_timeout(&route_test_request("/api/upload")),
        Some(Duration::from_secs(4))
    );
    assert_eq!(
        proxy.request_body_timeout(&route_test_request("/other")),
        None
    );
}

#[test]
fn native_route_proxy_does_not_inherit_fallback_timeout_for_redirect_route() {
    let fallback_upstream = "127.0.0.1:3001".parse().unwrap();
    let route = NativeHttp1RouteProxyRoute::prefix_redirect(
        "/old/",
        Vec::new(),
        "https://route.test/new{uri}".to_owned(),
        308,
    );
    let fallback =
        proxy_for(fallback_upstream).with_request_body_timeout(Some(Duration::from_secs(99)));
    let proxy = NativeHttp1RouteProxy::new(vec![route], Some(fallback));

    assert_eq!(
        proxy.request_body_timeout(&route_test_request("/old/path")),
        None
    );
    assert_eq!(
        proxy.request_body_timeout(&route_test_request("/fallback")),
        Some(Duration::from_secs(99))
    );
}

#[tokio::test]
async fn native_route_proxy_grpc_policy_rejects_non_grpc_requests() {
    let route = NativeHttp1RouteProxyRoute::prefix(
        "/grpc/",
        Vec::new(),
        proxy_for("127.0.0.1:9".parse().unwrap()),
    )
    .with_grpc_policy(GrpcRouteConfig {
        enabled: true,
        require_content_type: true,
    });
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let method_response = downstream_get(proxy, "/grpc/service.Method").await;
    let media_response = downstream_request(
        proxy,
        "POST /grpc/service.Method HTTP/1.1\r\nHost: route.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    let duplicate_media_response = downstream_request(
        proxy,
        "POST /grpc/service.Method HTTP/1.1\r\nHost: route.test\r\nContent-Type: application/grpc\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(method_response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
    assert_eq!(
        response_header(&method_response, "allow").as_deref(),
        Some("POST")
    );
    assert_eq!(
        response_header(&method_response, "grpc-status").as_deref(),
        Some("12")
    );
    assert!(method_response.ends_with("method not allowed\n"));
    assert!(media_response.starts_with("HTTP/1.1 415 Unsupported Media Type\r\n"));
    assert_eq!(
        response_header(&media_response, "grpc-status").as_deref(),
        Some("3")
    );
    assert!(media_response.ends_with("unsupported media type\n"));
    assert!(duplicate_media_response.starts_with("HTTP/1.1 415 Unsupported Media Type\r\n"));
    assert_eq!(
        response_header(&duplicate_media_response, "grpc-status").as_deref(),
        Some("3")
    );
    assert!(duplicate_media_response.ends_with("unsupported media type\n"));
}

#[tokio::test]
async fn native_route_proxy_grpc_policy_allows_grpc_content_type() {
    let upstream = upstream_expect_method_path("POST", "/grpc/service.Method", "grpc").await;
    let route = NativeHttp1RouteProxyRoute::prefix("/grpc/", Vec::new(), proxy_for(upstream))
        .with_grpc_policy(GrpcRouteConfig {
            enabled: true,
            require_content_type: true,
        });
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "POST /grpc/service.Method HTTP/1.1\r\nHost: route.test\r\nContent-Type: Application/gRPC+Proto; charset=utf-8\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("grpc"));
}

#[tokio::test]
async fn native_route_proxy_rejects_unsafe_rewritten_path() {
    let upstream = upstream_expect_path("/never", "never").await;
    let route = NativeHttp1RouteProxyRoute::prefix("/api/", Vec::new(), proxy_for(upstream))
        .with_strip_prefix("/api/");
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/api/%2e%2e/secret").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("bad request\n"));
}

#[tokio::test]
async fn native_route_proxy_rejects_double_slash_after_stripped_prefix() {
    let upstream = upstream_expect_path("/never", "never").await;
    let route = NativeHttp1RouteProxyRoute::prefix("/api", Vec::new(), proxy_for(upstream))
        .with_strip_prefix("/api");
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/api//evil").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("bad request\n"));
}

#[tokio::test]
async fn rejects_redirect_location_without_safe_host() {
    let upstream = upstream_expect_path("/never", "never").await;
    let proxy = NativeHttp1RouteProxy::new(
        vec![NativeHttp1RouteProxyRoute::prefix(
            "/",
            Vec::new(),
            proxy_for(upstream),
        )],
        None,
    )
    .with_https_redirect(fluxheim_config::HttpsRedirectConfig {
        enabled: true,
        status: 308,
        target_port: None,
    });
    let proxy = route_proxy_listener(proxy).await;

    let response = downstream_request(
        proxy,
        "GET /asset HTTP/1.1\r\nHost: example.test/bad\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("missing or invalid host\n"));
}

#[tokio::test]
async fn native_route_proxy_rejects_route_body_over_limit() {
    let route = NativeHttp1RouteProxyRoute::exact(
        "/upload",
        vec!["POST".to_owned()],
        NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:9")),
    )
    .with_max_request_body_bytes(4);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "POST /upload HTTP/1.1\r\nHost: route.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.ends_with("payload too large\n"));
}

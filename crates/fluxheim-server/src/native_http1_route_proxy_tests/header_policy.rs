use std::collections::BTreeMap;

use fluxheim_config::{HeaderValues, ResponseHeaderPolicyOverlayConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::{NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute};

#[cfg(feature = "otel-tracing")]
use super::upstream_echo_header;
use super::{
    downstream_get, downstream_request, proxy_for, response_header, route_proxy_listener,
    upstream_expect_header, upstream_response,
};

#[tokio::test]
async fn native_route_proxy_applies_route_response_headers() {
    let mut set = BTreeMap::new();
    set.insert("x-route".to_owned(), "native".to_owned());
    set.insert(
        "location".to_owned(),
        "https://override.example/target".to_owned(),
    );
    let mut append = BTreeMap::new();
    append.insert(
        "set-cookie".to_owned(),
        HeaderValues::Many(vec!["a=1".to_owned(), "b=2".to_owned()]),
    );
    let policy = ResponseHeaderPolicyOverlayConfig {
        x_frame_options: Some(Some("DENY".to_owned())),
        set,
        append,
        ..Default::default()
    };
    let route = NativeHttp1RouteProxyRoute::prefix_redirect(
        "/old/",
        Vec::new(),
        "https://new.example{uri}",
        302,
    )
    .with_response_header_policy(&policy);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/old/path").await;

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert_eq!(
        response_header(&response, "x-route").as_deref(),
        Some("native")
    );
    assert_eq!(
        response_header(&response, "x-frame-options").as_deref(),
        Some("DENY")
    );
    assert_eq!(
        response_header(&response, "location").as_deref(),
        Some("https://override.example/target")
    );
    assert!(response.contains("set-cookie: a=1\r\n"));
    assert!(response.contains("set-cookie: b=2\r\n"));
}

#[tokio::test]
async fn native_route_proxy_applies_route_response_rewrites() {
    let upstream = upstream_response(
        "HTTP/1.1 302 Found\r\n\
         location: http://backend.internal/login\r\n\
         refresh: 0;url=\"http://backend.internal\"\r\n\
         set-cookie: sid=1; Domain=backend.internal; Path=/internal\r\n\
         set-cookie: Domain=backend.internal; Secure\r\n\
         set-cookie: Path=/internal; Secure\r\n\
         content-length: 0\r\n\r\n",
    )
    .await;
    let policy = ResponseHeaderPolicyOverlayConfig {
        rewrite: fluxheim_config::ResponseHeaderRewriteConfig {
            location: vec![fluxheim_config::ResponseHeaderRewriteRuleConfig {
                from: "http://backend.internal/".to_owned(),
                to: "https://edge.example/".to_owned(),
            }],
            refresh: vec![fluxheim_config::ResponseHeaderRewriteRuleConfig {
                from: "http://backend.internal".to_owned(),
                to: "https://edge.example".to_owned(),
            }],
            cookie_domain: vec![fluxheim_config::ResponseHeaderRewriteRuleConfig {
                from: "backend.internal".to_owned(),
                to: "edge.example".to_owned(),
            }],
            cookie_path: vec![fluxheim_config::ResponseHeaderRewriteRuleConfig {
                from: "/internal".to_owned(),
                to: "/".to_owned(),
            }],
        },
        ..Default::default()
    };
    let route = NativeHttp1RouteProxyRoute::prefix("/api/", Vec::new(), proxy_for(upstream))
        .with_response_header_policy(&policy);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/api/login").await;

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert_eq!(
        response_header(&response, "location").as_deref(),
        Some("https://edge.example/login")
    );
    assert_eq!(
        response_header(&response, "refresh").as_deref(),
        Some("0;url=\"https://edge.example\"")
    );
    assert!(response.contains("set-cookie: sid=1; Domain=edge.example; Path=/\r\n"));
    assert!(response.contains("set-cookie: Domain=backend.internal; Secure\r\n"));
    assert!(response.contains("set-cookie: Path=/internal; Secure\r\n"));
}

#[tokio::test]
async fn native_route_proxy_applies_route_request_headers_before_forwarding() {
    let upstream = upstream_expect_header("/api/item", "x-route", "native", "x-remove").await;
    let mut set = BTreeMap::new();
    set.insert("x-route".to_owned(), "native".to_owned());
    let policy = fluxheim_config::RequestHeaderPolicyOverlayConfig {
        unset: vec!["x-remove".to_owned()],
        set,
        ..Default::default()
    };
    let route = NativeHttp1RouteProxyRoute::prefix("/api/", Vec::new(), proxy_for(upstream))
        .with_request_header_policy(&policy);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /api/item HTTP/1.1\r\nHost: route.test\r\nX-Remove: secret\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("headers"));
}

#[cfg(feature = "otel-tracing")]
#[tokio::test]
async fn native_route_proxy_regenerates_forwarded_traceparent_span_id() {
    let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
    let inbound_span_id = "00f067aa0ba902b7";
    let inbound_traceparent = format!("00-{trace_id}-{inbound_span_id}-01");
    let upstream = upstream_echo_header("/api/trace", "traceparent").await;
    let route = NativeHttp1RouteProxyRoute::prefix("/api/", Vec::new(), proxy_for(upstream));
    let tracing = fluxheim_config::TracingConfig {
        enabled: true,
        mode: fluxheim_config::TracingMode::PropagateOnly,
        traceparent: true,
        log_trace_id: true,
        otlp: Default::default(),
    };
    let proxy = route_proxy_listener(
        NativeHttp1RouteProxy::new(vec![route], None).with_trace_config(&tracing),
    )
    .await;

    let response = downstream_request(
        proxy,
        &format!(
            "GET /api/trace HTTP/1.1\r\nHost: route.test\r\nConnection: close\r\ntraceparent: {inbound_traceparent}\r\n\r\n"
        ),
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("-00"));
    assert!(response.contains(&format!("00-{trace_id}-")));
    assert!(!response.contains(inbound_span_id));
}

#[tokio::test]
async fn native_route_proxy_renders_request_header_templates_before_forwarding() {
    let upstream = upstream_expect_header(
        "/api/item?version=1",
        "x-route-host",
        "route.test",
        "x-remove",
    )
    .await;
    let mut set = BTreeMap::new();
    set.insert("x-route-host".to_owned(), "{host}".to_owned());
    set.insert("x-original-uri".to_owned(), "{uri}".to_owned());
    set.insert("x-client-upgrade".to_owned(), "{http.upgrade}".to_owned());
    let policy = fluxheim_config::RequestHeaderPolicyOverlayConfig {
        unset: vec!["x-remove".to_owned()],
        set,
        ..Default::default()
    };
    let route = NativeHttp1RouteProxyRoute::prefix("/api/", Vec::new(), proxy_for(upstream))
        .with_request_header_policy(&policy);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /api/item?version=1 HTTP/1.1\r\nHost: route.test\r\nX-Remove: secret\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("headers"));
}

#[tokio::test]
async fn native_route_proxy_renders_route_regex_captures_in_request_headers() {
    let upstream =
        upstream_expect_header("/internal/v2/users?id=7", "x-api-version", "2", "x-remove").await;
    let mut add = BTreeMap::new();
    add.insert(
        "x-api-version".to_owned(),
        "{route.regex.version}".to_owned(),
    );
    let policy = fluxheim_config::RequestHeaderPolicyOverlayConfig {
        add,
        ..Default::default()
    };
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
    let route = NativeHttp1RouteProxyRoute::from_config(&route_config, Some(proxy_for(upstream)))
        .unwrap()
        .with_request_header_policy(&policy);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/api/v2/users?id=7").await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("headers"));
}

#[tokio::test]
async fn native_route_proxy_inherits_base_request_and_response_headers_from_config() {
    let upstream =
        upstream_expect_header("/api/item", "x-root-request", "native", "x-remove").await;
    let mut base_headers = fluxheim_config::HeaderPolicyConfig::default();
    base_headers.request.unset.push("x-remove".to_owned());
    base_headers
        .request
        .set
        .insert("x-root-request".to_owned(), "native".to_owned());
    base_headers
        .response
        .set
        .insert("x-root-response".to_owned(), "native".to_owned());
    let mut route_headers = fluxheim_config::VhostHeaderPolicyConfig::default();
    route_headers
        .response
        .set
        .insert("x-route-response".to_owned(), "native".to_owned());
    let route_config = fluxheim_config::RouteConfig {
        name: "api".to_owned(),
        path_exact: None,
        path_prefix: Some("/api/".to_owned()),
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
        headers: route_headers,
    };
    let route = NativeHttp1RouteProxyRoute::from_config_with_inherited(
        &route_config,
        Some(proxy_for(upstream)),
        &base_headers,
        None,
        "route.test",
    )
    .unwrap();
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /api/item HTTP/1.1\r\nHost: route.test\r\nX-Remove: secret\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&response, "x-root-response").as_deref(),
        Some("native")
    );
    assert_eq!(
        response_header(&response, "x-route-response").as_deref(),
        Some("native")
    );
    assert_eq!(
        response_header(&response, "x-content-type-options").as_deref(),
        Some("nosniff")
    );
}

#[tokio::test]
async fn native_route_proxy_disabled_request_headers_suppress_inherited_policy() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        assert!(
            !request
                .lines()
                .any(|line| line.eq_ignore_ascii_case("x-root-request: native")),
            "disabled route request policy forwarded inherited header: {request:?}"
        );
        assert!(
            !request
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("x-forwarded-for:")),
            "disabled route request policy forwarded client IP header: {request:?}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\ndisabled")
            .await
            .unwrap();
    });
    let mut base_headers = fluxheim_config::HeaderPolicyConfig::default();
    base_headers
        .request
        .set
        .insert("x-root-request".to_owned(), "native".to_owned());
    let mut route_headers = fluxheim_config::VhostHeaderPolicyConfig::default();
    route_headers.request.enabled = Some(false);
    let route_config = fluxheim_config::RouteConfig {
        name: "api".to_owned(),
        path_exact: None,
        path_prefix: Some("/api/".to_owned()),
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
        headers: route_headers,
    };
    let route = NativeHttp1RouteProxyRoute::from_config_with_inherited(
        &route_config,
        Some(proxy_for(upstream)),
        &base_headers,
        None,
        "route.test",
    )
    .unwrap();
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /api/item HTTP/1.1\r\nHost: route.test\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("disabled"));
}

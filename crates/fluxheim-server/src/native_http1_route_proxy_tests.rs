use std::collections::BTreeMap;
#[cfg(feature = "compression-gzip")]
use std::io::Read as _;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "compression-gzip")]
use flate2::read::GzDecoder;
use fluxheim_config::{HeaderValues, ResponseHeaderPolicyOverlayConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute,
    NativeHttp1Upstream, serve_native_http1_listener,
};

async fn upstream_expect_path(
    expected_path: &'static str,
    body: &'static str,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
            request.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")),
            "unexpected upstream request: {request:?}"
        );
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    addr
}

async fn upstream_expect_header(
    expected_path: &'static str,
    expected_header: &'static str,
    expected_value: &'static str,
    forbidden_header: &'static str,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
            request.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")),
            "unexpected upstream request: {request:?}"
        );
        assert!(
            request.lines().any(|line| {
                line.eq_ignore_ascii_case(&format!("{expected_header}: {expected_value}"))
            }),
            "missing expected header in upstream request: {request:?}"
        );
        assert!(
            !request.lines().any(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case(forbidden_header))
            }),
            "forbidden header reached upstream request: {request:?}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\n\r\nheaders")
            .await
            .unwrap();
    });
    addr
}

async fn upstream_response(response: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    addr
}

async fn route_proxy_listener(route_proxy: NativeHttp1RouteProxy) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default(),
            Arc::new(route_proxy),
            async {
                let _ = shutdown_rx.await;
            },
        )
        .await
        .unwrap();
    });
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _ = shutdown_tx.send(());
    });
    addr
}

async fn downstream_get(proxy: std::net::SocketAddr, path: &str) -> String {
    downstream_request(
        proxy,
        &format!("GET {path} HTTP/1.1\r\nHost: route.test\r\nConnection: close\r\n\r\n"),
    )
    .await
}

async fn downstream_request(proxy: std::net::SocketAddr, request: &str) -> String {
    String::from_utf8(downstream_request_bytes(proxy, request).await).unwrap()
}

async fn downstream_request_bytes(proxy: std::net::SocketAddr, request: &str) -> Vec<u8> {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    response
}

fn proxy_for(upstream: std::net::SocketAddr) -> NativeHttp1Proxy {
    NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
}

fn response_header(response: &str, name: &str) -> Option<String> {
    let expected = name.to_ascii_lowercase();
    response.lines().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .eq_ignore_ascii_case(&expected)
            .then(|| value.trim().to_owned())
    })
}

#[tokio::test]
async fn native_route_proxy_builds_vhost_acme_and_redirect_routes_from_config() {
    let acme_upstream =
        upstream_expect_path("/.well-known/acme-challenge/token", "acme-route").await;
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
        acme_challenge: fluxheim_config::VhostAcmeChallengeConfig {
            enabled: true,
            upstream: Some(acme_upstream.to_string()),
            ..Default::default()
        },
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

    let acme_response = downstream_get(proxy, "/.well-known/acme-challenge/token").await;
    let redirect_response = downstream_get(proxy, "/docs?x=1").await;

    assert!(acme_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(acme_response.ends_with("acme-route"));
    assert!(redirect_response.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"));
    assert_eq!(
        response_header(&redirect_response, "location").as_deref(),
        Some("https://target.example/docs?x=1")
    );
}

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
async fn native_route_proxy_redirect_expands_uri_template() {
    let route = NativeHttp1RouteProxyRoute::prefix_redirect(
        "/old/",
        Vec::new(),
        "https://new.example{uri}",
        301,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/old/path?x=1").await;

    assert!(response.starts_with("HTTP/1.1 301 Moved Permanently\r\n"));
    assert_eq!(
        response_header(&response, "location").as_deref(),
        Some("https://new.example/old/path?x=1")
    );
    assert!(response.contains("Content-Length: 0\r\n"));
}

#[tokio::test]
async fn native_route_proxy_redirect_rejects_unsafe_uri_expansion() {
    let route = NativeHttp1RouteProxyRoute::prefix_redirect(
        "/old",
        Vec::new(),
        "https://new.example{uri}",
        308,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/old//admin").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("invalid redirect target\n"));
}

#[tokio::test]
async fn native_route_proxy_redirect_rejects_query_path_traversal_expansion() {
    let route = NativeHttp1RouteProxyRoute::exact_redirect(
        "/file",
        Vec::new(),
        "https://cdn.example/files/{query}",
        302,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/file?../../admin/secrets").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("invalid redirect target\n"));
}

#[tokio::test]
async fn native_route_proxy_redirect_rejects_percent_encoded_query_path_traversal_expansion() {
    let route = NativeHttp1RouteProxyRoute::exact_redirect(
        "/file",
        Vec::new(),
        "https://cdn.example/files/{query}",
        302,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/file?%2e%2e/%2e%2e/admin/secrets").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("invalid redirect target\n"));
}

#[tokio::test]
async fn native_route_proxy_redirect_rejects_double_encoded_query_path_traversal_expansion() {
    let route = NativeHttp1RouteProxyRoute::exact_redirect(
        "/file",
        Vec::new(),
        "https://cdn.example/files/{query}",
        302,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/file?%252e%252e/secret").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("invalid redirect target\n"));
}

#[tokio::test]
async fn native_route_proxy_redirect_rejects_double_slash_location_path() {
    let route = NativeHttp1RouteProxyRoute::exact_redirect(
        "/file",
        Vec::new(),
        "https://cdn.example/{path}",
        302,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/file").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("invalid redirect target\n"));
}

#[tokio::test]
async fn native_route_proxy_redirect_rejects_percent_encoded_double_slash_location_path() {
    let route = NativeHttp1RouteProxyRoute::exact_redirect(
        "/file",
        Vec::new(),
        "https://cdn.example/files/{query}",
        302,
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/file?%2f%2fadmin").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("invalid redirect target\n"));
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
         refresh: 0;url=http://backend.internal/next\r\n\
         set-cookie: sid=1; Domain=backend.internal; Path=/internal\r\n\
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
                from: "http://backend.internal/".to_owned(),
                to: "https://edge.example/".to_owned(),
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
        Some("0;url=https://edge.example/next")
    );
    assert!(response.contains("set-cookie: sid=1; Domain=edge.example; Path=/\r\n"));
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

#[cfg(not(feature = "privacy-mode"))]
#[tokio::test]
async fn native_route_proxy_request_header_builder_uses_secure_forwarded_defaults() {
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
        assert!(request.contains("x-forwarded-for: 127.0.0.1\r\n"));
        assert!(request.contains("x-forwarded-host: route.test\r\n"));
        assert!(request.contains("x-forwarded-proto: http\r\n"));
        assert!(!request.to_ascii_lowercase().contains("cf-connecting-ip:"));
        assert!(!request.contains("x-forwarded-for: 192.0.2.9\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\nbaseline")
            .await
            .unwrap();
    });
    let policy = fluxheim_config::RequestHeaderPolicyOverlayConfig::default();
    let route = NativeHttp1RouteProxyRoute::prefix("/api/", Vec::new(), proxy_for(upstream))
        .with_request_header_policy(&policy);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /api/item HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 192.0.2.9\r\n\
         CF-Connecting-IP: 192.0.2.10\r\n\
         Connection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("baseline"));
}

#[cfg(not(feature = "privacy-mode"))]
#[tokio::test]
async fn native_route_proxy_strip_append_does_not_preserve_spoofed_forwarded_chain() {
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
        assert!(request.contains("x-forwarded-for: 127.0.0.1\r\n"));
        assert!(!request.contains("x-forwarded-for: 192.0.2.9, 127.0.0.1\r\n"));
        assert!(!request.to_ascii_lowercase().contains("true-client-ip:"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nappend")
            .await
            .unwrap();
    });
    let policy = fluxheim_config::RequestHeaderPolicyOverlayConfig {
        strip_inbound_client_ip_headers: Some(true),
        x_forwarded_for: Some(fluxheim_config::ForwardedClientIpHeaderMode::Append),
        ..Default::default()
    };
    let route = NativeHttp1RouteProxyRoute::prefix("/api/", Vec::new(), proxy_for(upstream))
        .with_request_header_policy(&policy);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /api/item HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 192.0.2.9\r\n\
         True-Client-IP: 192.0.2.10\r\n\
         Connection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("append"));
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

#[cfg(feature = "compression-gzip")]
#[tokio::test]
async fn native_route_proxy_applies_gzip_route_compression() {
    let upstream = upstream_response(
        "HTTP/1.1 200 OK\r\n\
         content-type: text/plain\r\n\
         etag: \"origin-tag\"\r\n\r\n\
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression \
         hello native compression hello native compression hello native compression",
    )
    .await;
    let route = NativeHttp1RouteProxyRoute::prefix("/asset/", Vec::new(), proxy_for(upstream))
        .with_compression_config(fluxheim_config::CompressionConfig {
            enabled: true,
            gzip: true,
            min_bytes: fluxheim_config::ByteSize::from_bytes(1),
            max_input_bytes: fluxheim_config::ByteSize::from_bytes(4096),
            max_output_bytes: fluxheim_config::ByteSize::from_bytes(4096),
            ..Default::default()
        });
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request_bytes(
        proxy,
        "GET /asset/text HTTP/1.1\r\nHost: route.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    )
    .await;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = String::from_utf8(response[..split].to_vec()).unwrap();
    let body = &response[split + 4..];

    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(head.contains("\r\ncontent-encoding: gzip"));
    assert!(head.contains("\r\nvary: accept-encoding"));
    assert!(!head.contains("\r\netag:"));
    let mut decoded = String::new();
    GzDecoder::new(body).read_to_string(&mut decoded).unwrap();
    assert!(decoded.contains("hello native compression"));
}

#[cfg(feature = "compression-gzip")]
#[tokio::test]
async fn native_route_proxy_inherits_gzip_compression_config() {
    let upstream = upstream_response(
        "HTTP/1.1 200 OK\r\n\
         content-type: text/plain\r\n\r\n\
         inherited native compression inherited native compression \
         inherited native compression inherited native compression \
         inherited native compression inherited native compression",
    )
    .await;
    let route_config = fluxheim_config::RouteConfig {
        name: "asset".to_owned(),
        path_exact: None,
        path_prefix: Some("/asset/".to_owned()),
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
        headers: Default::default(),
    };
    let inherited = fluxheim_config::CompressionConfig {
        enabled: true,
        gzip: true,
        min_bytes: fluxheim_config::ByteSize::from_bytes(1),
        max_input_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_output_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        ..Default::default()
    };
    let route = NativeHttp1RouteProxyRoute::from_config_with_inherited(
        &route_config,
        Some(proxy_for(upstream)),
        &fluxheim_config::HeaderPolicyConfig::default(),
        Some(&inherited),
    )
    .unwrap();
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request_bytes(
        proxy,
        "GET /asset/text HTTP/1.1\r\nHost: route.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    )
    .await;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = String::from_utf8(response[..split].to_vec()).unwrap();
    let body = &response[split + 4..];

    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&head, "content-encoding").as_deref(),
        Some("gzip")
    );
    let mut decoded = String::new();
    GzDecoder::new(body).read_to_string(&mut decoded).unwrap();
    assert!(decoded.contains("inherited native compression"));
}

#[cfg(all(feature = "compression-gzip", feature = "compression-zstd"))]
#[tokio::test]
async fn native_route_proxy_prefers_higher_accept_encoding_quality() {
    let upstream = upstream_response(
        "HTTP/1.1 200 OK\r\n\
         content-type: text/plain\r\n\r\n\
         hello native compression quality hello native compression quality \
         hello native compression quality hello native compression quality",
    )
    .await;
    let route = NativeHttp1RouteProxyRoute::prefix("/asset/", Vec::new(), proxy_for(upstream))
        .with_compression_config(fluxheim_config::CompressionConfig {
            enabled: true,
            gzip: true,
            zstd: true,
            min_bytes: fluxheim_config::ByteSize::from_bytes(1),
            max_input_bytes: fluxheim_config::ByteSize::from_bytes(4096),
            max_output_bytes: fluxheim_config::ByteSize::from_bytes(4096),
            ..Default::default()
        });
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request_bytes(
        proxy,
        "GET /asset/text HTTP/1.1\r\nHost: route.test\r\nAccept-Encoding: zstd;q=0.1, gzip;q=1.0\r\nConnection: close\r\n\r\n",
    )
    .await;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = String::from_utf8(response[..split].to_vec()).unwrap();

    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&head, "content-encoding").as_deref(),
        Some("gzip")
    );
}

#[tokio::test]
async fn native_route_proxy_skips_disabled_route_response_headers() {
    let mut set = BTreeMap::new();
    set.insert("x-route".to_owned(), "native".to_owned());
    let policy = ResponseHeaderPolicyOverlayConfig {
        enabled: Some(false),
        set,
        ..Default::default()
    };
    let route = NativeHttp1RouteProxyRoute::exact_redirect(
        "/old",
        Vec::new(),
        "https://new.example{uri}",
        302,
    )
    .with_response_header_policy(&policy);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/old").await;

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert_eq!(response_header(&response, "x-route"), None);
    assert_eq!(
        response_header(&response, "location").as_deref(),
        Some("https://new.example/old")
    );
}

#[test]
fn native_route_proxy_builds_redirect_route_from_config_without_proxy() {
    let route = fluxheim_config::RouteConfig {
        name: "redirect".to_owned(),
        path_exact: Some("/old".to_owned()),
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
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: Some(fluxheim_config::RouteRedirectConfig {
            to: "https://new.example{uri}".to_owned(),
            status: 308,
        }),
        proxy: None,
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };

    let route = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap();

    assert!(route.is_redirect());
    assert!(route.proxy().is_none());
}

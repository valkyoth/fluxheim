use std::sync::Arc;
use std::time::Duration;

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
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

fn proxy_for(upstream: std::net::SocketAddr) -> NativeHttp1Proxy {
    NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
}

fn response_header(response: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}:");
    response.lines().find_map(|line| {
        line.strip_prefix(&prefix)
            .map(|value| value.trim().to_owned())
    })
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

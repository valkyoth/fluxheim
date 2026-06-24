use std::fs;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    DownstreamHttp1Policy, NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute, NativeHttp1StaticWeb,
    serve_native_http1_listener,
};

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

async fn downstream_post(proxy: std::net::SocketAddr, path: &str) -> String {
    downstream_request(
        proxy,
        &format!("POST {path} HTTP/1.1\r\nHost: route.test\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"),
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

fn response_header(response: &str, name: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

fn native_static_web(root: &std::path::Path) -> NativeHttp1StaticWeb {
    NativeHttp1StaticWeb::from_config(&fluxheim_config::WebConfig {
        root: Some(root.to_path_buf()),
        cache_control: "public, max-age=120".to_owned(),
        ..Default::default()
    })
    .unwrap()
    .unwrap()
}

fn native_static_web_with_cache(root: &std::path::Path) -> NativeHttp1StaticWeb {
    NativeHttp1StaticWeb::from_config_with_cache(
        &fluxheim_config::WebConfig {
            root: Some(root.to_path_buf()),
            cache_control: "public, max-age=120".to_owned(),
            ..Default::default()
        },
        Some(&fluxheim_config::CacheConfig {
            enabled: true,
            local_static: true,
            status_header: Some("x-fluxheim-cache".to_owned()),
            status_reason_header: Some("x-fluxheim-cache-reason".to_owned()),
            memory: fluxheim_config::CacheMemoryConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }),
    )
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn native_route_proxy_serves_static_web_file() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("asset.txt"), b"native-static\n").unwrap();
    let route = NativeHttp1RouteProxyRoute::prefix_static_web(
        "/static/",
        vec!["GET".to_owned(), "HEAD".to_owned()],
        native_static_web(root.path()),
    )
    .with_strip_prefix("/static/");
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/static/asset.txt").await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&response, "content-type").as_deref(),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(
        response_header(&response, "cache-control").as_deref(),
        Some("public, max-age=120")
    );
    assert!(response_header(&response, "etag").is_some());
    assert!(response.ends_with("native-static\n"));

    root.close().unwrap();
}

#[tokio::test]
async fn native_route_proxy_caches_static_web_file_in_memory() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("asset.png"), b"native-static-png\n").unwrap();
    let route = NativeHttp1RouteProxyRoute::prefix_static_web(
        "/static/",
        vec!["GET".to_owned()],
        native_static_web_with_cache(root.path()),
    )
    .with_strip_prefix("/static/");
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let first = downstream_get(proxy, "/static/asset.png").await;
    let second = downstream_get(proxy, "/static/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&first, "x-fluxheim-cache").as_deref(),
        Some("MISS")
    );
    assert!(first.ends_with("native-static-png\n"));
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&second, "x-fluxheim-cache").as_deref(),
        Some("HIT")
    );
    assert!(second.ends_with("native-static-png\n"));

    root.close().unwrap();
}

#[tokio::test]
async fn native_route_proxy_caches_vhost_static_web_file_in_memory() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("asset.png"), b"native-vhost-static-png\n").unwrap();
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
        proxy: fluxheim_config::ProxyConfig::disabled(),
        cache: fluxheim_config::CacheConfig {
            enabled: true,
            local_static: true,
            status_header: Some("x-fluxheim-cache".to_owned()),
            status_reason_header: Some("x-fluxheim-cache-reason".to_owned()),
            memory: fluxheim_config::CacheMemoryConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: fluxheim_config::WebConfig {
            root: Some(root.path().to_path_buf()),
            cache_control: "public, max-age=120".to_owned(),
            ..Default::default()
        },
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

    let first = downstream_get(proxy, "/asset.png").await;
    let second = downstream_get(proxy, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&first, "x-fluxheim-cache").as_deref(),
        Some("MISS")
    );
    assert!(first.ends_with("native-vhost-static-png\n"));
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&second, "x-fluxheim-cache").as_deref(),
        Some("HIT")
    );
    assert!(second.ends_with("native-vhost-static-png\n"));

    root.close().unwrap();
}

#[tokio::test]
async fn native_route_proxy_serves_static_web_range() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("asset.txt"), b"abcdef").unwrap();
    let route = NativeHttp1RouteProxyRoute::prefix_static_web(
        "/files/",
        Vec::new(),
        native_static_web(root.path()),
    )
    .with_strip_prefix("/files/");
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /files/asset.txt HTTP/1.1\r\nHost: route.test\r\nRange: bytes=1-3\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert_eq!(
        response_header(&response, "content-range").as_deref(),
        Some("bytes 1-3/6")
    );
    assert!(response.ends_with("bcd"));

    root.close().unwrap();
}

#[tokio::test]
async fn native_route_proxy_static_web_rejects_non_get_head_method() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("asset.txt"), b"native-static\n").unwrap();
    let route = NativeHttp1RouteProxyRoute::prefix_static_web(
        "/files/",
        Vec::new(),
        native_static_web(root.path()),
    )
    .with_strip_prefix("/files/");
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_post(proxy, "/files/asset.txt").await;

    assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
    assert_eq!(
        response_header(&response, "allow").as_deref(),
        Some("GET, HEAD")
    );
    assert!(response.ends_with("method not allowed\n"));

    root.close().unwrap();
}

#[tokio::test]
async fn native_route_proxy_static_web_rejects_traversal() {
    let root = TempDir::new().unwrap();
    let route = NativeHttp1RouteProxyRoute::prefix_static_web(
        "/files/",
        Vec::new(),
        native_static_web(root.path()),
    )
    .with_strip_prefix("/files/");
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/files/%2e%2e/secret.txt").await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("bad request\n"));

    root.close().unwrap();
}

#[test]
fn native_route_proxy_builds_static_web_route_from_config_without_proxy() {
    let root = TempDir::new().unwrap();
    let route = fluxheim_config::RouteConfig {
        name: "web".to_owned(),
        path_exact: None,
        path_prefix: Some("/static/".to_owned()),
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: Some("/static/".to_owned()),
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: None,
        proxy: None,
        web: Some(fluxheim_config::WebConfig {
            root: Some(root.path().to_path_buf()),
            ..Default::default()
        }),
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };

    let route = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap();

    assert!(route.is_static_web());
    assert!(route.proxy().is_none());

    root.close().unwrap();
}

#[test]
fn native_route_proxy_builds_static_web_route_from_config_with_memory_cache() {
    let root = TempDir::new().unwrap();
    let route = fluxheim_config::RouteConfig {
        name: "web-cache".to_owned(),
        path_exact: None,
        path_prefix: Some("/static/".to_owned()),
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: Some("/static/".to_owned()),
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: None,
        proxy: None,
        web: Some(fluxheim_config::WebConfig {
            root: Some(root.path().to_path_buf()),
            ..Default::default()
        }),
        php: None,
        cache: Some(fluxheim_config::CacheConfig {
            enabled: true,
            local_static: true,
            memory: fluxheim_config::CacheMemoryConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }),
        compression: None,
        headers: Default::default(),
    };

    let route = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap();

    assert!(route.is_static_web());
    assert!(route.proxy().is_none());

    root.close().unwrap();
}

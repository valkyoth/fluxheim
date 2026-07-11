use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    DownstreamHttp1Policy, DownstreamHttp2Policy, NativeHttp1HostRouter,
    NativeHttp1HostRouterConfigError, NativeHttp1ProxyConfigError, NativeHttp1RequestContext,
    NativeHttp1RouteProxyConfigError, NativeHttp2RouteAdapter, serve_native_http1_listener,
};

static HOST_REJECTION_MISSING: AtomicUsize = AtomicUsize::new(0);
static HOST_REJECTION_INVALID: AtomicUsize = AtomicUsize::new(0);
static HOST_REJECTION_UNKNOWN: AtomicUsize = AtomicUsize::new(0);

struct HostRoutingTestRecorder;

impl crate::NativeProxyMetricsRecorder for HostRoutingTestRecorder {
    fn record_outcome(&self, _vhost: &str, _method: &str, _status: u16) {}

    fn record_host_routing_rejection(&self, reason: &str) {
        match reason {
            "missing" => &HOST_REJECTION_MISSING,
            "invalid" => &HOST_REJECTION_INVALID,
            "unknown" => &HOST_REJECTION_UNKNOWN,
            _ => return,
        }
        .fetch_add(1, Ordering::AcqRel);
    }
}

async fn upstream_response(body: &'static str) -> std::net::SocketAddr {
    upstream_response_count(body, 1).await
}

async fn upstream_response_count(body: &'static str, count: usize) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..count {
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
        }
    });
    addr
}

async fn router_listener(router: NativeHttp1HostRouter) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default(),
            Arc::new(router),
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

async fn downstream_get(proxy: std::net::SocketAddr, host: Option<&str>) -> String {
    downstream_get_path(proxy, host, "/").await
}

async fn downstream_get_path(
    proxy: std::net::SocketAddr,
    host: Option<&str>,
    path: &str,
) -> String {
    let host_header = host
        .map(|host| format!("Host: {host}\r\n"))
        .unwrap_or_default();
    let request = format!("GET {path} HTTP/1.1\r\n{host_header}Connection: close\r\n\r\n");
    downstream_request(proxy, &request).await
}

async fn downstream_get_http10(proxy: std::net::SocketAddr) -> String {
    downstream_request(proxy, "GET / HTTP/1.0\r\nConnection: close\r\n\r\n").await
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

fn vhost(
    name: &str,
    hosts: &[&str],
    upstream: std::net::SocketAddr,
) -> fluxheim_config::VhostConfig {
    let mut proxy = fluxheim_config::ProxyConfig::disabled();
    proxy.upstream = Some(upstream.to_string());
    fluxheim_config::VhostConfig {
        name: name.to_owned(),
        hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
        acme_challenge: Default::default(),
        redirect: Default::default(),
        proxy,
        cache: Default::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: Vec::new(),
    }
}

#[tokio::test]
async fn native_host_router_serves_root_proxy_without_vhosts() {
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
        assert!(request.starts_with("GET / HTTP/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  content-length: 4\r\n\
                  x-powered-by: php\r\n\
                  x-root-remove: old\r\n\r\nroot",
            )
            .await
            .unwrap();
    });

    let mut config = fluxheim_config::Config::default();
    config.proxy.upstreams = vec![upstream.to_string()];
    config
        .headers
        .response
        .unset
        .push("x-root-remove".to_owned());
    config
        .headers
        .response
        .set
        .insert("x-root-response".to_owned(), "native".to_owned());

    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get(proxy, Some("anything.test")).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("x-root-response: native\r\n"));
    assert!(response.contains("x-content-type-options: nosniff\r\n"));
    assert!(!response.to_ascii_lowercase().contains("x-powered-by:"));
    assert!(!response.to_ascii_lowercase().contains("x-root-remove:"));
    assert!(response.ends_with("root"));
}

#[test]
fn native_host_router_rejects_empty_config_without_root_proxy() {
    let config = fluxheim_config::Config {
        proxy: fluxheim_config::ProxyConfig::disabled(),
        ..Default::default()
    };

    assert!(matches!(
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0),
        Err(NativeHttp1HostRouterConfigError::MissingVhost)
    ));
}

#[tokio::test]
async fn native_host_router_serves_root_static_web_without_vhosts() {
    let root = TempDir::new().unwrap();
    std::fs::write(root.path().join("asset.txt"), b"root static").unwrap();
    let config = fluxheim_config::Config {
        proxy: fluxheim_config::ProxyConfig::disabled(),
        web: fluxheim_config::WebConfig {
            root: Some(root.path().to_path_buf()),
            ..Default::default()
        },
        ..Default::default()
    };

    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let response = downstream_get_path(proxy, Some("anything.test"), "/asset.txt").await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: text/plain; charset=utf-8\r\n"));
    assert!(response.ends_with("root static"));
}

#[tokio::test]
async fn native_host_router_caches_root_static_web_without_vhosts() {
    let root = TempDir::new().unwrap();
    std::fs::write(root.path().join("asset.png"), b"root cached").unwrap();
    let config = fluxheim_config::Config {
        proxy: fluxheim_config::ProxyConfig::disabled(),
        web: fluxheim_config::WebConfig {
            root: Some(root.path().to_path_buf()),
            cache_control: "public, max-age=120".to_owned(),
            ..Default::default()
        },
        cache: fluxheim_config::CacheConfig {
            enabled: true,
            local_static: true,
            status_header: Some("x-fluxheim-cache".to_owned()),
            memory: fluxheim_config::CacheMemoryConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let first = downstream_get_path(proxy, Some("anything.test"), "/asset.png").await;
    let second = downstream_get_path(proxy, Some("anything.test"), "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&first, "x-fluxheim-cache").as_deref(),
        Some("MISS")
    );
    assert!(first.ends_with("root cached"));
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&second, "x-fluxheim-cache").as_deref(),
        Some("HIT")
    );
    assert!(second.ends_with("root cached"));
}

#[test]
fn native_host_router_rejects_root_static_web_unsupported_cache() {
    let root = TempDir::new().unwrap();
    std::fs::write(root.path().join("asset.txt"), b"root static").unwrap();
    let config = fluxheim_config::Config {
        proxy: fluxheim_config::ProxyConfig::disabled(),
        web: fluxheim_config::WebConfig {
            root: Some(root.path().to_path_buf()),
            ..Default::default()
        },
        cache: fluxheim_config::CacheConfig {
            enabled: true,
            local_static: true,
            memory: fluxheim_config::CacheMemoryConfig {
                enabled: true,
                ..Default::default()
            },
            disk: fluxheim_config::CacheDiskConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(matches!(
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0),
        Err(NativeHttp1HostRouterConfigError::RouteProxy(
            NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::CachePolicy)
        ))
    ));
}

#[tokio::test]
async fn native_host_router_routes_exact_hosts_and_default_fallback() {
    let primary = upstream_response("primary").await;
    let secondary = upstream_response("secondary").await;
    let fallback = upstream_response("fallback").await;
    let mut config = fluxheim_config::Config::default();
    config.server.default_vhost = Some("fallback".to_owned());
    config.vhosts = vec![
        vhost("primary", &["primary.test"], primary),
        vhost("secondary", &["secondary.test"], secondary),
        vhost("fallback", &["fallback.test"], fallback),
    ];

    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let primary_response = downstream_get(proxy, Some("primary.test")).await;
    let secondary_response = downstream_get(proxy, Some("secondary.test:80")).await;
    let fallback_response = downstream_get(proxy, Some("unknown.test")).await;

    assert!(primary_response.ends_with("primary"));
    assert!(secondary_response.ends_with("secondary"));
    assert!(fallback_response.ends_with("fallback"));
}

#[tokio::test]
async fn native_host_router_falls_back_for_missing_and_invalid_host() {
    let first = upstream_response("first").await;
    let fallback = upstream_response_count("fallback", 2).await;
    let mut config = fluxheim_config::Config::default();
    config.server.default_vhost = Some("fallback".to_owned());
    config.vhosts = vec![
        vhost("first", &["first.test"], first),
        vhost("fallback", &["fallback.test"], fallback),
    ];

    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let missing = downstream_get_http10(proxy).await;
    let unknown = downstream_get(proxy, Some("unknown.test")).await;

    assert!(missing.ends_with("fallback"));
    assert!(unknown.ends_with("fallback"));
}

#[tokio::test]
async fn native_host_router_strict_mode_rejects_missing_invalid_and_unknown_hosts() {
    let _ = crate::install_native_proxy_metrics_recorder(Arc::new(HostRoutingTestRecorder));
    HOST_REJECTION_MISSING.store(0, Ordering::Release);
    HOST_REJECTION_INVALID.store(0, Ordering::Release);
    HOST_REJECTION_UNKNOWN.store(0, Ordering::Release);
    let known = upstream_response("known").await;
    let mut config = fluxheim_config::Config::default();
    config.server.default_vhost = Some("known".to_owned());
    config.server.host_routing.strict = true;
    config.vhosts = vec![vhost("known", &["known.test"], known)];

    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let known = downstream_get(proxy, Some("known.test")).await;
    let missing = downstream_get_http10(proxy).await;
    let invalid = downstream_get(proxy, Some("%invalid.test")).await;
    let unknown = downstream_get(proxy, Some("unknown.test")).await;

    assert!(known.ends_with("known"));
    assert!(missing.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(invalid.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(unknown.starts_with("HTTP/1.1 421 Misdirected Request\r\n"));
    assert!(HOST_REJECTION_MISSING.load(Ordering::Acquire) >= 1);
    assert!(HOST_REJECTION_INVALID.load(Ordering::Acquire) >= 1);
    assert!(HOST_REJECTION_UNKNOWN.load(Ordering::Acquire) >= 1);
}

#[tokio::test]
async fn native_host_router_strict_mode_rejects_unknown_http2_authority() {
    let upstream = upstream_response("unexpected").await;
    let mut config = fluxheim_config::Config::default();
    config.server.default_vhost = Some("known".to_owned());
    config.server.host_routing.strict = true;
    config.vhosts = vec![vhost("known", &["known.test"], upstream)];
    let router = Arc::new(
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap(),
    );
    let (server_io, client_io) = tokio::io::duplex(4096);
    let adapter = Arc::new(NativeHttp2RouteAdapter::new(
        router,
        None,
        NativeHttp1RequestContext::default(),
    ));
    let server = tokio::spawn(
        crate::native_http2_stack::serve_native_http2_connection_until_idle(
            server_io,
            DownstreamHttp2Policy::default(),
            adapter,
            Duration::from_millis(50),
        ),
    );
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let connection = tokio::spawn(async move { connection.await.unwrap() });
    let request = http::Request::builder()
        .uri("https://unknown.test/")
        .body(())
        .unwrap();

    let (response, _) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();

    assert_eq!(response.status(), http::StatusCode::MISDIRECTED_REQUEST);
    drop(client);
    connection.await.unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn native_host_router_routes_wildcards_by_longest_suffix() {
    let wildcard = upstream_response("wildcard").await;
    let specific = upstream_response("specific").await;
    let default = upstream_response("default").await;
    let mut config = fluxheim_config::Config::default();
    config.server.default_vhost = Some("default".to_owned());
    config.vhosts = vec![
        vhost("wildcard", &["*.example.test"], wildcard),
        vhost("specific", &["*.api.example.test"], specific),
        vhost("default", &["default.test"], default),
    ];

    let router =
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0).unwrap();
    let proxy = router_listener(router).await;

    let wildcard_response = downstream_get(proxy, Some("www.example.test")).await;
    let specific_response = downstream_get(proxy, Some("v1.api.example.test")).await;
    let apex_response = downstream_get(proxy, Some("example.test")).await;

    assert!(wildcard_response.ends_with("wildcard"));
    assert!(specific_response.ends_with("specific"));
    assert!(apex_response.ends_with("default"));
}

#[test]
fn native_host_router_rejects_unknown_default_vhost() {
    let mut config = fluxheim_config::Config::default();
    config.server.default_vhost = Some("missing".to_owned());
    config.vhosts = vec![vhost(
        "first",
        &["first.test"],
        "127.0.0.1:3000".parse().unwrap(),
    )];

    assert!(matches!(
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0),
        Err(NativeHttp1HostRouterConfigError::MissingDefaultVhost { name })
            if name == "missing"
    ));
}

#[cfg(feature = "geoip")]
#[test]
fn native_host_router_constructs_geoip_runtime_fail_closed() {
    let root = TempDir::new().unwrap();
    let config = fluxheim_config::Config {
        geoip: fluxheim_config::GeoIpConfig {
            enabled: true,
            fallback_enabled: true,
            databases: vec![fluxheim_config::GeoIpDatabaseConfig {
                provider: fluxheim_config::GeoIpProvider::CirclGeoOpen,
                path: root.path().join("missing.mmdb"),
            }],
        },
        ..fluxheim_config::Config::default()
    };

    assert!(matches!(
        NativeHttp1HostRouter::from_config(&config, DownstreamHttp1Policy::default(), 0),
        Err(NativeHttp1HostRouterConfigError::GeoIp { .. })
    ));
}

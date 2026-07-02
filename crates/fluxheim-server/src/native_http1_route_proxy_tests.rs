use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{DownstreamHttp1Policy, NativeHttp1RouteProxy, serve_native_http1_listener};

#[path = "native_http1_route_proxy_tests/access_policy.rs"]
mod access_policy_tests;
#[path = "native_http1_route_proxy_tests/acme.rs"]
mod acme_tests;
#[path = "native_http1_route_proxy_tests/cache_config.rs"]
mod cache_config_tests;
#[path = "native_http1_route_proxy_tests/cache_control.rs"]
mod cache_control_tests;
#[path = "native_http1_route_proxy_tests/cache_freshness.rs"]
mod cache_freshness_tests;
#[path = "native_http1_route_proxy_tests/cache_peer.rs"]
mod cache_peer_tests;
#[path = "native_http1_route_proxy_tests/cache_range.rs"]
mod cache_range_tests;
#[path = "native_http1_route_proxy_tests/cache_storage.rs"]
mod cache_storage_tests;
#[path = "native_http1_route_proxy_tests/compression_response.rs"]
mod compression_response_tests;
#[cfg(not(feature = "privacy-mode"))]
#[path = "native_http1_route_proxy_tests/forwarded_headers.rs"]
mod forwarded_header_tests;
#[path = "native_http1_route_proxy_tests/header_defaults.rs"]
mod header_defaults_tests;
#[path = "native_http1_route_proxy_tests/header_policy.rs"]
mod header_policy_tests;
#[path = "native_http1_route_proxy_tests/php_fpm.rs"]
mod php_fpm_tests;
#[path = "native_http1_route_proxy_tests/rate_concurrency.rs"]
mod rate_concurrency_tests;
#[path = "native_http1_route_proxy_tests/rewrite.rs"]
mod rewrite_tests;
#[path = "native_http1_route_proxy_tests/routing_policy.rs"]
mod routing_policy_tests;
#[path = "native_http1_route_proxy_tests/support.rs"]
mod support;
#[path = "native_http1_route_proxy_tests/upstream_cache.rs"]
mod upstream_cache;
#[path = "native_http1_route_proxy_tests/websocket.rs"]
mod websocket_tests;

use support::*;
use upstream_cache::*;

async fn upstream_expect_path(
    expected_path: &'static str,
    body: &'static str,
) -> std::net::SocketAddr {
    upstream_expect_method_path("GET", expected_path, body).await
}

async fn upstream_expect_method_path(
    expected_method: &'static str,
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
            request.starts_with(&format!("{expected_method} {expected_path} HTTP/1.1\r\n")),
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

#[cfg(feature = "otel-tracing")]
async fn upstream_echo_header(
    expected_path: &'static str,
    header: &'static str,
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
        let value = request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case(header)
                    .then(|| value.trim().to_owned())
            })
            .unwrap_or_default();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                    value.len(),
                    value
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    addr
}

#[cfg(feature = "privacy-mode")]
async fn upstream_expect_headers_absent(
    expected_path: &'static str,
    forbidden_headers: &'static [&'static str],
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
        for forbidden_header in forbidden_headers {
            assert!(
                !request.lines().any(|line| {
                    line.split_once(':')
                        .is_some_and(|(name, _)| name.eq_ignore_ascii_case(forbidden_header))
                }),
                "forbidden header {forbidden_header:?} reached upstream request: {request:?}"
            );
        }
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

async fn upstream_hold_response(
    expected_path: &'static str,
    body: &'static str,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (observed_tx, observed_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
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
        let _ = observed_tx.send(());
        let _ = release_rx.await;
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
    (addr, observed_rx, release_tx)
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

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[cfg(feature = "acme")]
use crate::NativeHttp1AcmeHttp01Store;
use crate::{
    DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1Request, NativeHttp1RouteProxy,
    NativeHttp1RouteProxyRoute, NativeHttp1Upstream, serve_native_http1_listener,
};

#[path = "native_http1_route_proxy_tests/access_policy.rs"]
mod access_policy_tests;
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

async fn upstream_cacheable_once(body: &'static str) -> std::net::SocketAddr {
    upstream_cacheable_once_with_max_age(body, 60).await
}

async fn peer_fill_cacheable_once(body: &'static str) -> std::net::SocketAddr {
    peer_fill_response_once(format!(
        "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    ))
    .await
}

async fn peer_fill_response_once(response: impl Into<String>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let response = response.into();
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
            request.starts_with("GET /asset.png HTTP/1.1\r\n"),
            "unexpected peer-fill request: {request:?}"
        );
        assert!(
            request.contains("cache-control: only-if-cached\r\n")
                || request.contains("Cache-Control: only-if-cached\r\n"),
            "peer-fill request missing only-if-cached: {request:?}"
        );
        assert!(
            request.contains("x-fluxheim-peer-fill: 1\r\n")
                || request.contains("X-Fluxheim-Peer-Fill: 1\r\n"),
            "peer-fill request missing loop marker: {request:?}"
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    addr
}

async fn upstream_cacheable_once_with_max_age(
    body: &'static str,
    max_age_secs: u64,
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
            request.starts_with("GET /asset.png HTTP/1.1\r\n"),
            "unexpected upstream request: {request:?}"
        );
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age={max_age_secs}\r\ncontent-length: {}\r\n\r\n{}",
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

async fn upstream_delayed_cacheable_once(
    body: &'static str,
    delay: Duration,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
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
            request.starts_with("GET /asset.png HTTP/1.1\r\n"),
            "unexpected upstream request: {request:?}"
        );
        let _ = accepted_tx.send(());
        tokio::time::sleep(delay).await;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    (addr, accepted_rx)
}

async fn upstream_cacheable_sequence(
    responses: &'static [(&'static str, &'static str)],
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for (expected_path, body) in responses {
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
                        "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-length: {}\r\n\r\n{}",
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

async fn upstream_vary_sequence(
    responses: &'static [(&'static str, &'static str, &'static str, &'static str)],
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for (expected_path, expected_language, vary, body) in responses {
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
                request.lines().any(|line| line
                    .eq_ignore_ascii_case(&format!("accept-language: {expected_language}"))),
                "missing expected language {expected_language:?}: {request:?}"
            );
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\nvary: {vary}\r\ncontent-length: {}\r\n\r\n{}",
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

async fn upstream_raw_response_sequence(
    responses: &'static [(&'static str, &'static str)],
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for (expected_path, response) in responses {
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
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    addr
}

async fn upstream_slice_response_sequence(
    responses: &'static [(&'static str, &'static str, &'static str)],
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for (expected_path, expected_range, response) in responses {
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
                request
                    .lines()
                    .any(|line| { line.eq_ignore_ascii_case(&format!("range: {expected_range}")) }),
                "missing expected range {expected_range:?}: {request:?}"
            );
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("accept-encoding: identity")),
                "missing identity accept-encoding: {request:?}"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
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

fn proxy_for(upstream: std::net::SocketAddr) -> NativeHttp1Proxy {
    NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
}

fn native_proxy_memory_cache_config() -> fluxheim_config::CacheConfig {
    fluxheim_config::CacheConfig {
        enabled: true,
        status_header: Some("x-cache-status".to_owned()),
        status_reason_header: Some("x-cache-reason".to_owned()),
        memory: fluxheim_config::CacheMemoryConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn native_proxy_disk_cache_config(root: std::path::PathBuf) -> fluxheim_config::CacheConfig {
    let mut cache = native_proxy_memory_cache_config();
    cache.memory.enabled = false;
    cache.disk.enabled = true;
    cache.disk.path = Some(root);
    cache.disk.max_size_bytes = fluxheim_config::ByteSize::from_bytes(1024 * 1024);
    cache
}

fn native_proxy_encrypted_disk_cache_config(
    root: std::path::PathBuf,
    key_file: std::path::PathBuf,
) -> fluxheim_config::CacheConfig {
    let mut cache = native_proxy_disk_cache_config(root);
    cache.disk.encryption.enabled = true;
    cache.disk.encryption.key_file = Some(key_file);
    cache
}

fn native_proxy_storage_bin_cache_config(root: std::path::PathBuf) -> fluxheim_config::CacheConfig {
    let mut cache = native_proxy_disk_cache_config(root);
    cache.disk.backend = fluxheim_config::CacheDiskBackend::StorageBin;
    cache.disk.storage_bin.bin_size_bytes = fluxheim_config::ByteSize::from_bytes(64 * 1024);
    cache
}

fn native_proxy_encrypted_storage_bin_cache_config(
    root: std::path::PathBuf,
    key_file: std::path::PathBuf,
) -> fluxheim_config::CacheConfig {
    let mut cache = native_proxy_storage_bin_cache_config(root);
    cache.disk.encryption.enabled = true;
    cache.disk.encryption.key_file = Some(key_file);
    cache
}

#[cfg(feature = "openbao-cache-encryption")]
fn native_proxy_openbao_storage_bin_cache_config(
    root: std::path::PathBuf,
    address: String,
    token_file: std::path::PathBuf,
) -> fluxheim_config::CacheConfig {
    let mut cache = native_proxy_storage_bin_cache_config(root);
    cache.disk.encryption.enabled = true;
    cache.disk.encryption.provider = fluxheim_config::CacheDiskEncryptionProvider::OpenbaoTransit;
    cache.disk.encryption.key_id = Some("native-openbao-v1".to_owned());
    cache.disk.encryption.openbao.address = Some(address);
    cache.disk.encryption.openbao.mount = Some("transit/cache".to_owned());
    cache.disk.encryption.openbao.key_name = Some("native-key".to_owned());
    cache.disk.encryption.openbao.token_file = Some(token_file);
    cache
}

fn native_proxy_tiered_cache_config(root: std::path::PathBuf) -> fluxheim_config::CacheConfig {
    let mut cache = native_proxy_memory_cache_config();
    cache.disk.enabled = true;
    cache.disk.path = Some(root);
    cache.disk.max_size_bytes = fluxheim_config::ByteSize::from_bytes(1024 * 1024);
    cache
}

fn route_test_request(path: &str) -> NativeHttp1Request {
    NativeHttp1Request {
        method: "GET".to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: path.to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![("host".to_owned(), "route.test".to_owned())],
        body: zeroize::Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    }
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

fn response_header_values(response: &str, name: &str) -> Vec<String> {
    response
        .lines()
        .filter_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
        .collect()
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
async fn native_route_proxy_websocket_upgrade_tunnels_prebuffered_bytes() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                return;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /ws HTTP/1.1\r\n"));
        assert!(request.contains("upgrade: websocket\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\
                  Sec-WebSocket-Accept: test-accept\r\n\r\n",
            )
            .await
            .unwrap();
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });
    let route = NativeHttp1RouteProxyRoute::exact(
        "/ws",
        vec!["GET".to_owned()],
        NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream_addr.to_string()))
            .with_websocket_enabled(true),
    );
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET /ws HTTP/1.1\r\n\
              Host: route.test\r\n\
              Connection: Upgrade\r\n\
              Upgrade: websocket\r\n\
              Sec-WebSocket-Key: test-key\r\n\
              Sec-WebSocket-Version: 13\r\n\r\nping",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    let mut chunk = [0u8; 128];
    loop {
        let read = client.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "connection closed before route websocket response");
        response.extend_from_slice(&chunk[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let response_head_len = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap();
    let mut tunneled = response[response_head_len..].to_vec();
    while tunneled.len() < 4 {
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).await.unwrap();
        tunneled.push(byte[0]);
    }
    assert!(
        String::from_utf8(response[..response_head_len].to_vec())
            .unwrap()
            .starts_with("HTTP/1.1 101 Switching Protocols\r\n")
    );
    assert_eq!(&tunneled[..4], b"pong");
}

#[cfg(feature = "acme")]
#[tokio::test]
async fn native_route_proxy_serves_managed_acme_http_01_locally() {
    let storage = tempfile::tempdir().unwrap();
    let store = NativeHttp1AcmeHttp01Store::new(storage.path(), "route.test");
    std::fs::create_dir_all(store.root_for_tests()).unwrap();
    std::fs::write(
        store.root_for_tests().join("token_123"),
        b"token.key.authorization\n",
    )
    .unwrap();

    let mut config = fluxheim_config::Config::default();
    config.tls.acme.enabled = true;
    config.tls.acme.storage = Some(storage.path().to_path_buf());
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: fluxheim_config::VhostTlsConfig {
            enabled: true,
            acme: fluxheim_config::VhostAcmeConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
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
    config.vhosts = vec![vhost.clone()];
    let route_proxy = NativeHttp1RouteProxy::from_config(
        &config,
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = route_proxy_listener(route_proxy).await;

    let response = downstream_get(proxy, "/.well-known/acme-challenge/token_123").await;
    let head_response = downstream_request(
        proxy,
        "HEAD /.well-known/acme-challenge/token_123 HTTP/1.1\r\nHost: route.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    let post_response = downstream_request(
        proxy,
        "POST /.well-known/acme-challenge/token_123 HTTP/1.1\r\nHost: route.test\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&response, "content-type").as_deref(),
        Some("text/plain")
    );
    assert_eq!(
        response_header(&response, "cache-control").as_deref(),
        Some("no-store")
    );
    assert!(response.ends_with("token.key.authorization"));
    assert!(head_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&head_response, "content-length").as_deref(),
        Some("23")
    );
    assert!(head_response.ends_with("\r\n\r\n"));
    assert!(post_response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
    assert_eq!(
        response_header(&post_response, "allow").as_deref(),
        Some("GET, HEAD")
    );
}

#[cfg(feature = "acme")]
#[tokio::test]
async fn native_route_proxy_serves_managed_acme_http_01_for_alias_vhost() {
    let storage = tempfile::tempdir().unwrap();
    let store = NativeHttp1AcmeHttp01Store::new(storage.path(), "primary.test");
    std::fs::create_dir_all(store.root_for_tests()).unwrap();
    std::fs::write(
        store.root_for_tests().join("token_456"),
        b"alias.key.authorization\n",
    )
    .unwrap();

    let owner = fluxheim_config::VhostConfig {
        name: "primary.test".to_owned(),
        hosts: vec!["primary.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: fluxheim_config::VhostTlsConfig {
            enabled: true,
            acme: fluxheim_config::VhostAcmeConfig {
                enabled: true,
                domains: vec!["alias.test".to_owned()],
                ..Default::default()
            },
            ..Default::default()
        },
        acme_challenge: Default::default(),
        redirect: Default::default(),
        proxy: Default::default(),
        cache: Default::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: Vec::new(),
    };
    let alias = fluxheim_config::VhostConfig {
        name: "alias.test".to_owned(),
        hosts: vec!["alias.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
        acme_challenge: Default::default(),
        redirect: fluxheim_config::VhostRedirectConfig {
            enabled: true,
            to: Some("https://primary.test{uri}".to_owned()),
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
    let mut config = fluxheim_config::Config::default();
    config.tls.acme.enabled = true;
    config.tls.acme.storage = Some(storage.path().to_path_buf());
    config.vhosts = vec![owner, alias.clone()];
    let route_proxy = NativeHttp1RouteProxy::from_config(
        &config,
        &alias,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = route_proxy_listener(route_proxy).await;

    let response = downstream_get(proxy, "/.well-known/acme-challenge/token_456").await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("alias.key.authorization"));
}

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

fn native_route_proxy_test_vhost() -> fluxheim_config::VhostConfig {
    fluxheim_config::VhostConfig {
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
        cache: Default::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: Vec::new(),
    }
}

fn native_route_proxy_test_route() -> fluxheim_config::RouteConfig {
    fluxheim_config::RouteConfig {
        name: "route".to_owned(),
        path_exact: Some("/route".to_owned()),
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
            to: "https://target.example{uri}".to_owned(),
            status: 302,
        }),
        proxy: None,
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    }
}

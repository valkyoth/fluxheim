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

#[tokio::test]
async fn native_route_proxy_peer_fills_and_stores_memory_cache_response() {
    let peer = peer_fill_cacheable_once("peer-object").await;
    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let mut cache = native_proxy_memory_cache_config();
    cache.peer_fill.enabled = true;
    cache.peer_fill.allow_insecure_http = true;
    cache.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
        name: "local-peer".to_owned(),
        base_url: format!("http://{peer}"),
    }];
    let proxy = proxy_for(origin).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let second = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("peer-object"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("PEER-HIT")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("peer-object"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_client_peer_fill_marker_does_not_skip_peer_fill() {
    let peer = peer_fill_cacheable_once("peer-object").await;
    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let mut cache = native_proxy_memory_cache_config();
    cache.peer_fill.enabled = true;
    cache.peer_fill.allow_insecure_http = true;
    cache.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
        name: "local-peer".to_owned(),
        base_url: format!("http://{peer}"),
    }];
    let proxy = proxy_for(origin).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let response = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nX-Fluxheim-Peer-Fill: 1\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("peer-object"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("PEER-HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_only_if_cached_miss_does_not_contact_origin() {
    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(origin).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let response = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nCache-Control: only-if-cached\r\nX-Fluxheim-Peer-Fill: 1\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&response, "x-cache-reason").as_deref(),
        Some("only-if-cached-miss")
    );
}

#[tokio::test]
async fn native_route_proxy_peer_fill_subtracts_upstream_age_before_admission() {
    let peer = peer_fill_response_once(
        "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=2\r\nage: 2\r\ncontent-length: 10\r\n\r\nstale-peer",
    )
    .await;
    let unused_origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = unused_origin_listener.local_addr().unwrap();
    drop(unused_origin_listener);
    let mut cache = native_proxy_memory_cache_config();
    cache.peer_fill.enabled = true;
    cache.peer_fill.allow_insecure_http = true;
    cache.peer_fill.fail_open = false;
    cache.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
        name: "local-peer".to_owned(),
        base_url: format!("http://{peer}"),
    }];
    let proxy = proxy_for(origin).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let response = downstream_get(listener, "/asset.png").await;

    assert!(response.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&response, "x-cache-reason").as_deref(),
        Some("peer-fill-miss")
    );
}

#[tokio::test]
async fn native_route_proxy_min_uses_delays_memory_cache_admission() {
    let upstream = upstream_cacheable_sequence(&[
        ("/asset.png", "first-cacheable"),
        ("/asset.png", "second-cacheable"),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.min_uses = 2;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let second = downstream_get(listener, "/asset.png").await;
    let third = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("first-cacheable"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&first, "x-cache-reason").as_deref(),
        Some("cache-min-uses")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("second-cacheable"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(third.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(third.ends_with("second-cacheable"));
    assert_eq!(
        response_header(&third, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_predictor_passes_repeated_uncacheable_memory_response() {
    let upstream = upstream_raw_response_sequence(&[
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: no-store\r\ncontent-length: 17\r\n\r\nuncacheable-first",
        ),
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: no-store\r\ncontent-length: 18\r\n\r\nuncacheable-second",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.predictor.enabled = true;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let second = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("uncacheable-first"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&first, "x-cache-reason").as_deref(),
        Some("cache-control-no-store")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("uncacheable-second"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&second, "x-cache-reason").as_deref(),
        Some("cache-pass")
    );
}

#[tokio::test]
async fn native_route_proxy_serves_stale_while_revalidating_memory_cache() {
    let upstream = upstream_raw_response_sequence(&[
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=1\r\ncontent-length: 9\r\n\r\nstale-one",
        ),
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-length: 9\r\n\r\nfresh-two",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.stale_while_revalidate_secs = Some(60);
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let stale = downstream_get(listener, "/asset.png").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let refreshed = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("stale-one"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(stale.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(stale.ends_with("stale-one"));
    assert_eq!(
        response_header(&stale, "x-cache-status").as_deref(),
        Some("STALE-UPDATING")
    );
    assert_eq!(
        response_header(&stale, "x-cache-reason").as_deref(),
        Some("stale-while-revalidate")
    );
    assert!(refreshed.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(refreshed.ends_with("fresh-two"));
    assert_eq!(
        response_header(&refreshed, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_serves_bounded_range_from_memory_cache_hit() {
    let upstream = upstream_cacheable_once("0123456789").await;
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let range = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(range.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(range.ends_with("2345"));
    assert_eq!(
        response_header(&range, "content-range").as_deref(),
        Some("bytes 2-5/10")
    );
    assert_eq!(
        response_header(&range, "content-length").as_deref(),
        Some("4")
    );
    assert_eq!(
        response_header(&range, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_serves_range_not_satisfiable_from_memory_cache_hit() {
    let upstream = upstream_cacheable_once("0123456789").await;
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let range = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=20-29\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(range.starts_with("HTTP/1.1 416 Range Not Satisfiable\r\n"));
    assert!(range.ends_with("\r\n\r\n"));
    assert_eq!(
        response_header(&range, "content-range").as_deref(),
        Some("bytes */10")
    );
    assert_eq!(
        response_header(&range, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_bypasses_cache_fill_on_range_miss() {
    let upstream = upstream_raw_response_sequence(&[
        (
            "/asset.png",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-range: bytes 0-3/10\r\ncontent-length: 4\r\n\r\nrang",
        ),
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-length: 9\r\n\r\nfull-body",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let range = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=0-3\r\nConnection: close\r\n\r\n",
    )
    .await;
    let full = downstream_get(listener, "/asset.png").await;

    assert!(range.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(range.ends_with("rang"));
    assert_eq!(
        response_header(&range, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&range, "x-cache-reason").as_deref(),
        Some("range-miss")
    );
    assert!(full.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(full.ends_with("full-body"));
    assert_eq!(
        response_header(&full, "x-cache-status").as_deref(),
        Some("MISS")
    );
}

#[tokio::test]
async fn native_route_proxy_slice_cache_fills_and_composes_memory_range() {
    let upstream = upstream_slice_response_sequence(&[
        (
            "/asset.png",
            "bytes=0-3",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\netag: \"slice-v1\"\r\ncontent-range: bytes 0-3/10\r\ncontent-length: 4\r\n\r\n0123",
        ),
        (
            "/asset.png",
            "bytes=4-7",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\netag: \"slice-v1\"\r\ncontent-range: bytes 4-7/10\r\ncontent-length: 4\r\n\r\n4567",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    cache.range.slice.enabled = true;
    cache.range.slice.fill_missing = true;
    cache.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(4);
    cache.range.slice.max_slices = 4;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    )
    .await;
    let second = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(first.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(first.ends_with("2345"));
    assert_eq!(
        response_header(&first, "content-range").as_deref(),
        Some("bytes 2-5/10")
    );
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&first, "x-cache-reason").as_deref(),
        Some("slice-fill")
    );
    assert!(second.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(second.ends_with("2345"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
    assert_eq!(
        response_header(&second, "x-cache-reason").as_deref(),
        Some("slice")
    );
}

#[tokio::test]
async fn native_route_proxy_slice_cache_composes_multipart_memory_response() {
    let upstream = upstream_slice_response_sequence(&[
        (
            "/asset.png",
            "bytes=0-3",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\nlast-modified: Wed, 21 Oct 2015 07:28:00 GMT\r\ncontent-range: bytes 0-3/10\r\ncontent-length: 4\r\n\r\n0123",
        ),
        (
            "/asset.png",
            "bytes=4-7",
            "HTTP/1.1 206 Partial Content\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\nlast-modified: Wed, 21 Oct 2015 07:28:00 GMT\r\ncontent-range: bytes 4-7/10\r\ncontent-length: 4\r\n\r\n4567",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    cache.range.slice.enabled = true;
    cache.range.slice.fill_missing = true;
    cache.range.slice.size_bytes = fluxheim_config::ByteSize::from_bytes(4);
    cache.range.slice.max_slices = 4;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let response = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nRange: bytes=0-1,6-7\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(
        response_header(&response, "content-type")
            .as_deref()
            .is_some_and(|value| value.starts_with("multipart/byteranges; boundary=fluxheim-"))
    );
    assert!(response.contains("Content-Range: bytes 0-1/10\r\n\r\n01"));
    assert!(response.contains("Content-Range: bytes 6-7/10\r\n\r\n67"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&response, "x-cache-reason").as_deref(),
        Some("slice-fill")
    );
}

#[tokio::test]
async fn native_route_proxy_serves_stale_proxy_response_on_upstream_error() {
    let upstream = upstream_cacheable_once_with_max_age("stale-origin", 1).await;
    let mut cache = native_proxy_memory_cache_config();
    cache.stale_if_error_secs = Some(60);
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("stale-origin"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("stale-origin"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("STALE")
    );
    assert_eq!(
        response_header(&second, "x-cache-reason").as_deref(),
        Some("upstream-error")
    );
    assert!(
        response_header(&second, "age")
            .and_then(|age| age.parse::<u64>().ok())
            .is_some_and(|age| age >= 1),
        "response: {second:?}"
    );
}

#[tokio::test]
async fn native_route_proxy_serves_stale_proxy_response_on_upstream_status() {
    let upstream = upstream_raw_response_sequence(&[
        (
            "/asset.png",
            "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=1\r\ncontent-length: 12\r\n\r\nstatus-stale",
        ),
        (
            "/asset.png",
            "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 14\r\n\r\norigin-failure",
        ),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.stale_if_error_secs = Some(60);
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("status-stale"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("status-stale"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("STALE")
    );
    assert_eq!(
        response_header(&second, "x-cache-reason").as_deref(),
        Some("upstream-status")
    );
}

#[tokio::test]
async fn native_route_proxy_origin_protection_limits_concurrent_cache_fills() {
    let (upstream, accepted) =
        upstream_delayed_cacheable_once("slow-origin", Duration::from_millis(200)).await;
    let mut cache = native_proxy_memory_cache_config();
    cache.lock.enabled = false;
    cache.origin_protection.enabled = true;
    cache.origin_protection.max_concurrent_fills = 1;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = tokio::spawn(async move { downstream_get(listener, "/asset.png").await });
    accepted.await.unwrap();
    let second = downstream_get(listener, "/asset.png").await;
    let first = first.await.unwrap();

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("slow-origin"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(second.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&second, "x-cache-reason").as_deref(),
        Some("origin-protected")
    );
}

#[tokio::test]
async fn native_route_proxy_cache_lock_collapses_concurrent_memory_fills() {
    let (upstream, accepted) =
        upstream_delayed_cacheable_once("collapsed-fill", Duration::from_millis(150)).await;
    let mut cache = native_proxy_memory_cache_config();
    cache.lock.enabled = true;
    cache.lock.wait_timeout_secs = 5;
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = tokio::spawn(async move { downstream_get(listener, "/asset.png").await });
    accepted.await.unwrap();
    let second = downstream_get(listener, "/asset.png").await;
    let first = first.await.unwrap();

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("collapsed-fill"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("collapsed-fill"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_does_not_cache_authorized_proxy_response() {
    let upstream = upstream_cacheable_sequence(&[
        ("/tenant.png", "authorized-origin"),
        ("/tenant.png", "public-origin"),
    ])
    .await;
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let authorized = downstream_request(
        listener,
        "GET /tenant.png HTTP/1.1\r\nHost: route.test\r\nAuthorization: Bearer token-a\r\nConnection: close\r\n\r\n",
    )
    .await;
    let public = downstream_get(listener, "/tenant.png").await;

    assert!(authorized.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(authorized.ends_with("authorized-origin"));
    assert_eq!(
        response_header(&authorized, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&authorized, "x-cache-reason").as_deref(),
        Some("request-authorization")
    );
    assert!(public.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(public.ends_with("public-origin"));
    assert_eq!(
        response_header(&public, "x-cache-status").as_deref(),
        Some("MISS")
    );
}

#[tokio::test]
async fn native_route_proxy_applies_cache_bypass_status_to_upstream_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unused_upstream = listener.local_addr().unwrap();
    drop(listener);
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(unused_upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let response = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
    assert_eq!(
        response_header(&response, "x-cache-status").as_deref(),
        Some("BYPASS")
    );
    assert_eq!(
        response_header(&response, "x-cache-reason").as_deref(),
        Some("request-no-store")
    );
}

#[tokio::test]
async fn native_route_proxy_replaces_upstream_age_on_cache_hit() {
    let upstream = upstream_response(
        "HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\nage: 5\r\ncontent-length: 10\r\n\r\norigin-age",
    )
    .await;
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let second = downstream_get(listener, "/asset.png").await;

    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
    );
    let age_values = response_header_values(&second, "age");
    assert_eq!(age_values.len(), 1, "response: {second:?}");
}

#[tokio::test]
async fn native_route_proxy_respects_origin_vary_header_in_memory_cache() {
    let upstream = upstream_vary_sequence(&[
        ("/asset.png", "en", "accept-language", "hello"),
        ("/asset.png", "sv", "accept-language", "hej"),
    ])
    .await;
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let english = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: en\r\nConnection: close\r\n\r\n",
    )
    .await;
    let swedish = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: sv\r\nConnection: close\r\n\r\n",
    )
    .await;
    let english_hit = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: en\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(english.ends_with("hello"));
    assert_eq!(
        response_header(&english, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(swedish.ends_with("hej"));
    assert_eq!(
        response_header(&swedish, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(english_hit.ends_with("hello"));
    assert_eq!(
        response_header(&english_hit, "x-cache-status").as_deref(),
        Some("HIT")
    );
}

#[tokio::test]
async fn native_route_proxy_configured_vary_headers_isolate_memory_cache() {
    let upstream = upstream_cacheable_sequence(&[
        ("/asset.png", "configured-english"),
        ("/asset.png", "configured-swedish"),
    ])
    .await;
    let mut cache = native_proxy_memory_cache_config();
    cache.vary_request_headers = vec!["accept-language".to_owned()];
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let english = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: en\r\nConnection: close\r\n\r\n",
    )
    .await;
    let swedish = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: sv\r\nConnection: close\r\n\r\n",
    )
    .await;
    let english_hit = downstream_request(
        listener,
        "GET /asset.png HTTP/1.1\r\nHost: route.test\r\nAccept-Language: en\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(english.ends_with("configured-english"));
    assert_eq!(
        response_header(&english, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(swedish.ends_with("configured-swedish"));
    assert_eq!(
        response_header(&swedish, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(english_hit.ends_with("configured-english"));
    assert_eq!(
        response_header(&english_hit, "x-cache-status").as_deref(),
        Some("HIT")
    );
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

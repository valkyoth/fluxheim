use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1Request, NativeHttp1Upstream,
    serve_native_http1_listener,
};

#[path = "native_http1_proxy_tests/auth_mirror.rs"]
mod auth_mirror_tests;
#[path = "native_http1_proxy_tests/config_policy.rs"]
mod config_policy_tests;
#[path = "native_http1_proxy_tests/construction.rs"]
mod construction_tests;
#[path = "native_http1_proxy_tests/h2.rs"]
mod h2_tests;
#[path = "native_http1_proxy_tests/header_policy.rs"]
mod header_policy_tests;
#[path = "native_http1_proxy_tests/response_features.rs"]
mod response_features_tests;
#[path = "native_http1_proxy_tests/runtime_behavior.rs"]
mod runtime_behavior_tests;
#[path = "native_http1_proxy_tests/standards_metadata.rs"]
mod standards_metadata_tests;
#[path = "native_http1_proxy_tests/static_upstream.rs"]
mod static_upstream_tests;
#[path = "native_http1_proxy_tests/websocket.rs"]
mod websocket_tests;

async fn upstream<F, Fut>(handler: F) -> std::net::SocketAddr
where
    F: Fn(Vec<u8>, TcpStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
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
        handler(request, stream).await;
    });
    addr
}

async fn proxy_listener(upstream: std::net::SocketAddr) -> std::net::SocketAddr {
    proxy_listener_for(NativeHttp1Proxy::new(NativeHttp1Upstream::new(
        upstream.to_string(),
    )))
    .await
}

async fn proxy_listener_for(proxy: NativeHttp1Proxy) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = Arc::new(proxy);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_native_http1_listener(listener, DownstreamHttp1Policy::default(), proxy, async {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _ = shutdown_tx.send(());
    });
    addr
}

fn native_proxy_test_request() -> NativeHttp1Request {
    NativeHttp1Request {
        method: "GET".to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: "/socket-policy".to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![("host".to_owned(), "proxy.test".to_owned())],
        body: crate::NativeHttp1RequestBody::empty(),
        trailers: Vec::new(),
    }
}

fn native_proxy_test_request_for(target: &str) -> NativeHttp1Request {
    NativeHttp1Request {
        target: target.to_owned(),
        ..native_proxy_test_request()
    }
}

async fn counting_upstream(
    body: &'static str,
    responses: usize,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_for_task = Arc::clone(&count);
    tokio::spawn(async move {
        for _ in 0..responses {
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
            count_for_task.fetch_add(1, Ordering::Relaxed);
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
    (addr, count)
}

#[cfg(feature = "load-balancer")]
async fn cacheable_counting_upstream(
    body: &'static str,
    responses: usize,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_for_task = Arc::clone(&count);
    tokio::spawn(async move {
        for _ in 0..responses {
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
            count_for_task.fetch_add(1, Ordering::Relaxed);
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
    (addr, count)
}

async fn failover_proxy_listener(
    first: std::net::SocketAddr,
    second: std::net::SocketAddr,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = Arc::new(
        NativeHttp1Proxy::from_upstreams(vec![
            NativeHttp1Upstream::new(first.to_string())
                .with_connect_timeout(Duration::from_millis(25)),
            NativeHttp1Upstream::new(second.to_string())
                .with_connect_timeout(Duration::from_millis(25)),
        ])
        .unwrap(),
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_native_http1_listener(listener, DownstreamHttp1Policy::default(), proxy, async {
            let _ = shutdown_rx.await;
        })
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
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

#[cfg(feature = "load-balancer")]
fn response_header(response: &str, name: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

async fn rejecting_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    address
}

fn proxy_config_with_error_page(root: std::path::PathBuf) -> fluxheim_config::ProxyConfig {
    fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:9".to_owned()),
        connect_timeout_secs: Some(1),
        error_pages: vec![fluxheim_config::ProxyErrorPageConfig {
            status: 502,
            path: "/502.html".to_owned(),
            web: fluxheim_config::WebConfig {
                root: Some(root),
                ..Default::default()
            },
        }],
        ..Default::default()
    }
}

fn static_load_balance_without_health_check() -> fluxheim_config::LoadBalanceConfig {
    fluxheim_config::LoadBalanceConfig {
        health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn native_proxy_forwards_downstream_request_to_upstream() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /proxied HTTP/1.1\r\n"));
        assert!(request.contains("host: proxy.test\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 12\r\nx-origin: native\r\n\r\nhello native",
            )
            .await
            .unwrap();
    })
    .await;
    let proxy = proxy_listener(upstream).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET /proxied HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("x-origin: native\r\n"));
    assert!(response.ends_with("hello native"));
}

#[tokio::test]
async fn native_proxy_does_not_fail_over_body_bearing_get() {
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = first.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await;
    });
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_addr = second.local_addr().unwrap();
    let second_accepted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let second_accepted_task = Arc::clone(&second_accepted);
    tokio::spawn(async move {
        if let Ok(Ok((_stream, _))) =
            tokio::time::timeout(Duration::from_millis(500), second.accept()).await
        {
            second_accepted_task.store(true, std::sync::atomic::Ordering::Release);
        }
    });
    let proxy = failover_proxy_listener(first_addr, second_addr).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();

    client
        .write_all(
            b"GET /with-body HTTP/1.1\r\nHost: proxy.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    tokio::time::sleep(Duration::from_millis(550)).await;

    assert!(response.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
    assert!(!second_accepted.load(std::sync::atomic::Ordering::Acquire));
}

#[cfg(feature = "load-balancer")]
#[tokio::test]
async fn native_proxy_caches_load_balanced_response_in_memory() {
    let (first, first_count) = cacheable_counting_upstream("balanced-cache", 1).await;
    let (second, second_count) = cacheable_counting_upstream("balanced-cache", 1).await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstreams: vec![first.to_string(), second.to_string()],
        load_balance: fluxheim_config::LoadBalanceConfig {
            health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let (proxy, _service) = NativeHttp1Proxy::from_proxy_config_with_native_load_balancer(
        "lb-cache",
        "proxy.test",
        None,
        &proxy_config,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap()
    .expect("native load-balanced proxy");
    let cache = fluxheim_config::CacheConfig {
        enabled: true,
        status_header: Some("x-cache-status".to_owned()),
        memory: fluxheim_config::CacheMemoryConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let proxy = proxy_listener_for(proxy.with_proxy_cache_config(&cache)).await;

    let first_response = downstream_get(proxy, "/asset.png").await;
    let second_response = downstream_get(proxy, "/asset.png").await;

    assert!(first_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first_response.ends_with("balanced-cache"));
    assert_eq!(
        response_header(&first_response, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(second_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second_response.ends_with("balanced-cache"));
    assert_eq!(
        response_header(&second_response, "x-cache-status").as_deref(),
        Some("HIT")
    );
    assert_eq!(
        first_count.load(Ordering::Relaxed) + second_count.load(Ordering::Relaxed),
        1
    );
}

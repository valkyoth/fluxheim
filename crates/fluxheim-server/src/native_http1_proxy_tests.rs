use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1Request, NativeHttp1Upstream,
    native_http1_test_utils::read_request_head, serve_native_http1_listener,
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
        body: zeroize::Zeroizing::new(Vec::new()),
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

async fn pooled_proxy_listener(upstream: std::net::SocketAddr) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = Arc::new(NativeHttp1Proxy::new(
        NativeHttp1Upstream::new(upstream.to_string()).with_pool_max_idle(1),
    ));
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

async fn unused_local_address() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
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

#[tokio::test]
async fn native_proxy_reuses_origin_connection_for_separate_downstream_clients() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_for_task = Arc::clone(&accepted);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        accepted_for_task.fetch_add(1, Ordering::AcqRel);

        let first = String::from_utf8(read_request_head(&mut stream).await).unwrap();
        assert!(first.starts_with("GET /one HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\none")
            .await
            .unwrap();

        let second = String::from_utf8(read_request_head(&mut stream).await).unwrap();
        assert!(second.starts_with("GET /two HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\ntwo")
            .await
            .unwrap();
    });
    let proxy = pooled_proxy_listener(upstream).await;

    let first = downstream_get(proxy, "/one").await;
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("one"));

    let second = downstream_get(proxy, "/two").await;
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("two"));

    assert_eq!(accepted.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn native_proxy_writes_upstream_proxy_protocol_v1_from_listener_context() {
    let expected_destination_port = Arc::new(AtomicUsize::new(0));
    let expected_destination_port_for_upstream = Arc::clone(&expected_destination_port);
    let upstream = upstream(move |request, mut stream| {
        let expected_destination_port = Arc::clone(&expected_destination_port_for_upstream);
        async move {
            let request = String::from_utf8(request).unwrap();
            let proxy_line = request.lines().next().unwrap_or_default();
            let fields: Vec<_> = proxy_line.split_whitespace().collect();
            assert_eq!(fields.len(), 6);
            assert_eq!(fields[0], "PROXY");
            assert_eq!(fields[1], "TCP4");
            assert_eq!(fields[2], "127.0.0.1");
            assert_eq!(fields[3], "127.0.0.1");
            assert_ne!(fields[4], "0");
            assert_eq!(
                fields[5],
                expected_destination_port
                    .load(Ordering::Acquire)
                    .to_string()
            );
            assert!(request.contains("GET /proxy-protocol HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                .await
                .unwrap();
        }
    })
    .await;
    let proxy = NativeHttp1Proxy::new(
        NativeHttp1Upstream::new(upstream.to_string())
            .with_proxy_protocol(fluxheim_config::UpstreamProxyProtocol::V1),
    );
    let proxy_addr = proxy_listener_for(proxy).await;
    expected_destination_port.store(proxy_addr.port() as usize, Ordering::Release);

    let response = downstream_get(proxy_addr, "/proxy-protocol").await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("ok"));
}

#[tokio::test]
async fn native_proxy_maps_upstream_timeout_to_gateway_timeout() {
    let upstream = upstream(|_, stream| async move {
        let _hold_open = stream;
        tokio::time::sleep(Duration::from_secs(5)).await;
    })
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let proxy = Arc::new(NativeHttp1Proxy::new(
        NativeHttp1Upstream::new(upstream.to_string()).with_read_timeout(Duration::from_millis(25)),
    ));
    tokio::spawn(async move {
        serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default(),
            proxy,
            std::future::pending::<()>(),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"GET /slow HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"));
    assert!(response.ends_with("gateway timeout\n"));
}

#[tokio::test]
async fn native_proxy_request_body_timeout_is_enforced_before_upstream() {
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let upstream_hits_for_task = Arc::clone(&upstream_hits);
    let upstream = upstream(move |_, mut stream| {
        let upstream_hits = Arc::clone(&upstream_hits_for_task);
        async move {
            upstream_hits.fetch_add(1, Ordering::AcqRel);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nunexpected")
                .await
                .unwrap();
        }
    })
    .await;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_request_body_timeout(Some(Duration::from_millis(25)));
    let proxy = proxy_listener_for(proxy).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();

    stream
        .write_all(
            b"POST /slow HTTP/1.1\r\nHost: proxy.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .unwrap()
        .unwrap();

    assert_ne!(read, 0);
    let mut response = vec![byte[0]];
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 408 Request Timeout\r\n"));
    assert!(response.ends_with("request timeout\n"));
    assert_eq!(upstream_hits.load(Ordering::Acquire), 0);
}

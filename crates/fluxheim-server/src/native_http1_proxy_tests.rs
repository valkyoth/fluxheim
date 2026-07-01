use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
#[cfg(feature = "compression-gzip")]
use flate2::read::GzDecoder;
#[cfg(feature = "compression-gzip")]
use std::io::Read as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    DownstreamHttp1Policy, NativeHttp1Handler, NativeHttp1Proxy, NativeHttp1ProxyConfigError,
    NativeHttp1Request, NativeHttp1ResponseWritePolicy, NativeHttp1Upstream,
    native_http1_test_utils::read_request_head, serve_native_http1_listener,
};

#[path = "native_http1_proxy_tests/config_policy.rs"]
mod config_policy_tests;
#[path = "native_http1_proxy_tests/h2.rs"]
mod h2_tests;
#[path = "native_http1_proxy_tests/static_upstream.rs"]
mod static_upstream_tests;

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

async fn h2_upstream(requests: usize) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let accepted_connections_for_task = Arc::clone(&accepted_connections);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accepted_connections_for_task.fetch_add(1, Ordering::AcqRel);
        let mut connection = h2::server::handshake(stream).await.unwrap();
        for index in 0..requests {
            let Some(stream) = connection.accept().await else {
                panic!("expected native H2 upstream request");
            };
            let (request, mut respond) = stream.unwrap();
            assert_eq!(request.method(), http::Method::GET);
            assert_eq!(
                request.uri().path_and_query().unwrap().as_str(),
                "/h2-origin"
            );
            assert_eq!(request.uri().authority().unwrap().as_str(), "proxy.test");
            assert_eq!(request.headers().get("x-test").unwrap(), "h2");
            assert!(request.headers().get("host").is_none());
            assert!(request.headers().get("connection").is_none());
            assert!(request.headers().get("via").is_some());
            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header("x-origin-proto", "h2")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from(format!("h2 upstream {index}\n")), true)
                .unwrap();
        }
        connection.graceful_shutdown();
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|context| connection.poll_closed(context)),
        )
        .await;
    });
    (addr, accepted_connections)
}

async fn h2_idle_upstream() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let accepted_connections_for_task = Arc::clone(&accepted_connections);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accepted_connections_for_task.fetch_add(1, Ordering::AcqRel);
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(1), connection.accept()).await;
    });
    (addr, accepted_connections)
}

async fn h2_upstream_with_body(
    body: &'static str,
    requests: usize,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let accepted_connections_for_task = Arc::clone(&accepted_connections);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accepted_connections_for_task.fetch_add(1, Ordering::AcqRel);
        let mut connection = h2::server::handshake(stream).await.unwrap();
        for _ in 0..requests {
            let Some(stream) = connection.accept().await else {
                panic!("expected native H2 upstream request");
            };
            let (request, mut respond) = stream.unwrap();
            assert_eq!(request.method(), http::Method::GET);
            assert_eq!(
                request.uri().path_and_query().unwrap().as_str(),
                "/h2-origin"
            );
            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header("x-origin-proto", "h2")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from_static(body.as_bytes()), true)
                .unwrap();
        }
        connection.graceful_shutdown();
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|context| connection.poll_closed(context)),
        )
        .await;
    });
    (addr, accepted_connections)
}

async fn h2_reconnecting_upstream(
    body: &'static str,
    connections: usize,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let accepted_connections_for_task = Arc::clone(&accepted_connections);
    tokio::spawn(async move {
        for _ in 0..connections {
            let (stream, _) = listener.accept().await.unwrap();
            accepted_connections_for_task.fetch_add(1, Ordering::AcqRel);
            let mut connection = h2::server::handshake(stream).await.unwrap();
            let Some(stream) = connection.accept().await else {
                panic!("expected native H2 upstream request");
            };
            let (_request, mut respond) = stream.unwrap();
            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header("x-origin-proto", "h2")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from_static(body.as_bytes()), true)
                .unwrap();
            connection.graceful_shutdown();
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                std::future::poll_fn(|context| connection.poll_closed(context)),
            )
            .await;
        }
    });
    (addr, accepted_connections)
}

async fn h2_reset_then_ok_upstream() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let accepted_connections_for_task = Arc::clone(&accepted_connections);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accepted_connections_for_task.fetch_add(1, Ordering::AcqRel);
        let mut connection = h2::server::handshake(stream).await.unwrap();

        let Some(stream) = connection.accept().await else {
            panic!("expected first native H2 upstream request");
        };
        let (_request, mut respond) = stream.unwrap();
        respond.send_reset(h2::Reason::CANCEL);

        let Some(stream) = connection.accept().await else {
            panic!("expected second native H2 upstream request");
        };
        let (_request, mut respond) = stream.unwrap();
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("x-origin-proto", "h2")
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        send.send_data(Bytes::from_static(b"h2 survived reset\n"), true)
            .unwrap();

        connection.graceful_shutdown();
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|context| connection.poll_closed(context)),
        )
        .await;
    });
    (addr, accepted_connections)
}

async fn h2_blocking_upstream() -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let Some(stream) = connection.accept().await else {
            panic!("expected native H2 upstream request");
        };
        let (_request, _respond) = stream.unwrap();
        let _ = accepted_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            std::future::pending::<()>().await;
        })
        .await;
    });
    (addr, accepted_rx)
}

async fn h2_handshake_stall_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            std::future::pending::<()>().await;
        })
        .await;
    });
    addr
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

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
async fn mirror_endpoint() -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request_head(&mut stream).await;
        let request = String::from_utf8(request).unwrap();
        let _ = tx.send(request);
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    (addr, rx)
}

#[cfg(feature = "auth-request")]
async fn auth_endpoint(
    response: &'static [u8],
) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request_head(&mut stream).await;
        let request = String::from_utf8(request).unwrap();
        let _ = tx.send(request);
        stream.write_all(response).await.unwrap();
    });
    (addr, rx)
}

#[cfg(feature = "compression-gzip")]
async fn downstream_request_bytes(proxy: std::net::SocketAddr, request: &str) -> Vec<u8> {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    response
}

async fn unused_local_address() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

#[cfg(feature = "compression-gzip")]
#[tokio::test]
async fn native_proxy_applies_gzip_compression_config() {
    let upstream = upstream(|_, mut stream| async move {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  content-type: text/plain\r\n\
                  etag: \"origin\"\r\n\r\n\
                  hello native proxy compression hello native proxy compression \
                  hello native proxy compression hello native proxy compression \
                  hello native proxy compression hello native proxy compression",
            )
            .await
            .unwrap();
    })
    .await;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_compression_config(fluxheim_config::CompressionConfig {
            enabled: true,
            gzip: true,
            min_bytes: fluxheim_config::ByteSize::from_bytes(1),
            max_input_bytes: fluxheim_config::ByteSize::from_bytes(4096),
            max_output_bytes: fluxheim_config::ByteSize::from_bytes(4096),
            ..Default::default()
        });
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_request_bytes(
        proxy,
        "GET /asset.txt HTTP/1.1\r\nHost: proxy.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
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
    assert!(decoded.contains("hello native proxy compression"));
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
async fn native_proxy_websocket_upgrade_tunnels_prebuffered_bytes() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /ws HTTP/1.1\r\n"));
        assert!(request.contains("connection: Upgrade\r\n"));
        assert!(request.contains("upgrade: websocket\r\n"));
        assert!(request.contains("Sec-WebSocket-Key: test-key\r\n"));
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
        stream.flush().await.unwrap();
    })
    .await;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_websocket_enabled(true);
    let proxy = proxy_listener_for(proxy).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET /ws HTTP/1.1\r\n\
              Host: proxy.test\r\n\
              Connection: keep-alive, Upgrade\r\n\
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
        assert_ne!(read, 0, "connection closed before websocket response");
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
    let response_head = String::from_utf8(response[..response_head_len].to_vec()).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(response_head.contains("upgrade: websocket\r\n"));
    assert!(response_head.contains("sec-websocket-accept: test-accept\r\n"));
    while tunneled.len() < 4 {
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).await.unwrap();
        tunneled.push(byte[0]);
    }
    assert_eq!(&tunneled[..4], b"pong");
}

#[cfg(feature = "load-balancer")]
#[tokio::test]
async fn native_proxy_websocket_upgrade_uses_native_load_balancer_selection() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /ws-lb HTTP/1.1\r\n"));
        assert!(request.contains("upgrade: websocket\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").await.unwrap();
    })
    .await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstreams: vec![upstream.to_string()],
        websocket: true,
        load_balance: fluxheim_config::LoadBalanceConfig {
            health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let (proxy, service) = NativeHttp1Proxy::from_proxy_config_with_native_load_balancer(
        "websocket-lb",
        "websocket.test",
        None,
        &proxy_config,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap()
    .expect("native proxy");
    assert!(service.is_none());
    let proxy = proxy_listener_for(proxy).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET /ws-lb HTTP/1.1\r\n\
              Host: proxy.test\r\n\
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
        assert_ne!(read, 0, "connection closed before websocket response");
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

#[tokio::test]
async fn native_proxy_applies_header_policy() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /headers HTTP/1.1\r\n"));
        assert!(request.contains("x-root-request: native\r\n"));
        assert!(!request.contains("x-remove:"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-remove-response: old\r\n\r\nok")
            .await
            .unwrap();
    })
    .await;
    let mut headers = fluxheim_config::HeaderPolicyConfig::default();
    headers.request.unset.push("x-remove".to_owned());
    headers
        .request
        .set
        .insert("x-root-request".to_owned(), "native".to_owned());
    headers.response.unset.push("x-remove-response".to_owned());
    headers
        .response
        .set
        .insert("x-root-response".to_owned(), "native".to_owned());
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&headers);
    let proxy = proxy_listener_for(proxy).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET /headers HTTP/1.1\r\nHost: proxy.test\r\nX-Remove: secret\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("x-root-response: native\r\n"));
    assert!(response.contains("x-content-type-options: nosniff\r\n"));
    assert!(!response.contains("x-remove-response:"));
    assert!(response.ends_with("ok"));
}

#[tokio::test]
async fn native_proxy_root_config_applies_response_header_policy() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /root-policy HTTP/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  content-length: 4\r\n\
                  x-powered-by: php\r\n\
                  x-root-remove: old\r\n\r\nroot",
            )
            .await
            .unwrap();
    })
    .await;

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
    config.headers.response.append.insert(
        "x-root-append".to_owned(),
        fluxheim_config::HeaderValues::Many(vec!["one".to_owned()]),
    );

    let proxy = NativeHttp1Proxy::from_root_config(&config, DownstreamHttp1Policy::default(), 0)
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET /root-policy HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("x-root-response: native\r\n"));
    assert!(response.contains("x-root-append: one\r\n"));
    assert!(response.contains("x-content-type-options: nosniff\r\n"));
    assert!(!response.to_ascii_lowercase().contains("x-powered-by:"));
    assert!(!response.to_ascii_lowercase().contains("x-root-remove:"));
    assert!(response.ends_with("root"));
}

#[cfg(not(feature = "privacy-mode"))]
#[tokio::test]
async fn native_proxy_applies_default_forwarded_header_policy() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains("x-forwarded-for: 127.0.0.1\r\n"));
        assert!(request.contains("x-real-ip: 127.0.0.1\r\n"));
        assert!(request.contains("x-forwarded-host: proxy.test\r\n"));
        assert!(request.contains("x-forwarded-proto: http\r\n"));
        assert!(!request.contains("x-forwarded-for: 192.0.2.9\r\n"));
        assert!(!request.contains("forwarded: for=192.0.2.9\r\n"));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    })
    .await;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&fluxheim_config::HeaderPolicyConfig::default());
    let proxy = proxy_listener_for(proxy).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET /forwarded HTTP/1.1\r\n\
              Host: proxy.test\r\n\
              X-Forwarded-For: 192.0.2.9\r\n\
              Forwarded: for=192.0.2.9\r\n\
              Connection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 204 No Content\r\n"));
}

#[cfg(not(feature = "privacy-mode"))]
#[tokio::test]
async fn native_proxy_honors_forwarded_for_off_policy() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(!request.to_ascii_lowercase().contains("x-forwarded-for:"));
        assert!(request.contains("x-forwarded-host: proxy.test\r\n"));
        assert!(request.contains("x-forwarded-proto: http\r\n"));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    })
    .await;
    let mut headers = fluxheim_config::HeaderPolicyConfig::default();
    headers.request.x_forwarded_for = fluxheim_config::ForwardedClientIpHeaderMode::Off;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&headers);
    let proxy = proxy_listener_for(proxy).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET /forwarded HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 204 No Content\r\n"));
}

#[tokio::test]
async fn native_proxy_serves_configured_error_page_on_bad_gateway() {
    let errors = tempfile::tempdir().unwrap();
    std::fs::write(errors.path().join("502.html"), "native custom 502\n").unwrap();
    let mut config = proxy_config_with_error_page(errors.path().to_path_buf());
    config.upstream = Some(unused_local_address().await.to_string());
    let proxy = NativeHttp1Proxy::from_proxy_config(&config, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_get(proxy, "/failing").await;

    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("\r\nConnection: close\r\n"));
    assert!(response.contains("content-type: text/html"));
    assert!(response.ends_with("native custom 502\n"));
}

#[tokio::test]
async fn native_proxy_falls_back_when_configured_error_page_is_too_large() {
    let errors = tempfile::tempdir().unwrap();
    let oversized = std::fs::File::create(errors.path().join("502.html")).unwrap();
    oversized.set_len(64 * 1024 * 1024 + 1).unwrap();
    let mut config = proxy_config_with_error_page(errors.path().to_path_buf());
    config.upstream = Some(unused_local_address().await.to_string());
    let proxy = NativeHttp1Proxy::from_proxy_config(&config, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_get(proxy, "/failing").await;

    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(!response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.ends_with("bad gateway\n"));
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
#[tokio::test]
async fn native_proxy_mirrors_safe_requests_without_changing_origin_response() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(!request.contains("\r\nx-fluxheim-mirror:"));
        assert!(!request.contains("\r\nx-fluxheim-mirror-signature:"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\norigin-ok")
            .await
            .unwrap();
    })
    .await;
    let (mirror, mirror_rx) = mirror_endpoint().await;
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        mirror: fluxheim_config::TrafficMirrorConfig {
            enabled: true,
            base_url: Some(format!("http://{mirror}/shadow")),
            sample_per_mille: 1000,
            methods: vec!["GET".to_owned()],
            forward_headers: vec!["x-request-id".to_owned()],
            timeout_secs: 2,
            max_response_bytes: fluxheim_config::ByteSize::from_bytes(1024),
            max_in_flight: 1,
        },
        ..Default::default()
    };
    let proxy = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET /asset.png?q=1 HTTP/1.1\r\n\
              Host: proxy.test\r\n\
              X-Request-Id: mirror-1\r\n\
              X-Fluxheim-Mirror: 1\r\n\
              X-Fluxheim-Mirror-Signature: attacker\r\n\
              Connection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    let mirrored = tokio::time::timeout(Duration::from_secs(2), mirror_rx)
        .await
        .unwrap()
        .unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("origin-ok"));
    assert!(mirrored.starts_with("GET /shadow/asset.png?q=1 HTTP/1.1\r\n"));
    assert!(mirrored.contains("\r\nx-fluxheim-mirror: 1\r\n"));
    assert!(mirrored.contains("\r\nx-fluxheim-mirror-signature: "));
    assert!(mirrored.contains("\r\nx-request-id: mirror-1\r\n"));
}

#[cfg(feature = "auth-request")]
#[tokio::test]
async fn native_proxy_auth_request_allows_and_injects_response_headers() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains("\r\nx-auth-request-user: alice\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\norigin-ok")
            .await
            .unwrap();
    })
    .await;
    let (auth, auth_rx) = auth_endpoint(
        b"HTTP/1.1 204 No Content\r\nx-auth-request-user: alice\r\ncontent-length: 0\r\n\r\n",
    )
    .await;
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        auth_request: fluxheim_config::AuthRequestConfig {
            enabled: true,
            url: Some(format!("http://{auth}/auth")),
            forward_headers: vec![
                "x-original-uri".to_owned(),
                "x-forwarded-host".to_owned(),
                "cookie".to_owned(),
            ],
            allow_response_headers: vec!["x-auth-request-user".to_owned()],
            connect_timeout_secs: 1,
            read_timeout_secs: 1,
            max_response_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        },
        ..Default::default()
    };
    let proxy = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET /private?x=1 HTTP/1.1\r\n\
              Host: proxy.test\r\n\
              Cookie: a=1\r\n\
              Cookie: b=2\r\n\
              Connection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    let auth_request = tokio::time::timeout(Duration::from_secs(2), auth_rx)
        .await
        .unwrap()
        .unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("origin-ok"));
    assert!(auth_request.starts_with("GET /auth HTTP/1.1\r\n"));
    assert!(auth_request.contains("\r\nx-original-uri: /private?x=1\r\n"));
    assert!(auth_request.contains("\r\nx-forwarded-host: proxy.test\r\n"));
    assert!(auth_request.contains("\r\ncookie: a=1; b=2\r\n"));
}

#[cfg(feature = "auth-request")]
#[tokio::test]
async fn native_proxy_auth_request_denies_before_upstream_forwarding() {
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let upstream_hits_for_task = Arc::clone(&upstream_hits);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((_, _)) = listener.accept().await {
            upstream_hits_for_task.fetch_add(1, Ordering::Relaxed);
        }
    });
    let (auth, _auth_rx) =
        auth_endpoint(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 7\r\n\r\ndenied\n").await;
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        auth_request: fluxheim_config::AuthRequestConfig {
            enabled: true,
            url: Some(format!("http://{auth}/auth")),
            connect_timeout_secs: 1,
            read_timeout_secs: 1,
            max_response_bytes: fluxheim_config::ByteSize::from_bytes(1024),
            ..Default::default()
        },
        ..Default::default()
    };
    let proxy = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_get(proxy, "/private").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("denied\n"));
    assert_eq!(upstream_hits.load(Ordering::Relaxed), 0);
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

#[test]
fn native_proxy_config_accepts_plain_static_upstream() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        connect_timeout_secs: Some(2),
        read_timeout_secs: Some(3),
        send_timeout_secs: Some(4),
        downstream_write_timeout_secs: Some(7),
        downstream_total_response_timeout_secs: Some(11),
        downstream_min_send_rate_bytes_per_sec: Some(1024),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(
        native.upstream(),
        &NativeHttp1Upstream::new("127.0.0.1:3000")
            .with_connect_timeout(Duration::from_secs(2))
            .with_read_timeout(Duration::from_secs(3))
            .with_write_timeout(Duration::from_secs(4))
    );
    assert_eq!(
        native.response_write_policy(),
        NativeHttp1ResponseWritePolicy::new(
            Some(Duration::from_secs(7)),
            Some(Duration::from_secs(11)),
            Some(1024)
        )
    );
}

#[test]
fn native_proxy_config_accepts_ordered_static_upstreams() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: static_load_balance_without_health_check(),
        connect_timeout_secs: Some(2),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(native.upstreams().len(), 2);
    assert_eq!(
        native.upstreams()[0],
        NativeHttp1Upstream::new("127.0.0.1:3000").with_connect_timeout(Duration::from_secs(2))
    );
    assert_eq!(
        native.upstreams()[1],
        NativeHttp1Upstream::new("127.0.0.1:3001").with_connect_timeout(Duration::from_secs(2))
    );
}

#[test]
fn native_proxy_config_accepts_weighted_static_upstreams() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_weights: vec![2, 1],
        load_balance: static_load_balance_without_health_check(),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(native.upstream_slots(), &[0, 0, 1]);
}

#[test]
fn native_proxy_config_accepts_static_upstreams_with_disabled_health_check() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: fluxheim_config::LoadBalanceConfig {
            health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(native.upstreams().len(), 2);
    assert_eq!(native.upstream_slots(), &[0, 1]);
}

#[cfg(feature = "load-balancer")]
#[test]
fn native_proxy_config_accepts_scoped_advanced_static_load_balance_policy() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_priority_groups: vec![100, 50],
        upstream_max_in_flight: vec![1, 2],
        upstream_aliases: vec!["primary-a".to_owned(), "primary-b".to_owned()],
        backup_upstreams: vec!["127.0.0.1:3001".to_owned()],
        load_balance: fluxheim_config::LoadBalanceConfig {
            health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let (native, service) = NativeHttp1Proxy::from_proxy_config_with_native_load_balancer(
        "advanced-static",
        "advanced.test",
        None,
        &proxy,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap()
    .expect("native proxy");

    assert_eq!(native.upstreams().len(), 2);
    assert!(service.is_none());
}

#[test]
fn native_proxy_config_rejects_custom_disabled_health_check_policy() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: fluxheim_config::LoadBalanceConfig {
            health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
                enabled: false,
                interval_secs: 7,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).unwrap_err(),
        NativeHttp1ProxyConfigError::LoadBalancing
    );
}

#[test]
fn native_proxy_config_applies_pool_capacity() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config_with_pool_size(
        &proxy,
        DownstreamHttp1Policy::default(),
        16,
    )
    .unwrap()
    .expect("native proxy");

    assert_eq!(native.upstream().pool_max_idle(), 16);
}

#[test]
fn native_proxy_config_accepts_http1_upstream_proxy_protocol_and_disables_pooling() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_proxy_protocol: fluxheim_config::UpstreamProxyProtocol::V2,
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config_with_pool_size(
        &proxy,
        DownstreamHttp1Policy::default(),
        16,
    )
    .unwrap()
    .expect("native proxy");

    assert_eq!(
        native.upstream().proxy_protocol(),
        fluxheim_config::UpstreamProxyProtocol::V2
    );
    assert_eq!(native.upstream().pool_max_idle(), 0);
}

#[test]
fn native_proxy_config_rejects_upstream_proxy_protocol_with_http2() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        upstream_proxy_protocol: fluxheim_config::UpstreamProxyProtocol::V1,
        ..Default::default()
    };

    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamProxyProtocol)
    );
}

#[test]
fn native_proxy_config_applies_total_connection_timeout() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_total_connection_timeout_secs: Some(9),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(
        native.upstream().total_connection_timeout(),
        Some(Duration::from_secs(9))
    );
}

#[test]
fn native_proxy_config_applies_downstream_read_timeout() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        downstream_read_timeout_secs: Some(7),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(native.request_body_timeout(), Some(Duration::from_secs(7)));
}

#[test]
fn native_proxy_config_applies_portable_socket_options() {
    let mut proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_tcp_recv_buffer_bytes: Some(fluxheim_config::ByteSize::from_bytes(65_536)),
        upstream_dscp: Some(10),
        upstream_tcp_keepalive_idle_secs: Some(30),
        upstream_tcp_keepalive_interval_secs: Some(10),
        upstream_tcp_keepalive_count: Some(3),
        ..Default::default()
    };
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    ))]
    {
        proxy.upstream_tcp_user_timeout_ms = Some(15000);
    }

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(native.upstream().recv_buffer_size(), Some(65_536));
    assert_eq!(native.upstream().dscp(), Some(10));
    let keepalive = native.upstream().tcp_keepalive().unwrap();
    assert_eq!(keepalive.idle(), Duration::from_secs(30));
    assert_eq!(keepalive.interval(), Duration::from_secs(10));
    assert_eq!(keepalive.count(), 3);
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    ))]
    assert_eq!(
        native.upstream().tcp_user_timeout(),
        Some(Duration::from_millis(15000))
    );
}

#[test]
fn native_proxy_config_rejects_oversized_socket_receive_buffer() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_tcp_recv_buffer_bytes: Some(fluxheim_config::ByteSize::from_bytes(
            u64::from(u32::MAX) + 1,
        )),
        ..Default::default()
    };

    let error =
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).unwrap_err();

    assert_eq!(error, NativeHttp1ProxyConfigError::RecvBufferTooLarge);
}

#[tokio::test]
async fn native_proxy_socket_options_connect_to_upstream() {
    let upstream = upstream(|_, mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 13\r\n\r\nsocket-policy")
            .await
            .unwrap();
    })
    .await;
    let mut proxy = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        upstream_tcp_recv_buffer_bytes: Some(fluxheim_config::ByteSize::from_bytes(65_536)),
        upstream_dscp: Some(10),
        upstream_tcp_keepalive_idle_secs: Some(30),
        upstream_tcp_keepalive_interval_secs: Some(10),
        upstream_tcp_keepalive_count: Some(3),
        ..Default::default()
    };
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    ))]
    {
        proxy.upstream_tcp_user_timeout_ms = Some(15000);
    }
    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    let response = native.handle(native_proxy_test_request()).await;

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"socket-policy");
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

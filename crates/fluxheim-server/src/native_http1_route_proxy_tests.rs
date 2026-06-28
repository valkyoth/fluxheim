use std::collections::BTreeMap;
#[cfg(feature = "compression-gzip")]
use std::io::Read as _;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "compression-gzip")]
use flate2::read::GzDecoder;
use fluxheim_config::{GrpcRouteConfig, HeaderValues, ResponseHeaderPolicyOverlayConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[cfg(feature = "acme")]
use crate::NativeHttp1AcmeHttp01Store;
#[cfg(not(feature = "privacy-mode"))]
use crate::ProxyProtocolTrustedSource;
use crate::{
    DownstreamHttp1Policy, NativeHttp1GeoContext, NativeHttp1Handler, NativeHttp1Proxy,
    NativeHttp1ProxyConfigError, NativeHttp1Request, NativeHttp1RouteProxy,
    NativeHttp1RouteProxyConfigError, NativeHttp1RouteProxyRoute, NativeHttp1TlsClientIdentity,
    NativeHttp1Upstream, serve_native_http1_listener,
};

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

#[cfg(feature = "php-fpm")]
async fn fastcgi_responder(stdout: &'static [u8]) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request_id = 1_u16;
        let mut params_done = false;
        let mut stdin_done = false;
        while !(params_done && stdin_done) {
            let (record_type, id, content) = read_fastcgi_record(&mut stream).await;
            request_id = id;
            match record_type {
                4 if content.is_empty() => params_done = true,
                5 if content.is_empty() => stdin_done = true,
                _ => {}
            }
        }
        write_fastcgi_record(&mut stream, 6, request_id, stdout)
            .await
            .unwrap();
        write_fastcgi_record(&mut stream, 6, request_id, b"")
            .await
            .unwrap();
        write_fastcgi_record(&mut stream, 3, request_id, &[0, 0, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    addr
}

#[cfg(feature = "php-fpm")]
async fn read_fastcgi_record(stream: &mut TcpStream) -> (u8, u16, Vec<u8>) {
    let mut header = [0_u8; 8];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 1, "unexpected FastCGI version");
    let record_type = header[1];
    let request_id = u16::from_be_bytes([header[2], header[3]]);
    let content_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    let padding_len = header[6] as usize;
    let mut content = vec![0_u8; content_len];
    if content_len > 0 {
        stream.read_exact(&mut content).await.unwrap();
    }
    if padding_len > 0 {
        let mut padding = vec![0_u8; padding_len];
        stream.read_exact(&mut padding).await.unwrap();
    }
    (record_type, request_id, content)
}

#[cfg(feature = "php-fpm")]
async fn write_fastcgi_record(
    stream: &mut TcpStream,
    record_type: u8,
    request_id: u16,
    content: &[u8],
) -> std::io::Result<()> {
    let len = u16::try_from(content.len()).unwrap();
    let mut header = [0_u8; 8];
    header[0] = 1;
    header[1] = record_type;
    header[2..4].copy_from_slice(&request_id.to_be_bytes());
    header[4..6].copy_from_slice(&len.to_be_bytes());
    stream.write_all(&header).await?;
    stream.write_all(content).await
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

#[tokio::test]
async fn native_route_proxy_vhost_access_denies_before_redirect() {
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: fluxheim_config::AccessPolicyConfig {
            deny: vec!["127.0.0.1".to_owned()],
            ..Default::default()
        },
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
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
    let route_proxy = NativeHttp1RouteProxy::from_vhost_config(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = route_proxy_listener(route_proxy).await;

    let response = downstream_get(proxy, "/blocked").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("forbidden\n"));
}

#[tokio::test]
async fn native_route_proxy_route_access_denies_before_route_action() {
    let route = fluxheim_config::RouteConfig {
        name: "admin".to_owned(),
        path_exact: Some("/admin".to_owned()),
        path_prefix: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: fluxheim_config::AccessPolicyConfig {
            deny: vec!["127.0.0.1".to_owned()],
            ..Default::default()
        },
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: Some(fluxheim_config::RouteRedirectConfig {
            to: "https://target.example/admin".to_owned(),
            status: 302,
        }),
        proxy: None,
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };
    let route = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap();
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/admin").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("forbidden\n"));
}

#[tokio::test]
async fn native_route_proxy_route_access_checks_decoded_policy_path() {
    let protected = fluxheim_config::RouteConfig {
        name: "admin".to_owned(),
        path_exact: Some("/admin".to_owned()),
        path_prefix: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: fluxheim_config::AccessPolicyConfig {
            deny: vec!["127.0.0.1".to_owned()],
            ..Default::default()
        },
        rate_limit: Default::default(),
        concurrency: Default::default(),
        grpc: Default::default(),
        redirect: Some(fluxheim_config::RouteRedirectConfig {
            to: "https://target.example/admin".to_owned(),
            status: 302,
        }),
        proxy: None,
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };
    let fallback = fluxheim_config::RouteConfig {
        name: "fallback".to_owned(),
        path_exact: None,
        path_prefix: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: true,
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
            to: "https://target.example/fallback".to_owned(),
            status: 302,
        }),
        proxy: None,
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: Default::default(),
    };
    let protected = NativeHttp1RouteProxyRoute::from_config(&protected, None).unwrap();
    let fallback = NativeHttp1RouteProxyRoute::from_config(&fallback, None).unwrap();
    let proxy =
        route_proxy_listener(NativeHttp1RouteProxy::new(vec![protected, fallback], None)).await;

    let response = downstream_get(proxy, "/%61dmin").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("forbidden\n"));
}

#[tokio::test]
async fn native_route_proxy_vhost_concurrency_rejects_second_request() {
    let (upstream, observed, release) = upstream_hold_response("/slow", "released").await;
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: fluxheim_config::ConcurrencyLimitConfig {
            enabled: true,
            max_in_flight: 1,
            status: 429,
            ..Default::default()
        },
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
    let first = tokio::spawn(async move { downstream_get(proxy, "/slow").await });
    observed.await.unwrap();

    let rejected = downstream_get(proxy, "/slow").await;
    release.send(()).unwrap();
    let first = first.await.unwrap();

    assert!(rejected.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
    assert!(rejected.ends_with("too many requests\n"));
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("released"));
}

#[tokio::test]
async fn native_route_proxy_route_concurrency_rejects_second_request() {
    let (upstream, observed, release) = upstream_hold_response("/slow", "released").await;
    let route_config = fluxheim_config::RouteConfig {
        name: "slow".to_owned(),
        path_exact: Some("/slow".to_owned()),
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
        concurrency: fluxheim_config::ConcurrencyLimitConfig {
            enabled: true,
            max_in_flight: 1,
            status: 429,
            ..Default::default()
        },
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
    let first = tokio::spawn(async move { downstream_get(proxy, "/slow").await });
    observed.await.unwrap();

    let rejected = downstream_get(proxy, "/slow").await;
    release.send(()).unwrap();
    let first = first.await.unwrap();

    assert!(rejected.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
    assert!(rejected.ends_with("too many requests\n"));
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("released"));
}

#[tokio::test]
async fn native_route_proxy_vhost_rate_limit_rejects_second_request() {
    let upstream = upstream_expect_path("/limited", "first").await;
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: fluxheim_config::RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst: 1,
            status: 429,
            ..Default::default()
        },
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

    let first = downstream_get(proxy, "/limited").await;
    let second = downstream_get(proxy, "/limited").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("first"));
    assert!(second.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
    assert!(second.ends_with("rate limited\n"));
}

#[tokio::test]
async fn native_route_proxy_route_rate_limit_rejects_second_request() {
    let upstream = upstream_expect_path("/limited", "first").await;
    let route_config = fluxheim_config::RouteConfig {
        name: "limited".to_owned(),
        path_exact: Some("/limited".to_owned()),
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
        rate_limit: fluxheim_config::RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst: 1,
            status: 429,
            ..Default::default()
        },
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

    let first = downstream_get(proxy, "/limited").await;
    let second = downstream_get(proxy, "/limited").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("first"));
    assert!(second.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
    assert!(second.ends_with("rate limited\n"));
}

#[tokio::test]
async fn native_route_proxy_rate_limit_delay_consumes_concurrency() {
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: fluxheim_config::RateLimitConfig {
            enabled: true,
            requests_per_second: 10,
            burst: 1,
            status: 429,
            mode: fluxheim_config::RateLimitMode::Delay,
            max_delay_ms: 500,
            ..Default::default()
        },
        concurrency: fluxheim_config::ConcurrencyLimitConfig {
            enabled: true,
            max_in_flight: 1,
            max_queue: 0,
            queue_timeout_ms: 0,
            status: 503,
        },
        tls: Default::default(),
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
    let route_proxy = NativeHttp1RouteProxy::from_vhost_config(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();
    let proxy = route_proxy_listener(route_proxy).await;

    let first = downstream_get(proxy, "/delayed").await;
    assert!(first.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"));

    let delayed = tokio::spawn(async move { downstream_get(proxy, "/delayed").await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let rejected_by_concurrency = downstream_get(proxy, "/delayed").await;
    let delayed = delayed.await.unwrap();

    assert!(rejected_by_concurrency.starts_with("HTTP/1.1 503 Too Many Requests\r\n"));
    assert!(rejected_by_concurrency.ends_with("too many requests\n"));
    assert!(delayed.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"));
}

#[cfg(not(feature = "privacy-mode"))]
#[tokio::test]
async fn native_route_proxy_vhost_access_uses_trusted_forwarded_chain() {
    let vhost = fluxheim_config::VhostConfig {
        name: "route.test".to_owned(),
        hosts: vec!["route.test".to_owned()],
        max_request_body_bytes: None,
        access: fluxheim_config::AccessPolicyConfig {
            allow: vec!["203.0.113.5".to_owned()],
            ..Default::default()
        },
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
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
    let route_proxy = NativeHttp1RouteProxy::from_vhost_config_with_trusted_sources(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
        &[ProxyProtocolTrustedSource::Ip("127.0.0.1".parse().unwrap())],
    )
    .unwrap();
    let proxy = route_proxy_listener(route_proxy).await;

    let allowed = downstream_request(
        proxy,
        "GET /trusted HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 203.0.113.5\r\n\
         Connection: close\r\n\r\n",
    )
    .await;
    let denied = downstream_request(
        proxy,
        "GET /trusted HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 203.0.113.6\r\n\
         Connection: close\r\n\r\n",
    )
    .await;
    let duplicate_header_denied = downstream_request(
        proxy,
        "GET /trusted HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 203.0.113.5\r\n\
         X-Forwarded-For: 203.0.113.6\r\n\
         Connection: close\r\n\r\n",
    )
    .await;
    let duplicate_header_allowed = downstream_request(
        proxy,
        "GET /trusted HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 203.0.113.6\r\n\
         X-Forwarded-For: 203.0.113.5\r\n\
         Connection: close\r\n\r\n",
    )
    .await;

    assert!(allowed.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"));
    assert_eq!(
        response_header(&allowed, "location").as_deref(),
        Some("https://target.example/trusted")
    );
    assert!(denied.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(duplicate_header_denied.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(duplicate_header_allowed.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"));
}

#[tokio::test]
async fn native_route_proxy_access_policy_checks_tls_client_identity() {
    let allowed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let denied = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let upstream = upstream_expect_path("/mtls", "mtls-ok").await;
    let route_config = fluxheim_config::RouteConfig {
        name: "mtls".to_owned(),
        path_prefix: Some("/mtls".to_owned()),
        path_exact: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: fluxheim_config::AccessPolicyConfig {
            require_client_cert: true,
            allow_client_cert_sha256: vec![allowed.to_owned()],
            deny_client_cert_sha256: vec![denied.to_owned()],
            ..Default::default()
        },
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
    let proxy = NativeHttp1RouteProxy::new(vec![route], None);

    let mut allowed_request = route_test_request("/mtls");
    allowed_request.tls_identity = Some(NativeHttp1TlsClientIdentity {
        cert_sha256: Some(allowed.to_ascii_uppercase()),
        ..Default::default()
    });
    let mut denied_request = route_test_request("/mtls");
    denied_request.tls_identity = Some(NativeHttp1TlsClientIdentity {
        cert_sha256: Some(denied.to_owned()),
        ..Default::default()
    });
    let mut unknown_request = route_test_request("/mtls");
    unknown_request.tls_identity = Some(NativeHttp1TlsClientIdentity {
        cert_sha256: Some(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
        ),
        ..Default::default()
    });

    let allowed_response = proxy.handle(allowed_request).await;
    let denied_response = proxy.handle(denied_request).await;
    let unknown_response = proxy.handle(unknown_request).await;
    let missing_response = proxy.handle(route_test_request("/mtls")).await;

    assert_eq!(allowed_response.status(), 200);
    assert_eq!(allowed_response.body(), b"mtls-ok");
    assert_eq!(denied_response.status(), 403);
    assert_eq!(unknown_response.status(), 403);
    assert_eq!(missing_response.status(), 403);
}

#[tokio::test]
async fn native_route_proxy_access_policy_checks_geo_context() {
    let upstream = upstream_expect_path("/geo", "geo-ok").await;
    let route_config = fluxheim_config::RouteConfig {
        name: "geo".to_owned(),
        path_prefix: Some("/geo".to_owned()),
        path_exact: None,
        path_regex: None,
        methods: Vec::new(),
        fallback: false,
        https_redirect_exempt: false,
        strip_prefix: None,
        rewrite_prefix: None,
        rewrite_template: None,
        max_request_body_bytes: None,
        access: fluxheim_config::AccessPolicyConfig {
            allow_countries: vec!["SE".to_owned()],
            deny_asns: vec![64512],
            ..Default::default()
        },
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
    let proxy = NativeHttp1RouteProxy::new(vec![route], None);

    let mut allowed_request = route_test_request("/geo");
    allowed_request.geo_context = Some(NativeHttp1GeoContext {
        country_iso: Some("se".to_owned()),
        asn: Some(12552),
    });
    let mut denied_country_request = route_test_request("/geo");
    denied_country_request.geo_context = Some(NativeHttp1GeoContext {
        country_iso: Some("NO".to_owned()),
        asn: Some(12552),
    });
    let mut denied_asn_request = route_test_request("/geo");
    denied_asn_request.geo_context = Some(NativeHttp1GeoContext {
        country_iso: Some("SE".to_owned()),
        asn: Some(64512),
    });

    let allowed_response = proxy.handle(allowed_request).await;
    let denied_country_response = proxy.handle(denied_country_request).await;
    let denied_asn_response = proxy.handle(denied_asn_request).await;
    let missing_response = proxy.handle(route_test_request("/geo")).await;

    assert_eq!(allowed_response.status(), 200);
    assert_eq!(allowed_response.body(), b"geo-ok");
    assert_eq!(denied_country_response.status(), 403);
    assert_eq!(denied_asn_response.status(), 403);
    assert_eq!(missing_response.status(), 403);
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

#[test]
fn native_route_proxy_selects_route_request_body_timeout() {
    let route_upstream = "127.0.0.1:3000".parse().unwrap();
    let fallback_upstream = "127.0.0.1:3001".parse().unwrap();
    let route = NativeHttp1RouteProxyRoute::prefix(
        "/api/",
        Vec::new(),
        proxy_for(route_upstream).with_request_body_timeout(Some(Duration::from_secs(4))),
    );
    let proxy = NativeHttp1RouteProxy::new(vec![route], Some(proxy_for(fallback_upstream)));

    assert_eq!(
        proxy.request_body_timeout(&route_test_request("/api/upload")),
        Some(Duration::from_secs(4))
    );
    assert_eq!(
        proxy.request_body_timeout(&route_test_request("/other")),
        None
    );
}

#[test]
fn native_route_proxy_does_not_inherit_fallback_timeout_for_redirect_route() {
    let fallback_upstream = "127.0.0.1:3001".parse().unwrap();
    let route = NativeHttp1RouteProxyRoute::prefix_redirect(
        "/old/",
        Vec::new(),
        "https://route.test/new{uri}".to_owned(),
        308,
    );
    let fallback =
        proxy_for(fallback_upstream).with_request_body_timeout(Some(Duration::from_secs(99)));
    let proxy = NativeHttp1RouteProxy::new(vec![route], Some(fallback));

    assert_eq!(
        proxy.request_body_timeout(&route_test_request("/old/path")),
        None
    );
    assert_eq!(
        proxy.request_body_timeout(&route_test_request("/fallback")),
        Some(Duration::from_secs(99))
    );
}

#[tokio::test]
async fn native_route_proxy_grpc_policy_rejects_non_grpc_requests() {
    let route = NativeHttp1RouteProxyRoute::prefix(
        "/grpc/",
        Vec::new(),
        proxy_for("127.0.0.1:9".parse().unwrap()),
    )
    .with_grpc_policy(GrpcRouteConfig {
        enabled: true,
        require_content_type: true,
    });
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let method_response = downstream_get(proxy, "/grpc/service.Method").await;
    let media_response = downstream_request(
        proxy,
        "POST /grpc/service.Method HTTP/1.1\r\nHost: route.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    let duplicate_media_response = downstream_request(
        proxy,
        "POST /grpc/service.Method HTTP/1.1\r\nHost: route.test\r\nContent-Type: application/grpc\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(method_response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
    assert_eq!(
        response_header(&method_response, "allow").as_deref(),
        Some("POST")
    );
    assert_eq!(
        response_header(&method_response, "grpc-status").as_deref(),
        Some("12")
    );
    assert!(method_response.ends_with("method not allowed\n"));
    assert!(media_response.starts_with("HTTP/1.1 415 Unsupported Media Type\r\n"));
    assert_eq!(
        response_header(&media_response, "grpc-status").as_deref(),
        Some("3")
    );
    assert!(media_response.ends_with("unsupported media type\n"));
    assert!(duplicate_media_response.starts_with("HTTP/1.1 415 Unsupported Media Type\r\n"));
    assert_eq!(
        response_header(&duplicate_media_response, "grpc-status").as_deref(),
        Some("3")
    );
    assert!(duplicate_media_response.ends_with("unsupported media type\n"));
}

#[tokio::test]
async fn native_route_proxy_grpc_policy_allows_grpc_content_type() {
    let upstream = upstream_expect_method_path("POST", "/grpc/service.Method", "grpc").await;
    let route = NativeHttp1RouteProxyRoute::prefix("/grpc/", Vec::new(), proxy_for(upstream))
        .with_grpc_policy(GrpcRouteConfig {
            enabled: true,
            require_content_type: true,
        });
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "POST /grpc/service.Method HTTP/1.1\r\nHost: route.test\r\nContent-Type: Application/gRPC+Proto; charset=utf-8\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("grpc"));
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

#[tokio::test]
async fn native_route_proxy_renders_request_header_templates_before_forwarding() {
    let upstream = upstream_expect_header(
        "/api/item?version=1",
        "x-forwarded-host",
        "route.test",
        "x-remove",
    )
    .await;
    let mut set = BTreeMap::new();
    set.insert("x-forwarded-host".to_owned(), "{host}".to_owned());
    set.insert("x-original-uri".to_owned(), "{uri}".to_owned());
    set.insert("x-client-upgrade".to_owned(), "{http.upgrade}".to_owned());
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
        "GET /api/item?version=1 HTTP/1.1\r\nHost: route.test\r\nX-Remove: secret\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("headers"));
}

#[tokio::test]
async fn native_route_proxy_renders_route_regex_captures_in_request_headers() {
    let upstream =
        upstream_expect_header("/internal/v2/users?id=7", "x-api-version", "2", "x-remove").await;
    let mut add = BTreeMap::new();
    add.insert(
        "x-api-version".to_owned(),
        "{route.regex.version}".to_owned(),
    );
    let policy = fluxheim_config::RequestHeaderPolicyOverlayConfig {
        add,
        ..Default::default()
    };
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
    let route = NativeHttp1RouteProxyRoute::from_config(&route_config, Some(proxy_for(upstream)))
        .unwrap()
        .with_request_header_policy(&policy);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/api/v2/users?id=7").await;

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

#[cfg(not(feature = "privacy-mode"))]
#[tokio::test]
async fn native_route_proxy_trusted_append_preserves_forwarded_chain() {
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
        assert!(
            request.contains("x-forwarded-for: 198.51.100.9, 203.0.113.10, 198.51.100.9\r\n"),
            "unexpected trusted append request: {request:?}"
        );
        assert!(
            request.contains("x-real-ip: 198.51.100.9\r\n"),
            "unexpected trusted append request: {request:?}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 14\r\n\r\ntrusted-append")
            .await
            .unwrap();
    });
    let policy = fluxheim_config::RequestHeaderPolicyOverlayConfig {
        strip_inbound_client_ip_headers: Some(false),
        x_forwarded_for: Some(fluxheim_config::ForwardedClientIpHeaderMode::Append),
        x_real_ip: Some(true),
        ..Default::default()
    };
    let route = NativeHttp1RouteProxyRoute::prefix("/api/", Vec::new(), proxy_for(upstream))
        .with_request_header_policy(&policy)
        .with_trusted_sources(&[
            ProxyProtocolTrustedSource::Ip("127.0.0.1".parse().unwrap()),
            ProxyProtocolTrustedSource::Ip("203.0.113.10".parse().unwrap()),
        ]);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /api/item HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 198.51.100.9, 203.0.113.10\r\n\
         Connection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("trusted-append"));
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
        "route.test",
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

#[tokio::test]
async fn native_route_proxy_disabled_request_headers_suppress_inherited_policy() {
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
        assert!(
            !request
                .lines()
                .any(|line| line.eq_ignore_ascii_case("x-root-request: native")),
            "disabled route request policy forwarded inherited header: {request:?}"
        );
        assert!(
            !request
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("x-forwarded-for:")),
            "disabled route request policy forwarded client IP header: {request:?}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\ndisabled")
            .await
            .unwrap();
    });
    let mut base_headers = fluxheim_config::HeaderPolicyConfig::default();
    base_headers
        .request
        .set
        .insert("x-root-request".to_owned(), "native".to_owned());
    let mut route_headers = fluxheim_config::VhostHeaderPolicyConfig::default();
    route_headers.request.enabled = Some(false);
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
        "route.test",
    )
    .unwrap();
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /api/item HTTP/1.1\r\nHost: route.test\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("disabled"));
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
        "route.test",
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

#[test]
fn native_route_proxy_rejects_vhost_cache_policy_until_native_adapter_exists() {
    let mut vhost = native_route_proxy_test_vhost();
    vhost.cache.enabled = true;

    let error = NativeHttp1RouteProxy::from_vhost_config(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::CachePolicy)
    );
}

#[test]
fn native_route_proxy_accepts_vhost_memory_proxy_cache() {
    let mut vhost = native_route_proxy_test_vhost();
    vhost.proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    };
    vhost.cache = native_proxy_memory_cache_config();

    let proxy = NativeHttp1RouteProxy::from_vhost_config(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap();

    assert!(proxy.fallback().is_some());
}

#[test]
fn native_route_proxy_rejects_vhost_php_without_root() {
    let mut vhost = native_route_proxy_test_vhost();
    vhost.php.enabled = true;

    let error = NativeHttp1RouteProxy::from_vhost_config(
        &vhost,
        &fluxheim_config::HeaderPolicyConfig::default(),
        None,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap_err();

    assert_eq!(
        error,
        NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::PhpFpm)
    );
}

#[test]
fn native_route_proxy_rejects_route_cache_policy_until_native_adapter_exists() {
    let mut route = native_route_proxy_test_route();
    route.cache = Some(fluxheim_config::CacheConfig {
        enabled: true,
        ..Default::default()
    });

    let error = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap_err();

    assert_eq!(
        error,
        NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::CachePolicy)
    );
}

#[test]
fn native_route_proxy_accepts_route_memory_proxy_cache() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    route.cache = Some(native_proxy_memory_cache_config());

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let route = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap();

    assert!(route.proxy().is_some());
}

#[test]
fn native_route_proxy_accepts_route_memory_proxy_cache_with_origin_protection() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.origin_protection.enabled = true;
    cache.origin_protection.max_concurrent_fills = 1;
    route.cache = Some(cache);

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let route = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap();

    assert!(route.proxy().is_some());
}

#[test]
fn native_route_proxy_accepts_route_memory_proxy_cache_with_range_policy() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.range.enabled = true;
    route.cache = Some(cache);

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let route = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap();

    assert!(route.proxy().is_some());
}

#[test]
fn native_route_proxy_accepts_route_memory_proxy_cache_with_predictor_policy() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.predictor.enabled = true;
    cache.min_uses = 2;
    cache.pass_uncacheable_after = 1;
    route.cache = Some(cache);

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let route = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap();

    assert!(route.proxy().is_some());
}

#[test]
fn native_route_proxy_accepts_route_memory_proxy_cache_with_stale_while_revalidate() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.proxy = Some(fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    });
    let mut cache = native_proxy_memory_cache_config();
    cache.stale_while_revalidate_secs = Some(60);
    route.cache = Some(cache);

    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new("127.0.0.1:3000"));
    let route = NativeHttp1RouteProxyRoute::from_config(&route, Some(proxy)).unwrap();

    assert!(route.proxy().is_some());
}

#[tokio::test]
async fn native_route_proxy_caches_proxy_response_in_memory() {
    let upstream = upstream_cacheable_once("origin-one").await;
    let cache = native_proxy_memory_cache_config();
    let proxy = proxy_for(upstream).with_proxy_cache_config(&cache);
    let listener = route_proxy_listener(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy))).await;

    let first = downstream_get(listener, "/asset.png").await;
    let second = downstream_get(listener, "/asset.png").await;

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("origin-one"));
    assert_eq!(
        response_header(&first, "x-cache-status").as_deref(),
        Some("MISS")
    );
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("origin-one"));
    assert_eq!(
        response_header(&second, "x-cache-status").as_deref(),
        Some("HIT")
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

#[test]
fn native_route_proxy_rejects_route_php_without_root() {
    let mut route = native_route_proxy_test_route();
    route.redirect = None;
    route.php = Some(fluxheim_config::PhpConfig {
        enabled: true,
        ..Default::default()
    });

    let error = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap_err();

    assert_eq!(
        error,
        NativeHttp1RouteProxyConfigError::Proxy(NativeHttp1ProxyConfigError::PhpFpm)
    );
}

#[cfg(feature = "php-fpm")]
#[tokio::test]
async fn native_route_proxy_php_route_fails_closed_when_fpm_unavailable() {
    let root = tempfile::TempDir::new().unwrap();
    std::fs::write(root.path().join("index.php"), b"<?php echo 'ok';").unwrap();
    let mut route = native_route_proxy_test_route();
    route.path_exact = Some("/index.php".to_owned());
    route.redirect = None;
    route.php = Some(fluxheim_config::PhpConfig {
        enabled: true,
        root: Some(root.path().to_path_buf()),
        fpm: fluxheim_config::PhpFpmConfig {
            tcp: Some("127.0.0.1:9".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    });

    let route = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap();
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/index.php").await;

    assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
    assert!(response.ends_with("php-fpm failed\n"));
}

#[cfg(feature = "php-fpm")]
#[tokio::test]
async fn native_route_proxy_php_route_executes_fastcgi_responder() {
    let fpm = fastcgi_responder(
        b"Status: 201 Created\r\nContent-Type: text/plain\r\nX-Powered-By: php\r\n\r\nphp-ok",
    )
    .await;
    let root = tempfile::TempDir::new().unwrap();
    std::fs::write(root.path().join("index.php"), b"<?php echo 'ok';").unwrap();
    let mut route = native_route_proxy_test_route();
    route.path_exact = Some("/index.php".to_owned());
    route.redirect = None;
    route.php = Some(fluxheim_config::PhpConfig {
        enabled: true,
        root: Some(root.path().to_path_buf()),
        hide_response_headers: vec!["x-powered-by".to_owned()],
        fpm: fluxheim_config::PhpFpmConfig {
            tcp: Some(fpm.to_string()),
            ..Default::default()
        },
        ..Default::default()
    });

    let route = NativeHttp1RouteProxyRoute::from_config(&route, None).unwrap();
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_get(proxy, "/index.php").await;

    assert!(
        response.starts_with("HTTP/1.1 201 Created\r\n"),
        "unexpected response: {response:?}"
    );
    assert_eq!(
        response_header(&response, "content-type").as_deref(),
        Some("text/plain")
    );
    assert_eq!(response_header(&response, "x-powered-by"), None);
    assert!(response.ends_with("php-ok"));
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

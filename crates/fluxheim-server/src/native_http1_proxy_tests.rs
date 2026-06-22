use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

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
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: "/socket-policy".to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![("host".to_owned(), "proxy.test".to_owned())],
        body: Vec::new(),
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
async fn native_proxy_fails_over_get_to_second_static_upstream() {
    let first = unused_local_address().await;
    let second = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /failover HTTP/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 15\r\nx-origin: second\r\n\r\nsecond upstream",
            )
            .await
            .unwrap();
    })
    .await;
    let proxy = failover_proxy_listener(first, second).await;

    let response = downstream_get(proxy, "/failover").await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("x-origin: second\r\n"));
    assert!(response.ends_with("second upstream"));
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

#[tokio::test]
async fn native_proxy_round_robins_successful_static_upstreams() {
    let first = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /balanced HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-origin: one\r\n\r\none-1")
            .await
            .unwrap();
    })
    .await;
    let second = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /balanced HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-origin: two\r\n\r\ntwo-2")
            .await
            .unwrap();
    })
    .await;
    let proxy = failover_proxy_listener(first, second).await;

    let first_response = downstream_get(proxy, "/balanced").await;
    let second_response = downstream_get(proxy, "/balanced").await;

    assert!(first_response.contains("x-origin: one\r\n"));
    assert!(first_response.ends_with("one-1"));
    assert!(second_response.contains("x-origin: two\r\n"));
    assert!(second_response.ends_with("two-2"));
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
#[tokio::test]
async fn native_proxy_mirrors_safe_requests_without_changing_origin_response() {
    let upstream = upstream(|_, mut stream| async move {
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

#[tokio::test]
async fn native_proxy_weighted_round_robins_static_upstreams() {
    let (first, first_count) = counting_upstream("one", 2).await;
    let (second, second_count) = counting_upstream("two", 1).await;
    let proxy = NativeHttp1Proxy::from_weighted_upstreams(
        vec![
            NativeHttp1Upstream::new(first.to_string()),
            NativeHttp1Upstream::new(second.to_string()),
        ],
        &[2, 1],
    )
    .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let first_response = downstream_get(proxy, "/weighted").await;
    let second_response = downstream_get(proxy, "/weighted").await;
    let third_response = downstream_get(proxy, "/weighted").await;

    assert!(first_response.ends_with("one"));
    assert!(second_response.ends_with("one"));
    assert!(third_response.ends_with("two"));
    assert_eq!(first_count.load(Ordering::Relaxed), 2);
    assert_eq!(second_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn native_proxy_does_not_fail_over_unsafe_method() {
    let first = unused_local_address().await;
    let second = upstream(|_, mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nsecond")
            .await
            .unwrap();
    })
    .await;
    let proxy = failover_proxy_listener(first, second).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"POST /submit HTTP/1.1\r\nHost: proxy.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.ends_with("bad gateway\n"));
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
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(native.upstream_slots(), &[0, 0, 1]);
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

#[test]
fn native_proxy_config_returns_none_without_upstream() {
    let proxy = fluxheim_config::ProxyConfig::disabled();

    let native =
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).unwrap();

    assert!(native.is_none());
}

#[test]
fn native_proxy_config_rejects_unsupported_upstream_features() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_tls: true,
        ..Default::default()
    };
    #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTls)
    );
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy)
    );

    let proxy = fluxheim_config::ProxyConfig {
        upstreams_file: Some(std::path::PathBuf::from("/tmp/upstreams.txt")),
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::DynamicUpstreamDiscovery)
    );
}

#[test]
fn native_proxy_config_rejects_unsupported_proxy_policy_layers() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        auth_request: fluxheim_config::AuthRequestConfig {
            enabled: true,
            url: Some("http://127.0.0.1:3001/auth".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    };
    #[cfg(not(feature = "auth-request"))]
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::AuthRequest)
    );
    #[cfg(feature = "auth-request")]
    assert!(NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).is_ok());

    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        mirror: fluxheim_config::TrafficMirrorConfig {
            enabled: true,
            base_url: Some("http://127.0.0.1:3001".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    };
    #[cfg(not(all(feature = "traffic-mirror", not(feature = "privacy-mode"))))]
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::TrafficMirror)
    );
    #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
    assert!(NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).is_ok());

    let errors = tempfile::tempdir().unwrap();
    std::fs::write(errors.path().join("502.html"), "native error page\n").unwrap();
    let proxy = proxy_config_with_error_page(errors.path().to_path_buf());
    assert!(NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).is_ok());
}

#[test]
fn native_proxy_config_rejects_unsupported_transport_and_accepts_downstream_timeout() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_tcp_keepalive_idle_secs: Some(30),
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy)
    );

    #[cfg(not(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    )))]
    {
        let proxy = fluxheim_config::ProxyConfig {
            upstream: Some("127.0.0.1:3000".to_owned()),
            upstream_tcp_keepalive_idle_secs: Some(30),
            upstream_tcp_keepalive_interval_secs: Some(10),
            upstream_tcp_keepalive_count: Some(3),
            upstream_tcp_user_timeout_ms: Some(15000),
            ..Default::default()
        };
        assert_eq!(
            NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
            Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy)
        );
    }

    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_tcp_keepalive_idle_secs: Some(30),
        upstream_tcp_keepalive_interval_secs: Some(10),
        upstream_tcp_keepalive_count: Some(3),
        upstream_tcp_fast_open: true,
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy)
    );

    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        downstream_read_timeout_secs: Some(1),
        ..Default::default()
    };
    assert!(NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).is_ok());
}

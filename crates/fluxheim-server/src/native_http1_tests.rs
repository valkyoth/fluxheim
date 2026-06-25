use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use fluxheim_cache::{CacheRequestView, request_cache_bypass_reason, selected_cache_range_request};
use fluxheim_config::CacheConfig;
use fluxheim_protocol::Http1Version;

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
use crate::serve_native_http1_openssl_listener;
#[cfg(feature = "tls-rustls-backend")]
use crate::serve_native_http1_rustls_listener;
use crate::{
    DownstreamHttp1Policy, NativeHttp1ConnectionStream, NativeHttp1Error, NativeHttp1GeoContext,
    NativeHttp1Handler, NativeHttp1Request, NativeHttp1Response, serve_native_http1_connection,
    serve_native_http1_listener,
};

async fn spawn_server(
    handler: impl Fn(NativeHttp1Request) -> NativeHttp1Response + Send + Sync + 'static,
) -> std::net::SocketAddr {
    spawn_server_with_policy(DownstreamHttp1Policy::default(), handler).await
}

async fn spawn_server_with_policy(
    policy: DownstreamHttp1Policy,
    handler: impl Fn(NativeHttp1Request) -> NativeHttp1Response + Send + Sync + 'static,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(move |request| {
        let response = handler(request);
        async move { response }
    });
    tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        serve_native_http1_connection(stream, Some(peer_addr), policy, handler)
            .await
            .unwrap();
    });
    addr
}

async fn read_response<S>(stream: &mut S) -> String
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "connection closed before response");
        response.extend_from_slice(&chunk[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            let text = String::from_utf8(response.clone()).unwrap();
            let length = text
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap();
            let head_len = response
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;
            if response.len() >= head_len + length {
                return String::from_utf8(response).unwrap();
            }
        }
    }
}

async fn read_response_head(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "connection closed before response head");
        response.extend_from_slice(&chunk[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            let head_len = response
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;
            return String::from_utf8(response[..head_len].to_vec()).unwrap();
        }
    }
}

fn native_http1_cache_view_request(
    method: &str,
    target: &str,
    headers: Vec<(String, String)>,
) -> NativeHttp1Request {
    NativeHttp1Request {
        method: method.to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: target.to_owned(),
        version: Http1Version::Http11,
        headers,
        body: Vec::new(),
    }
}

#[test]
fn native_http1_request_implements_cache_request_view_for_origin_targets() {
    let request = native_http1_cache_view_request(
        "GET",
        "/assets/logo.png?v=1",
        vec![
            ("cache-control".to_owned(), "no-store".to_owned()),
            ("x-cache-bypass".to_owned(), "1".to_owned()),
        ],
    );
    let cache = CacheConfig {
        bypass_request_headers: vec!["x-cache-bypass".to_owned()],
        ..Default::default()
    };

    assert_eq!(CacheRequestView::method(&request), "GET");
    assert_eq!(CacheRequestView::path(&request), "/assets/logo.png");
    assert_eq!(CacheRequestView::query(&request), Some("v=1"));
    assert!(CacheRequestView::contains_header(&request, "Cache-Control"));
    assert_eq!(
        request_cache_bypass_reason(&request, &cache),
        Some("request-header")
    );
}

#[cfg(feature = "load-balancer")]
#[test]
fn native_http1_request_implements_load_balancer_request_view() {
    let request = native_http1_cache_view_request(
        "GET",
        "/api/items?page=2",
        vec![
            ("X-Hash".to_owned(), "one".to_owned()),
            ("x-hash".to_owned(), "two".to_owned()),
            ("Cookie".to_owned(), "session=abc; shard=blue".to_owned()),
            ("cookie".to_owned(), "other=ignored".to_owned()),
        ],
    );

    assert_eq!(
        fluxheim_load_balancer::LoadBalancerRequestView::uri_key(&request),
        b"/api/items?page=2".to_vec()
    );
    assert_eq!(
        fluxheim_load_balancer::LoadBalancerRequestView::header_values(&request, "x-hash")
            .map(|value| std::str::from_utf8(value)
                .expect("valid header value")
                .to_owned())
            .collect::<Vec<_>>(),
        vec!["one".to_owned(), "two".to_owned()]
    );
    assert_eq!(
        fluxheim_load_balancer::LoadBalancerRequestView::cookie_headers(&request)
            .collect::<Vec<_>>(),
        vec!["session=abc; shard=blue", "other=ignored"]
    );
}

#[cfg(feature = "load-balancer")]
#[test]
fn native_http1_request_drives_load_balancer_header_hash_selection() {
    let balancer = fluxheim_load_balancer::UpstreamLoadBalancer::from_proxy_config(
        &fluxheim_config::ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: fluxheim_config::LoadBalanceConfig {
                selection: fluxheim_config::LoadBalanceSelection::HeaderHash,
                hash_header: Some("x-shard".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .expect("load balancer config")
    .expect("load balancer");
    let first_request = native_http1_cache_view_request(
        "GET",
        "/api/items",
        vec![("x-shard".to_owned(), "tenant-a".to_owned())],
    );
    let second_request = native_http1_cache_view_request(
        "GET",
        "/api/items",
        vec![("X-Shard".to_owned(), "tenant-a".to_owned())],
    );

    let first = balancer
        .select(&first_request, None)
        .expect("first selection");
    let second = balancer
        .select(&second_request, None)
        .expect("second selection");

    assert_eq!(first.address(), second.address());
    assert!(first.authority() == "127.0.0.1:3000" || first.authority() == "127.0.0.1:3001");
}

#[test]
fn native_http1_request_cache_view_handles_absolute_targets_and_duplicate_headers() {
    let request = native_http1_cache_view_request(
        "GET",
        "http://example.test/images/a.webp?size=1",
        vec![
            ("range".to_owned(), "bytes=0-9".to_owned()),
            ("Range".to_owned(), "bytes=10-19".to_owned()),
        ],
    );
    let cache = CacheConfig {
        range: fluxheim_config::CacheRangeConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut ranges = Vec::new();
    CacheRequestView::visit_header_values(&request, "range", &mut |value| {
        ranges.push(value.to_owned());
    });

    assert_eq!(CacheRequestView::path(&request), "/images/a.webp");
    assert_eq!(CacheRequestView::query(&request), Some("size=1"));
    assert_eq!(ranges, ["bytes=0-9", "bytes=10-19"]);
    assert_eq!(selected_cache_range_request(&request, &cache), None);
}

#[cfg(feature = "tls-rustls-backend")]
fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[tokio::test]
async fn native_http1_serves_keep_alive_requests() {
    let addr = spawn_server(|request| {
        NativeHttp1Response::new(200, "OK", format!("{} {}", request.method, request.target))
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(b"GET /one HTTP/1.1\r\nHost: local.test\r\n\r\n")
        .await
        .unwrap();
    let first = read_response(&mut stream).await;
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("GET /one"));

    stream
        .write_all(b"GET /two HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let second = read_response(&mut stream).await;
    assert!(second.contains("Connection: close\r\n"));
    assert!(second.ends_with("GET /two"));
}

#[tokio::test]
async fn native_http1_plain_listener_request_context_defaults_to_none() {
    let addr = spawn_server(|request| {
        assert!(!request.downstream_tls);
        assert_eq!(request.tls_identity, None);
        assert_eq!(request.geo_context, None);
        NativeHttp1Response::new(200, "OK", "context")
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(b"GET /context HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("context"));
}

struct GeoContextTestHandler;

impl NativeHttp1Handler for GeoContextTestHandler {
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            assert_eq!(
                request.geo_context,
                Some(NativeHttp1GeoContext {
                    country_iso: Some("SE".to_owned()),
                    asn: Some(12552),
                })
            );
            NativeHttp1Response::new(200, "OK", "geo-context")
        })
    }

    fn prepare_request_context(&self, request: &mut NativeHttp1Request) {
        request.geo_context = Some(NativeHttp1GeoContext {
            country_iso: Some("SE".to_owned()),
            asn: Some(12552),
        });
    }
}

struct ConnectionTakeoverTestHandler;

impl NativeHttp1Handler for ConnectionTakeoverTestHandler {
    fn handle<'a>(
        &'a self,
        _request: NativeHttp1Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            NativeHttp1Response::new(500, "Internal Server Error", "unexpected buffered response")
        })
    }

    fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        request
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("upgrade") && value == "test")
    }

    fn handle_connection_takeover<'a>(
        &'a self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        mut stream: NativeHttp1ConnectionStream,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), NativeHttp1Error>> + Send + 'a>,
    > {
        Box::pin(async move {
            assert_eq!(request.target, "/takeover");
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Connection: Upgrade\r\n\
                      Upgrade: test\r\n\r\n",
                )
                .await
                .map_err(NativeHttp1Error::Io)?;
            stream.flush().await.map_err(NativeHttp1Error::Io)?;

            let mut payload = prebuffered;
            while payload.len() < 4 {
                let mut byte = [0u8; 1];
                stream
                    .read_exact(&mut byte)
                    .await
                    .map_err(NativeHttp1Error::Io)?;
                payload.push(byte[0]);
            }
            stream
                .write_all(&payload[..4])
                .await
                .map_err(NativeHttp1Error::Io)?;
            stream.flush().await.map_err(NativeHttp1Error::Io)
        })
    }
}

#[tokio::test]
async fn native_http1_handler_can_populate_request_context_before_handling() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        serve_native_http1_connection(
            stream,
            Some(peer_addr),
            DownstreamHttp1Policy::default(),
            Arc::new(GeoContextTestHandler),
        )
        .await
        .unwrap();
    });
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(b"GET /context HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("geo-context"));
}

#[tokio::test]
async fn native_http1_handler_can_take_over_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        serve_native_http1_connection(
            stream,
            Some(peer_addr),
            DownstreamHttp1Policy::default(),
            Arc::new(ConnectionTakeoverTestHandler),
        )
        .await
        .unwrap();
    });
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"GET /takeover HTTP/1.1\r\n\
              Host: local.test\r\n\
              Connection: Upgrade\r\n\
              Upgrade: test\r\n\r\nping",
        )
        .await
        .unwrap();

    let mut response = Vec::new();
    let mut chunk = [0u8; 64];
    loop {
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "connection closed before takeover response");
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
    let echoed_prefix = response[response_head_len..].to_vec();
    let response_head = String::from_utf8(response[..response_head_len].to_vec()).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(response_head.contains("Upgrade: test\r\n"));

    let mut echoed = echoed_prefix;
    while echoed.len() < 4 {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        echoed.push(byte[0]);
    }
    assert_eq!(&echoed[..4], b"ping");
}

#[tokio::test]
async fn native_http10_accepts_missing_host_and_closes_by_default() {
    let addr = spawn_server(|request| {
        assert_eq!(request.version, Http1Version::Http10);
        assert!(
            !request
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("host"))
        );
        NativeHttp1Response::new(200, "OK", request.target)
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(b"GET /http10 HTTP/1.0\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("Connection: close\r\n"));
    assert!(response.ends_with("/http10"));
    let mut buffer = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);
}

#[tokio::test]
async fn native_http10_honors_explicit_keep_alive() {
    let addr = spawn_server(|request| {
        assert_eq!(request.version, Http1Version::Http10);
        NativeHttp1Response::new(200, "OK", request.target)
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(b"GET /one HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
        .await
        .unwrap();
    let first = read_response(&mut stream).await;
    assert!(first.contains("Connection: keep-alive\r\n"));
    assert!(first.ends_with("/one"));

    stream
        .write_all(b"GET /two HTTP/1.0\r\n\r\n")
        .await
        .unwrap();
    let second = read_response(&mut stream).await;
    assert!(second.contains("Connection: close\r\n"));
    assert!(second.ends_with("/two"));
}

#[tokio::test]
async fn native_http1_reads_content_length_body() {
    let addr = spawn_server(|request| {
        NativeHttp1Response::new(200, "OK", format!("{} bytes", request.body.len()))
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"POST /upload HTTP/1.1\r\nHost: local.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("5 bytes"));
}

#[tokio::test]
async fn native_http1_reads_chunked_body() {
    let addr = spawn_server(|request| {
        NativeHttp1Response::new(200, "OK", String::from_utf8(request.body).unwrap())
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"POST /upload HTTP/1.1\r\nHost: local.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("hello"));
}

#[tokio::test]
async fn native_http1_enforces_configured_body_limit() {
    let policy = DownstreamHttp1Policy::from_server_limits(fluxheim_config::ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_request_headers: 32,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(4),
    });
    let addr = spawn_server_with_policy(policy, |_| {
        NativeHttp1Response::new(200, "OK", b"unexpected")
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"POST /upload HTTP/1.1\r\nHost: local.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.ends_with("payload too large\n"));
}

#[tokio::test]
async fn native_http1_owns_response_framing_headers() {
    let addr = spawn_server(|_| {
        NativeHttp1Response::new(200, "OK", b"ok")
            .with_header("Content-Length", "999")
            .with_header("Connection", "close")
            .with_header("Date", "Thu, 01 Jan 1970 00:00:00 GMT")
            .with_header("X-Test", "kept")
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert_eq!(response.matches("Content-Length:").count(), 1);
    assert_eq!(response.matches("Date:").count(), 1);
    assert!(response.contains("Content-Length: 2\r\n"));
    assert!(response.contains("Connection: close\r\n"));
    assert!(response.contains("X-Test: kept\r\n"));
}

#[tokio::test]
async fn native_http1_sanitizes_response_reason_phrase() {
    let addr =
        spawn_server(|_| NativeHttp1Response::new(200, "OK\rX-Injected: yes\u{7f}\u{80}", b"ok"))
            .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OKX-Injected: yes\r\n"));
    assert!(!response.contains("\rX-Injected: yes\r\n"));
}

#[tokio::test]
async fn native_http1_can_advertise_explicit_response_length() {
    let addr = spawn_server(|_| {
        NativeHttp1Response::new(304, "Not Modified", Vec::new()).with_content_length(123)
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response_head(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 304 Not Modified\r\n"));
    assert!(response.contains("Content-Length: 123\r\n"));
    assert!(response.ends_with("\r\n\r\n"));
}

#[tokio::test]
async fn native_http1_threads_peer_addr_to_handler() {
    let addr = spawn_server(|request| {
        NativeHttp1Response::new(200, "OK", request.peer_addr.is_some().to_string())
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.ends_with("true"));
}

#[tokio::test]
async fn native_http1_times_out_slow_request_head() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(|_| async { NativeHttp1Response::new(200, "OK", b"unexpected") });
    let join = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        serve_native_http1_connection(
            stream,
            Some(peer_addr),
            DownstreamHttp1Policy::default().with_request_head_timeout(Duration::from_millis(10)),
            handler,
        )
        .await
    });

    let _stream = TcpStream::connect(addr).await.unwrap();
    let error = join.await.unwrap().unwrap_err();

    assert!(matches!(
        error,
        crate::NativeHttp1Error::Io(ref io_error)
            if io_error.kind() == std::io::ErrorKind::TimedOut
    ));
}

#[tokio::test]
async fn native_http1_times_out_slow_request_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(|_| async { NativeHttp1Response::new(200, "OK", b"unexpected") });
    let join = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        serve_native_http1_connection(
            stream,
            Some(peer_addr),
            DownstreamHttp1Policy::default().with_request_body_timeout(Duration::from_millis(10)),
            handler,
        )
        .await
    });
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"POST / HTTP/1.1\r\nHost: local.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    join.await.unwrap().unwrap();
    assert!(response.starts_with("HTTP/1.1 408 Request Timeout\r\n"));
    assert!(response.ends_with("request timeout\n"));
}

#[tokio::test]
async fn native_http1_listener_drops_connections_over_budget() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handler = Arc::new(|_| async { NativeHttp1Response::new(200, "OK", b"unexpected") });
    let join = tokio::spawn(async move {
        serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default()
                .with_max_connections(1)
                .with_request_head_timeout(Duration::from_secs(5)),
            handler,
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
        .unwrap();
    });
    let _held_stream = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buffer = [0u8; 1];
    let read_result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer))
        .await
        .unwrap();
    match read_result {
        Ok(read) => assert_eq!(read, 0),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(error) => panic!("unexpected read error: {error}"),
    }

    shutdown_tx.send(()).unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn native_http1_listener_serves_until_shutdown() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handler =
        Arc::new(|_| async { NativeHttp1Response::new(200, "OK", b"listener".as_slice()) });
    let join = tokio::spawn(async move {
        serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default(),
            handler,
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
        .unwrap();
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    assert!(response.ends_with("listener"));

    shutdown_tx.send(()).unwrap();
    join.await.unwrap();
}

#[cfg(feature = "tls-rustls-backend")]
#[tokio::test]
async fn native_http1_rustls_listener_serves_request() {
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
    use rustls::{ClientConfig, RootCertStore, server::WebPkiClientVerifier};
    use sha2::{Digest, Sha256};
    use tokio_rustls::TlsConnector;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_pem = certificate.pem();
    let key_pem = key.serialize_pem();
    let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let server_private_key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let client_private_key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let expected_client_cert_sha256 = hex_lower(&Sha256::digest(certs[0].as_ref()));
    let mut client_auth_roots = RootCertStore::empty();
    client_auth_roots.add(certs[0].clone()).unwrap();
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
        .build()
        .unwrap();
    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs.clone(), server_private_key)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs.clone(), client_private_key)
        .unwrap();
    let connector = TlsConnector::from(Arc::new(client_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handler = Arc::new(move |request: NativeHttp1Request| {
        let expected_client_cert_sha256 = expected_client_cert_sha256.clone();
        async move {
            assert_eq!(request.target, "/secure");
            assert!(request.downstream_tls);
            let identity = request.tls_identity.expect("TLS identity");
            assert!(identity.version.is_some());
            assert!(identity.cipher.is_some());
            assert_eq!(identity.cert_sha256, Some(expected_client_cert_sha256));
            NativeHttp1Response::new(200, "OK", b"native tls listener".as_slice())
        }
    });
    let join = tokio::spawn(async move {
        serve_native_http1_rustls_listener(
            listener,
            DownstreamHttp1Policy::default(),
            Arc::new(server_config),
            handler,
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
        .unwrap();
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost".to_owned()).unwrap();
    let mut stream = connector.connect(server_name, tcp).await.unwrap();
    stream
        .write_all(b"GET /secure HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("native tls listener"));
    shutdown_tx.send(()).unwrap();
    join.await.unwrap();
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
#[tokio::test]
async fn native_http1_openssl_listener_serves_request() {
    use openssl::pkey::PKey;
    use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
    use openssl::x509::{X509, store::X509StoreBuilder};
    use rcgen::{CertificateParams, KeyPair};
    use tokio_openssl::SslStream;

    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_pem = certificate.pem();
    let key_pem = key.serialize_pem();
    let certs = X509::stack_from_pem(cert_pem.as_bytes()).unwrap();
    let (leaf, intermediates) = certs.split_first().unwrap();
    let private_key = PKey::private_key_from_pem(key_pem.as_bytes()).unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls_server()).unwrap();
    acceptor.set_certificate(leaf).unwrap();
    for certificate in intermediates {
        acceptor.add_extra_chain_cert(certificate.clone()).unwrap();
    }
    acceptor.set_private_key(&private_key).unwrap();

    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(leaf.clone()).unwrap();
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_cert_store(store.build());
    connector.set_verify(SslVerifyMode::PEER);
    let connector = connector.build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handler = Arc::new(|request: NativeHttp1Request| async move {
        assert_eq!(request.target, "/secure");
        assert!(request.downstream_tls);
        let identity = request.tls_identity.expect("TLS identity");
        assert!(identity.version.is_some());
        assert!(identity.cipher.is_some());
        assert_eq!(identity.cert_sha256, None);
        NativeHttp1Response::new(200, "OK", b"native openssl listener".as_slice())
    });
    let join = tokio::spawn(async move {
        serve_native_http1_openssl_listener(
            listener,
            DownstreamHttp1Policy::default(),
            Arc::new(acceptor.build()),
            handler,
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
        .unwrap();
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let ssl = connector
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap();
    let mut stream = SslStream::new(ssl, tcp).unwrap();
    std::pin::Pin::new(&mut stream).connect().await.unwrap();
    stream
        .write_all(b"GET /secure HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("native openssl listener"));
    shutdown_tx.send(()).unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn native_http1_rejects_missing_http11_host() {
    let addr = spawn_server(|_| NativeHttp1Response::new(200, "OK", b"unexpected")).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("bad request\n"));
}

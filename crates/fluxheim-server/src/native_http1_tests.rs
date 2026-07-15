use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use fluxheim_protocol::Http1Version;

use crate::{
    DownstreamHttp1Policy, NativeHttp1ConnectionStream, NativeHttp1Error, NativeHttp1GeoContext,
    NativeHttp1Handler, NativeHttp1Request, NativeHttp1Response, NativeRequestBodyBudget,
    serve_native_http1_connection,
};

struct HoldingBodyBudgetHandler {
    budget: NativeRequestBodyBudget,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

struct PinningBodyBudgetHandler {
    pinned: Arc<HoldingBodyBudgetHandler>,
}

struct RetainingBodyBudgetHandler {
    budget: NativeRequestBodyBudget,
    retained: std::sync::Mutex<Option<crate::NativeHttp1RequestBody>>,
}

impl NativeHttp1Handler for PinningBodyBudgetHandler {
    fn pin_request_handler(&self) -> Option<Arc<dyn NativeHttp1Handler>> {
        Some(self.pinned.clone())
    }

    fn handle<'a>(
        &'a self,
        _request: NativeHttp1Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async { NativeHttp1Response::new(500, "Internal Server Error", b"unpinned\n") })
    }
}

impl NativeHttp1Handler for HoldingBodyBudgetHandler {
    fn request_body_budget(&self) -> NativeRequestBodyBudget {
        self.budget.clone()
    }

    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            drop(request);
            NativeHttp1Response::new(200, "OK", b"ok\n").close_connection()
        })
    }
}

impl NativeHttp1Handler for RetainingBodyBudgetHandler {
    fn request_body_budget(&self) -> NativeRequestBodyBudget {
        self.budget.clone()
    }

    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            *self.retained.lock().unwrap() = Some(request.body);
            NativeHttp1Response::new(200, "OK", b"retained\n").close_connection()
        })
    }
}

pub(crate) async fn spawn_server(
    handler: impl Fn(NativeHttp1Request) -> NativeHttp1Response + Send + Sync + 'static,
) -> std::net::SocketAddr {
    spawn_server_with_policy(DownstreamHttp1Policy::default(), handler).await
}

pub(crate) async fn spawn_server_with_policy(
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

pub(crate) async fn read_response<S>(stream: &mut S) -> String
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

#[tokio::test]
async fn native_http1_returns_431_when_request_header_count_exceeds_limit() {
    let policy = DownstreamHttp1Policy::from_server_limits(fluxheim_config::ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(2048),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(512),
        max_request_headers: 1,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(16),
        max_buffered_request_body_bytes: fluxheim_config::ByteSize::from_bytes(16),
    });
    let addr = spawn_server_with_policy(policy, |_| {
        NativeHttp1Response::new(200, "OK", b"unexpected")
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: local.test\r\nX-Extra: value\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"));
    assert!(response.ends_with("request header fields too large\n"));
}

#[tokio::test]
async fn native_http1_rejects_aggregate_request_body_overcommit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handler = Arc::new(HoldingBodyBudgetHandler {
        budget: NativeRequestBodyBudget::new(64 * 1024),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let server_handler = Arc::new(PinningBodyBudgetHandler {
        pinned: handler.clone(),
    });
    let server = tokio::spawn(async move {
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let (stream, peer) = listener.accept().await.unwrap();
            let handler = server_handler.clone();
            tasks.push(tokio::spawn(serve_native_http1_connection(
                stream,
                Some(peer),
                DownstreamHttp1Policy::default(),
                handler,
            )));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
    });

    let mut first = TcpStream::connect(address).await.unwrap();
    first
        .write_all(
            b"POST /first HTTP/1.1\r\nHost: local.test\r\nContent-Length: 1\r\nConnection: close\r\n\r\na",
        )
        .await
        .unwrap();
    handler.entered.notified().await;

    let mut second = TcpStream::connect(address).await.unwrap();
    second
        .write_all(
            b"POST /second HTTP/1.1\r\nHost: local.test\r\nContent-Length: 1\r\nConnection: close\r\n\r\nb",
        )
        .await
        .unwrap();
    let response = read_response(&mut second).await;
    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.contains("retry-after: 1\r\n"));

    handler.release.notify_one();
    assert!(
        read_response(&mut first)
            .await
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    server.await.unwrap();
}

#[tokio::test]
async fn native_http1_body_retains_admission_after_handler_returns() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let budget = NativeRequestBodyBudget::new(64 * 1024);
    let handler = Arc::new(RetainingBodyBudgetHandler {
        budget: budget.clone(),
        retained: std::sync::Mutex::new(None),
    });
    let server_handler = handler.clone();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        serve_native_http1_connection(
            stream,
            Some(peer),
            DownstreamHttp1Policy::default(),
            server_handler,
        )
        .await
        .unwrap();
    });
    let mut stream = TcpStream::connect(address).await.unwrap();

    stream
        .write_all(
            b"POST /retain HTTP/1.1\r\nHost: local.test\r\nContent-Length: 1\r\nConnection: close\r\n\r\na",
        )
        .await
        .unwrap();
    assert!(
        read_response(&mut stream)
            .await
            .starts_with("HTTP/1.1 200 OK\r\n")
    );
    server.await.unwrap();

    assert!(budget.reserve(1).await.is_err());
    handler.retained.lock().unwrap().take();
    assert!(budget.reserve(1).await.is_ok());
}

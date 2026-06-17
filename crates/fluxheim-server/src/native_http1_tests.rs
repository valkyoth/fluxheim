use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use crate::{
    DownstreamHttp1Policy, NativeHttp1Request, NativeHttp1Response, serve_native_http1_connection,
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

async fn read_response(stream: &mut TcpStream) -> String {
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
    let error = join.await.unwrap().unwrap_err();

    assert!(matches!(
        error,
        crate::NativeHttp1Error::Io(ref io_error)
            if io_error.kind() == std::io::ErrorKind::TimedOut
    ));
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

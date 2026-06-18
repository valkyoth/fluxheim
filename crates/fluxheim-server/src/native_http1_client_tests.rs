use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{NativeHttp1Error, NativeHttp1Request, NativeHttp1Upstream};

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

async fn read_request_head(stream: &mut TcpStream) -> Vec<u8> {
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
    request
}

fn request() -> NativeHttp1Request {
    NativeHttp1Request {
        method: "GET".to_owned(),
        peer_addr: None,
        target: "/hello?name=fluxheim".to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![
            ("Host".to_owned(), "example.test".to_owned()),
            ("Accept".to_owned(), "text/plain".to_owned()),
        ],
        body: Vec::new(),
    }
}

#[tokio::test]
async fn native_upstream_forwards_request_and_reads_content_length_response() {
    let addr = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /hello?name=fluxheim HTTP/1.1\r\n"));
        assert!(request.contains("host: example.test\r\n"));
        assert!(request.contains("Accept: text/plain\r\n"));
        stream
            .write_all(b"HTTP/1.1 201 Created\r\ncontent-length: 7\r\nx-test: yes\r\n\r\ncreated")
            .await
            .unwrap();
    })
    .await;

    let response = NativeHttp1Upstream::new(addr.to_string())
        .send(&request())
        .await
        .unwrap();

    assert_eq!(response.status(), 201);
    assert_eq!(response.reason(), "Created");
    assert_eq!(response.body(), b"created");
    assert_eq!(response.content_length(), Some(7));
    assert!(
        response
            .headers()
            .iter()
            .any(|(name, value)| name == "x-test" && value == "yes")
    );
}

#[tokio::test]
async fn native_upstream_reuses_safe_content_length_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let first = String::from_utf8(read_request_head(&mut stream).await).unwrap();
        assert!(first.contains("connection: keep-alive\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nfirst")
            .await
            .unwrap();

        let second = String::from_utf8(read_request_head(&mut stream).await).unwrap();
        assert!(second.contains("connection: keep-alive\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nsecond")
            .await
            .unwrap();
    });

    let upstream = NativeHttp1Upstream::new(addr.to_string()).with_pool_max_idle(1);

    let response = upstream.send(&request()).await.unwrap();
    assert_eq!(response.body(), b"first");
    assert_eq!(upstream.idle_connection_count().await, 1);

    let response = upstream.send(&request()).await.unwrap();
    assert_eq!(response.body(), b"second");
    assert_eq!(upstream.idle_connection_count().await, 1);
}

#[tokio::test]
async fn native_upstream_does_not_pool_connection_close_response() {
    let addr = upstream(|_, mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 4\r\n\r\nstop")
            .await
            .unwrap();
    })
    .await;

    let upstream = NativeHttp1Upstream::new(addr.to_string()).with_pool_max_idle(1);
    let response = upstream.send(&request()).await.unwrap();

    assert_eq!(response.body(), b"stop");
    assert_eq!(upstream.idle_connection_count().await, 0);
}

#[tokio::test]
async fn native_upstream_expires_idle_pool_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_for_task = Arc::clone(&accepted);
    tokio::spawn(async move {
        for body in [b"first".as_slice(), b"fresh".as_slice()] {
            let (mut stream, _) = listener.accept().await.unwrap();
            accepted_for_task.fetch_add(1, Ordering::AcqRel);
            let _request = read_request_head(&mut stream).await;
            stream
                .write_all(
                    format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len()).as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(body).await.unwrap();
        }
    });

    let upstream = NativeHttp1Upstream::new(addr.to_string())
        .with_pool_idle_timeout(Some(Duration::from_millis(1)))
        .with_pool_max_idle(1);

    let response = upstream.send(&request()).await.unwrap();
    assert_eq!(response.body(), b"first");
    assert_eq!(upstream.idle_connection_count().await, 1);

    tokio::time::sleep(Duration::from_millis(5)).await;

    let response = upstream.send(&request()).await.unwrap();
    assert_eq!(response.body(), b"fresh");
    assert_eq!(accepted.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn native_upstream_decodes_chunked_response_and_strips_hop_by_hop_headers() {
    let addr = upstream(|_, mut stream| async move {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-length: 999\r\nconnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            )
            .await
            .unwrap();
    })
    .await;

    let response = NativeHttp1Upstream::new(addr.to_string())
        .send(&request())
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"hello world");
    assert!(response.headers().iter().all(|(name, _)| {
        !name.eq_ignore_ascii_case("transfer-encoding")
            && !name.eq_ignore_ascii_case("connection")
            && !name.eq_ignore_ascii_case("content-length")
    }));
}

#[tokio::test]
async fn native_upstream_reads_close_delimited_response() {
    let addr = upstream(|_, mut stream| async move {
        stream
            .write_all(b"HTTP/1.0 200 OK\r\nserver: test\r\n\r\nclose body")
            .await
            .unwrap();
    })
    .await;

    let response = NativeHttp1Upstream::new(addr.to_string())
        .send(&request())
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"close body");
    assert_eq!(response.content_length(), None);
}

#[tokio::test]
async fn native_upstream_rejects_oversized_close_delimited_response() {
    let addr = upstream(|_, mut stream| async move {
        stream
            .write_all(b"HTTP/1.0 200 OK\r\nserver: test\r\n\r\n12345")
            .await
            .unwrap();
    })
    .await;

    let error = NativeHttp1Upstream::new(addr.to_string())
        .with_max_body_bytes(4)
        .send(&request())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        NativeHttp1Error::Parse(fluxheim_protocol::Http1ParseError::BodyTooLarge)
    ));
}

#[tokio::test]
async fn native_upstream_accepts_exact_limit_close_delimited_response() {
    let addr = upstream(|_, mut stream| async move {
        stream
            .write_all(b"HTTP/1.0 200 OK\r\nserver: test\r\n\r\n1234")
            .await
            .unwrap();
    })
    .await;

    let response = NativeHttp1Upstream::new(addr.to_string())
        .with_max_body_bytes(4)
        .send(&request())
        .await
        .unwrap();

    assert_eq!(response.body(), b"1234");
}

#[tokio::test]
async fn native_upstream_strips_request_hop_by_hop_headers() {
    let addr = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(!request.to_ascii_lowercase().contains("x-hop:"));
        assert!(!request.to_ascii_lowercase().contains("upgrade:"));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 99\r\n\r\n")
            .await
            .unwrap();
    })
    .await;

    let mut request = request();
    request
        .headers
        .push(("Connection".to_owned(), "x-hop, upgrade".to_owned()));
    request
        .headers
        .push(("X-Hop".to_owned(), "drop".to_owned()));
    request
        .headers
        .push(("Upgrade".to_owned(), "websocket".to_owned()));

    let response = NativeHttp1Upstream::new(addr.to_string())
        .send(&request)
        .await
        .unwrap();

    assert_eq!(response.status(), 204);
    assert_eq!(response.body(), b"");
}

#[tokio::test]
async fn native_upstream_adds_owned_proxy_headers() {
    let addr = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains("via: 1.0 prior, 1.1 fluxheim\r\n"));
        assert!(request.contains("x-forwarded-for: 198.51.100.17\r\n"));
        assert!(!request.contains("x-forwarded-for: 192.0.2.9\r\n"));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    })
    .await;

    let mut request = request();
    request.peer_addr = Some(SocketAddr::from(([198, 51, 100, 17], 49000)));
    request
        .headers
        .push(("Via".to_owned(), "1.0 prior".to_owned()));
    request
        .headers
        .push(("X-Forwarded-For".to_owned(), "192.0.2.9".to_owned()));

    let response = NativeHttp1Upstream::new(addr.to_string())
        .send(&request)
        .await
        .unwrap();

    assert_eq!(response.status(), 204);
}

#[cfg(feature = "privacy-mode")]
#[tokio::test]
async fn privacy_mode_native_upstream_does_not_add_forwarded_for() {
    let addr = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(!request.to_ascii_lowercase().contains("x-forwarded-for:"));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    })
    .await;

    let mut request = request();
    request.peer_addr = Some(SocketAddr::from(([198, 51, 100, 17], 49000)));

    let response = NativeHttp1Upstream::new(addr.to_string())
        .send(&request)
        .await
        .unwrap();

    assert_eq!(response.status(), 204);
}

#[tokio::test]
async fn native_upstream_rejects_invalid_forwarded_request_header() {
    let (client, _peer) = tokio::io::duplex(4096);
    let mut request = request();
    request
        .headers
        .push(("X-Bad".to_owned(), "bad\u{7f}".to_owned()));

    let error = NativeHttp1Upstream::new("127.0.0.1:3000")
        .send_on_stream(client, &request)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        NativeHttp1Error::Parse(fluxheim_protocol::Http1ParseError::InvalidHeaderValue)
    ));
}

#[tokio::test]
async fn native_upstream_rejects_invalid_forwarded_host_header() {
    let (client, _peer) = tokio::io::duplex(4096);
    let mut request = request();
    request.headers[0] = ("Host".to_owned(), "bad\u{7f}".to_owned());

    let error = NativeHttp1Upstream::new("127.0.0.1:3000")
        .send_on_stream(client, &request)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        NativeHttp1Error::Parse(fluxheim_protocol::Http1ParseError::InvalidHeaderValue)
    ));
}

#[tokio::test]
async fn native_upstream_read_timeout_is_bounded() {
    let addr = upstream(|_, stream| async move {
        let _hold_open = stream;
        tokio::time::sleep(Duration::from_secs(5)).await;
    })
    .await;

    let error = NativeHttp1Upstream::new(addr.to_string())
        .with_read_timeout(Duration::from_millis(25))
        .send(&request())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        NativeHttp1Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut
    ));
}

#[tokio::test]
async fn native_upstream_write_timeout_is_bounded() {
    let (client, _blocked_peer) = tokio::io::duplex(1);
    let mut request = request();
    request.method = "POST".to_owned();
    request.body = vec![b'a'; 1024 * 1024];

    let error = NativeHttp1Upstream::new("127.0.0.1:3000")
        .with_write_timeout(Duration::from_millis(25))
        .send_on_stream(client, &request)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        NativeHttp1Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut
    ));
}

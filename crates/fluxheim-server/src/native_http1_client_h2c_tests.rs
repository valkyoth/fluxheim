use bytes::Bytes;
use http::Response;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::native_http1_client_tests::request;
use crate::native_http1_test_utils::read_request_head;
use crate::{DownstreamHttp2Policy, NativeHttp1Upstream};

#[tokio::test]
async fn native_upstream_uses_explicit_h2c_upgrade_for_mixed_plaintext_origin() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let upgrade = String::from_utf8(read_request_head(&mut stream).await).unwrap();
        assert!(upgrade.starts_with("OPTIONS * HTTP/1.1\r\n"));
        assert!(upgrade.contains("Upgrade: h2c\r\n"));
        assert!(upgrade.contains("HTTP2-Settings: "));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: h2c\r\n\
                  \r\n",
            )
            .await
            .unwrap();

        let mut h2 = h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = h2.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.uri().path(), "/hello");
        assert_eq!(request.uri().query(), Some("name=fluxheim"));
        let response = Response::builder()
            .status(200)
            .header("x-upstream-protocol", "h2c")
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        send.send_data(Bytes::from_static(b"native h2c"), true)
            .unwrap();
        h2.graceful_shutdown();
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|context| h2.poll_closed(context)),
        )
        .await;
    });

    let response = NativeHttp1Upstream::new(addr.to_string())
        .with_http1_and_http2_policy(DownstreamHttp2Policy::default())
        .with_h2c_upgrade(true)
        .send(&mut request())
        .await;
    server.await.unwrap();
    let response = response.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"native h2c");
    assert!(response.headers().iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("x-upstream-protocol") && value == "h2c"
    }));
}

#[tokio::test]
async fn native_upstream_falls_back_when_explicit_h2c_upgrade_is_not_accepted() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut probe, _) = listener.accept().await.unwrap();
        let upgrade = String::from_utf8(read_request_head(&mut probe).await).unwrap();
        assert!(upgrade.starts_with("OPTIONS * HTTP/1.1\r\n"));
        probe
            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
        drop(probe);

        let (mut fallback, _) = listener.accept().await.unwrap();
        let request = String::from_utf8(read_request_head(&mut fallback).await).unwrap();
        assert!(request.starts_with("GET /hello?name=fluxheim HTTP/1.1\r\n"));
        fallback
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 14\r\n\r\nhttp1 fallback")
            .await
            .unwrap();
    });

    let response = NativeHttp1Upstream::new(addr.to_string())
        .with_http1_and_http2_policy(DownstreamHttp2Policy::default())
        .with_h2c_upgrade(true)
        .send(&mut request())
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"http1 fallback");
}

#[tokio::test]
async fn native_upstream_preserves_body_until_h2c_fallback_is_selected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut probe, _) = listener.accept().await.unwrap();
        let upgrade = String::from_utf8(read_request_head(&mut probe).await).unwrap();
        assert!(upgrade.starts_with("OPTIONS * HTTP/1.1\r\n"));
        probe
            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
        drop(probe);

        let (mut fallback, _) = listener.accept().await.unwrap();
        let received = read_request_head(&mut fallback).await;
        let head_end = received
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let head = String::from_utf8(received[..head_end].to_vec()).unwrap();
        assert!(head.starts_with("POST /hello?name=fluxheim HTTP/1.1\r\n"));
        assert!(head.contains("content-length: 13\r\n"));
        let mut body = received[head_end..].to_vec();
        let remaining = 13usize.saturating_sub(body.len());
        let mut tail = vec![0u8; remaining];
        fallback.read_exact(&mut tail).await.unwrap();
        body.extend_from_slice(&tail);
        assert_eq!(body, b"fallback body");
        fallback
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let mut request = request();
    request.method = "POST".to_owned();
    request
        .headers
        .push(("content-length".to_owned(), "13".to_owned()));
    request.body = crate::NativeHttp1RequestBody::from_vec(b"fallback body".to_vec());

    let response = NativeHttp1Upstream::new(addr.to_string())
        .with_http1_and_http2_policy(DownstreamHttp2Policy::default())
        .with_h2c_upgrade(true)
        .send(&mut request)
        .await
        .unwrap();
    server.await.unwrap();

    assert_eq!(response.status(), 204);
    assert_eq!(request.body.as_ref(), b"fallback body");
}

#[tokio::test]
async fn native_upstream_falls_back_when_explicit_h2c_upgrade_connection_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut probe, _) = listener.accept().await.unwrap();
        let upgrade = String::from_utf8(read_request_head(&mut probe).await).unwrap();
        assert!(upgrade.starts_with("OPTIONS * HTTP/1.1\r\n"));
        drop(probe);

        let (mut fallback, _) = listener.accept().await.unwrap();
        let request = String::from_utf8(read_request_head(&mut fallback).await).unwrap();
        assert!(request.starts_with("GET /hello?name=fluxheim HTTP/1.1\r\n"));
        fallback
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 17\r\n\r\nclosed then http1")
            .await
            .unwrap();
    });

    let response = NativeHttp1Upstream::new(addr.to_string())
        .with_http1_and_http2_policy(DownstreamHttp2Policy::default())
        .with_h2c_upgrade(true)
        .send(&mut request())
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"closed then http1");
}

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::native_http1_client_tests::{request, upstream};
use crate::{NativeHttp1Error, NativeHttp1Upstream};

#[cfg(not(feature = "privacy-mode"))]
#[tokio::test]
async fn native_upstream_appends_owned_via_header() {
    let addr = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains("via: 1.0 prior, 1.1 fluxheim\r\n"));
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
    request.body = zeroize::Zeroizing::new(vec![b'a'; 1024 * 1024]);

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

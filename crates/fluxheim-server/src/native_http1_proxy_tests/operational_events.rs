use super::*;
use fluxheim_observability::event_test_support::Capture;

#[tokio::test]
async fn operational_dns_failure_is_private_and_returns_bad_gateway() {
    let capture = Capture::start();
    // Invalid port fails name resolution locally without depending on public DNS.
    let proxy = proxy_listener_for(NativeHttp1Proxy::new(NativeHttp1Upstream::new(
        "SECRET-CANARY:invalid",
    )))
    .await;
    let response = downstream_get(proxy, "/SECRET-CANARY?token=SECRET-CANARY").await;
    assert!(response.starts_with("HTTP/1.1 502"));
    assert!(response.ends_with("bad gateway\n"));
    capture.assert_reason("dns", 1);
    assert!(
        capture
            .events()
            .iter()
            .all(|event| !event.to_string().contains("SECRET-CANARY"))
    );
}

#[tokio::test]
async fn operational_refused_connection_is_not_a_protocol_error() {
    let capture = Capture::start();
    // Keep the port reserved without listening, so another test cannot take it.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let proxy = proxy_listener(socket.local_addr().unwrap()).await;
    let response = downstream_get(proxy, "/").await;
    assert!(response.starts_with("HTTP/1.1 502"));
    assert!(response.ends_with("bad gateway\n"));
    capture.assert_reason("connection_refused", 1);
    capture.assert_reason("upstream_protocol", 0);
}

#[tokio::test]
async fn operational_blocked_origin_write_times_out_once() {
    let capture = Capture::start();
    let (stream, _held_peer) = tokio::io::duplex(1);
    let upstream =
        NativeHttp1Upstream::new("private.test:80").with_write_timeout(Duration::from_millis(10));
    let error = upstream
        .send_on_stream(stream, &crate::native_http1_client_tests::request())
        .await
        .unwrap_err();
    assert!(
        matches!(error, crate::NativeHttp1Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut)
    );
    capture.assert_reason("write_timeout", 1);
    capture.assert_reason("upstream_protocol", 0);
}

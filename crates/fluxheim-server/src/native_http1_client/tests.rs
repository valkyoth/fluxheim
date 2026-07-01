use super::http2::{
    h2c_upgrade_error_can_fallback, h2c_upgrade_settings_header, native_http2_error,
    native_http2_response_to_http1, native_http2_upstream_request,
};
use super::request::{upstream_owned_header_for_request, write_websocket_upgrade_request};
use super::upgrade::{
    validate_switching_protocols_response, websocket_downstream_upgrade_response_head,
};
use crate::native_http1_upstream_response::parsed_upstream_response_head;
use crate::{
    DownstreamHttp2Policy, NativeHttp1Error, NativeHttp1Request, NativeHttp2StackError,
    NativeHttp2UpstreamResponse,
};

#[test]
fn h2c_settings_header_uses_url_safe_unpadded_base64() {
    let settings = h2c_upgrade_settings_header(DownstreamHttp2Policy::default());

    assert!(!settings.is_empty());
    assert!(!settings.contains('='));
    assert!(
        settings
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    );
}

#[test]
fn upstream_request_filter_strips_peer_fill_internal_headers_only_for_normal_requests() {
    let normal = NativeHttp1Request {
        method: "GET".to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: "/".to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: Vec::new(),
        body: zeroize::Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    };
    let peer_fill = NativeHttp1Request {
        headers: vec![("x-fluxheim-peer-fill".to_owned(), "1".to_owned())],
        ..normal.clone()
    };

    for name in [
        "x-fluxheim-peer-fill",
        "x-fluxheim-peer-fill-nonce",
        "x-fluxheim-peer-fill-request-signature",
        "x-fluxheim-peer-fill-response-signature",
    ] {
        assert!(upstream_owned_header_for_request(name, &normal));
        assert!(!upstream_owned_header_for_request(name, &peer_fill));
    }
}

#[test]
fn response_capacity_closed_does_not_trigger_h2c_fallback() {
    let error = native_http2_error(NativeHttp2StackError::ResponseCapacityClosed);

    assert!(!h2c_upgrade_error_can_fallback(&error));
    match error {
        NativeHttp1Error::Io(error) => assert_eq!(error.kind(), std::io::ErrorKind::Other),
        other => panic!("expected native HTTP/2 error to map to IO error, got {other:?}"),
    }
}

#[test]
fn switching_protocols_validator_accepts_expected_upgrade_token() {
    validate_switching_protocols_response(
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c, websocket\r\n\r\n",
        fluxheim_protocol::Http1HeadLimits::default(),
        "websocket",
        "upgrade rejected",
        "missing upgrade",
    )
    .unwrap();
}

#[test]
fn switching_protocols_validator_rejects_missing_upgrade_token() {
    let error = validate_switching_protocols_response(
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\n\r\n",
        fluxheim_protocol::Http1HeadLimits::default(),
        "websocket",
        "upgrade rejected",
        "missing upgrade",
    )
    .unwrap_err();

    assert!(error.to_string().contains("missing upgrade"));
}

#[test]
fn switching_protocols_validator_rejects_non_101_status() {
    let error = validate_switching_protocols_response(
        b"HTTP/1.1 200 OK\r\nUpgrade: websocket\r\n\r\n",
        fluxheim_protocol::Http1HeadLimits::default(),
        "websocket",
        "upgrade rejected",
        "missing upgrade",
    )
    .unwrap_err();

    assert!(error.to_string().contains("upgrade rejected"));
}

#[tokio::test]
async fn websocket_upgrade_request_strips_hop_by_hop_headers() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let mut request = NativeHttp1Request {
        method: "GET".to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: "/socket".to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![
            ("host".to_owned(), "client.test".to_owned()),
            ("connection".to_owned(), "Upgrade, x-secret-hop".to_owned()),
            ("upgrade".to_owned(), "websocket".to_owned()),
            ("proxy-authorization".to_owned(), "Basic secret".to_owned()),
            ("keep-alive".to_owned(), "timeout=5".to_owned()),
            ("x-secret-hop".to_owned(), "remove-me".to_owned()),
            ("sec-websocket-key".to_owned(), "abc".to_owned()),
        ],
        body: zeroize::Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    };
    request
        .headers
        .push(("x-keep".to_owned(), "yes".to_owned()));

    let writer = tokio::spawn(async move {
        write_websocket_upgrade_request(&mut client, "origin.test", &request)
            .await
            .unwrap();
    });
    let mut bytes = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut server, &mut bytes)
        .await
        .unwrap();
    writer.await.unwrap();
    let request = String::from_utf8(bytes).unwrap();

    assert!(request.contains("host: client.test\r\n"));
    assert!(!request.contains("host: origin.test\r\n"));
    assert!(request.contains("connection: Upgrade\r\n"));
    assert!(request.contains("upgrade: websocket\r\n"));
    assert!(request.contains("sec-websocket-key: abc\r\n"));
    assert!(request.contains("x-keep: yes\r\n"));
    assert!(!request.contains("proxy-authorization:"));
    assert!(!request.contains("keep-alive:"));
    assert!(!request.contains("x-secret-hop:"));
}

#[test]
fn websocket_downstream_upgrade_response_strips_untrusted_headers() {
    let head = parsed_upstream_response_head(
        b"HTTP/1.1 101 Switching Protocols\r\n\
          Connection: upgrade\r\n\
          Upgrade: websocket\r\n\
          Sec-WebSocket-Accept: abc\r\n\
          Sec-WebSocket-Protocol: chat\r\n\
          Set-Cookie: sid=leak\r\n\
          Server: origin\r\n\
          X-Internal: secret\r\n\r\n",
        fluxheim_protocol::Http1HeadLimits::default(),
    )
    .unwrap();

    let response = websocket_downstream_upgrade_response_head(&head).unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(response.contains("connection: Upgrade\r\n"));
    assert!(response.contains("upgrade: websocket\r\n"));
    assert!(response.contains("sec-websocket-accept: abc\r\n"));
    assert!(response.contains("sec-websocket-protocol: chat\r\n"));
    assert!(!response.contains("Set-Cookie"));
    assert!(!response.contains("Server:"));
    assert!(!response.contains("X-Internal"));
}

#[test]
fn h2_response_conversion_strips_hop_by_hop_headers() {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::CONTENT_LENGTH, "2".parse().unwrap());
    headers.insert(http::header::CONNECTION, "close".parse().unwrap());
    headers.insert(
        http::header::DATE,
        "Tue, 23 Jun 2026 00:00:00 GMT".parse().unwrap(),
    );
    headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
    headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
    headers.insert("keep-alive", "timeout=5".parse().unwrap());
    headers.insert("proxy-connection", "keep-alive".parse().unwrap());
    headers.insert("te", "trailers".parse().unwrap());
    headers.insert("trailer", "x-later".parse().unwrap());
    headers.insert("x-origin", "h2".parse().unwrap());

    let response = NativeHttp2UpstreamResponse::for_test(http::StatusCode::OK, headers, "ok");
    let response = native_http2_response_to_http1(response).unwrap();
    let header_names: Vec<_> = response
        .headers()
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();

    assert_eq!(response.body(), b"ok");
    assert!(header_names.contains(&"x-origin"));
    assert!(!header_names.contains(&"content-length"));
    assert!(!header_names.contains(&"connection"));
    assert!(!header_names.contains(&"date"));
    assert!(!header_names.contains(&"transfer-encoding"));
    assert!(!header_names.contains(&"upgrade"));
    assert!(!header_names.contains(&"keep-alive"));
    assert!(!header_names.contains(&"proxy-connection"));
    assert!(!header_names.contains(&"te"));
    assert!(!header_names.contains(&"trailer"));
}

#[test]
fn h2_upstream_request_preserves_client_host_as_authority() {
    let request = NativeHttp1Request {
        method: "GET".to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: true,
        tls_identity: None,
        geo_context: None,
        target: "/resource?x=1".to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![("host".to_owned(), "client.example".to_owned())],
        body: zeroize::Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    };

    let request = native_http2_upstream_request(&request, "origin.internal:8443", "https").unwrap();

    assert_eq!(
        request.uri.authority().map(|authority| authority.as_str()),
        Some("client.example")
    );
    assert_eq!(
        request.uri.path_and_query().map(|target| target.as_str()),
        Some("/resource?x=1")
    );
}

#[test]
fn h2_upstream_request_preserves_native_request_trailers() {
    let request = NativeHttp1Request {
        method: "POST".to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: true,
        tls_identity: None,
        geo_context: None,
        target: "/grpc.Service/Call".to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![
            ("host".to_owned(), "origin.test".to_owned()),
            ("content-type".to_owned(), "application/grpc".to_owned()),
        ],
        body: zeroize::Zeroizing::new(b"request".to_vec()),
        trailers: vec![("grpc-status".to_owned(), "0".to_owned())],
    };

    let request = native_http2_upstream_request(&request, "origin.test", "https").unwrap();
    let trailers = request.trailers.as_ref().expect("trailers");

    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
}

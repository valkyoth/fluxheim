use super::*;
use std::future::poll_fn;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[test]
fn native_http2_preview_starts_blocked_until_all_safety_hooks_exist() {
    let preview = NativeHttp2Preview::from_downstream_policy(DownstreamHttp2Policy::default());

    assert!(!preview.is_cutover_ready());
    assert_eq!(
        preview
            .blocking_reports()
            .map(|report| report.hook())
            .collect::<Vec<_>>(),
        vec![NativeHttp2SafetyHook::HeaderFieldCount]
    );
}

#[test]
fn native_http2_preview_records_every_required_safety_hook_once() {
    let preview = NativeHttp2Preview::from_downstream_policy(DownstreamHttp2Policy::default());
    let mut hooks = preview
        .reports()
        .iter()
        .map(|report| report.hook())
        .collect::<Vec<_>>();
    hooks.sort_by_key(|hook| hook.name());

    let mut required = NativeHttp2Preview::required_hooks().to_vec();
    required.sort_by_key(|hook| hook.name());

    assert_eq!(hooks, required);
}

#[test]
fn native_http2_preview_preserves_downstream_policy_values() {
    let preview = NativeHttp2Preview::from_downstream_policy(DownstreamHttp2Policy::default());
    let policy = preview.downstream_policy();

    assert_eq!(policy.max_header_list_size(), 64 * 1024);
    assert_eq!(policy.max_header_count(), 100);
    assert_eq!(policy.max_uri_bytes(), 8 * 1024);
    assert_eq!(policy.max_body_bytes(), 16 * 1024 * 1024);
    assert_eq!(policy.handler_timeout(), Duration::from_secs(30));
    assert_eq!(policy.response_write_lifetime(), Duration::from_secs(30));
    assert_eq!(policy.response_body_timeout(), Duration::from_secs(30));
    assert_eq!(policy.max_concurrent_streams(), 32);
    assert_eq!(policy.initial_window_size(), 64 * 1024);
    assert_eq!(policy.max_send_buffer_size(), 256 * 1024);
    assert_eq!(policy.max_pending_accept_reset_streams(), 8);
}

#[tokio::test]
async fn native_http2_connection_passes_request_trailers_to_handler() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let observed = Arc::new(Mutex::new(None));
    let observed_for_handler = observed.clone();
    let handler = Arc::new(move |request: NativeHttp2Request| {
        let observed_for_handler = observed_for_handler.clone();
        async move {
            let trailers = request.trailers.expect("request trailers");
            let status = trailers.get("grpc-status").cloned();
            *observed_for_handler.lock().unwrap() = status;
            NativeHttp2Response::no_content()
        }
    });
    let server = tokio::spawn(serve_native_http2_connection(
        server_io,
        DownstreamHttp2Policy::default(),
        handler,
    ));
    let (client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        connection.await.unwrap();
    });
    let mut client = client.ready().await.unwrap();
    let request = http::Request::builder().uri("/grpc").body(()).unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));

    send_stream.send_trailers(trailers).unwrap();
    let response = response.await.unwrap();

    assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
    assert_eq!(
        observed.lock().unwrap().as_ref(),
        Some(&http::HeaderValue::from_static("0"))
    );
}

#[tokio::test]
async fn native_http2_connection_times_out_slow_handler() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let policy = DownstreamHttp2Policy::default().with_handler_timeout(Duration::from_millis(10));
    let handler = Arc::new(|_request: NativeHttp2Request| async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        NativeHttp2Response::no_content()
    });
    let server = tokio::spawn(serve_native_http2_connection(server_io, policy, handler));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder().uri("/slow").body(()).unwrap();

    let (_response, _send_stream) = client.send_request(request, true).unwrap();
    let error = server.await.unwrap().unwrap_err();

    assert!(matches!(error, NativeHttp2StackError::HandlerTimeout));
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_stack_probe_rejects_too_many_decoded_headers() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let policy = DownstreamHttp2Policy::from_server_limits(fluxheim_config::ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_request_headers: 1,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(2048),
    });
    let server = tokio::spawn(native_http2_stack_probe(server_io, policy));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .uri("/")
        .header("x-one", "1")
        .header("x-two", "2")
        .body(())
        .unwrap();
    let _ = client.send_request(request, true).unwrap();

    let error = server.await.unwrap().unwrap_err();
    assert!(matches!(
        error,
        NativeHttp2StackError::TooManyHeaders { count: 2, limit: 1 }
    ));
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_stack_probe_rejects_oversized_uri() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let policy = DownstreamHttp2Policy::from_server_limits(fluxheim_config::ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(4),
        max_request_headers: 16,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(2048),
    });
    let server = tokio::spawn(native_http2_stack_probe(server_io, policy));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder().uri("/too-long").body(()).unwrap();
    let _ = client.send_request(request, true).unwrap();

    let error = server.await.unwrap().unwrap_err();
    assert!(matches!(
        error,
        NativeHttp2StackError::UriTooLarge { len: 9, limit: 4 }
    ));
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_stack_probe_accepts_bounded_request_body() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(native_http2_stack_probe(
        server_io,
        DownstreamHttp2Policy::default(),
    ));
    let (client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        connection.await.unwrap();
    });
    let mut client = client.ready().await.unwrap();
    let request = http::Request::builder().uri("/").body(()).unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();

    send_stream
        .send_data(bytes::Bytes::from_static(b"ok"), true)
        .unwrap();
    let response = response.await.unwrap();

    assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_stack_probe_releases_body_flow_control_window() {
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    let policy = DownstreamHttp2Policy::default().with_request_body_timeout(Duration::from_secs(3));
    let body_len = policy.initial_window_size() as usize + 1;
    let server = tokio::spawn(native_http2_stack_probe(server_io, policy));
    let (client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        connection.await.unwrap();
    });
    let mut client = client.ready().await.unwrap();
    let request = http::Request::builder().uri("/").body(()).unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();

    send_body_respecting_flow_control(&mut send_stream, body_len, 16 * 1024).await;
    let response = response.await.unwrap();

    assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

async fn send_body_respecting_flow_control(
    send_stream: &mut h2::SendStream<bytes::Bytes>,
    mut remaining: usize,
    max_chunk: usize,
) {
    while remaining > 0 {
        send_stream.reserve_capacity(remaining.min(max_chunk));
        let capacity = poll_fn(|context| send_stream.poll_capacity(context))
            .await
            .expect("send stream still open")
            .expect("capacity available");
        if capacity == 0 {
            continue;
        }
        let chunk_len = capacity.min(remaining).min(max_chunk);
        remaining -= chunk_len;
        send_stream
            .send_data(bytes::Bytes::from(vec![b'a'; chunk_len]), remaining == 0)
            .unwrap();
    }
}

#[tokio::test]
async fn native_http2_stack_probe_rejects_oversized_request_body() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let policy = DownstreamHttp2Policy::from_server_limits(fluxheim_config::ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_request_headers: 16,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(1),
    });
    let server = tokio::spawn(native_http2_stack_probe(server_io, policy));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder().uri("/").body(()).unwrap();
    let (_response, mut send_stream) = client.send_request(request, false).unwrap();

    send_stream
        .send_data(bytes::Bytes::from_static(b"too-large"), true)
        .unwrap();
    let error = server.await.unwrap().unwrap_err();

    assert!(matches!(
        error,
        NativeHttp2StackError::BodyTooLarge { limit: 1 }
    ));
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_stack_probe_times_out_slow_request_body() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let policy =
        DownstreamHttp2Policy::default().with_request_body_timeout(Duration::from_millis(10));
    let server = tokio::spawn(native_http2_stack_probe(server_io, policy));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder().uri("/").body(()).unwrap();

    let (_response, _send_stream) = client.send_request(request, false).unwrap();
    let error = server.await.unwrap().unwrap_err();

    assert!(matches!(error, NativeHttp2StackError::BodyReadTimeout));
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_stack_probe_serves_single_response() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(native_http2_stack_probe(
        server_io,
        DownstreamHttp2Policy::default(),
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        connection.await.unwrap();
    });
    let request = http::Request::builder().uri("/").body(()).unwrap();

    let (response, _send_stream) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();

    assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_stack_probe_sends_response_trailers() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let response = NativeHttp2Response::new(http::StatusCode::OK, bytes::Bytes::from_static(b"ok"))
        .with_trailer(
            http::HeaderName::from_static("grpc-status"),
            http::HeaderValue::from_static("0"),
        );
    let server = tokio::spawn(native_http2_stack_probe_with_response(
        server_io,
        DownstreamHttp2Policy::default(),
        response,
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        connection.await.unwrap();
    });
    let request = http::Request::builder().uri("/").body(()).unwrap();

    let (response, _send_stream) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    let mut body = response.into_body();
    let data = body.data().await.unwrap().unwrap();
    let trailers = body.trailers().await.unwrap().unwrap();

    assert_eq!(&data[..], b"ok");
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_stack_probe_sends_empty_body_response_trailers() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let response = NativeHttp2Response::new(http::StatusCode::OK, bytes::Bytes::new())
        .with_trailer(
            http::HeaderName::from_static("grpc-status"),
            http::HeaderValue::from_static("0"),
        );
    let server = tokio::spawn(native_http2_stack_probe_with_response(
        server_io,
        DownstreamHttp2Policy::default(),
        response,
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        connection.await.unwrap();
    });
    let request = http::Request::builder().uri("/").body(()).unwrap();

    let (response, _send_stream) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    let mut body = response.into_body();
    let trailers = body.trailers().await.unwrap().unwrap();

    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_stack_probe_rejects_prohibited_response_headers() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let response = NativeHttp2Response::new(http::StatusCode::OK, bytes::Bytes::new()).with_header(
        http::header::CONNECTION,
        http::HeaderValue::from_static("close"),
    );
    let server = tokio::spawn(native_http2_stack_probe_with_response(
        server_io,
        DownstreamHttp2Policy::default(),
        response,
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder().uri("/").body(()).unwrap();

    let (_response, _send_stream) = client.send_request(request, true).unwrap();
    let error = server.await.unwrap().unwrap_err();

    assert!(matches!(
        error,
        NativeHttp2StackError::ProhibitedResponseHeader { .. }
    ));
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_stack_probe_times_out_response_flow_control_hold() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let policy =
        DownstreamHttp2Policy::default().with_response_write_lifetime(Duration::from_millis(25));
    let response = NativeHttp2Response::new(
        http::StatusCode::OK,
        bytes::Bytes::from(vec![b'x'; policy.initial_window_size() as usize + 1]),
    );
    let server = tokio::spawn(native_http2_stack_probe_with_response(
        server_io, policy, response,
    ));
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(1);
    let (mut client, connection) = builder
        .handshake::<_, bytes::Bytes>(client_io)
        .await
        .unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder().uri("/").body(()).unwrap();

    let (_response, _send_stream) = client.send_request(request, true).unwrap();
    let error = server.await.unwrap().unwrap_err();

    assert!(matches!(error, NativeHttp2StackError::ResponseWriteTimeout));
    client_connection.await.unwrap();
}

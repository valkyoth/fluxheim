use super::*;
use std::future::poll_fn;
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
        vec![
            NativeHttp2SafetyHook::HeaderFieldCount,
            NativeHttp2SafetyHook::ResponseWriteLifetime,
            NativeHttp2SafetyHook::TrailerAndGrpcPassThrough,
        ]
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
    assert_eq!(policy.max_concurrent_streams(), 32);
    assert_eq!(policy.initial_window_size(), 64 * 1024);
    assert_eq!(policy.max_send_buffer_size(), 256 * 1024);
    assert_eq!(policy.max_pending_accept_reset_streams(), 8);
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

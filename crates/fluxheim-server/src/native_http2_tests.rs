use super::*;
use crate::native_http2_stack::serve_native_http2_connection_until_idle;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct TransportDropProbe<T> {
    inner: T,
    dropped: Option<tokio::sync::oneshot::Sender<()>>,
}

struct HoldingHttp2BodyBudgetHandler {
    budget: NativeRequestBodyBudget,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

struct RetainingHttp2BodyBudgetHandler {
    budget: NativeRequestBodyBudget,
    retained: Mutex<Option<crate::NativeHttp1RequestBody>>,
}

impl NativeHttp2Handler for HoldingHttp2BodyBudgetHandler {
    fn request_body_budget(&self) -> NativeRequestBodyBudget {
        self.budget.clone()
    }

    fn handle<'a>(
        &'a self,
        request: NativeHttp2Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NativeHttp2Response> + Send + 'a>> {
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            drop(request);
            NativeHttp2Response::no_content()
        })
    }
}

impl NativeHttp2Handler for RetainingHttp2BodyBudgetHandler {
    fn request_body_budget(&self) -> NativeRequestBodyBudget {
        self.budget.clone()
    }

    fn handle<'a>(
        &'a self,
        request: NativeHttp2Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = NativeHttp2Response> + Send + 'a>> {
        Box::pin(async move {
            *self.retained.lock().unwrap() = Some(request.body);
            NativeHttp2Response::no_content()
        })
    }
}

impl<T> Drop for TransportDropProbe<T> {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

impl<T> AsyncRead for TransportDropProbe<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<T> AsyncWrite for TransportDropProbe<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[test]
fn native_http2_preview_marks_downstream_dispatch_ready_after_alpn_wiring() {
    let preview = NativeHttp2Preview::from_downstream_policy(DownstreamHttp2Policy::default());

    assert!(preview.is_cutover_ready());
    assert!(preview.reports().iter().any(|report| {
        report.hook() == NativeHttp2SafetyHook::DownstreamListenerDispatch
            && report.status() == NativeHttp2SafetyStatus::Satisfied
            && report.detail().contains("h2 ALPN")
    }));
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

#[test]
fn native_http2_preview_documents_header_count_and_hpack_bounds() {
    let preview = NativeHttp2Preview::from_downstream_policy(DownstreamHttp2Policy::default());
    let report = preview
        .reports()
        .iter()
        .find(|report| report.hook() == NativeHttp2SafetyHook::HeaderFieldCount)
        .expect("header-count report");

    assert_eq!(report.status(), NativeHttp2SafetyStatus::Satisfied);
    assert!(report.detail().contains("decoded header-count"));
    assert!(report.detail().contains("max_header_list_size"));
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
    let server = tokio::spawn(serve_native_http2_connection_until_idle(
        server_io,
        DownstreamHttp2Policy::default(),
        handler,
        Duration::from_millis(50),
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
    drop(client);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
    assert_eq!(
        observed.lock().unwrap().as_ref(),
        Some(&http::HeaderValue::from_static("0"))
    );
}

#[tokio::test]
async fn native_http2_charges_declared_length_instead_of_maximum_body_size() {
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);
    let handler = Arc::new(HoldingHttp2BodyBudgetHandler {
        budget: NativeRequestBodyBudget::new(2 * 64 * 1024),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let server = tokio::spawn(serve_native_http2_connection_until_idle(
        server_io,
        DownstreamHttp2Policy::default(),
        handler.clone(),
        Duration::from_secs(1),
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });

    let first = http::Request::builder()
        .uri("/first")
        .header(http::header::CONTENT_LENGTH, "1")
        .body(())
        .unwrap();
    let (first_response, mut first_body) = client.send_request(first, false).unwrap();
    first_body
        .send_data(bytes::Bytes::from_static(b"a"), true)
        .unwrap();
    handler.entered.notified().await;

    client = client.ready().await.unwrap();
    let second = http::Request::builder()
        .uri("/second")
        .header(http::header::CONTENT_LENGTH, "1")
        .body(())
        .unwrap();
    let (second_response, mut second_body) = client.send_request(second, false).unwrap();
    second_body
        .send_data(bytes::Bytes::from_static(b"b"), true)
        .unwrap();
    handler.entered.notified().await;
    handler.release.notify_waiters();
    assert_eq!(
        first_response.await.unwrap().status(),
        http::StatusCode::NO_CONTENT
    );
    assert_eq!(
        second_response.await.unwrap().status(),
        http::StatusCode::NO_CONTENT
    );
    drop(client);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_grows_unknown_body_reservations_before_buffering() {
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);
    let handler = Arc::new(HoldingHttp2BodyBudgetHandler {
        budget: NativeRequestBodyBudget::new(64 * 1024),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let server = tokio::spawn(serve_native_http2_connection_until_idle(
        server_io,
        DownstreamHttp2Policy::default(),
        handler.clone(),
        Duration::from_secs(1),
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });

    let first = http::Request::builder().uri("/first").body(()).unwrap();
    let (first_response, mut first_body) = client.send_request(first, false).unwrap();
    first_body
        .send_data(bytes::Bytes::from_static(b"a"), true)
        .unwrap();
    handler.entered.notified().await;

    client = client.ready().await.unwrap();
    let second = http::Request::builder().uri("/second").body(()).unwrap();
    let (second_response, mut second_body) = client.send_request(second, false).unwrap();
    second_body
        .send_data(bytes::Bytes::from_static(b"b"), true)
        .unwrap();
    let second_response = second_response.await.unwrap();
    assert_eq!(
        second_response.status(),
        http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        second_response.headers().get(http::header::RETRY_AFTER),
        Some(&http::HeaderValue::from_static("1"))
    );

    handler.release.notify_one();
    assert_eq!(
        first_response.await.unwrap().status(),
        http::StatusCode::NO_CONTENT
    );
    drop(client);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_fragmented_unknown_body_grows_buffer_logarithmically() {
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    let observed = Arc::new(Mutex::new(None));
    let observed_for_handler = observed.clone();
    let handler = Arc::new(move |request: NativeHttp2Request| {
        let observed_for_handler = observed_for_handler.clone();
        async move {
            *observed_for_handler.lock().unwrap() =
                Some((request.body.len(), request.body.capacity_replacements()));
            NativeHttp2Response::no_content()
        }
    });
    let limits = fluxheim_config::ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(64 * 1024),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(8 * 1024),
        max_request_headers: 100,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(512 * 1024),
        max_buffered_request_body_bytes: fluxheim_config::ByteSize::from_bytes(1024 * 1024),
    };
    let policy = DownstreamHttp2Policy::from_server_limits(limits)
        .with_request_body_timeout(Duration::from_secs(3));
    let server = tokio::spawn(serve_native_http2_connection_until_idle(
        server_io,
        policy,
        handler,
        Duration::from_secs(1),
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .uri("/fragmented")
        .body(())
        .unwrap();
    let (response, mut body) = client.send_request(request, false).unwrap();

    send_body_respecting_flow_control(&mut body, 512 * 1024, 1024).await;

    assert_eq!(
        response.await.unwrap().status(),
        http::StatusCode::NO_CONTENT
    );
    let (body_len, capacity_replacements) = observed.lock().unwrap().unwrap();
    assert_eq!(body_len, 512 * 1024);
    assert!(capacity_replacements > 0);
    assert!(capacity_replacements <= 4);
    drop(client);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_body_retains_admission_after_handler_returns() {
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);
    let budget = NativeRequestBodyBudget::new(64 * 1024);
    let handler = Arc::new(RetainingHttp2BodyBudgetHandler {
        budget: budget.clone(),
        retained: Mutex::new(None),
    });
    let server = tokio::spawn(serve_native_http2_connection_until_idle(
        server_io,
        DownstreamHttp2Policy::default(),
        handler.clone(),
        Duration::from_secs(1),
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .uri("/retain")
        .header(http::header::CONTENT_LENGTH, "1")
        .body(())
        .unwrap();
    let (response, mut body) = client.send_request(request, false).unwrap();
    body.send_data(bytes::Bytes::from_static(b"a"), true)
        .unwrap();

    assert_eq!(
        response.await.unwrap().status(),
        http::StatusCode::NO_CONTENT
    );
    assert!(budget.reserve(1).await.is_err());
    handler.retained.lock().unwrap().take();
    assert!(budget.reserve(1).await.is_ok());

    drop(client);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_rejects_body_length_mismatch() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(serve_native_http2_connection_until_idle(
        server_io,
        DownstreamHttp2Policy::default(),
        Arc::new(|_request: NativeHttp2Request| async { NativeHttp2Response::no_content() }),
        Duration::from_millis(50),
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .uri("/mismatch")
        .header(http::header::CONTENT_LENGTH, "2")
        .body(())
        .unwrap();
    let (response, mut body) = client.send_request(request, false).unwrap();
    body.send_data(bytes::Bytes::from_static(b"a"), true)
        .unwrap();

    assert!(response.await.is_err());
    drop(client);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_connection_times_out_slow_handler() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let policy = DownstreamHttp2Policy::default().with_handler_timeout(Duration::from_millis(10));
    let handler = Arc::new(|_request: NativeHttp2Request| async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        NativeHttp2Response::no_content()
    });
    let server = tokio::spawn(serve_native_http2_connection_until_idle(
        server_io,
        policy,
        handler,
        Duration::from_millis(25),
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder().uri("/slow").body(()).unwrap();

    let (response, send_stream) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();

    assert_eq!(response.status(), http::StatusCode::GATEWAY_TIMEOUT);
    drop(send_stream);
    drop(client);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_releases_closed_transport_before_waiting_for_handler() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let (transport_dropped, transport_drop) = tokio::sync::oneshot::channel();
    let handler_started = Arc::new(tokio::sync::Notify::new());
    let release_handler = Arc::new(tokio::sync::Notify::new());
    let handler = {
        let handler_started = handler_started.clone();
        let release_handler = release_handler.clone();
        Arc::new(move |_request: NativeHttp2Request| {
            let handler_started = handler_started.clone();
            let release_handler = release_handler.clone();
            async move {
                handler_started.notify_one();
                release_handler.notified().await;
                NativeHttp2Response::no_content()
            }
        })
    };
    let server = tokio::spawn(serve_native_http2_connection(
        TransportDropProbe {
            inner: server_io,
            dropped: Some(transport_dropped),
        },
        DownstreamHttp2Policy::default(),
        handler,
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(connection);
    let request = http::Request::builder().uri("/held").body(()).unwrap();
    let (response, _send_stream) = client.send_request(request, true).unwrap();
    handler_started.notified().await;

    drop(response);
    drop(client);
    client_connection.abort();
    let _ = client_connection.await;
    tokio::time::timeout(Duration::from_secs(1), transport_drop)
        .await
        .expect("closed HTTP/2 transport must be released")
        .unwrap();

    release_handler.notify_waiters();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn native_http2_stack_probe_rejects_too_many_decoded_headers() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let policy = DownstreamHttp2Policy::from_server_limits(fluxheim_config::ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_request_headers: 1,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(2048),
        max_buffered_request_body_bytes: fluxheim_config::ByteSize::from_bytes(2048),
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
    let (response, _send_stream) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();

    assert_eq!(
        response.status(),
        http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    drop(client);
    server.await.unwrap().unwrap();
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
        max_buffered_request_body_bytes: fluxheim_config::ByteSize::from_bytes(2048),
    });
    let server = tokio::spawn(native_http2_stack_probe(server_io, policy));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder().uri("/too-long").body(()).unwrap();
    let (response, _send_stream) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();

    assert_eq!(response.status(), http::StatusCode::URI_TOO_LONG);
    drop(client);
    server.await.unwrap().unwrap();
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
    drop(client);
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
    drop(client);
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
        max_buffered_request_body_bytes: fluxheim_config::ByteSize::from_bytes(1),
    });
    let server = tokio::spawn(native_http2_stack_probe(server_io, policy));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder().uri("/").body(()).unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();

    send_stream
        .send_data(bytes::Bytes::from_static(b"too-large"), true)
        .unwrap();
    let response = response.await.unwrap();

    assert_eq!(response.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
    drop(client);
    server.await.unwrap().unwrap();
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

    let (response, _send_stream) = client.send_request(request, false).unwrap();
    let response = response.await.unwrap();

    assert_eq!(response.status(), http::StatusCode::REQUEST_TIMEOUT);
    drop(client);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_bad_stream_does_not_abort_sibling_stream() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let policy = DownstreamHttp2Policy::from_server_limits(fluxheim_config::ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_request_headers: 16,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(1),
        max_buffered_request_body_bytes: fluxheim_config::ByteSize::from_bytes(1),
    });
    let server = tokio::spawn(native_http2_stack_probe(server_io, policy));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let bad_request = http::Request::builder().uri("/bad").body(()).unwrap();
    let good_request = http::Request::builder().uri("/good").body(()).unwrap();

    let (bad_response, mut bad_stream) = client.send_request(bad_request, false).unwrap();
    let (good_response, _good_stream) = client.send_request(good_request, true).unwrap();
    bad_stream
        .send_data(bytes::Bytes::from_static(b"too-large"), true)
        .unwrap();

    let bad_response = bad_response.await.unwrap();
    let good_response = good_response.await.unwrap();

    assert_eq!(bad_response.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(good_response.status(), http::StatusCode::NO_CONTENT);
    drop(client);
    server.await.unwrap().unwrap();
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
    drop(client);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

#[tokio::test]
async fn native_http2_stack_probe_serves_multiple_streams_on_one_connection() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(native_http2_stack_probe(
        server_io,
        DownstreamHttp2Policy::default(),
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        connection.await.unwrap();
    });
    let first_request = http::Request::builder().uri("/one").body(()).unwrap();
    let second_request = http::Request::builder().uri("/two").body(()).unwrap();

    let (first_response, _first_send_stream) = client.send_request(first_request, true).unwrap();
    let (second_response, _second_send_stream) = client.send_request(second_request, true).unwrap();
    let first_response = first_response.await.unwrap();
    let second_response = second_response.await.unwrap();

    assert_eq!(first_response.status(), http::StatusCode::NO_CONTENT);
    assert_eq!(second_response.status(), http::StatusCode::NO_CONTENT);
    drop(client);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

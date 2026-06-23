use super::*;
use bytes::Bytes;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::native_http2_client::native_http2_upstream_client_on_io_with_keepalive;

#[tokio::test]
async fn native_http2_upstream_preserves_request_and_response_trailers() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let Some(stream) = connection.accept().await else {
            panic!("expected upstream request");
        };
        let (request, mut respond) = stream.unwrap();
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(
            request.uri().path_and_query().unwrap().as_str(),
            "/grpc.Service/Call"
        );
        let mut body = request.into_body();
        while let Some(data) = body.data().await {
            let data = data.unwrap();
            body.flow_control().release_capacity(data.len()).unwrap();
        }
        let trailers = body.trailers().await.unwrap().unwrap();
        assert_eq!(trailers.get("grpc-status").unwrap(), "0");

        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        let mut send_stream = respond.send_response(response, false).unwrap();
        send_stream
            .send_data(Bytes::from_static(b"world"), false)
            .unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        send_stream.send_trailers(trailers).unwrap();
        drive_test_server_to_close(connection).await;
    });
    let request = NativeHttp2UpstreamRequest::new(
        http::Method::POST,
        http::Uri::from_static("http://upstream.test/grpc.Service/Call"),
    )
    .with_header(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/grpc"),
    )
    .with_trailer(
        http::HeaderName::from_static("grpc-status"),
        http::HeaderValue::from_static("0"),
    );

    let response =
        send_native_http2_upstream_on_io(client_io, DownstreamHttp2Policy::default(), request)
            .await
            .unwrap();

    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/grpc"
    );
    assert_eq!(response.body(), b"world");
    assert_eq!(
        response.trailers().unwrap().get("grpc-status").unwrap(),
        "0"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn native_http2_upstream_rejects_oversized_response_body() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let Some(stream) = connection.accept().await else {
            panic!("expected upstream request");
        };
        let (_request, mut respond) = stream.unwrap();
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .unwrap();
        let mut send_stream = respond.send_response(response, false).unwrap();
        send_stream
            .send_data(Bytes::from_static(b"too-large"), true)
            .unwrap();
        drive_test_server_to_close(connection).await;
    });
    let request = NativeHttp2UpstreamRequest::new(
        http::Method::GET,
        http::Uri::from_static("http://upstream.test/"),
    );
    let policy = DownstreamHttp2Policy::from_server_limits(fluxheim_config::ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_request_headers: 16,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(1),
    });

    let error = send_native_http2_upstream_on_io(client_io, policy, request)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        NativeHttp2StackError::BodyTooLarge { limit: 1 }
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn native_http2_upstream_times_out_slow_response_body() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let Some(stream) = connection.accept().await else {
            panic!("expected upstream request");
        };
        let (_request, mut respond) = stream.unwrap();
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .unwrap();
        let _send_stream = respond.send_response(response, false).unwrap();
        let driver = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_millis(100),
                poll_fn(|context| connection.poll_closed(context)),
            )
            .await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        driver.abort();
        let _ = driver.await;
    });
    let request = NativeHttp2UpstreamRequest::new(
        http::Method::GET,
        http::Uri::from_static("http://upstream.test/slow-body"),
    );
    let policy =
        DownstreamHttp2Policy::default().with_response_body_timeout(Duration::from_millis(10));

    let error = send_native_http2_upstream_on_io(client_io, policy, request)
        .await
        .unwrap_err();

    assert!(matches!(error, NativeHttp2StackError::BodyReadTimeout));
    server.await.unwrap();
}

#[tokio::test]
async fn native_http2_upstream_times_out_request_flow_control_hold() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut builder = h2::server::Builder::new();
        builder.initial_window_size(1);
        let mut connection = builder.handshake::<_, Bytes>(server_io).await.unwrap();
        let Some(stream) = connection.accept().await else {
            panic!("expected upstream request");
        };
        let (_request, _respond) = stream.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    });
    let request = NativeHttp2UpstreamRequest::new(
        http::Method::POST,
        http::Uri::from_static("http://upstream.test/"),
    )
    .with_body(Bytes::from(vec![b'x'; 128 * 1024]));
    let policy =
        DownstreamHttp2Policy::default().with_response_write_lifetime(Duration::from_millis(10));

    let error = send_native_http2_upstream_on_io(client_io, policy, request)
        .await
        .unwrap_err();

    assert!(matches!(error, NativeHttp2StackError::ResponseWriteTimeout));
    server.await.unwrap();
}

#[tokio::test]
async fn native_http2_upstream_rejects_too_many_response_headers() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let Some(stream) = connection.accept().await else {
            panic!("expected upstream request");
        };
        let (_request, mut respond) = stream.unwrap();
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("x-one", "1")
            .header("x-two", "2")
            .body(())
            .unwrap();
        let _send_stream = respond.send_response(response, true).unwrap();
        drive_test_server_to_close(connection).await;
    });
    let request = NativeHttp2UpstreamRequest::new(
        http::Method::GET,
        http::Uri::from_static("http://upstream.test/"),
    );
    let policy = DownstreamHttp2Policy::from_server_limits(fluxheim_config::ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_request_headers: 1,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(2048),
    });

    let error = send_native_http2_upstream_on_io(client_io, policy, request)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        NativeHttp2StackError::TooManyHeaders { count: 2, limit: 1 }
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn native_http2_upstream_surfaces_stream_reset() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let Some(stream) = connection.accept().await else {
            panic!("expected upstream request");
        };
        let (_request, mut respond) = stream.unwrap();
        respond.send_reset(h2::Reason::CANCEL);
        drive_test_server_to_close(connection).await;
    });
    let request = NativeHttp2UpstreamRequest::new(
        http::Method::GET,
        http::Uri::from_static("http://upstream.test/reset"),
    );

    let error =
        send_native_http2_upstream_on_io(client_io, DownstreamHttp2Policy::default(), request)
            .await
            .unwrap_err();

    assert!(matches!(error, NativeHttp2StackError::Stream(_)));
    server.await.unwrap();
}

#[tokio::test]
async fn native_http2_upstream_keepalive_sends_ping_frame() {
    let (client_io, server_io) = tokio::io::duplex(4096);
    let saw_ping = Arc::new(AtomicBool::new(false));
    let saw_ping_for_server = Arc::clone(&saw_ping);
    let server = tokio::spawn(async move {
        let observed = ObservedHttp2Read::new(server_io, Arc::clone(&saw_ping_for_server));
        let mut connection = h2::server::handshake(observed).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !saw_ping_for_server.load(Ordering::Acquire) {
                tokio::select! {
                    stream = connection.accept() => {
                        if stream.is_none() {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {}
                }
            }
        })
        .await
        .expect("expected native upstream H2 keepalive ping");
        assert!(saw_ping_for_server.load(Ordering::Acquire));
        drive_test_server_to_close(connection).await;
    });
    let policy = DownstreamHttp2Policy::default().with_handler_timeout(Duration::from_secs(1));
    let (client, driver) = native_http2_upstream_client_on_io_with_keepalive(
        client_io,
        policy,
        Some(Duration::from_millis(10)),
    )
    .await
    .unwrap();
    let _ready_client = tokio::time::timeout(Duration::from_secs(1), client.ready())
        .await
        .unwrap()
        .unwrap();

    server.await.unwrap();
    driver.abort_and_join().await;
}

struct ObservedHttp2Read<T> {
    inner: T,
    saw_client_ping: Arc<AtomicBool>,
    preface_remaining: usize,
    frame_buffer: Vec<u8>,
}

impl<T> ObservedHttp2Read<T> {
    fn new(inner: T, saw_client_ping: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            saw_client_ping,
            preface_remaining: 24,
            frame_buffer: Vec::new(),
        }
    }

    fn observe(&mut self, mut bytes: &[u8]) {
        if self.preface_remaining > 0 {
            let skipped = self.preface_remaining.min(bytes.len());
            self.preface_remaining -= skipped;
            bytes = &bytes[skipped..];
        }
        if bytes.is_empty() {
            return;
        }
        self.frame_buffer.extend_from_slice(bytes);
        while self.frame_buffer.len() >= 9 {
            let length = ((self.frame_buffer[0] as usize) << 16)
                | ((self.frame_buffer[1] as usize) << 8)
                | self.frame_buffer[2] as usize;
            if self.frame_buffer.len() < 9 + length {
                break;
            }
            let frame_type = self.frame_buffer[3];
            let flags = self.frame_buffer[4];
            let stream_id = u32::from_be_bytes([
                self.frame_buffer[5],
                self.frame_buffer[6],
                self.frame_buffer[7],
                self.frame_buffer[8],
            ]) & 0x7fff_ffff;
            if frame_type == 6 && flags & 0x1 == 0 && stream_id == 0 && length == 8 {
                self.saw_client_ping.store(true, Ordering::Release);
            }
            self.frame_buffer.drain(..9 + length);
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ObservedHttp2Read<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut self.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                let after = buffer.filled().len();
                self.observe(&buffer.filled()[before..after]);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedHttp2Read<T> {
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

async fn drive_test_server_to_close<T>(mut connection: h2::server::Connection<T, Bytes>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    connection.graceful_shutdown();
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        poll_fn(|context| connection.poll_closed(context)),
    )
    .await;
}

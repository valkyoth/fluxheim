use super::*;
use bytes::Bytes;
use std::future::poll_fn;
use std::time::Duration;

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

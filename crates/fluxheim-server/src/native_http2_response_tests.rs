use super::*;
use crate::native_http2_route_adapter::NativeHttp2RouteAdapter;
use crate::native_http2_stack::serve_native_http2_connection_until_idle;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::test]
async fn native_http2_route_adapter_serves_native_http1_handler() {
    let (server_io, client_io) = tokio::io::duplex(4096);
    let observed = Arc::new(Mutex::new(None));
    let observed_for_handler = observed.clone();
    let handler = Arc::new(move |request: NativeHttp1Request| {
        let observed_for_handler = observed_for_handler.clone();
        async move {
            *observed_for_handler.lock().unwrap() = Some((
                request.method,
                request.target,
                request
                    .headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("host"))
                    .map(|(_, value)| value.clone()),
                request.body,
                request.trailers,
            ));
            NativeHttp1Response::new(200, "OK", b"adapter-ok")
                .with_header("set-cookie", "a=1")
                .with_header("set-cookie", "b=2")
                .with_header("connection", "close")
        }
    });
    let adapter = Arc::new(NativeHttp2RouteAdapter::new(
        handler,
        "127.0.0.1:12345".parse().ok(),
        NativeHttp1RequestContext {
            downstream_tls: true,
            ..NativeHttp1RequestContext::default()
        },
    ));
    let server = tokio::spawn(serve_native_http2_connection_until_idle(
        server_io,
        DownstreamHttp2Policy::default(),
        adapter,
        Duration::from_millis(50),
    ));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let client_connection = tokio::spawn(async move {
        connection.await.unwrap();
    });
    let request = http::Request::builder()
        .method("POST")
        .uri("https://native.test/upload?x=1")
        .body(())
        .unwrap();
    let (response, mut send_stream) = client.send_request(request, false).unwrap();
    send_stream
        .send_data(bytes::Bytes::from_static(b"body"), false)
        .unwrap();
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
    send_stream.send_trailers(trailers).unwrap();
    let response = response.await.unwrap();
    let cookies = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut body = response.into_body();
    let data = body.data().await.unwrap().unwrap();

    assert_eq!(&data[..], b"adapter-ok");
    assert_eq!(cookies, vec!["a=1", "b=2"]);
    assert!(body.trailers().await.unwrap().is_none());
    assert_eq!(
        observed.lock().unwrap().as_ref(),
        Some(&(
            "POST".to_owned(),
            "/upload?x=1".to_owned(),
            Some("native.test".to_owned()),
            crate::NativeHttp1RequestBody::from_vec(b"body".to_vec()),
            vec![("grpc-status".to_owned(), "0".to_owned())]
        ))
    );
    drop(client);
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
    drop(client);
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
    drop(client);
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

    let (response, _send_stream) = client.send_request(request, true).unwrap();
    let error = response.await.unwrap_err();

    assert!(error.is_reset() || error.is_io(), "{error:?}");
    drop(client);
    server.await.unwrap().unwrap();
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

    let (response, _send_stream) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();

    assert_eq!(response.status(), http::StatusCode::OK);
    drop(client);
    server.await.unwrap().unwrap();
    client_connection.await.unwrap();
}

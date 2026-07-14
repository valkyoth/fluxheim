use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::NativeHttp1Response;
use crate::native_http1_tests::{read_response, spawn_server};

#[tokio::test]
async fn native_http1_rejects_conflicting_absolute_authority_and_host() {
    let addr = spawn_server(|_| NativeHttp1Response::new(200, "OK", b"unexpected")).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET http://public.test/secret HTTP/1.1\r\nHost: internal.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("bad request\n"));
}

#[tokio::test]
async fn native_http10_rejects_transfer_encoding_even_with_keep_alive() {
    let addr = spawn_server(|_| NativeHttp1Response::new(200, "OK", b"unexpected")).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"POST / HTTP/1.0\r\nHost: local.test\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("Connection: close\r\n"));
    assert!(response.ends_with("bad request\n"));
}

#[tokio::test]
async fn native_http1_dispatches_only_the_canonical_absolute_authority() {
    let addr = spawn_server(|request| {
        let hosts = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>();
        assert_eq!(hosts, ["PUBLIC.test:8080"]);
        NativeHttp1Response::new(200, "OK", b"canonical")
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET http://PUBLIC.test:8080/path HTTP/1.1\r\nHost: public.test:8080\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("canonical"));
}

#[tokio::test]
async fn native_http1_rejects_raw_characters_outside_uri_grammar() {
    let addr = spawn_server(|_| NativeHttp1Response::new(200, "OK", b"unexpected")).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /raw{brace} HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.ends_with("bad request\n"));
}

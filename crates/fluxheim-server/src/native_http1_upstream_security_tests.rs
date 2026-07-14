use std::time::Duration;

use tokio::io::AsyncWriteExt as _;

use crate::native_http1_client_tests::{request, upstream};
use crate::{NativeHttp1Error, NativeHttp1Upstream};

#[tokio::test]
async fn native_upstream_strips_connection_nominated_and_proxy_connection_headers() {
    let addr = upstream(|_, mut stream| async move {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: x-internal-session\r\nproxy-connection: keep-alive\r\nx-internal-session: secret\r\nx-end-to-end: visible\r\n\r\nok",
            )
            .await
            .unwrap();
    })
    .await;

    let response = NativeHttp1Upstream::new(addr.to_string())
        .send(&request())
        .await
        .unwrap();

    assert!(response.headers().iter().all(|(name, _)| {
        !name.eq_ignore_ascii_case("connection")
            && !name.eq_ignore_ascii_case("proxy-connection")
            && !name.eq_ignore_ascii_case("x-internal-session")
    }));
    assert!(
        response
            .headers()
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-end-to-end") && value == "visible")
    );
}

#[tokio::test]
async fn native_upstream_rejects_invalid_connection_option() {
    let addr = upstream(|_, mut stream| async move {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: invalid option\r\n\r\nok",
            )
            .await
            .unwrap();
    })
    .await;

    let error = NativeHttp1Upstream::new(addr.to_string())
        .send(&request())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        NativeHttp1Error::Parse(fluxheim_protocol::Http1ParseError::InvalidConnection)
    ));
}

#[tokio::test]
async fn native_upstream_consumes_informational_responses_before_final_response() {
    let addr = upstream(|_, mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        stream
            .write_all(
                b"HTTP/1.1 103 Early Hints\r\nlink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-final: yes\r\n\r\nfinal",
            )
            .await
            .unwrap();
    })
    .await;

    let response = NativeHttp1Upstream::new(addr.to_string())
        .send(&request())
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"final");
    assert!(
        response
            .headers()
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("x-final") && value == "yes")
    );
    assert!(
        response
            .headers()
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("link"))
    );
}

#[tokio::test]
async fn native_upstream_bounds_informational_response_chain() {
    let addr = upstream(|_, mut stream| async move {
        let mut responses = Vec::new();
        for _ in 0..9 {
            responses.extend_from_slice(b"HTTP/1.1 103 Early Hints\r\n\r\n");
        }
        responses.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
        stream.write_all(&responses).await.unwrap();
    })
    .await;

    let error = NativeHttp1Upstream::new(addr.to_string())
        .send(&request())
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        NativeHttp1Error::Parse(fluxheim_protocol::Http1ParseError::InvalidResponseLine)
    ));
}

#[tokio::test]
async fn native_upstream_rejects_unsupported_transfer_coding_chains() {
    for transfer_encoding in ["gzip, chunked", "chunked, chunked", "gzip"] {
        let addr = upstream(move |_, mut stream| async move {
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ntransfer-encoding: {transfer_encoding}\r\n\r\n0\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        })
        .await;

        let error = NativeHttp1Upstream::new(addr.to_string())
            .send(&request())
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            NativeHttp1Error::Parse(
                fluxheim_protocol::Http1ParseError::UnsupportedTransferEncoding
            )
        ));
    }
}

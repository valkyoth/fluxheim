use fluxheim_config::UpstreamProxyProtocol;
use fluxheim_protocol::PROXY_PROTOCOL_V2_SIGNATURE;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::NativeHttp1Upstream;
use crate::native_http1_client_tests::{proxy_protocol_request, upstream};
use crate::native_http1_test_utils::read_request_head;

#[tokio::test]
async fn native_upstream_writes_proxy_protocol_v1_before_http_request() {
    let addr = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with(
            "PROXY TCP4 198.51.100.10 127.0.0.1 0 8443\r\nGET /hello?name=fluxheim HTTP/1.1\r\n"
        ));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
            .await
            .unwrap();
    })
    .await;

    let response = NativeHttp1Upstream::new(addr.to_string())
        .with_proxy_protocol(UpstreamProxyProtocol::V1)
        .send(&proxy_protocol_request())
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"ok");
}

#[tokio::test]
async fn native_upstream_writes_proxy_protocol_v2_before_http_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = [0u8; 28];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..12], &PROXY_PROTOCOL_V2_SIGNATURE[..]);
        assert_eq!(&header[12..16], &[0x21, 0x11, 0x00, 0x0c]);
        assert_eq!(&header[16..20], &[198, 51, 100, 10]);
        assert_eq!(&header[20..24], &[127, 0, 0, 1]);
        assert_eq!(&header[24..26], &0u16.to_be_bytes());
        assert_eq!(&header[26..28], &8443u16.to_be_bytes());
        let http = String::from_utf8(read_request_head(&mut stream).await).unwrap();
        assert!(http.starts_with("GET /hello?name=fluxheim HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
            .await
            .unwrap();
    });

    let response = NativeHttp1Upstream::new(addr.to_string())
        .with_proxy_protocol(UpstreamProxyProtocol::V2)
        .send(&proxy_protocol_request())
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"ok");
}

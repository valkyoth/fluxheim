#[cfg(feature = "compression-gzip")]
use std::io::Read as _;

#[cfg(feature = "compression-gzip")]
use flate2::read::GzDecoder;
#[cfg(feature = "compression-gzip")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "compression-gzip")]
use tokio::net::TcpStream;

#[cfg(feature = "compression-gzip")]
use crate::NativeHttp1Upstream;
use crate::{DownstreamHttp1Policy, NativeHttp1Proxy};

#[cfg(feature = "compression-gzip")]
use super::upstream;
use super::{
    downstream_get, proxy_config_with_error_page, proxy_listener_for, unused_local_address,
};

#[cfg(feature = "compression-gzip")]
async fn downstream_request_bytes(proxy: std::net::SocketAddr, request: &str) -> Vec<u8> {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    response
}

#[cfg(feature = "compression-gzip")]
#[tokio::test]
async fn native_proxy_applies_gzip_compression_config() {
    let upstream = upstream(|_, mut stream| async move {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  content-type: text/plain\r\n\
                  etag: \"origin\"\r\n\r\n\
                  hello native proxy compression hello native proxy compression \
                  hello native proxy compression hello native proxy compression \
                  hello native proxy compression hello native proxy compression",
            )
            .await
            .unwrap();
    })
    .await;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_compression_config(fluxheim_config::CompressionConfig {
            enabled: true,
            gzip: true,
            min_bytes: fluxheim_config::ByteSize::from_bytes(1),
            max_input_bytes: fluxheim_config::ByteSize::from_bytes(4096),
            max_output_bytes: fluxheim_config::ByteSize::from_bytes(4096),
            ..Default::default()
        });
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_request_bytes(
        proxy,
        "GET /asset.txt HTTP/1.1\r\nHost: proxy.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    )
    .await;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = String::from_utf8(response[..split].to_vec()).unwrap();
    let body = &response[split + 4..];

    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(head.contains("\r\ncontent-encoding: gzip"));
    assert!(head.contains("\r\nvary: accept-encoding"));
    assert!(!head.contains("\r\netag:"));
    let mut decoded = String::new();
    GzDecoder::new(body).read_to_string(&mut decoded).unwrap();
    assert!(decoded.contains("hello native proxy compression"));
}

#[tokio::test]
async fn native_proxy_serves_configured_error_page_on_bad_gateway() {
    let errors = tempfile::tempdir().unwrap();
    std::fs::write(errors.path().join("502.html"), "native custom 502\n").unwrap();
    let mut config = proxy_config_with_error_page(errors.path().to_path_buf());
    config.upstream = Some(unused_local_address().await.to_string());
    let proxy = NativeHttp1Proxy::from_proxy_config(&config, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_get(proxy, "/failing").await;

    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("\r\nConnection: close\r\n"));
    assert!(response.contains("content-type: text/html"));
    assert!(response.ends_with("native custom 502\n"));
}

#[tokio::test]
async fn native_proxy_falls_back_when_configured_error_page_is_too_large() {
    let errors = tempfile::tempdir().unwrap();
    let oversized = std::fs::File::create(errors.path().join("502.html")).unwrap();
    oversized.set_len(64 * 1024 * 1024 + 1).unwrap();
    let mut config = proxy_config_with_error_page(errors.path().to_path_buf());
    config.upstream = Some(unused_local_address().await.to_string());
    let proxy = NativeHttp1Proxy::from_proxy_config(&config, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_get(proxy, "/failing").await;

    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(!response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.ends_with("bad gateway\n"));
}

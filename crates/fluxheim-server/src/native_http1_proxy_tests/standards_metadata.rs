use std::time::Duration;

use crate::{NativeHttp1Proxy, NativeHttp1Upstream};
#[cfg(feature = "compression-gzip")]
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use super::{counting_upstream, downstream_get, proxy_listener_for, upstream};

fn metadata_headers() -> fluxheim_config::HeaderPolicyConfig {
    let mut headers = fluxheim_config::HeaderPolicyConfig::default();
    headers.response.metadata = fluxheim_config::ResponseMetadataConfig {
        identifier: Some("edge-gateway".to_owned()),
        cache_status: true,
        proxy_status: true,
        content_digest: true,
        repr_digest: true,
    };
    headers
}

fn response_header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response.lines().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

fn response_bytes_header<'a>(response: &'a [u8], name: &str) -> Option<&'a str> {
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    std::str::from_utf8(&response[..head_end])
        .ok()?
        .lines()
        .find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name
                .eq_ignore_ascii_case(name)
                .then_some(value.trim())
        })
}

fn response_body(response: &[u8]) -> &[u8] {
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    &response[head_end + 4..]
}

#[cfg(feature = "compression-gzip")]
fn digest_field_value(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!(
        "sha-256=:{}:",
        base64_ng::STANDARD.encode_string_infallible(digest.as_slice())
    )
}

async fn downstream_request(proxy: std::net::SocketAddr, request: &str) -> Vec<u8> {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn native_proxy_emits_rfc_9530_digests_for_complete_response() {
    let (upstream, _) = counting_upstream("hello", 1).await;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&metadata_headers());
    let response = downstream_get(proxy_listener_for(proxy).await, "/digest").await;

    let expected = "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:";
    assert_eq!(response_header(&response, "content-digest"), Some(expected));
    assert_eq!(response_header(&response, "repr-digest"), Some(expected));
    assert!(response.ends_with("hello"));
}

#[tokio::test]
async fn native_proxy_leaves_standards_metadata_disabled_by_default() {
    let (upstream, _) = counting_upstream("hello", 1).await;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()));
    let response = downstream_get(proxy_listener_for(proxy).await, "/default").await;

    assert_eq!(response_header(&response, "cache-status"), None);
    assert_eq!(response_header(&response, "proxy-status"), None);
    assert_eq!(response_header(&response, "content-digest"), None);
    assert_eq!(response_header(&response, "repr-digest"), None);
}

#[cfg(feature = "compression-gzip")]
#[tokio::test]
async fn native_proxy_digests_final_compressed_wire_content() {
    let body = "compressed metadata proof ".repeat(32);
    let upstream_body = body.clone();
    let upstream = upstream(move |_, mut stream| {
        let upstream_body = upstream_body.clone();
        async move {
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{}",
                        upstream_body.len(),
                        upstream_body
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    })
    .await;
    let compression = fluxheim_config::CompressionConfig {
        enabled: true,
        gzip: true,
        min_bytes: fluxheim_config::ByteSize::from_bytes(1),
        max_input_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_output_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        ..Default::default()
    };
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&metadata_headers())
        .with_compression_config(compression);
    let response = downstream_request(
        proxy_listener_for(proxy).await,
        "GET /compressed HTTP/1.1\r\nHost: proxy.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    )
    .await;
    let wire_body = response_body(&response);
    let expected = digest_field_value(wire_body);

    assert_eq!(
        response_bytes_header(&response, "content-encoding"),
        Some("gzip")
    );
    assert_eq!(
        response_bytes_header(&response, "content-digest"),
        Some(expected.as_str())
    );
    assert_eq!(
        response_bytes_header(&response, "repr-digest"),
        Some(expected.as_str())
    );
    assert_ne!(expected, digest_field_value(body.as_bytes()));
}

#[tokio::test]
async fn native_proxy_head_digests_empty_content_without_repr_digest() {
    let upstream = upstream(|request, mut stream| async move {
        assert!(request.starts_with(b"HEAD /head HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\netag: \"head\"\r\n\r\n")
            .await
            .unwrap();
    })
    .await;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&metadata_headers());
    let response = downstream_request(
        proxy_listener_for(proxy).await,
        "HEAD /head HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert_eq!(response_body(&response), b"");
    assert_eq!(
        response_bytes_header(&response, "content-digest"),
        Some("sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:")
    );
    assert_eq!(response_bytes_header(&response, "repr-digest"), None);
}

#[tokio::test]
async fn native_proxy_range_digests_partial_content_without_repr_digest() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
        assert!(request.contains("range: bytes=1-3\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 206 Partial Content\r\ncontent-range: bytes 1-3/5\r\ncontent-length: 3\r\n\r\nell",
            )
            .await
            .unwrap();
    })
    .await;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&metadata_headers());
    let response = downstream_request(
        proxy_listener_for(proxy).await,
        "GET /range HTTP/1.1\r\nHost: proxy.test\r\nRange: bytes=1-3\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert_eq!(response_body(&response), b"ell");
    assert_eq!(
        response_bytes_header(&response, "content-digest"),
        Some("sha-256=:uuqWUAmX/1zWz9Jlkql41rc9SAtK0z0AJJnPAEGsmZY=:")
    );
    assert_eq!(response_bytes_header(&response, "repr-digest"), None);
}

#[tokio::test]
async fn native_proxy_conditional_not_modified_digests_empty_content_only() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
        assert!(request.contains("if-none-match: \"current\"\r\n"));
        stream
            .write_all(b"HTTP/1.1 304 Not Modified\r\netag: \"current\"\r\n\r\n")
            .await
            .unwrap();
    })
    .await;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&metadata_headers());
    let response = downstream_request(
        proxy_listener_for(proxy).await,
        "GET /conditional HTTP/1.1\r\nHost: proxy.test\r\nIf-None-Match: \"current\"\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert_eq!(response_body(&response), b"");
    assert_eq!(
        response_bytes_header(&response, "content-digest"),
        Some("sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:")
    );
    assert_eq!(response_bytes_header(&response, "repr-digest"), None);
}

#[tokio::test]
async fn native_proxy_emits_rfc_9211_cache_status_from_real_outcomes() {
    let upstream = upstream(|_, mut stream| async move {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=60\r\ncontent-length: 6\r\n\r\ncached",
            )
            .await
            .unwrap();
    })
    .await;
    let cache = fluxheim_config::CacheConfig {
        enabled: true,
        default_status_ttl_secs: Some(60),
        memory: fluxheim_config::CacheMemoryConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_header_policy(&metadata_headers())
        .with_proxy_cache_config(&cache);
    let listener = proxy_listener_for(proxy).await;

    let miss = downstream_get(listener, "/cached.png").await;
    let hit = downstream_get(listener, "/cached.png").await;

    assert_eq!(
        response_header(&miss, "cache-status"),
        Some("edge-gateway; fwd=uri-miss; stored")
    );
    assert_eq!(
        response_header(&hit, "cache-status"),
        Some("edge-gateway; hit")
    );
    let expected = "sha-256=:NnMBTnK2c4O+MCSFaUVVpXrTk6/euu1t7REKd1vQVW0=:";
    assert_eq!(response_header(&miss, "content-digest"), Some(expected));
    assert_eq!(response_header(&hit, "content-digest"), Some(expected));
    assert_eq!(response_header(&hit, "repr-digest"), Some(expected));
    assert!(hit.ends_with("cached"));
}

#[tokio::test]
async fn native_proxy_emits_low_cardinality_rfc_9209_failure() {
    let unavailable_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable = unavailable_listener.local_addr().unwrap();
    drop(unavailable_listener);
    let proxy = NativeHttp1Proxy::new(
        NativeHttp1Upstream::new(unavailable.to_string())
            .with_connect_timeout(Duration::from_millis(100)),
    )
    .with_header_policy(&metadata_headers());
    let response = downstream_get(proxy_listener_for(proxy).await, "/failure").await;

    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "unexpected proxy failure response: {response:?}"
    );
    assert_eq!(
        response_header(&response, "proxy-status"),
        Some("edge-gateway; error=connection_refused")
    );
    assert!(!response.contains(&unavailable.to_string()));
}

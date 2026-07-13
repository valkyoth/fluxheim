use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::{NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute, ProxyProtocolTrustedSource};

use super::{downstream_request, proxy_for, route_proxy_listener};

#[tokio::test]
async fn native_route_proxy_request_header_builder_uses_secure_forwarded_defaults() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains("x-forwarded-for: 127.0.0.1\r\n"));
        assert!(request.contains("x-forwarded-host: route.test\r\n"));
        assert!(request.contains("x-forwarded-proto: http\r\n"));
        assert!(!request.to_ascii_lowercase().contains("cf-connecting-ip:"));
        assert!(!request.to_ascii_lowercase().contains("client-ip:"));
        assert!(!request.contains("x-forwarded-for: 192.0.2.9\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\nbaseline")
            .await
            .unwrap();
    });
    let policy = fluxheim_config::RequestHeaderPolicyOverlayConfig::default();
    let route = NativeHttp1RouteProxyRoute::prefix("/api/", Vec::new(), proxy_for(upstream))
        .with_request_header_policy(&policy);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /api/item HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 192.0.2.9\r\n\
         CF-Connecting-IP: 192.0.2.10\r\n\
         Client-IP: 192.0.2.11\r\n\
         Connection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("baseline"));
}

#[tokio::test]
async fn native_route_proxy_strip_append_does_not_preserve_spoofed_forwarded_chain() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains("x-forwarded-for: 127.0.0.1\r\n"));
        assert!(!request.contains("x-forwarded-for: 192.0.2.9, 127.0.0.1\r\n"));
        assert!(!request.to_ascii_lowercase().contains("true-client-ip:"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nappend")
            .await
            .unwrap();
    });
    let policy = fluxheim_config::RequestHeaderPolicyOverlayConfig {
        strip_inbound_client_ip_headers: Some(true),
        x_forwarded_for: Some(fluxheim_config::ForwardedClientIpHeaderMode::Append),
        ..Default::default()
    };
    let route = NativeHttp1RouteProxyRoute::prefix("/api/", Vec::new(), proxy_for(upstream))
        .with_request_header_policy(&policy);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /api/item HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 192.0.2.9\r\n\
         True-Client-IP: 192.0.2.10\r\n\
         Connection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("append"));
}

#[tokio::test]
async fn native_route_proxy_trusted_append_preserves_forwarded_chain() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).unwrap();
        assert!(
            request.contains("x-forwarded-for: 198.51.100.9, 203.0.113.10, 198.51.100.9\r\n"),
            "unexpected trusted append request: {request:?}"
        );
        assert!(
            request.contains("x-real-ip: 198.51.100.9\r\n"),
            "unexpected trusted append request: {request:?}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 14\r\n\r\ntrusted-append")
            .await
            .unwrap();
    });
    let policy = fluxheim_config::RequestHeaderPolicyOverlayConfig {
        strip_inbound_client_ip_headers: Some(false),
        x_forwarded_for: Some(fluxheim_config::ForwardedClientIpHeaderMode::Append),
        x_real_ip: Some(true),
        ..Default::default()
    };
    let route = NativeHttp1RouteProxyRoute::prefix("/api/", Vec::new(), proxy_for(upstream))
        .with_request_header_policy(&policy)
        .with_trusted_sources(&[
            ProxyProtocolTrustedSource::Ip("127.0.0.1".parse().unwrap()),
            ProxyProtocolTrustedSource::Ip("203.0.113.10".parse().unwrap()),
        ]);
    let proxy = route_proxy_listener(NativeHttp1RouteProxy::new(vec![route], None)).await;

    let response = downstream_request(
        proxy,
        "GET /api/item HTTP/1.1\r\n\
         Host: route.test\r\n\
         X-Forwarded-For: 198.51.100.9, 203.0.113.10\r\n\
         Connection: close\r\n\r\n",
    )
    .await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("trusted-append"));
}

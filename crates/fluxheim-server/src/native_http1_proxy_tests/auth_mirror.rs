#[cfg(feature = "auth-request")]
use std::sync::Arc;
#[cfg(feature = "auth-request")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(any(
    feature = "auth-request",
    all(feature = "traffic-mirror", not(feature = "privacy-mode"))
))]
use std::time::Duration;

#[cfg(any(
    feature = "auth-request",
    all(feature = "traffic-mirror", not(feature = "privacy-mode"))
))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(any(
    feature = "auth-request",
    all(feature = "traffic-mirror", not(feature = "privacy-mode"))
))]
use tokio::net::{TcpListener, TcpStream};

#[cfg(any(
    feature = "auth-request",
    all(feature = "traffic-mirror", not(feature = "privacy-mode"))
))]
use crate::native_http1_test_utils::read_request_head;
#[cfg(any(
    feature = "auth-request",
    all(feature = "traffic-mirror", not(feature = "privacy-mode"))
))]
use crate::{DownstreamHttp1Policy, NativeHttp1Proxy};

#[cfg(feature = "auth-request")]
use super::downstream_get;
#[cfg(any(
    feature = "auth-request",
    all(feature = "traffic-mirror", not(feature = "privacy-mode"))
))]
use super::{proxy_listener_for, upstream};

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
async fn mirror_endpoint() -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request_head(&mut stream).await;
        let request = String::from_utf8(request).unwrap();
        let _ = tx.send(request);
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    (addr, rx)
}

#[cfg(feature = "auth-request")]
async fn auth_endpoint(
    response: &'static [u8],
) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request_head(&mut stream).await;
        let request = String::from_utf8(request).unwrap();
        let _ = tx.send(request);
        stream.write_all(response).await.unwrap();
    });
    (addr, rx)
}

#[cfg(feature = "auth-request")]
async fn stalled_auth_endpoint() -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_request_head(&mut stream).await;
        let _ = accepted_tx.send(());
        let _ = release_rx.await;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    (addr, accepted_rx, release_tx)
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
#[tokio::test]
async fn native_proxy_mirrors_safe_requests_without_changing_origin_response() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(!request.contains("\r\nx-fluxheim-mirror:"));
        assert!(!request.contains("\r\nx-fluxheim-mirror-signature:"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\norigin-ok")
            .await
            .unwrap();
    })
    .await;
    let (mirror, mirror_rx) = mirror_endpoint().await;
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        mirror: fluxheim_config::TrafficMirrorConfig {
            enabled: true,
            base_url: Some(format!("http://{mirror}/shadow")),
            sample_per_mille: 1000,
            methods: vec!["GET".to_owned()],
            forward_headers: vec!["x-request-id".to_owned()],
            timeout_secs: 2,
            max_response_bytes: fluxheim_config::ByteSize::from_bytes(1024),
            max_in_flight: 1,
        },
        ..Default::default()
    };
    let proxy = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET /asset.png?q=1 HTTP/1.1\r\n\
              Host: proxy.test\r\n\
              X-Request-Id: mirror-1\r\n\
              X-Fluxheim-Mirror: 1\r\n\
              X-Fluxheim-Mirror-Signature: attacker\r\n\
              Connection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    let mirrored = tokio::time::timeout(Duration::from_secs(2), mirror_rx)
        .await
        .unwrap()
        .unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("origin-ok"));
    assert!(mirrored.starts_with("GET /shadow/asset.png?q=1 HTTP/1.1\r\n"));
    assert!(mirrored.contains("\r\nx-fluxheim-mirror: 1\r\n"));
    assert!(mirrored.contains("\r\nx-fluxheim-mirror-signature: "));
    assert!(mirrored.contains("\r\nx-request-id: mirror-1\r\n"));
}

#[cfg(feature = "auth-request")]
#[tokio::test]
async fn native_proxy_auth_request_allows_and_injects_response_headers() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains("\r\nx-auth-request-user: alice\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\norigin-ok")
            .await
            .unwrap();
    })
    .await;
    let (auth, auth_rx) = auth_endpoint(
        b"HTTP/1.1 204 No Content\r\nx-auth-request-user: alice\r\ncontent-length: 0\r\n\r\n",
    )
    .await;
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        auth_request: fluxheim_config::AuthRequestConfig {
            enabled: true,
            url: Some(format!("http://{auth}/auth")),
            forward_headers: vec![
                "x-original-uri".to_owned(),
                "x-forwarded-host".to_owned(),
                "cookie".to_owned(),
            ],
            allow_response_headers: vec!["x-auth-request-user".to_owned()],
            connect_timeout_secs: 1,
            read_timeout_secs: 1,
            max_response_bytes: fluxheim_config::ByteSize::from_bytes(1024),
            max_in_flight: 64,
        },
        ..Default::default()
    };
    let proxy = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET /private?x=1 HTTP/1.1\r\n\
              Host: proxy.test\r\n\
              Cookie: a=1\r\n\
              Cookie: b=2\r\n\
              Connection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    let auth_request = tokio::time::timeout(Duration::from_secs(2), auth_rx)
        .await
        .unwrap()
        .unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("origin-ok"));
    assert!(auth_request.starts_with("GET /auth HTTP/1.1\r\n"));
    assert!(auth_request.contains("\r\nx-original-uri: /private?x=1\r\n"));
    assert!(auth_request.contains("\r\nx-forwarded-host: proxy.test\r\n"));
    assert!(auth_request.contains("\r\ncookie: a=1; b=2\r\n"));
}

#[cfg(feature = "auth-request")]
#[tokio::test]
async fn native_proxy_auth_request_denies_before_upstream_forwarding() {
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let upstream_hits_for_task = Arc::clone(&upstream_hits);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((_, _)) = listener.accept().await {
            upstream_hits_for_task.fetch_add(1, Ordering::Relaxed);
        }
    });
    let (auth, _auth_rx) =
        auth_endpoint(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 7\r\n\r\ndenied\n").await;
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        auth_request: fluxheim_config::AuthRequestConfig {
            enabled: true,
            url: Some(format!("http://{auth}/auth")),
            connect_timeout_secs: 1,
            read_timeout_secs: 1,
            max_response_bytes: fluxheim_config::ByteSize::from_bytes(1024),
            ..Default::default()
        },
        ..Default::default()
    };
    let proxy = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_get(proxy, "/private").await;

    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response.ends_with("denied\n"));
    assert_eq!(upstream_hits.load(Ordering::Relaxed), 0);
}

#[cfg(feature = "auth-request")]
#[tokio::test]
async fn native_proxy_auth_request_rejects_before_submitting_saturated_blocking_work() {
    let origin = upstream(|_request, mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
            .await
            .unwrap();
    })
    .await;
    let (auth, accepted, release) = stalled_auth_endpoint().await;
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some(origin.to_string()),
        auth_request: fluxheim_config::AuthRequestConfig {
            enabled: true,
            url: Some(format!("http://{auth}/auth")),
            connect_timeout_secs: 1,
            read_timeout_secs: 2,
            max_in_flight: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let proxy = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let first = tokio::spawn(async move { downstream_get(proxy, "/private").await });
    tokio::time::timeout(Duration::from_secs(1), accepted)
        .await
        .unwrap()
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(1), downstream_get(proxy, "/private"))
        .await
        .unwrap();
    assert!(second.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(second.ends_with("auth_request failed\n"));

    let _ = release.send(());
    let first = first.await.unwrap();
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("ok"));
}

use super::*;

async fn exchange(proxy: std::net::SocketAddr, request: &[u8]) -> String {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut result = Vec::new();
        client.take(8192).read_to_end(&mut result).await.unwrap();
        String::from_utf8(result).unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn auth_websocket_currently_bypasses_rejecting_auth_service() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&hits);
    let auth_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = crate::native_http1_test_utils::read_request_head(&mut stream).await;
            count.fetch_add(1, Ordering::SeqCst);
            stream
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        }
    });
    let origin = upstream(|_, mut stream| async move {
        stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: test-accept\r\n\r\n").await.unwrap();
    }).await;
    let config = fluxheim_config::ProxyConfig {
        upstream: Some(origin.to_string()),
        websocket: true,
        auth_request: fluxheim_config::AuthRequestConfig {
            enabled: true,
            url: Some(format!("http://{auth}/auth")),
            ..Default::default()
        },
        ..Default::default()
    };
    config.validate().unwrap();
    let proxy = NativeHttp1Proxy::from_proxy_config(&config, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;
    let denied = exchange(
        proxy,
        b"GET /ws HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(denied.starts_with("HTTP/1.1 403 "));
    let upgraded = exchange(proxy, b"GET /ws HTTP/1.1\r\nHost: proxy.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: test-key\r\nSec-WebSocket-Version: 13\r\n\r\n").await;
    auth_task.abort();
    let _ = auth_task.await;
    // documented contract: changing only the request to an upgrade bypasses auth.
    assert!(upgraded.starts_with("HTTP/1.1 101 "), "{upgraded}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn auth_missing_identity_response_currently_preserves_client_identity() {
    let auth = upstream(|_, mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    })
    .await;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = std::sync::Mutex::new(Some(tx));
    let origin = upstream(move |request, mut stream| {
        tx.lock().unwrap().take().unwrap().send(request).unwrap();
        async move {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        }
    })
    .await;
    let config = fluxheim_config::ProxyConfig {
        upstream: Some(origin.to_string()),
        auth_request: fluxheim_config::AuthRequestConfig {
            enabled: true,
            url: Some(format!("http://{auth}/auth")),
            allow_response_headers: vec!["x-auth-request-user".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let proxy = NativeHttp1Proxy::from_proxy_config(&config, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    let proxy = proxy_listener_for(proxy).await;
    let response = exchange(proxy, b"GET /private HTTP/1.1\r\nHost: proxy.test\r\nX-Auth-Request-User: attacker\r\nConnection: close\r\n\r\n").await;
    assert!(response.starts_with("HTTP/1.1 200 "));
    let request = tokio::time::timeout(Duration::from_secs(1), rx)
        .await
        .unwrap()
        .unwrap();
    // documented contract: the response allowlist is not an inbound identity scrubber.
    assert!(
        String::from_utf8(request)
            .unwrap()
            .to_ascii_lowercase()
            .contains("\r\nx-auth-request-user: attacker\r\n")
    );
}

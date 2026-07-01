#[cfg(feature = "load-balancer")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "load-balancer")]
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[cfg(feature = "load-balancer")]
use crate::DownstreamHttp1Policy;
use crate::{NativeHttp1Proxy, NativeHttp1Upstream};

use super::{proxy_listener_for, upstream};

#[tokio::test]
async fn native_proxy_websocket_upgrade_tunnels_prebuffered_bytes() {
    let upstream = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        let lower_request = request.to_ascii_lowercase();
        assert!(request.starts_with("GET /ws HTTP/1.1\r\n"));
        assert!(
            lower_request
                .lines()
                .any(|line| line.starts_with("connection:") && line.contains("upgrade"))
        );
        assert!(lower_request.contains("upgrade: websocket\r\n"));
        assert!(lower_request.contains("sec-websocket-key: test-key\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\
                  Sec-WebSocket-Accept: test-accept\r\n\r\n",
            )
            .await
            .unwrap();
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").await.unwrap();
        stream.flush().await.unwrap();
    })
    .await;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_websocket_enabled(true);
    let proxy = proxy_listener_for(proxy).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET /ws HTTP/1.1\r\n\
              Host: proxy.test\r\n\
              Connection: keep-alive, Upgrade\r\n\
              Upgrade: websocket\r\n\
              Sec-WebSocket-Key: test-key\r\n\
              Sec-WebSocket-Version: 13\r\n\r\nping",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    let mut chunk = [0u8; 128];
    loop {
        let read = client.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "connection closed before websocket response");
        response.extend_from_slice(&chunk[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let response_head_len = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap();
    let mut tunneled = response[response_head_len..].to_vec();
    let response_head = String::from_utf8(response[..response_head_len].to_vec()).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert!(response_head.contains("upgrade: websocket\r\n"));
    assert!(response_head.contains("sec-websocket-accept: test-accept\r\n"));
    while tunneled.len() < 4 {
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).await.unwrap();
        tunneled.push(byte[0]);
    }
    assert_eq!(&tunneled[..4], b"pong");
}

#[cfg(feature = "load-balancer")]
#[tokio::test]
async fn native_proxy_websocket_upgrade_uses_native_load_balancer_selection() {
    let (request_tx, request_rx) = tokio::sync::oneshot::channel::<String>();
    let request_tx = Arc::new(Mutex::new(Some(request_tx)));
    let first_request_tx = Arc::clone(&request_tx);
    let first_upstream = upstream(move |request, mut stream| {
        let request_tx = Arc::clone(&first_request_tx);
        async move {
            let request = String::from_utf8(request).unwrap();
            if let Some(request_tx) = request_tx.lock().unwrap().take() {
                let _ = request_tx.send(request);
            }
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\
                  Sec-WebSocket-Accept: test-accept\r\n\r\n",
                )
                .await
                .unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.unwrap();
        }
    })
    .await;
    let second_upstream = upstream(move |request, mut stream| {
        let request_tx = Arc::clone(&request_tx);
        async move {
            let request = String::from_utf8(request).unwrap();
            if let Some(request_tx) = request_tx.lock().unwrap().take() {
                let _ = request_tx.send(request);
            }
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                  Connection: Upgrade\r\n\
                  Upgrade: websocket\r\n\
                  Sec-WebSocket-Accept: test-accept\r\n\r\n",
                )
                .await
                .unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.unwrap();
        }
    })
    .await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstreams: vec![first_upstream.to_string(), second_upstream.to_string()],
        websocket: true,
        load_balance: fluxheim_config::LoadBalanceConfig {
            health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let (proxy, service) = NativeHttp1Proxy::from_proxy_config_with_native_load_balancer(
        "websocket-lb",
        "websocket.test",
        None,
        &proxy_config,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap()
    .expect("native proxy");
    assert!(service.is_none());
    let proxy = proxy_listener_for(proxy).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET /ws-lb HTTP/1.1\r\n\
              Host: proxy.test\r\n\
              Connection: Upgrade\r\n\
              Upgrade: websocket\r\n\
              Sec-WebSocket-Key: test-key\r\n\
              Sec-WebSocket-Version: 13\r\n\r\nping",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    let mut chunk = [0u8; 128];
    loop {
        let read = client.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "connection closed before websocket response");
        response.extend_from_slice(&chunk[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let response_head_len = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap();
    let mut tunneled = response[response_head_len..].to_vec();
    while tunneled.len() < 4 {
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).await.unwrap();
        tunneled.push(byte[0]);
    }
    assert!(
        String::from_utf8(response[..response_head_len].to_vec())
            .unwrap()
            .starts_with("HTTP/1.1 101 Switching Protocols\r\n")
    );
    assert_eq!(&tunneled[..4], b"pong");
    let request = tokio::time::timeout(Duration::from_secs(1), request_rx)
        .await
        .unwrap()
        .unwrap();
    let lower_request = request.to_ascii_lowercase();
    assert!(request.starts_with("GET /ws-lb HTTP/1.1\r\n"));
    assert!(lower_request.contains("upgrade: websocket\r\n"));
}

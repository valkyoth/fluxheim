use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::native_http1_test_utils::read_request_head;
use crate::{
    DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1Upstream, serve_native_http1_listener,
};

use super::{downstream_get, proxy_listener_for, upstream};

async fn pooled_proxy_listener(upstream: std::net::SocketAddr) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = Arc::new(NativeHttp1Proxy::new(
        NativeHttp1Upstream::new(upstream.to_string()).with_pool_max_idle(1),
    ));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_native_http1_listener(listener, DownstreamHttp1Policy::default(), proxy, async {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _ = shutdown_tx.send(());
    });
    addr
}

#[tokio::test]
async fn native_proxy_reuses_origin_connection_for_separate_downstream_clients() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_for_task = Arc::clone(&accepted);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        accepted_for_task.fetch_add(1, Ordering::AcqRel);

        let first = String::from_utf8(read_request_head(&mut stream).await).unwrap();
        assert!(first.starts_with("GET /one HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\none")
            .await
            .unwrap();

        let second = String::from_utf8(read_request_head(&mut stream).await).unwrap();
        assert!(second.starts_with("GET /two HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\ntwo")
            .await
            .unwrap();
    });
    let proxy = pooled_proxy_listener(upstream).await;

    let first = downstream_get(proxy, "/one").await;
    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first.ends_with("one"));

    let second = downstream_get(proxy, "/two").await;
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.ends_with("two"));

    assert_eq!(accepted.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn native_proxy_writes_upstream_proxy_protocol_v1_from_listener_context() {
    let expected_destination_port = Arc::new(AtomicUsize::new(0));
    #[cfg(not(feature = "privacy-mode"))]
    let expected_destination_port_for_upstream = Arc::clone(&expected_destination_port);
    let upstream = upstream(move |request, mut stream| {
        #[cfg(not(feature = "privacy-mode"))]
        let expected_destination_port = Arc::clone(&expected_destination_port_for_upstream);
        async move {
            let request = String::from_utf8(request).unwrap();
            let proxy_line = request.lines().next().unwrap_or_default();
            let fields: Vec<_> = proxy_line.split_whitespace().collect();
            #[cfg(feature = "privacy-mode")]
            {
                assert_eq!(fields, ["PROXY", "UNKNOWN"]);
            }
            #[cfg(not(feature = "privacy-mode"))]
            {
                assert_eq!(fields.len(), 6);
                assert_eq!(fields[0], "PROXY");
                assert_eq!(fields[1], "TCP4");
                assert_eq!(fields[2], "127.0.0.1");
                assert_eq!(fields[3], "127.0.0.1");
                assert_ne!(fields[4], "0");
                assert_eq!(
                    fields[5],
                    expected_destination_port
                        .load(Ordering::Acquire)
                        .to_string()
                );
            }
            assert!(request.contains("GET /proxy-protocol HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                .await
                .unwrap();
        }
    })
    .await;
    let proxy = NativeHttp1Proxy::new(
        NativeHttp1Upstream::new(upstream.to_string())
            .with_proxy_protocol(fluxheim_config::UpstreamProxyProtocol::V1),
    );
    let proxy_addr = proxy_listener_for(proxy).await;
    expected_destination_port.store(proxy_addr.port() as usize, Ordering::Release);

    let response = downstream_get(proxy_addr, "/proxy-protocol").await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("ok"));
}

#[tokio::test]
async fn native_proxy_maps_upstream_timeout_to_gateway_timeout() {
    let upstream = upstream(|_, stream| async move {
        let _hold_open = stream;
        tokio::time::sleep(Duration::from_secs(5)).await;
    })
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let proxy = Arc::new(NativeHttp1Proxy::new(
        NativeHttp1Upstream::new(upstream.to_string()).with_read_timeout(Duration::from_millis(25)),
    ));
    tokio::spawn(async move {
        serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default(),
            proxy,
            std::future::pending::<()>(),
        )
        .await
        .unwrap();
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"GET /slow HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"));
    assert!(response.ends_with("gateway timeout\n"));
}

#[tokio::test]
async fn native_proxy_request_body_timeout_is_enforced_before_upstream() {
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let upstream_hits_for_task = Arc::clone(&upstream_hits);
    let upstream = upstream(move |_, mut stream| {
        let upstream_hits = Arc::clone(&upstream_hits_for_task);
        async move {
            upstream_hits.fetch_add(1, Ordering::AcqRel);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nunexpected")
                .await
                .unwrap();
        }
    })
    .await;
    let proxy = NativeHttp1Proxy::new(NativeHttp1Upstream::new(upstream.to_string()))
        .with_request_body_timeout(Some(Duration::from_millis(25)));
    let proxy = proxy_listener_for(proxy).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();

    stream
        .write_all(
            b"POST /slow HTTP/1.1\r\nHost: proxy.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .unwrap()
        .unwrap();

    assert_ne!(read, 0);
    let mut response = vec![byte[0]];
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 408 Request Timeout\r\n"));
    assert!(response.ends_with("request timeout\n"));
    assert_eq!(upstream_hits.load(Ordering::Acquire), 0);
}

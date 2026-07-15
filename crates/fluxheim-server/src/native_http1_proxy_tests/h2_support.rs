use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::net::TcpListener;

pub(super) async fn h2_upstream(requests: usize) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let accepted_connections_for_task = Arc::clone(&accepted_connections);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accepted_connections_for_task.fetch_add(1, Ordering::AcqRel);
        let mut connection = h2::server::handshake(stream).await.unwrap();
        for index in 0..requests {
            let Some(stream) = connection.accept().await else {
                panic!("expected native H2 upstream request");
            };
            let (request, mut respond) = stream.unwrap();
            assert_eq!(request.method(), http::Method::GET);
            assert_eq!(
                request.uri().path_and_query().unwrap().as_str(),
                "/h2-origin"
            );
            assert_eq!(request.uri().authority().unwrap().as_str(), "proxy.test");
            assert_eq!(request.headers().get("x-test").unwrap(), "h2");
            assert!(request.headers().get("host").is_none());
            assert!(request.headers().get("connection").is_none());
            assert!(request.headers().get("via").is_some());
            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header("x-origin-proto", "h2")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from(format!("h2 upstream {index}\n")), true)
                .unwrap();
        }
        connection.graceful_shutdown();
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|context| connection.poll_closed(context)),
        )
        .await;
    });
    (addr, accepted_connections)
}

pub(super) async fn h2_idle_upstream() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let accepted_connections_for_task = Arc::clone(&accepted_connections);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accepted_connections_for_task.fetch_add(1, Ordering::AcqRel);
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(1), connection.accept()).await;
    });
    (addr, accepted_connections)
}

pub(super) async fn h2_upstream_with_body(
    body: &'static str,
    requests: usize,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let accepted_connections_for_task = Arc::clone(&accepted_connections);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accepted_connections_for_task.fetch_add(1, Ordering::AcqRel);
        let mut connection = h2::server::handshake(stream).await.unwrap();
        for _ in 0..requests {
            let Some(stream) = connection.accept().await else {
                panic!("expected native H2 upstream request");
            };
            let (request, mut respond) = stream.unwrap();
            assert_eq!(request.method(), http::Method::GET);
            assert_eq!(
                request.uri().path_and_query().unwrap().as_str(),
                "/h2-origin"
            );
            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header("x-origin-proto", "h2")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from_static(body.as_bytes()), true)
                .unwrap();
        }
        connection.graceful_shutdown();
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|context| connection.poll_closed(context)),
        )
        .await;
    });
    (addr, accepted_connections)
}

pub(super) async fn h2_upstream_receiving_body(expected: &'static [u8]) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let Some(stream) = connection.accept().await else {
            panic!("expected native H2 upstream request body");
        };
        let (request, mut respond) = stream.unwrap();
        let mut handler = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut body = request.into_body();
            while received.len() < expected.len() {
                let Some(chunk) = body.data().await else {
                    panic!("native H2 upstream request body ended early");
                };
                let chunk = chunk.unwrap();
                received.extend_from_slice(&chunk);
                body.flow_control().release_capacity(chunk.len()).unwrap();
            }
            assert_eq!(received, expected);
            let response = http::Response::builder()
                .status(http::StatusCode::NO_CONTENT)
                .body(())
                .unwrap();
            respond.send_response(response, true).unwrap();
        });
        loop {
            tokio::select! {
                result = &mut handler => {
                    result.unwrap();
                    break;
                }
                stream = connection.accept() => {
                    if stream.is_some() {
                        panic!("unexpected second native H2 upstream request");
                    }
                }
            }
        }
        connection.graceful_shutdown();
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|context| connection.poll_closed(context)),
        )
        .await;
    });
    addr
}

pub(super) async fn h2_reconnecting_upstream(
    body: &'static str,
    connections: usize,
) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let accepted_connections_for_task = Arc::clone(&accepted_connections);
    tokio::spawn(async move {
        for _ in 0..connections {
            let (stream, _) = listener.accept().await.unwrap();
            accepted_connections_for_task.fetch_add(1, Ordering::AcqRel);
            let mut connection = h2::server::handshake(stream).await.unwrap();
            let Some(stream) = connection.accept().await else {
                panic!("expected native H2 upstream request");
            };
            let (_request, mut respond) = stream.unwrap();
            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header("x-origin-proto", "h2")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            send.send_data(Bytes::from_static(body.as_bytes()), true)
                .unwrap();
            connection.graceful_shutdown();
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                std::future::poll_fn(|context| connection.poll_closed(context)),
            )
            .await;
        }
    });
    (addr, accepted_connections)
}

pub(super) async fn h2_reset_then_ok_upstream() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let accepted_connections_for_task = Arc::clone(&accepted_connections);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accepted_connections_for_task.fetch_add(1, Ordering::AcqRel);
        let mut connection = h2::server::handshake(stream).await.unwrap();

        let Some(stream) = connection.accept().await else {
            panic!("expected first native H2 upstream request");
        };
        let (_request, mut respond) = stream.unwrap();
        respond.send_reset(h2::Reason::CANCEL);

        let Some(stream) = connection.accept().await else {
            panic!("expected second native H2 upstream request");
        };
        let (_request, mut respond) = stream.unwrap();
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("x-origin-proto", "h2")
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        send.send_data(Bytes::from_static(b"h2 survived reset\n"), true)
            .unwrap();

        connection.graceful_shutdown();
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|context| connection.poll_closed(context)),
        )
        .await;
    });
    (addr, accepted_connections)
}

pub(super) async fn h2_blocking_upstream()
-> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let Some(stream) = connection.accept().await else {
            panic!("expected native H2 upstream request");
        };
        let (_request, _respond) = stream.unwrap();
        let _ = accepted_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            std::future::pending::<()>().await;
        })
        .await;
    });
    (addr, accepted_rx)
}

pub(super) async fn h2_handshake_stall_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            std::future::pending::<()>().await;
        })
        .await;
    });
    addr
}

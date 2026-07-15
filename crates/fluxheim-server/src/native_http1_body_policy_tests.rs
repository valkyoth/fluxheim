use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use crate::native_http1_tests::{read_response, spawn_server, spawn_server_with_policy};
use crate::{
    DownstreamHttp1Policy, NativeHttp1Error, NativeHttp1Request, NativeHttp1Response,
    serve_native_http1_connection, serve_native_http1_listener,
};

#[tokio::test]
async fn native_http1_reads_content_length_body() {
    let addr = spawn_server(|request| {
        NativeHttp1Response::new(200, "OK", format!("{} bytes", request.body.len()))
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"POST /upload HTTP/1.1\r\nHost: local.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("5 bytes"));
}

#[tokio::test]
async fn native_http1_reads_chunked_body() {
    let addr = spawn_server(|request| {
        NativeHttp1Response::new(200, "OK", String::from_utf8(request.body.to_vec()).unwrap())
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"POST /upload HTTP/1.1\r\nHost: local.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("hello"));
}

#[tokio::test]
async fn native_http1_preserves_pipelined_request_after_chunked_body() {
    let addr = spawn_server(|request| {
        NativeHttp1Response::new(
            200,
            "OK",
            format!(
                "{}:{}",
                request.target,
                String::from_utf8_lossy(&request.body)
            ),
        )
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"POST /one HTTP/1.1\r\nHost: local.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET /two HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert_eq!(response.matches("HTTP/1.1 200 OK\r\n").count(), 2);
    assert!(response.contains("/one:hello"));
    assert!(response.ends_with("/two:"));
}

#[tokio::test]
async fn native_http1_preserves_pipelined_request_after_fragmented_final_chunk() {
    let addr = spawn_server(|request| {
        NativeHttp1Response::new(
            200,
            "OK",
            format!(
                "{}:{}",
                request.target,
                String::from_utf8_lossy(&request.body)
            ),
        )
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.set_nodelay(true).unwrap();

    stream
        .write_all(
            b"POST /one HTTP/1.1\r\nHost: local.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhe",
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    stream
        .write_all(
            b"llo\r\n0\r\n\r\nGET /two HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert_eq!(response.matches("HTTP/1.1 200 OK\r\n").count(), 2);
    assert!(response.contains("/one:hello"));
    assert!(response.ends_with("/two:"));
}

#[tokio::test]
async fn native_http1_preserves_pipelined_request_after_content_length_body() {
    let addr = spawn_server(|request| {
        NativeHttp1Response::new(
            200,
            "OK",
            format!(
                "{}:{}",
                request.target,
                String::from_utf8_lossy(&request.body)
            ),
        )
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"POST /one HTTP/1.1\r\nHost: local.test\r\nContent-Length: 5\r\n\r\nhelloGET /two HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert_eq!(response.matches("HTTP/1.1 200 OK\r\n").count(), 2);
    assert!(response.contains("/one:hello"));
    assert!(response.ends_with("/two:"));
}

#[tokio::test]
async fn native_http1_rejects_overflow_sized_chunk_header() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (result_tx, result_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        let handler = Arc::new(|_| async { NativeHttp1Response::new(200, "OK", b"unexpected") });
        let result =
            serve_native_http1_connection(stream, Some(peer_addr), Default::default(), handler)
                .await;
        let _ = result_tx.send(result);
    });
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"POST /upload HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nffffffffffffffff\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let result = result_rx.await.unwrap();

    assert!(matches!(
        result,
        Err(NativeHttp1Error::Parse(
            fluxheim_protocol::Http1ParseError::ChunkTooLarge
        ))
    ));
}

#[tokio::test]
async fn native_http1_enforces_configured_body_limit() {
    let policy = DownstreamHttp1Policy::from_server_limits(fluxheim_config::ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_request_headers: 32,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(4),
        max_buffered_request_body_bytes: fluxheim_config::ByteSize::from_bytes(4),
    });
    let addr = spawn_server_with_policy(policy, |_| {
        NativeHttp1Response::new(200, "OK", b"unexpected")
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"POST /upload HTTP/1.1\r\nHost: local.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.ends_with("payload too large\n"));
}

#[tokio::test]
async fn rejects_header_bytes_over_global_limit() {
    let policy = DownstreamHttp1Policy::from_server_limits(fluxheim_config::ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(64),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_request_headers: 32,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_buffered_request_body_bytes: fluxheim_config::ByteSize::from_bytes(1024),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (result_tx, result_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        let handler = Arc::new(|_| async { NativeHttp1Response::new(200, "OK", b"unexpected") });
        let result = serve_native_http1_connection(stream, Some(peer_addr), policy, handler).await;
        let _ = result_tx.send(result);
    });
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: local.test\r\nX-Oversized: abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    let result = result_rx.await.unwrap();

    assert!(response.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"));
    assert!(response.ends_with("request header fields too large\n"));
    assert!(result.is_ok());
}

#[tokio::test]
async fn native_http1_times_out_slow_request_head() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(|_| async { NativeHttp1Response::new(200, "OK", b"unexpected") });
    let join = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        serve_native_http1_connection(
            stream,
            Some(peer_addr),
            DownstreamHttp1Policy::default().with_request_head_timeout(Duration::from_millis(10)),
            handler,
        )
        .await
    });

    let _stream = TcpStream::connect(addr).await.unwrap();
    let error = join.await.unwrap().unwrap_err();

    assert!(matches!(
        error,
        crate::NativeHttp1Error::Io(ref io_error)
            if io_error.kind() == std::io::ErrorKind::TimedOut
    ));
}

#[tokio::test]
async fn native_http1_times_out_slow_request_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(|_| async { NativeHttp1Response::new(200, "OK", b"unexpected") });
    let join = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        serve_native_http1_connection(
            stream,
            Some(peer_addr),
            DownstreamHttp1Policy::default().with_request_body_timeout(Duration::from_millis(10)),
            handler,
        )
        .await
    });
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(
            b"POST / HTTP/1.1\r\nHost: local.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    join.await.unwrap().unwrap();
    assert!(response.starts_with("HTTP/1.1 408 Request Timeout\r\n"));
    assert!(response.ends_with("request timeout\n"));
}

#[tokio::test]
async fn native_http1_listener_drops_connections_over_budget() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handler = Arc::new(|_| async { NativeHttp1Response::new(200, "OK", b"unexpected") });
    let join = tokio::spawn(async move {
        serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default()
                .with_max_connections(1)
                .with_request_head_timeout(Duration::from_secs(5)),
            handler,
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
        .unwrap();
    });
    let held_stream = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buffer = [0u8; 1];
    let read_result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer))
        .await
        .unwrap();
    match read_result {
        Ok(read) => assert_eq!(read, 0),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(error) => panic!("unexpected read error: {error}"),
    }

    drop(held_stream);
    shutdown_tx.send(()).unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn native_http1_listener_serves_until_shutdown() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handler =
        Arc::new(|_| async { NativeHttp1Response::new(200, "OK", b"listener".as_slice()) });
    let join = tokio::spawn(async move {
        serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default(),
            handler,
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
        .unwrap();
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;
    assert!(response.ends_with("listener"));

    shutdown_tx.send(()).unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn native_http1_listener_drains_existing_keep_alive_after_shutdown() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handler = Arc::new(|request: NativeHttp1Request| async move {
        NativeHttp1Response::new(200, "OK", request.target)
    });
    let mut join = tokio::spawn(async move {
        serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default(),
            handler,
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
        .unwrap();
    });

    let mut established = TcpStream::connect(addr).await.unwrap();
    established
        .write_all(b"GET /before HTTP/1.1\r\nHost: local.test\r\n\r\n")
        .await
        .unwrap();
    let before = read_response(&mut established).await;
    assert!(before.ends_with("/before"));

    shutdown_tx.send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(
        !join.is_finished(),
        "listener exited before keep-alive drain"
    );

    let mut refused = false;
    for _ in 0..20 {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                drop(stream);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Err(_) => {
                refused = true;
                break;
            }
        }
    }
    assert!(refused, "draining listener continued accepting connections");

    established
        .write_all(b"GET /during-drain HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let during_drain = read_response(&mut established).await;
    assert!(during_drain.ends_with("/during-drain"));

    tokio::time::timeout(Duration::from_secs(1), &mut join)
        .await
        .unwrap()
        .unwrap();
}

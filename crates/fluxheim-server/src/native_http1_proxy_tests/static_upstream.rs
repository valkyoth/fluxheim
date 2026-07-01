use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{NativeHttp1Proxy, NativeHttp1Upstream};

use super::{
    counting_upstream, downstream_get, failover_proxy_listener, proxy_listener_for,
    unused_local_address, upstream,
};

#[tokio::test]
async fn native_proxy_fails_over_get_to_second_static_upstream() {
    let first = unused_local_address().await;
    let second = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /failover HTTP/1.1\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 15\r\nx-origin: second\r\n\r\nsecond upstream",
            )
            .await
            .unwrap();
    })
    .await;
    let proxy = failover_proxy_listener(first, second).await;

    let response = downstream_get(proxy, "/failover").await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("x-origin: second\r\n"));
    assert!(response.ends_with("second upstream"));
}

#[tokio::test]
async fn native_proxy_round_robins_successful_static_upstreams() {
    let first = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /balanced HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-origin: one\r\n\r\none-1")
            .await
            .unwrap();
    })
    .await;
    let second = upstream(|request, mut stream| async move {
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /balanced HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-origin: two\r\n\r\ntwo-2")
            .await
            .unwrap();
    })
    .await;
    let proxy = failover_proxy_listener(first, second).await;

    let first_response = downstream_get(proxy, "/balanced").await;
    let second_response = downstream_get(proxy, "/balanced").await;

    assert!(first_response.contains("x-origin: one\r\n"));
    assert!(first_response.ends_with("one-1"));
    assert!(second_response.contains("x-origin: two\r\n"));
    assert!(second_response.ends_with("two-2"));
}

#[tokio::test]
async fn native_proxy_weighted_round_robins_static_upstreams() {
    let (first, first_count) = counting_upstream("one", 2).await;
    let (second, second_count) = counting_upstream("two", 1).await;
    let proxy = NativeHttp1Proxy::from_weighted_upstreams(
        vec![
            NativeHttp1Upstream::new(first.to_string()),
            NativeHttp1Upstream::new(second.to_string()),
        ],
        &[2, 1],
    )
    .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let first_response = downstream_get(proxy, "/weighted").await;
    let second_response = downstream_get(proxy, "/weighted").await;
    let third_response = downstream_get(proxy, "/weighted").await;

    assert!(first_response.ends_with("one"));
    assert!(second_response.ends_with("one"));
    assert!(third_response.ends_with("two"));
    assert_eq!(first_count.load(Ordering::Relaxed), 2);
    assert_eq!(second_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn native_proxy_weighted_failover_skips_duplicate_slots() {
    let first = unused_local_address().await;
    let (second, second_count) = counting_upstream("second", 1).await;
    let proxy = NativeHttp1Proxy::from_weighted_upstreams(
        vec![
            NativeHttp1Upstream::new(first.to_string())
                .with_connect_timeout(Duration::from_millis(25)),
            NativeHttp1Upstream::new(second.to_string())
                .with_connect_timeout(Duration::from_millis(25)),
        ],
        &[2, 1],
    )
    .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_get(proxy, "/weighted-failover").await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.ends_with("second"));
    assert_eq!(second_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn native_proxy_does_not_fail_over_unsafe_method() {
    let first = unused_local_address().await;
    let second = upstream(|_, mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nsecond")
            .await
            .unwrap();
    })
    .await;
    let proxy = failover_proxy_listener(first, second).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"POST /submit HTTP/1.1\r\nHost: proxy.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.ends_with("bad gateway\n"));
}

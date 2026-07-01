use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{
    DownstreamHttp1Policy, DownstreamHttp2Policy, NativeHttp1Error, NativeHttp1Proxy,
    NativeHttp1ProxyConfigError, NativeHttp1Upstream,
};

use super::{
    downstream_get, native_proxy_test_request_for, proxy_listener_for,
    static_load_balance_without_health_check, unused_local_address,
};

#[path = "h2_support.rs"]
mod support;

use support::{
    h2_blocking_upstream, h2_handshake_stall_upstream, h2_idle_upstream, h2_reconnecting_upstream,
    h2_reset_then_ok_upstream, h2_upstream, h2_upstream_with_body,
};

#[tokio::test]
async fn native_proxy_forwards_downstream_request_to_http2_upstream() {
    let (upstream, accepted_connections) = h2_upstream(2).await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        upstream_h2_max_streams: Some(8),
        read_timeout_secs: Some(5),
        send_timeout_secs: Some(5),
        ..Default::default()
    };
    let proxy =
        NativeHttp1Proxy::from_proxy_config(&proxy_config, DownstreamHttp1Policy::default())
            .unwrap()
            .unwrap();
    assert!(proxy.upstream().uses_http2());
    let proxy = proxy_listener_for(proxy).await;

    for index in 0..2 {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(
                b"GET /h2-origin HTTP/1.1\r\nHost: proxy.test\r\nX-Test: h2\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();

        assert!(
            response.starts_with("HTTP/1.1 200 OK\r\n"),
            "unexpected response: {response:?}"
        );
        assert!(response.contains("x-origin-proto: h2\r\n"));
        assert!(response.ends_with(&format!("h2 upstream {index}\n")));
    }
    assert_eq!(accepted_connections.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn native_proxy_http2_upstream_rejects_too_many_headers_before_connect() {
    let (origin, accepted_connections) = h2_idle_upstream().await;
    let upstream = NativeHttp1Upstream::new(origin.to_string())
        .with_http2_policy(DownstreamHttp2Policy::default().with_max_concurrent_streams(1));
    let mut request = native_proxy_test_request_for("/h2-origin");
    for index in 0..101 {
        request
            .headers
            .push((format!("x-extra-{index}"), "1".to_owned()));
    }

    let error = upstream.send(&request).await.unwrap_err();
    match error {
        NativeHttp1Error::Io(error) => assert_eq!(error.kind(), std::io::ErrorKind::InvalidData),
        NativeHttp1Error::Parse(error) => panic!("unexpected parse error: {error:?}"),
    }
    assert_eq!(accepted_connections.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn native_proxy_http2_upstream_stream_slot_wait_is_bounded() {
    let (origin, accepted) = h2_blocking_upstream().await;
    let upstream = Arc::new(
        NativeHttp1Upstream::new(origin.to_string())
            .with_connect_timeout(Duration::from_millis(1))
            .with_read_timeout(Duration::from_millis(50))
            .with_http2_policy(
                DownstreamHttp2Policy::default()
                    .with_max_concurrent_streams(1)
                    .with_handler_timeout(Duration::from_secs(5)),
            ),
    );
    let first = native_proxy_test_request_for("/h2-origin");
    let first_upstream = Arc::clone(&upstream);
    let first_task = tokio::spawn(async move { first_upstream.send(&first).await });
    accepted.await.unwrap();

    let second = native_proxy_test_request_for("/h2-origin");
    let started = std::time::Instant::now();
    let error = upstream.send(&second).await.unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(1));
    match error {
        NativeHttp1Error::Io(error) => assert_eq!(error.kind(), std::io::ErrorKind::TimedOut),
        NativeHttp1Error::Parse(error) => panic!("unexpected parse error: {error:?}"),
    }
    first_task.abort();
    let _ = first_task.await;
}

#[tokio::test]
async fn native_proxy_http2_upstream_total_connection_timeout_includes_h2_handshake() {
    let origin = h2_handshake_stall_upstream().await;
    let upstream = NativeHttp1Upstream::new(origin.to_string())
        .with_connect_timeout(Duration::from_secs(5))
        .with_total_connection_timeout(Some(Duration::from_millis(50)))
        .with_http2_policy(
            DownstreamHttp2Policy::default().with_handler_timeout(Duration::from_secs(5)),
        );
    assert_eq!(
        upstream.total_connection_timeout(),
        Some(Duration::from_millis(50))
    );
    let started = std::time::Instant::now();
    let error = upstream
        .send(&native_proxy_test_request_for("/h2-origin"))
        .await
        .unwrap_err();

    assert!(started.elapsed() < Duration::from_secs(1));
    match error {
        NativeHttp1Error::Io(error) => assert_eq!(error.kind(), std::io::ErrorKind::TimedOut),
        NativeHttp1Error::Parse(error) => panic!("unexpected parse error: {error:?}"),
    }
}

#[tokio::test]
async fn native_proxy_http2_upstream_reconnects_after_origin_goaway() {
    let (upstream, accepted_connections) = h2_reconnecting_upstream("h2 reconnect\n", 2).await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        upstream_h2_max_streams: Some(1),
        read_timeout_secs: Some(5),
        send_timeout_secs: Some(5),
        ..Default::default()
    };
    let proxy =
        NativeHttp1Proxy::from_proxy_config(&proxy_config, DownstreamHttp1Policy::default())
            .unwrap()
            .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let first_response = downstream_get(proxy, "/h2-origin").await;
    let second_response = downstream_get(proxy, "/h2-origin").await;

    assert!(first_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(first_response.ends_with("h2 reconnect\n"));
    assert!(second_response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second_response.ends_with("h2 reconnect\n"));
    assert_eq!(accepted_connections.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn native_proxy_http2_upstream_stream_reset_keeps_pooled_connection() {
    let (upstream, accepted_connections) = h2_reset_then_ok_upstream().await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        upstream_h2_max_streams: Some(1),
        read_timeout_secs: Some(5),
        send_timeout_secs: Some(5),
        ..Default::default()
    };
    let proxy =
        NativeHttp1Proxy::from_proxy_config(&proxy_config, DownstreamHttp1Policy::default())
            .unwrap()
            .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let first_response = downstream_get(proxy, "/h2-origin").await;
    let second_response = downstream_get(proxy, "/h2-origin").await;

    assert!(
        first_response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "unexpected first response: {first_response:?}"
    );
    assert!(
        second_response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected second response: {second_response:?}"
    );
    assert!(second_response.ends_with("h2 survived reset\n"));
    assert_eq!(accepted_connections.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn native_proxy_round_robins_successful_http2_static_upstreams() {
    let (first, first_connections) = h2_upstream_with_body("h2-one\n", 1).await;
    let (second, second_connections) = h2_upstream_with_body("h2-two\n", 1).await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstreams: vec![first.to_string(), second.to_string()],
        load_balance: static_load_balance_without_health_check(),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        upstream_h2_max_streams: Some(4),
        read_timeout_secs: Some(5),
        send_timeout_secs: Some(5),
        ..Default::default()
    };
    let proxy =
        NativeHttp1Proxy::from_proxy_config(&proxy_config, DownstreamHttp1Policy::default())
            .unwrap()
            .unwrap();
    assert_eq!(proxy.upstreams().len(), 2);
    assert!(
        proxy
            .upstreams()
            .iter()
            .all(NativeHttp1Upstream::uses_http2)
    );
    let proxy = proxy_listener_for(proxy).await;

    let first_response = downstream_get(proxy, "/h2-origin").await;
    let second_response = downstream_get(proxy, "/h2-origin").await;

    assert!(first_response.contains("x-origin-proto: h2\r\n"));
    assert!(first_response.ends_with("h2-one\n"));
    assert!(second_response.contains("x-origin-proto: h2\r\n"));
    assert!(second_response.ends_with("h2-two\n"));
    assert_eq!(first_connections.load(Ordering::Acquire), 1);
    assert_eq!(second_connections.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn native_proxy_weighted_round_robins_successful_http2_static_upstreams() {
    let (first, first_connections) = h2_upstream_with_body("h2-weight-one\n", 2).await;
    let (second, second_connections) = h2_upstream_with_body("h2-weight-two\n", 1).await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstreams: vec![first.to_string(), second.to_string()],
        upstream_weights: vec![2, 1],
        load_balance: static_load_balance_without_health_check(),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        upstream_h2_max_streams: Some(4),
        read_timeout_secs: Some(5),
        send_timeout_secs: Some(5),
        ..Default::default()
    };
    let proxy =
        NativeHttp1Proxy::from_proxy_config(&proxy_config, DownstreamHttp1Policy::default())
            .unwrap()
            .unwrap();
    assert_eq!(proxy.upstream_slots(), &[0, 0, 1]);
    assert!(
        proxy
            .upstreams()
            .iter()
            .all(NativeHttp1Upstream::uses_http2)
    );
    let proxy = proxy_listener_for(proxy).await;

    let first_response = downstream_get(proxy, "/h2-origin").await;
    let second_response = downstream_get(proxy, "/h2-origin").await;
    let third_response = downstream_get(proxy, "/h2-origin").await;

    assert!(first_response.contains("x-origin-proto: h2\r\n"));
    assert!(first_response.ends_with("h2-weight-one\n"));
    assert!(second_response.contains("x-origin-proto: h2\r\n"));
    assert!(second_response.ends_with("h2-weight-one\n"));
    assert!(third_response.contains("x-origin-proto: h2\r\n"));
    assert!(third_response.ends_with("h2-weight-two\n"));
    assert_eq!(first_connections.load(Ordering::Acquire), 1);
    assert_eq!(second_connections.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn native_proxy_http2_safe_method_fails_over_to_second_static_upstream() {
    let first = unused_local_address().await;
    let (second, second_connections) = h2_upstream_with_body("h2 failover\n", 1).await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstreams: vec![first.to_string(), second.to_string()],
        load_balance: static_load_balance_without_health_check(),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        upstream_h2_max_streams: Some(4),
        connect_timeout_secs: Some(1),
        read_timeout_secs: Some(5),
        send_timeout_secs: Some(5),
        ..Default::default()
    };
    let proxy =
        NativeHttp1Proxy::from_proxy_config(&proxy_config, DownstreamHttp1Policy::default())
            .unwrap()
            .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let response = downstream_get(proxy, "/h2-origin").await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("x-origin-proto: h2\r\n"));
    assert!(response.ends_with("h2 failover\n"));
    assert_eq!(second_connections.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn native_proxy_http2_does_not_fail_over_unsafe_method() {
    let first = unused_local_address().await;
    let (second, second_connections) = h2_upstream_with_body("h2 unsafe replay\n", 1).await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstreams: vec![first.to_string(), second.to_string()],
        load_balance: static_load_balance_without_health_check(),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        upstream_h2_max_streams: Some(4),
        connect_timeout_secs: Some(1),
        read_timeout_secs: Some(5),
        send_timeout_secs: Some(5),
        ..Default::default()
    };
    let proxy =
        NativeHttp1Proxy::from_proxy_config(&proxy_config, DownstreamHttp1Policy::default())
            .unwrap()
            .unwrap();
    let proxy = proxy_listener_for(proxy).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"POST /h2-origin HTTP/1.1\r\nHost: proxy.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",
        )
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
    assert_eq!(second_connections.load(Ordering::Acquire), 0);
}

#[test]
fn native_proxy_config_accepts_plain_http2_upstream() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        upstream_h2_max_streams: Some(64),
        ..Default::default()
    };
    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();
    assert!(native.upstream().uses_http2());
}

#[test]
fn native_proxy_config_maps_http2_handler_timeout_from_read_timeout() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        read_timeout_secs: Some(7),
        upstream_h2_ping_interval_secs: Some(11),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .unwrap();

    assert_eq!(
        native.upstream().http2_policy().handler_timeout(),
        Duration::from_secs(7)
    );
    assert_eq!(
        native.upstream().http2_policy().response_body_timeout(),
        Duration::from_secs(7)
    );
    assert_eq!(
        native.upstream().http2_keepalive_interval(),
        Some(Duration::from_secs(11))
    );
}

#[test]
fn native_proxy_config_rejects_http2_knobs_for_http1_upstream() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http1,
        upstream_h2_max_streams: Some(64),
        ..Default::default()
    };

    let error =
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).unwrap_err();

    assert_eq!(error, NativeHttp1ProxyConfigError::UpstreamTransportPolicy);
}

#[test]
fn native_proxy_config_rejects_oversized_http2_stream_limit() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        upstream_h2_max_streams: Some(1025),
        ..Default::default()
    };

    let error =
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).unwrap_err();

    assert_eq!(error, NativeHttp1ProxyConfigError::UpstreamHttp2);
}

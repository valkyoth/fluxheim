use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::{
    DownstreamHttp1Policy, NativeHttp1Handler, NativeHttp1Proxy, NativeHttp1ProxyConfigError,
    NativeHttp1ResponseWritePolicy, NativeHttp1Upstream,
};

use super::{native_proxy_test_request, static_load_balance_without_health_check, upstream};

#[test]
fn native_proxy_config_accepts_plain_static_upstream() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        connect_timeout_secs: Some(2),
        read_timeout_secs: Some(3),
        send_timeout_secs: Some(4),
        downstream_write_timeout_secs: Some(7),
        downstream_total_response_timeout_secs: Some(11),
        downstream_min_send_rate_bytes_per_sec: Some(1024),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(
        native.upstream(),
        &NativeHttp1Upstream::new("127.0.0.1:3000")
            .with_connect_timeout(Duration::from_secs(2))
            .with_read_timeout(Duration::from_secs(3))
            .with_write_timeout(Duration::from_secs(4))
    );
    assert_eq!(
        native.response_write_policy(),
        NativeHttp1ResponseWritePolicy::new(
            Some(Duration::from_secs(7)),
            Some(Duration::from_secs(11)),
            Some(1024)
        )
    );
}

#[test]
fn native_proxy_config_accepts_ordered_static_upstreams() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: static_load_balance_without_health_check(),
        connect_timeout_secs: Some(2),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(native.upstreams().len(), 2);
    assert_eq!(
        native.upstreams()[0],
        NativeHttp1Upstream::new("127.0.0.1:3000").with_connect_timeout(Duration::from_secs(2))
    );
    assert_eq!(
        native.upstreams()[1],
        NativeHttp1Upstream::new("127.0.0.1:3001").with_connect_timeout(Duration::from_secs(2))
    );
}

#[test]
fn native_proxy_config_accepts_weighted_static_upstreams() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_weights: vec![2, 1],
        load_balance: static_load_balance_without_health_check(),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(native.upstream_slots(), &[0, 0, 1]);
}

#[test]
fn native_proxy_config_accepts_static_upstreams_with_disabled_health_check() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: fluxheim_config::LoadBalanceConfig {
            health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(native.upstreams().len(), 2);
    assert_eq!(native.upstream_slots(), &[0, 1]);
}

#[cfg(feature = "load-balancer")]
#[test]
fn native_proxy_config_accepts_scoped_advanced_static_load_balance_policy() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_priority_groups: vec![100, 50],
        upstream_max_in_flight: vec![1, 2],
        upstream_aliases: vec!["primary-a".to_owned(), "primary-b".to_owned()],
        backup_upstreams: vec!["127.0.0.1:3001".to_owned()],
        load_balance: fluxheim_config::LoadBalanceConfig {
            health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    let (native, service) = NativeHttp1Proxy::from_proxy_config_with_native_load_balancer(
        "advanced-static",
        "advanced.test",
        None,
        &proxy,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap()
    .expect("native proxy");

    assert_eq!(native.upstreams().len(), 2);
    assert!(service.is_none());
}

#[test]
fn native_proxy_config_rejects_custom_disabled_health_check_policy() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        load_balance: fluxheim_config::LoadBalanceConfig {
            health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
                enabled: false,
                interval_secs: 7,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };

    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).unwrap_err(),
        NativeHttp1ProxyConfigError::LoadBalancing
    );
}

#[test]
fn native_proxy_config_applies_pool_capacity() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config_with_pool_size(
        &proxy,
        DownstreamHttp1Policy::default(),
        16,
    )
    .unwrap()
    .expect("native proxy");

    assert_eq!(native.upstream().pool_max_idle(), 16);
}

#[test]
fn native_proxy_config_accepts_http1_upstream_proxy_protocol_and_disables_pooling() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_proxy_protocol: fluxheim_config::UpstreamProxyProtocol::V2,
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config_with_pool_size(
        &proxy,
        DownstreamHttp1Policy::default(),
        16,
    )
    .unwrap()
    .expect("native proxy");

    assert_eq!(
        native.upstream().proxy_protocol(),
        fluxheim_config::UpstreamProxyProtocol::V2
    );
    assert_eq!(native.upstream().pool_max_idle(), 0);
}

#[test]
fn native_proxy_config_rejects_upstream_proxy_protocol_with_http2() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        upstream_proxy_protocol: fluxheim_config::UpstreamProxyProtocol::V1,
        ..Default::default()
    };

    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamProxyProtocol)
    );
}

#[test]
fn native_proxy_config_applies_total_connection_timeout() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_total_connection_timeout_secs: Some(9),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(
        native.upstream().total_connection_timeout(),
        Some(Duration::from_secs(9))
    );
}

#[test]
fn native_proxy_config_applies_downstream_read_timeout() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        downstream_read_timeout_secs: Some(7),
        ..Default::default()
    };

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(native.request_body_timeout(), Some(Duration::from_secs(7)));
}

#[test]
fn native_proxy_config_applies_portable_socket_options() {
    let mut proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_tcp_recv_buffer_bytes: Some(fluxheim_config::ByteSize::from_bytes(65_536)),
        upstream_dscp: Some(10),
        upstream_tcp_keepalive_idle_secs: Some(30),
        upstream_tcp_keepalive_interval_secs: Some(10),
        upstream_tcp_keepalive_count: Some(3),
        ..Default::default()
    };
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    ))]
    {
        proxy.upstream_tcp_user_timeout_ms = Some(15000);
    }

    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    assert_eq!(native.upstream().recv_buffer_size(), Some(65_536));
    assert_eq!(native.upstream().dscp(), Some(10));
    let keepalive = native.upstream().tcp_keepalive().unwrap();
    assert_eq!(keepalive.idle(), Duration::from_secs(30));
    assert_eq!(keepalive.interval(), Duration::from_secs(10));
    assert_eq!(keepalive.count(), 3);
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    ))]
    assert_eq!(
        native.upstream().tcp_user_timeout(),
        Some(Duration::from_millis(15000))
    );
}

#[test]
fn native_proxy_config_rejects_oversized_socket_receive_buffer() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_tcp_recv_buffer_bytes: Some(fluxheim_config::ByteSize::from_bytes(
            u64::from(u32::MAX) + 1,
        )),
        ..Default::default()
    };

    let error =
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).unwrap_err();

    assert_eq!(error, NativeHttp1ProxyConfigError::RecvBufferTooLarge);
}

#[tokio::test]
async fn native_proxy_socket_options_connect_to_upstream() {
    let upstream = upstream(|_, mut stream| async move {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 13\r\n\r\nsocket-policy")
            .await
            .unwrap();
    })
    .await;
    let mut proxy = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        upstream_tcp_recv_buffer_bytes: Some(fluxheim_config::ByteSize::from_bytes(65_536)),
        upstream_dscp: Some(10),
        upstream_tcp_keepalive_idle_secs: Some(30),
        upstream_tcp_keepalive_interval_secs: Some(10),
        upstream_tcp_keepalive_count: Some(3),
        ..Default::default()
    };
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    ))]
    {
        proxy.upstream_tcp_user_timeout_ms = Some(15000);
    }
    let native = NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default())
        .unwrap()
        .expect("native proxy");

    let response = native.handle(native_proxy_test_request()).await;

    assert_eq!(response.status(), 200);
    assert_eq!(response.body(), b"socket-policy");
}

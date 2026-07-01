use super::{
    UdpAcquireError, UdpProxyApp, udp_error_counts_for_passive_health, unspecified_bind_addr,
};
use crate::config::{UdpRouteConfig, UdpRouteMode};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::net::UdpSocket;

fn route(upstream: String, mode: UdpRouteMode) -> UdpRouteConfig {
    UdpRouteConfig {
        name: "udp-test".to_owned(),
        mode,
        listen: vec!["127.0.0.1:5353".to_owned()],
        upstream: Some(upstream),
        upstreams: Vec::new(),
        upstream_weights: Vec::new(),
        upstream_aliases: Vec::new(),
        idle_timeout_secs: 1,
        response_timeout_secs: 1,
        max_datagram_bytes: 512,
        max_sessions: 1,
        max_sessions_per_source: 1,
        max_responses_per_source_per_second: 256,
        passive_health_enabled: true,
        passive_health_failures: 3,
        passive_health_ejection_secs: 10,
    }
}

#[tokio::test]
async fn udp_dns_mode_forwards_response_to_downstream() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut buf = [0u8; 32];
        let (len, peer) = upstream.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"query");
        upstream.send_to(b"answer", peer).await.unwrap();
    });

    let app = UdpProxyApp::from_config(&route(
        upstream_addr.to_string(),
        UdpRouteMode::DnsLoadBalance,
    ))
    .unwrap();
    let downstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.process_datagram(
        downstream.clone(),
        downstream.local_addr().unwrap(),
        client.local_addr().unwrap(),
        b"query".to_vec(),
    )
    .await;

    let mut response = [0u8; 32];
    let (len, _peer) = client.recv_from(&mut response).await.unwrap();
    assert_eq!(&response[..len], b"answer");
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn udp_dns_mode_drops_oversized_upstream_response() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut buf = [0u8; 32];
        let (_len, peer) = upstream.recv_from(&mut buf).await.unwrap();
        let oversized = vec![b'x'; 513];
        upstream.send_to(&oversized, peer).await.unwrap();
    });

    let app = UdpProxyApp::from_config(&route(
        upstream_addr.to_string(),
        UdpRouteMode::DnsLoadBalance,
    ))
    .unwrap();
    let downstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app.process_datagram(
        downstream.clone(),
        downstream.local_addr().unwrap(),
        client.local_addr().unwrap(),
        b"query".to_vec(),
    )
    .await;

    let mut response = [0u8; 32];
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            client.recv_from(&mut response)
        )
        .await
        .is_err()
    );
    upstream_task.await.unwrap();
}

#[tokio::test]
async fn udp_syslog_mode_forwards_without_response() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let app = UdpProxyApp::from_config(&route(
        upstream_addr.to_string(),
        UdpRouteMode::SyslogForward,
    ))
    .unwrap();
    let downstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    app.process_datagram(
        downstream.clone(),
        downstream.local_addr().unwrap(),
        client.local_addr().unwrap(),
        b"<13>message".to_vec(),
    )
    .await;

    let mut received = [0u8; 32];
    let (len, _peer) = upstream.recv_from(&mut received).await.unwrap();
    assert_eq!(&received[..len], b"<13>message");
}

#[test]
fn udp_session_slot_releases_counted_counter() {
    let app = UdpProxyApp::from_config(&route(
        "127.0.0.1:53".to_owned(),
        UdpRouteMode::DnsLoadBalance,
    ))
    .unwrap();
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let slot = app.acquire_session_slot(source).unwrap();
    assert!(matches!(
        app.acquire_session_slot(source),
        Err(UdpAcquireError::RouteLimit)
    ));
    drop(slot);
    assert!(app.acquire_session_slot(source).is_ok());
}

#[test]
fn udp_session_slot_enforces_per_source_limit() {
    let mut route = route("127.0.0.1:53".to_owned(), UdpRouteMode::DnsLoadBalance);
    route.max_sessions = 2;
    route.max_sessions_per_source = 1;
    let app = UdpProxyApp::from_config(&route).unwrap();
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let other = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

    let slot = app.acquire_session_slot(source).unwrap();
    assert!(matches!(
        app.acquire_session_slot(source),
        Err(UdpAcquireError::SourceLimit)
    ));
    assert!(app.acquire_session_slot(other).is_ok());
    drop(slot);
    assert!(app.acquire_session_slot(source).is_ok());
}

#[test]
fn udp_response_rate_limit_is_per_source_per_second() {
    let mut route = route("127.0.0.1:53".to_owned(), UdpRouteMode::DnsLoadBalance);
    route.max_responses_per_source_per_second = 1;
    let app = UdpProxyApp::from_config(&route).unwrap();
    let source = IpAddr::V4(Ipv4Addr::LOCALHOST);

    assert!(app.allow_response_to_source(source));
    assert!(!app.allow_response_to_source(source));
}

#[test]
fn udp_response_rate_limit_rolls_generation_without_per_packet_scan() {
    let mut route = route("127.0.0.1:53".to_owned(), UdpRouteMode::DnsLoadBalance);
    route.max_responses_per_source_per_second = 2;
    let app = UdpProxyApp::from_config(&route).unwrap();
    let old_source = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let new_source = IpAddr::V4(Ipv4Addr::LOCALHOST);

    {
        let mut state = app.lock_response_rate_windows();
        state.window_secs = (super::udp_log_millis() / 1_000).saturating_sub(1);
        state
            .windows
            .insert(old_source, super::UdpResponseRateWindow { count: 2 });
    }

    assert!(app.allow_response_to_source(new_source));
    let state = app.lock_response_rate_windows();
    assert_eq!(state.windows.len(), 1);
    assert!(state.windows.contains_key(&new_source));
    assert!(!state.windows.contains_key(&old_source));
}

#[test]
fn udp_selection_skips_passively_ejected_upstream() {
    let mut route = route("127.0.0.1:53".to_owned(), UdpRouteMode::DnsLoadBalance);
    route.upstream = None;
    route.upstreams = vec!["127.0.0.1:53".to_owned(), "127.0.0.1:54".to_owned()];
    route.upstream_weights = vec![1, 1];
    route.upstream_aliases = vec!["bad".to_owned(), "good".to_owned()];
    let app = UdpProxyApp::from_config(&route).unwrap();

    app.upstreams[0].ejected_until_millis.store(
        super::udp_log_millis().saturating_add(10_000),
        Ordering::Release,
    );

    let selected = app.select_upstream();
    assert_eq!(selected.alias.as_deref(), Some("good"));
}

#[test]
fn udp_passive_health_ejects_and_success_restores_upstream() {
    let mut route = route("127.0.0.1:53".to_owned(), UdpRouteMode::DnsLoadBalance);
    route.passive_health_failures = 1;
    let app = UdpProxyApp::from_config(&route).unwrap();
    let upstream = &app.upstreams[0];

    app.record_upstream_failure(upstream);
    assert!(upstream.ejected_until_millis.load(Ordering::Acquire) > super::udp_log_millis());

    upstream.record_success();
    assert_eq!(upstream.failures.load(Ordering::Acquire), 0);
    assert_eq!(upstream.ejected_until_millis.load(Ordering::Acquire), 0);
}

#[test]
fn udp_passive_health_ignores_local_drop_errors() {
    assert!(!udp_error_counts_for_passive_health(&io::Error::new(
        io::ErrorKind::WouldBlock,
        "response rate limit exceeded"
    )));
    assert!(!udp_error_counts_for_passive_health(&io::Error::new(
        io::ErrorKind::InvalidData,
        "upstream response exceeded datagram cap"
    )));
    assert!(udp_error_counts_for_passive_health(&io::Error::new(
        io::ErrorKind::TimedOut,
        "upstream response timed out"
    )));
    assert!(udp_error_counts_for_passive_health(&io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "upstream refused datagram"
    )));
}

#[test]
fn udp_unspecified_bind_addr_matches_address_family() {
    assert_eq!(
        unspecified_bind_addr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        "0.0.0.0:0".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        unspecified_bind_addr(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        "[::]:0".parse::<SocketAddr>().unwrap()
    );
}

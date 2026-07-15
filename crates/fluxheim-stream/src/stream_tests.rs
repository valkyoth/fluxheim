use super::*;
use fluxheim_config::config::{DownstreamProxyProtocol, UpstreamProxyProtocol};

#[test]
fn stream_selector_selects_upstreams_round_robin() {
    let selector = StreamUpstreamSelector::from_route(&StreamRouteConfig {
        name: "tcp".to_owned(),
        listen: vec!["127.0.0.1:12345".to_owned()],
        upstream: None,
        upstreams: vec!["127.0.0.1:5432".to_owned(), "127.0.0.1:6432".to_owned()],
        upstream_weights: Vec::new(),
        upstream_aliases: Vec::new(),
        backup_upstreams: Vec::new(),
        drain_upstreams: Vec::new(),
        connect_timeout_secs: 1,
        idle_timeout_secs: 1,
        proxy_header_timeout_secs: 10,
        max_connection_secs: None,
        max_connection_bytes: None,
        max_connections: 0,
        downstream_proxy_protocol: DownstreamProxyProtocol::Off,
        trusted_proxies: Vec::new(),
        allow_sources: Vec::new(),
        deny_sources: Vec::new(),
        upstream_proxy_protocol: UpstreamProxyProtocol::Off,
        upstream_tls: false,
        upstream_dns_allow_private_addresses: false,
        upstream_sni: None,
        upstream_verify_cert: true,
        upstream_verify_hostname: true,
        upstream_alternative_cn: None,
        upstream_ca_path: None,
        upstream_client_cert_path: None,
        upstream_client_key_path: None,
    })
    .unwrap();

    assert_eq!(
        selector.select_candidates()[0].authority.as_ref(),
        "127.0.0.1:5432"
    );
    assert_eq!(
        selector.select_candidates()[0].authority.as_ref(),
        "127.0.0.1:6432"
    );
    assert_eq!(
        selector.select_candidates()[0].authority.as_ref(),
        "127.0.0.1:5432"
    );
}

#[test]
fn stream_selector_respects_weights_and_drained_upstreams() {
    let selector = StreamUpstreamSelector::from_route(&StreamRouteConfig {
        name: "tcp".to_owned(),
        listen: vec!["127.0.0.1:12345".to_owned()],
        upstream: None,
        upstreams: vec![
            "127.0.0.1:5432".to_owned(),
            "127.0.0.1:6432".to_owned(),
            "127.0.0.1:7432".to_owned(),
        ],
        upstream_weights: vec![1, 2, 1],
        upstream_aliases: vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
        backup_upstreams: vec!["127.0.0.1:7432".to_owned()],
        drain_upstreams: vec!["127.0.0.1:5432".to_owned()],
        ..StreamRouteConfig::default()
    })
    .unwrap();

    let first = selector.select_candidates();
    let second = selector.select_candidates();
    let third = selector.select_candidates();

    assert_eq!(first[0].label(), "b");
    assert_eq!(second[0].label(), "b");
    assert_eq!(third[0].label(), "b");
    assert!(first.iter().any(|candidate| candidate.backup));
    assert!(
        first
            .iter()
            .all(|candidate| candidate.authority.as_ref() != "127.0.0.1:5432")
    );
}

#[test]
fn stream_selector_rejects_weights_outside_runtime_bounds() {
    let route = StreamRouteConfig {
        name: "tcp".to_owned(),
        upstreams: vec!["127.0.0.1:5432".to_owned(), "127.0.0.1:6432".to_owned()],
        upstream_weights: vec![usize::MAX, 1],
        ..StreamRouteConfig::default()
    };

    assert!(StreamUpstreamSelector::from_route(&route).is_err());

    let route = StreamRouteConfig {
        upstream_weights: vec![0, 1],
        ..route
    };
    assert!(StreamUpstreamSelector::from_route(&route).is_err());
}

#[test]
fn stream_trusted_sources_match_exact_and_cidr() {
    let exact = StreamSourceMatcher::parse("127.0.0.1", "trusted proxy").unwrap();
    assert!(exact.matches("127.0.0.1".parse().unwrap()));
    assert!(!exact.matches("127.0.0.2".parse().unwrap()));

    let cidr = StreamSourceMatcher::parse("10.0.0.0/24", "trusted proxy").unwrap();
    assert!(cidr.matches("10.0.0.42".parse().unwrap()));
    assert!(!cidr.matches("10.0.1.42".parse().unwrap()));

    assert!(StreamSourceMatcher::parse("10.0.0.0/64", "trusted proxy").is_err());
}

#[test]
fn stream_source_policy_denies_before_allowing() {
    let policy = StreamSourcePolicy::from_route(&StreamRouteConfig {
        name: "tcp".to_owned(),
        listen: vec!["127.0.0.1:12345".to_owned()],
        upstream: Some("127.0.0.1:5432".to_owned()),
        allow_sources: vec!["10.0.0.0/8".to_owned()],
        deny_sources: vec!["10.0.0.13".to_owned()],
        ..StreamRouteConfig::default()
    })
    .unwrap();

    assert!(policy.source_allowed(Some("10.0.0.12:1234".parse().unwrap())));
    assert!(!policy.source_allowed(Some("10.0.0.13:1234".parse().unwrap())));
    assert!(!policy.source_allowed(Some("192.0.2.10:1234".parse().unwrap())));
    assert!(!policy.source_allowed(None));

    let policy = StreamSourcePolicy::from_route(&StreamRouteConfig {
        name: "tcp".to_owned(),
        listen: vec!["127.0.0.1:12345".to_owned()],
        upstream: Some("127.0.0.1:5432".to_owned()),
        deny_sources: vec!["192.0.2.0/24".to_owned()],
        ..StreamRouteConfig::default()
    })
    .unwrap();
    assert!(policy.source_allowed(None));
    assert!(policy.source_allowed(Some("10.0.0.12:1234".parse().unwrap())));
    assert!(!policy.source_allowed(Some("192.0.2.10:1234".parse().unwrap())));
}

#[test]
fn stream_dns_rebind_guard_rejects_private_resolved_addresses() {
    assert!(!stream_dns_resolved_address_allowed(
        "127.0.0.1".parse().unwrap()
    ));
    assert!(!stream_dns_resolved_address_allowed(
        "10.0.0.1".parse().unwrap()
    ));
    assert!(!stream_dns_resolved_address_allowed(
        "169.254.169.254".parse().unwrap()
    ));
    assert!(!stream_dns_resolved_address_allowed(
        "100.64.0.1".parse().unwrap()
    ));
    assert!(!stream_dns_resolved_address_allowed(
        "198.18.0.1".parse().unwrap()
    ));
    assert!(!stream_dns_resolved_address_allowed(
        "240.0.0.1".parse().unwrap()
    ));
    assert!(!stream_dns_resolved_address_allowed("::1".parse().unwrap()));
    assert!(!stream_dns_resolved_address_allowed(
        "fc00::1".parse().unwrap()
    ));
    assert!(!stream_dns_resolved_address_allowed(
        "2001:db8::1".parse().unwrap()
    ));
    for address in [
        "192.0.0.8",
        "192.0.0.170",
        "64:ff9b::1",
        "64:ff9b:1::1",
        "100::1",
        "100:0:0:1::1",
        "2001:2::1",
        "2002::1",
        "3fff::1",
        "5f00::1",
        "fec0::1",
    ] {
        assert!(
            !stream_dns_resolved_address_allowed(address.parse().unwrap()),
            "special-purpose address {address} must not pass DNS admission"
        );
    }
    assert!(!stream_dns_resolved_address_allowed(
        "::ffff:127.0.0.1".parse().unwrap()
    ));
    assert!(!stream_dns_resolved_address_allowed(
        "::ffff:10.0.0.1".parse().unwrap()
    ));
    assert!(!stream_dns_resolved_address_allowed(
        "::ffff:169.254.169.254".parse().unwrap()
    ));
    assert!(!stream_dns_resolved_address_allowed(
        "::127.0.0.1".parse().unwrap()
    ));
    assert!(stream_dns_resolved_address_allowed(
        "1.1.1.1".parse().unwrap()
    ));
    assert!(stream_dns_resolved_address_allowed(
        "192.0.0.9".parse().unwrap()
    ));
    assert!(stream_dns_resolved_address_allowed(
        "192.0.0.10".parse().unwrap()
    ));
    assert!(stream_dns_resolved_address_allowed(
        "::ffff:1.1.1.1".parse().unwrap()
    ));
    assert!(stream_dns_resolved_address_allowed(
        "2606:4700:4700::1111".parse().unwrap()
    ));
}

#[tokio::test(start_paused = true)]
async fn stream_downstream_proxy_protocol_v1_has_one_absolute_header_deadline() {
    assert_proxy_header_drip_times_out(DownstreamProxyProtocol::V1, b"PROX").await;
}

#[tokio::test(start_paused = true)]
async fn stream_downstream_proxy_protocol_v2_has_one_absolute_header_deadline() {
    assert_proxy_header_drip_times_out(
        DownstreamProxyProtocol::V2,
        &PROXY_PROTOCOL_V2_SIGNATURE[..4],
    )
    .await;
}

async fn assert_proxy_header_drip_times_out(protocol: DownstreamProxyProtocol, bytes: &[u8]) {
    const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
    const DRIP_INTERVAL: Duration = Duration::from_secs(4);

    let (mut downstream, mut peer) = tokio::io::duplex(64);
    let trusted = [StreamSourceMatcher::parse("127.0.0.1", "trusted proxy").unwrap()];
    let parse = apply_downstream_proxy_protocol_to_stream(
        &mut downstream,
        protocol,
        &trusted,
        Some("127.0.0.1:443".parse().unwrap()),
        HEADER_TIMEOUT,
    );
    let drip = async {
        for byte in bytes {
            if peer.write_all(&[*byte]).await.is_err() {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::advance(DRIP_INTERVAL).await;
        }
    };

    let (result, ()) = tokio::join!(parse, drip);
    assert!(matches!(result, Err(FluxError::Timeout { .. })));
}

#[test]
fn stream_downstream_proxy_protocol_v1_parser_extracts_source() {
    let parsed =
        parse_downstream_proxy_protocol_v1(b"PROXY TCP4 203.0.113.10 192.0.2.20 42300 443\r\n")
            .unwrap();

    assert_eq!(parsed, Some("203.0.113.10:42300".parse().unwrap()));
    assert_eq!(
        parse_downstream_proxy_protocol_v1(b"PROXY UNKNOWN\r\n").unwrap(),
        None
    );
    assert_eq!(
        parse_downstream_proxy_protocol_v1(b"PROXY UNKNOWN 192.0.2.20 203.0.113.10 443 42300\r\n")
            .unwrap(),
        None
    );
    assert!(
        parse_downstream_proxy_protocol_v1(b"PROXY TCP4 2001:db8::10 192.0.2.20 42300 443\r\n")
            .is_err()
    );
}

#[test]
fn stream_downstream_proxy_protocol_v2_parser_extracts_source() {
    let mut header = [0u8; PROXY_PROTOCOL_V2_HEADER_LEN];
    header[..PROXY_PROTOCOL_V2_SIGNATURE.len()].copy_from_slice(PROXY_PROTOCOL_V2_SIGNATURE);
    header[12] = 0x21;
    header[13] = 0x11;
    header[14..16].copy_from_slice(&12u16.to_be_bytes());
    let mut payload = Vec::new();
    payload.extend_from_slice(&[203, 0, 113, 10]);
    payload.extend_from_slice(&[192, 0, 2, 20]);
    payload.extend_from_slice(&42300u16.to_be_bytes());
    payload.extend_from_slice(&443u16.to_be_bytes());

    assert_eq!(
        parse_downstream_proxy_protocol_v2(&header, &payload).unwrap(),
        Some("203.0.113.10:42300".parse().unwrap())
    );

    header[12] = 0x20;
    header[13] = 0x00;
    header[14..16].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(
        parse_downstream_proxy_protocol_v2(&header, &[]).unwrap(),
        None
    );
}

#[test]
fn stream_byte_counter_rejects_overflow_and_limit() {
    assert_eq!(checked_stream_byte_count(2, 3, Some(5)).unwrap(), 5);
    assert_eq!(
        checked_stream_byte_count(2, 4, Some(5))
            .unwrap_err()
            .into_io()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        checked_stream_byte_count(u64::MAX, 1, None)
            .unwrap_err()
            .into_io()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn stream_copy_preserves_both_directions_under_partial_write_backpressure() {
    let (mut downstream_proxy, downstream_client) = tokio::io::duplex(1);
    let (mut upstream_proxy, upstream_server) = tokio::io::duplex(1);
    let downstream_payload = (0..4096).map(|index| index as u8).collect::<Vec<_>>();
    let upstream_payload = (0..4096)
        .map(|index| 255u8.wrapping_sub(index as u8))
        .collect::<Vec<_>>();

    let copy = copy_bidirectional_with_limits(
        &mut downstream_proxy,
        &mut upstream_proxy,
        Duration::from_secs(5),
        None,
    );
    let client = exchange_duplex_payload(downstream_client, downstream_payload.clone());
    let server = exchange_duplex_payload(upstream_server, upstream_payload.clone());
    let (copy_result, client_result, server_result) = tokio::join!(copy, client, server);

    assert_eq!(copy_result.unwrap(), (4096, 4096));
    assert_eq!(client_result.unwrap(), upstream_payload);
    assert_eq!(server_result.unwrap(), downstream_payload);
}

#[tokio::test(start_paused = true)]
async fn stream_copy_one_way_activity_keeps_shared_idle_deadline_alive() {
    const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
    const ACTIVITY_INTERVAL: Duration = Duration::from_secs(8);

    let (mut downstream_proxy, downstream_client) = tokio::io::duplex(16);
    let (mut upstream_proxy, upstream_server) = tokio::io::duplex(16);
    let copy = copy_bidirectional_with_limits(
        &mut downstream_proxy,
        &mut upstream_proxy,
        IDLE_TIMEOUT,
        None,
    );
    let traffic = async move {
        let (mut downstream_reader, mut downstream_writer) = tokio::io::split(downstream_client);
        let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream_server);
        upstream_writer.shutdown().await?;

        for byte in b"alive" {
            downstream_writer.write_all(&[*byte]).await?;
            tokio::task::yield_now().await;
            tokio::time::advance(ACTIVITY_INTERVAL).await;
        }
        downstream_writer.shutdown().await?;

        let mut forwarded = Vec::new();
        upstream_reader.read_to_end(&mut forwarded).await?;
        let mut reverse = Vec::new();
        downstream_reader.read_to_end(&mut reverse).await?;
        Ok::<_, io::Error>((forwarded, reverse))
    };

    let (copy_result, traffic_result) = tokio::join!(copy, traffic);
    assert_eq!(copy_result.unwrap(), (5, 0));
    assert_eq!(traffic_result.unwrap(), (b"alive".to_vec(), Vec::new()));
}

#[tokio::test(start_paused = true)]
async fn stream_copy_partial_writes_refresh_shared_idle_deadline() {
    const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
    const ACTIVITY_INTERVAL: Duration = Duration::from_secs(8);

    let (mut downstream_proxy, mut downstream_client) = tokio::io::duplex(16);
    let (mut upstream_proxy, upstream_server) = tokio::io::duplex(1);
    let copy = copy_bidirectional_with_limits(
        &mut downstream_proxy,
        &mut upstream_proxy,
        IDLE_TIMEOUT,
        None,
    );
    let traffic = async move {
        let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream_server);
        upstream_writer.shutdown().await?;
        downstream_client.write_all(b"slow").await?;
        downstream_client.shutdown().await?;

        let mut forwarded = Vec::with_capacity(4);
        for index in 0..4 {
            let mut byte = [0u8; 1];
            upstream_reader.read_exact(&mut byte).await?;
            forwarded.push(byte[0]);
            tokio::task::yield_now().await;
            if index < 3 {
                tokio::time::advance(ACTIVITY_INTERVAL).await;
            }
        }
        Ok::<_, io::Error>(forwarded)
    };

    let (copy_result, traffic_result) = tokio::join!(copy, traffic);
    assert_eq!(copy_result.unwrap(), (4, 0));
    assert_eq!(traffic_result.unwrap(), b"slow");
}

#[tokio::test(start_paused = true)]
async fn stream_copy_true_idle_returns_timeout() {
    let (mut downstream_proxy, _downstream_client) = tokio::io::duplex(16);
    let (mut upstream_proxy, _upstream_server) = tokio::io::duplex(16);
    let idle_timeout = Duration::from_secs(10);
    let copy = copy_bidirectional_with_limits(
        &mut downstream_proxy,
        &mut upstream_proxy,
        idle_timeout,
        None,
    );
    let advance_past_deadline = async {
        tokio::time::advance(idle_timeout + Duration::from_secs(1)).await;
    };

    let (copy_result, ()) = tokio::join!(copy, advance_past_deadline);
    assert!(matches!(copy_result, Err(FluxError::Timeout { .. })));
}

async fn exchange_duplex_payload(
    stream: tokio::io::DuplexStream,
    payload: Vec<u8>,
) -> io::Result<Vec<u8>> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let send = async {
        writer.write_all(&payload).await?;
        writer.shutdown().await
    };
    let receive = async {
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await?;
        Ok::<_, io::Error>(received)
    };
    let (send_result, receive_result) = tokio::join!(send, receive);
    send_result?;
    receive_result
}

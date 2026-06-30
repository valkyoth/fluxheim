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
    assert!(stream_dns_resolved_address_allowed(
        "1.1.1.1".parse().unwrap()
    ));
    assert!(stream_dns_resolved_address_allowed(
        "2606:4700:4700::1111".parse().unwrap()
    ));
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

use std::net::{IpAddr, SocketAddr};

use super::{
    DownstreamProxyProtocolParseError, PROXY_PROTOCOL_V2_HEADER_LEN, PROXY_PROTOCOL_V2_SIGNATURE,
    ProxyProtocolTrustedSource, ProxyProtocolTrustedSourceParseError,
    parse_downstream_proxy_protocol_v1, parse_downstream_proxy_protocol_v2,
    parse_proxy_protocol_trusted_source, proxy_protocol_v1_header, proxy_protocol_v2_header,
};

#[test]
fn parses_proxy_protocol_trusted_ip_and_cidr_sources() {
    assert_eq!(
        parse_proxy_protocol_trusted_source("192.0.2.10"),
        Ok(ProxyProtocolTrustedSource::Ip(IpAddr::from([
            192, 0, 2, 10
        ])))
    );
    assert_eq!(
        parse_proxy_protocol_trusted_source("2001:db8::1"),
        Ok(ProxyProtocolTrustedSource::Ip(
            "2001:db8::1".parse().expect("valid IPv6")
        ))
    );
    assert_eq!(
        parse_proxy_protocol_trusted_source("198.51.100.0/24"),
        Ok(ProxyProtocolTrustedSource::Cidr {
            network: IpAddr::from([198, 51, 100, 0]),
            prefix: 24,
        })
    );
    assert_eq!(
        parse_proxy_protocol_trusted_source("2001:db8::/32"),
        Ok(ProxyProtocolTrustedSource::Cidr {
            network: "2001:db8::".parse().expect("valid IPv6 network"),
            prefix: 32,
        })
    );
}

#[test]
fn rejects_invalid_proxy_protocol_trusted_sources() {
    assert_eq!(
        parse_proxy_protocol_trusted_source("example.com"),
        Err(ProxyProtocolTrustedSourceParseError::InvalidAddress)
    );
    assert_eq!(
        parse_proxy_protocol_trusted_source("192.0.2.0/not-a-prefix"),
        Err(ProxyProtocolTrustedSourceParseError::InvalidPrefix)
    );
    assert_eq!(
        parse_proxy_protocol_trusted_source("192.0.2.0/33"),
        Err(ProxyProtocolTrustedSourceParseError::InvalidPrefix)
    );
    assert_eq!(
        parse_proxy_protocol_trusted_source("2001:db8::/129"),
        Err(ProxyProtocolTrustedSourceParseError::InvalidPrefix)
    );
    assert_eq!(
        parse_proxy_protocol_trusted_source("192.0.2.1/24"),
        Err(ProxyProtocolTrustedSourceParseError::InvalidNetwork)
    );
    assert_eq!(
        parse_proxy_protocol_trusted_source("2001:db8::1/32"),
        Err(ProxyProtocolTrustedSourceParseError::InvalidNetwork)
    );
}

#[test]
fn proxy_protocol_v1_header_encodes_matching_ip_families() {
    let source: SocketAddr = "192.0.2.10:12345".parse().expect("valid source");
    let destination: SocketAddr = "198.51.100.20:443".parse().expect("valid destination");
    assert_eq!(
        proxy_protocol_v1_header(Some(source), Some(destination)),
        b"PROXY TCP4 192.0.2.10 198.51.100.20 12345 443\r\n"
    );

    let source: SocketAddr = "[2001:db8::1]:12345".parse().expect("valid source");
    let destination: SocketAddr = "[2001:db8::2]:443".parse().expect("valid destination");
    assert_eq!(
        proxy_protocol_v1_header(Some(source), Some(destination)),
        b"PROXY TCP6 2001:db8::1 2001:db8::2 12345 443\r\n"
    );
}

#[test]
fn proxy_protocol_v1_header_falls_back_to_unknown_for_ambiguous_inputs() {
    let source: SocketAddr = "192.0.2.10:12345".parse().expect("valid source");
    let destination: SocketAddr = "[2001:db8::2]:443".parse().expect("valid destination");
    assert_eq!(
        proxy_protocol_v1_header(Some(source), Some(destination)),
        b"PROXY UNKNOWN\r\n"
    );
    assert_eq!(
        proxy_protocol_v1_header(None, Some(destination)),
        b"PROXY UNKNOWN\r\n"
    );
}

#[test]
fn proxy_protocol_v2_header_encodes_matching_ip_families() {
    let source: SocketAddr = "192.0.2.10:12345".parse().expect("valid source");
    let destination: SocketAddr = "198.51.100.20:443".parse().expect("valid destination");
    let header = proxy_protocol_v2_header(Some(source), Some(destination));
    assert_eq!(&header[..12], b"\r\n\r\n\0\r\nQUIT\n");
    assert_eq!(&header[12..16], &[0x21, 0x11, 0x00, 0x0c]);
    assert_eq!(&header[16..20], &[192, 0, 2, 10]);
    assert_eq!(&header[20..24], &[198, 51, 100, 20]);
    assert_eq!(&header[24..26], &12345u16.to_be_bytes());
    assert_eq!(&header[26..28], &443u16.to_be_bytes());

    let source: SocketAddr = "[2001:db8::1]:12345".parse().expect("valid source");
    let destination: SocketAddr = "[2001:db8::2]:443".parse().expect("valid destination");
    let header = proxy_protocol_v2_header(Some(source), Some(destination));
    assert_eq!(&header[12..16], &[0x21, 0x21, 0x00, 0x24]);
    assert_eq!(&header[48..50], &12345u16.to_be_bytes());
    assert_eq!(&header[50..52], &443u16.to_be_bytes());
}

#[test]
fn proxy_protocol_v2_header_falls_back_to_unspec_for_ambiguous_inputs() {
    let source: SocketAddr = "192.0.2.10:12345".parse().expect("valid source");
    let destination: SocketAddr = "[2001:db8::2]:443".parse().expect("valid destination");
    assert_eq!(
        &proxy_protocol_v2_header(Some(source), Some(destination))[12..16],
        &[0x21, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        &proxy_protocol_v2_header(None, Some(destination))[12..16],
        &[0x21, 0x00, 0x00, 0x00]
    );
}

#[test]
fn proxy_protocol_v1_parser_extracts_source() {
    assert_eq!(
        parse_downstream_proxy_protocol_v1(b"PROXY TCP4 203.0.113.10 192.0.2.20 42300 443\r\n")
            .expect("valid v1 source"),
        Some("203.0.113.10:42300".parse().expect("valid socket"))
    );
    assert_eq!(
        parse_downstream_proxy_protocol_v1(b"PROXY UNKNOWN\r\n").expect("valid unknown v1"),
        None
    );
    assert_eq!(
        parse_downstream_proxy_protocol_v1(b"PROXY UNKNOWN 192.0.2.20 203.0.113.10 443 42300\r\n")
            .expect("valid unknown v1 with ignored fields"),
        None
    );
    assert_eq!(
        parse_downstream_proxy_protocol_v1(b"PROXY TCP4 2001:db8::10 192.0.2.20 42300 443\r\n"),
        Err(DownstreamProxyProtocolParseError::V1FamilyAddressMismatch)
    );
}

#[test]
fn proxy_protocol_v2_parser_extracts_source() {
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
        parse_downstream_proxy_protocol_v2(&header, &payload).expect("valid v2 source"),
        Some("203.0.113.10:42300".parse().expect("valid socket"))
    );

    header[12] = 0x20;
    header[13] = 0x00;
    header[14..16].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(
        parse_downstream_proxy_protocol_v2(&header, &[]).expect("valid local command"),
        None
    );
}

#[test]
fn proxy_protocol_v2_parser_rejects_invalid_signature() {
    let header = [0u8; PROXY_PROTOCOL_V2_HEADER_LEN];

    assert_eq!(
        parse_downstream_proxy_protocol_v2(&header, &[]),
        Err(DownstreamProxyProtocolParseError::V2InvalidSignature)
    );
}

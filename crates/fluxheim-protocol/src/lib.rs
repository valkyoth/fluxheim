#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProxyProtocolTrustedSource {
    Ip(IpAddr),
    Cidr { network: IpAddr, prefix: u8 },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProxyProtocolTrustedSourceParseError {
    InvalidAddress,
    InvalidPrefix,
}

impl std::fmt::Display for ProxyProtocolTrustedSourceParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAddress => formatter.write_str("invalid PROXY protocol trusted address"),
            Self::InvalidPrefix => {
                formatter.write_str("invalid PROXY protocol trusted CIDR prefix")
            }
        }
    }
}

impl std::error::Error for ProxyProtocolTrustedSourceParseError {}

pub fn parse_proxy_protocol_trusted_source(
    value: &str,
) -> Result<ProxyProtocolTrustedSource, ProxyProtocolTrustedSourceParseError> {
    if let Some((address, prefix)) = value.split_once('/') {
        let network = address
            .parse::<IpAddr>()
            .map_err(|_| ProxyProtocolTrustedSourceParseError::InvalidAddress)?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| ProxyProtocolTrustedSourceParseError::InvalidPrefix)?;
        return Ok(ProxyProtocolTrustedSource::Cidr { network, prefix });
    }
    Ok(ProxyProtocolTrustedSource::Ip(
        value
            .parse::<IpAddr>()
            .map_err(|_| ProxyProtocolTrustedSourceParseError::InvalidAddress)?,
    ))
}

pub fn route_method_matches(methods: &[String], method: &str) -> bool {
    methods.is_empty()
        || methods
            .iter()
            .any(|configured| configured.eq_ignore_ascii_case(method))
}

pub fn route_prefix_matches_path(prefix: &str, path: &str) -> bool {
    let Some(suffix) = path.strip_prefix(prefix) else {
        return false;
    };
    prefix == "/" || prefix.ends_with('/') || suffix.is_empty() || suffix.starts_with('/')
}

pub fn route_strip_prefix_suffix<'a>(strip_prefix: &str, path: &'a str) -> Option<&'a str> {
    let suffix = path.strip_prefix(strip_prefix)?;
    (strip_prefix == "/"
        || strip_prefix.ends_with('/')
        || suffix.is_empty()
        || suffix.starts_with('/'))
    .then_some(suffix)
}

pub fn http_token_valid(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
                    | b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
            )
        })
}

pub fn http_upgrade_token_valid(value: &str) -> bool {
    http_token_valid(value)
}

pub const FLUXHEIM_VIA_VALUE: &str = "1.1 fluxheim";

pub fn append_fluxheim_via_value(existing: &str) -> String {
    if existing.trim().is_empty() {
        FLUXHEIM_VIA_VALUE.to_owned()
    } else {
        format!("{}, {}", existing.trim(), FLUXHEIM_VIA_VALUE)
    }
}

pub fn response_rewrite_prefix_matches(value: &str, prefix: &str) -> bool {
    if !value.starts_with(prefix) {
        return false;
    }
    if !response_rewrite_prefix_requires_authority_boundary(prefix) {
        return true;
    }
    matches!(
        value.as_bytes().get(prefix.len()),
        None | Some(b'/' | b'?' | b'#')
    )
}

fn response_rewrite_prefix_requires_authority_boundary(prefix: &str) -> bool {
    let Some(authority_and_path) = prefix
        .strip_prefix("http://")
        .or_else(|| prefix.strip_prefix("https://"))
    else {
        return false;
    };
    !authority_and_path
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'/' | b'?' | b'#'))
}

pub fn proxy_protocol_v1_header(
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
) -> Vec<u8> {
    let Some(source) = source else {
        return b"PROXY UNKNOWN\r\n".to_vec();
    };
    let Some(destination) = destination else {
        return b"PROXY UNKNOWN\r\n".to_vec();
    };

    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => format!(
            "PROXY TCP4 {source_ip} {destination_ip} {} {}\r\n",
            source.port(),
            destination.port()
        )
        .into_bytes(),
        (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => format!(
            "PROXY TCP6 {source_ip} {destination_ip} {} {}\r\n",
            source.port(),
            destination.port()
        )
        .into_bytes(),
        _ => b"PROXY UNKNOWN\r\n".to_vec(),
    }
}

const PROXY_PROTOCOL_V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

pub fn proxy_protocol_v2_header(
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
) -> Vec<u8> {
    let mut header = Vec::from(&PROXY_PROTOCOL_V2_SIGNATURE[..]);
    let Some(source) = source else {
        header.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]);
        return header;
    };
    let Some(destination) = destination else {
        header.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]);
        return header;
    };

    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            header.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
            header.extend_from_slice(&source_ip.octets());
            header.extend_from_slice(&destination_ip.octets());
            header.extend_from_slice(&source.port().to_be_bytes());
            header.extend_from_slice(&destination.port().to_be_bytes());
        }
        (IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            header.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
            header.extend_from_slice(&source_ip.octets());
            header.extend_from_slice(&destination_ip.octets());
            header.extend_from_slice(&source.port().to_be_bytes());
            header.extend_from_slice(&destination.port().to_be_bytes());
        }
        _ => header.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]),
    }
    header
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use super::{
        ProxyProtocolTrustedSource, ProxyProtocolTrustedSourceParseError,
        append_fluxheim_via_value, http_token_valid, http_upgrade_token_valid,
        parse_proxy_protocol_trusted_source, proxy_protocol_v1_header, proxy_protocol_v2_header,
        response_rewrite_prefix_matches, route_method_matches, route_prefix_matches_path,
        route_strip_prefix_suffix,
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
    }

    #[test]
    fn route_method_matching_treats_inbound_case_as_equivalent() {
        let methods = vec!["GET".to_owned(), "HEAD".to_owned()];

        assert!(route_method_matches(&methods, "GET"));
        assert!(route_method_matches(&methods, "get"));
        assert!(route_method_matches(&methods, "Head"));
        assert!(!route_method_matches(&methods, "POST"));
    }

    #[test]
    fn route_prefixes_require_path_segment_boundary() {
        assert!(route_prefix_matches_path("/repo", "/repo"));
        assert!(route_prefix_matches_path("/repo", "/repo/"));
        assert!(route_prefix_matches_path("/repo", "/repo/file"));
        assert!(!route_prefix_matches_path("/repo", "/repository"));
    }

    #[test]
    fn route_strip_prefix_requires_path_segment_boundary() {
        assert_eq!(route_strip_prefix_suffix("/api", "/api/v1"), Some("/v1"));
        assert_eq!(route_strip_prefix_suffix("/", "/api/v1"), Some("api/v1"));
        assert_eq!(route_strip_prefix_suffix("/api", "/apiv1"), None);
    }

    #[test]
    fn http_upgrade_tokens_follow_http_token_grammar() {
        assert!(http_token_valid("websocket"));
        assert!(http_token_valid("h2c"));
        assert!(http_token_valid("token!#$%&'*+-.^_`|~09AZaz"));
        assert!(http_upgrade_token_valid("websocket"));
        assert!(!http_token_valid(""));
        assert!(!http_token_valid("web socket"));
        assert!(!http_token_valid("websocket\r\nx"));
        assert!(!http_token_valid("websocket;param"));
        assert!(!http_token_valid("websocket/1"));
    }

    #[test]
    fn appends_fluxheim_via_value_to_existing_chain() {
        assert_eq!(append_fluxheim_via_value(""), "1.1 fluxheim");
        assert_eq!(append_fluxheim_via_value("   "), "1.1 fluxheim");
        assert_eq!(
            append_fluxheim_via_value(" 1.0 edge, 1.1 cache "),
            "1.0 edge, 1.1 cache, 1.1 fluxheim"
        );
    }

    #[test]
    fn response_rewrite_prefix_requires_authority_boundary_for_origin_prefixes() {
        assert!(response_rewrite_prefix_matches(
            "http://backend.internal",
            "http://backend.internal"
        ));
        assert!(response_rewrite_prefix_matches(
            "http://backend.internal/login",
            "http://backend.internal"
        ));
        assert!(response_rewrite_prefix_matches(
            "http://backend.internal?next=/",
            "http://backend.internal"
        ));
        assert!(response_rewrite_prefix_matches(
            "http://backend.internal#fragment",
            "http://backend.internal"
        ));
        assert!(!response_rewrite_prefix_matches(
            "http://backend.internal@evil.example/phish",
            "http://backend.internal"
        ));
        assert!(!response_rewrite_prefix_matches(
            "http://backend.internal.evil.example/phish",
            "http://backend.internal"
        ));
        assert!(!response_rewrite_prefix_matches(
            "http://backend.internal.evil.example/phish",
            "http://backend.internal."
        ));
        assert!(response_rewrite_prefix_matches("/old/path", "/old"));
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
}

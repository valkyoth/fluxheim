use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProxyProtocolTrustedSource {
    Ip(IpAddr),
    Cidr { network: IpAddr, prefix: u8 },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProxyProtocolTrustedSourceParseError {
    InvalidAddress,
    InvalidNetwork,
    InvalidPrefix,
}

impl std::fmt::Display for ProxyProtocolTrustedSourceParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAddress => formatter.write_str("invalid PROXY protocol trusted address"),
            Self::InvalidNetwork => {
                formatter.write_str("invalid PROXY protocol trusted CIDR network address")
            }
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
        let max_prefix = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            return Err(ProxyProtocolTrustedSourceParseError::InvalidPrefix);
        }
        if !cidr_network_address_is_canonical(network, prefix) {
            return Err(ProxyProtocolTrustedSourceParseError::InvalidNetwork);
        }
        return Ok(ProxyProtocolTrustedSource::Cidr { network, prefix });
    }
    Ok(ProxyProtocolTrustedSource::Ip(
        value
            .parse::<IpAddr>()
            .map_err(|_| ProxyProtocolTrustedSourceParseError::InvalidAddress)?,
    ))
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

pub const PROXY_PROTOCOL_V1_MAX_LINE: usize = 108;
pub const PROXY_PROTOCOL_V2_HEADER_LEN: usize = 16;
pub const PROXY_PROTOCOL_V2_MAX_PAYLOAD: usize = 4096;
pub const PROXY_PROTOCOL_V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DownstreamProxyProtocolParseError {
    V1LineTooLong,
    V1NotUtf8,
    V1MissingCrlf,
    V1MissingPrefix,
    V1MissingFamily,
    V1MissingSourceAddress,
    V1MissingDestinationAddress,
    V1MissingSourcePort,
    V1MissingDestinationPort,
    V1UnexpectedFields,
    V1InvalidSourceAddress,
    V1InvalidDestinationAddress,
    V1FamilyAddressMismatch,
    InvalidPort,
    V2InvalidSignature,
    V2InvalidVersion,
    V2InvalidCommand,
    V2InvalidLength,
    V2TruncatedTcp4,
    V2TruncatedTcp6,
    V2InvalidTcp6Source,
    V2UnsupportedAddressFamily,
}

impl std::fmt::Display for DownstreamProxyProtocolParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_static_str())
    }
}

impl std::error::Error for DownstreamProxyProtocolParseError {}

impl DownstreamProxyProtocolParseError {
    pub const fn as_static_str(self) -> &'static str {
        match self {
            Self::V1LineTooLong => "stream downstream PROXY v1 header exceeds 108 bytes",
            Self::V1NotUtf8 => "stream downstream PROXY v1 header is not UTF-8",
            Self::V1MissingCrlf => "stream downstream PROXY v1 header is missing CRLF",
            Self::V1MissingPrefix => "stream downstream PROXY v1 header is missing prefix",
            Self::V1MissingFamily => "stream downstream PROXY v1 header is missing family",
            Self::V1MissingSourceAddress => {
                "stream downstream PROXY v1 header is missing source address"
            }
            Self::V1MissingDestinationAddress => {
                "stream downstream PROXY v1 header is missing destination address"
            }
            Self::V1MissingSourcePort => "stream downstream PROXY v1 header is missing source port",
            Self::V1MissingDestinationPort => {
                "stream downstream PROXY v1 header is missing destination port"
            }
            Self::V1UnexpectedFields => "stream downstream PROXY v1 header has unexpected fields",
            Self::V1InvalidSourceAddress => "stream downstream PROXY v1 source address is invalid",
            Self::V1InvalidDestinationAddress => {
                "stream downstream PROXY v1 destination address is invalid"
            }
            Self::V1FamilyAddressMismatch => {
                "stream downstream PROXY v1 family does not match address types"
            }
            Self::InvalidPort => "stream downstream PROXY port is invalid",
            Self::V2InvalidVersion => "stream downstream PROXY v2 header has invalid version",
            Self::V2InvalidSignature => "stream downstream PROXY v2 header has invalid signature",
            Self::V2InvalidCommand => "stream downstream PROXY v2 header has invalid command",
            Self::V2InvalidLength => {
                "stream downstream PROXY v2 payload length does not match its header"
            }
            Self::V2TruncatedTcp4 => "stream downstream PROXY v2 TCP4 address is truncated",
            Self::V2TruncatedTcp6 => "stream downstream PROXY v2 TCP6 address is truncated",
            Self::V2InvalidTcp6Source => "stream downstream PROXY v2 TCP6 source is invalid",
            Self::V2UnsupportedAddressFamily => {
                "stream downstream PROXY v2 address family is unsupported"
            }
        }
    }
}

pub fn parse_downstream_proxy_protocol_v1(
    line: &[u8],
) -> Result<Option<SocketAddr>, DownstreamProxyProtocolParseError> {
    if line.len() > PROXY_PROTOCOL_V1_MAX_LINE {
        return Err(DownstreamProxyProtocolParseError::V1LineTooLong);
    }
    let line =
        std::str::from_utf8(line).map_err(|_| DownstreamProxyProtocolParseError::V1NotUtf8)?;
    let line = line
        .strip_suffix("\r\n")
        .ok_or(DownstreamProxyProtocolParseError::V1MissingCrlf)?;
    let mut fields = line.split_whitespace();
    if fields.next() != Some("PROXY") {
        return Err(DownstreamProxyProtocolParseError::V1MissingPrefix);
    }
    let family = fields
        .next()
        .ok_or(DownstreamProxyProtocolParseError::V1MissingFamily)?;
    if family == "UNKNOWN" {
        return Ok(None);
    }
    let source_addr = fields
        .next()
        .ok_or(DownstreamProxyProtocolParseError::V1MissingSourceAddress)?;
    let destination_addr = fields
        .next()
        .ok_or(DownstreamProxyProtocolParseError::V1MissingDestinationAddress)?;
    let source_port = fields
        .next()
        .ok_or(DownstreamProxyProtocolParseError::V1MissingSourcePort)?;
    let destination_port = fields
        .next()
        .ok_or(DownstreamProxyProtocolParseError::V1MissingDestinationPort)?;
    if fields.next().is_some() {
        return Err(DownstreamProxyProtocolParseError::V1UnexpectedFields);
    }
    let source_ip = source_addr
        .parse::<IpAddr>()
        .map_err(|_| DownstreamProxyProtocolParseError::V1InvalidSourceAddress)?;
    let destination_ip = destination_addr
        .parse::<IpAddr>()
        .map_err(|_| DownstreamProxyProtocolParseError::V1InvalidDestinationAddress)?;
    match (family, source_ip, destination_ip) {
        ("TCP4", IpAddr::V4(_), IpAddr::V4(_)) | ("TCP6", IpAddr::V6(_), IpAddr::V6(_)) => {}
        _ => return Err(DownstreamProxyProtocolParseError::V1FamilyAddressMismatch),
    }
    let source_port = parse_proxy_protocol_port(source_port)?;
    let _destination_port = parse_proxy_protocol_port(destination_port)?;
    Ok(Some(SocketAddr::new(source_ip, source_port)))
}

pub fn parse_downstream_proxy_protocol_v2(
    header: &[u8; PROXY_PROTOCOL_V2_HEADER_LEN],
    payload: &[u8],
) -> Result<Option<SocketAddr>, DownstreamProxyProtocolParseError> {
    let declared_length = usize::from(u16::from_be_bytes([header[14], header[15]]));
    if declared_length > PROXY_PROTOCOL_V2_MAX_PAYLOAD || payload.len() != declared_length {
        return Err(DownstreamProxyProtocolParseError::V2InvalidLength);
    }
    if &header[..PROXY_PROTOCOL_V2_SIGNATURE.len()] != PROXY_PROTOCOL_V2_SIGNATURE {
        return Err(DownstreamProxyProtocolParseError::V2InvalidSignature);
    }
    if header[12] >> 4 != 0x2 {
        return Err(DownstreamProxyProtocolParseError::V2InvalidVersion);
    }
    match header[12] & 0x0f {
        0x00 => return Ok(None),
        0x01 => {}
        _ => return Err(DownstreamProxyProtocolParseError::V2InvalidCommand),
    }
    match header[13] {
        0x11 => {
            if payload.len() < 12 {
                return Err(DownstreamProxyProtocolParseError::V2TruncatedTcp4);
            }
            let source = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let port = u16::from_be_bytes([payload[8], payload[9]]);
            Ok(Some(SocketAddr::new(IpAddr::V4(source), port)))
        }
        0x21 => {
            if payload.len() < 36 {
                return Err(DownstreamProxyProtocolParseError::V2TruncatedTcp6);
            }
            let source = Ipv6Addr::from(
                <[u8; 16]>::try_from(&payload[0..16])
                    .map_err(|_| DownstreamProxyProtocolParseError::V2InvalidTcp6Source)?,
            );
            let port = u16::from_be_bytes([payload[32], payload[33]]);
            Ok(Some(SocketAddr::new(IpAddr::V6(source), port)))
        }
        0x00 => Ok(None),
        _ => Err(DownstreamProxyProtocolParseError::V2UnsupportedAddressFamily),
    }
}

fn parse_proxy_protocol_port(value: &str) -> Result<u16, DownstreamProxyProtocolParseError> {
    value
        .parse::<u16>()
        .map_err(|_| DownstreamProxyProtocolParseError::InvalidPort)
}

fn cidr_network_address_is_canonical(network: IpAddr, prefix: u8) -> bool {
    match network {
        IpAddr::V4(address) => {
            let address = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            address & !mask == 0
        }
        IpAddr::V6(address) => {
            let address = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            address & !mask == 0
        }
    }
}

#[cfg(test)]
#[path = "proxy_protocol_tests.rs"]
mod tests;

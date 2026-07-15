#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::config::{DownstreamProxyProtocol, UpstreamProxyProtocol};
use fluxheim_config::config_stream::StreamRouteConfig;
use fluxheim_protocol::{
    DownstreamProxyProtocolParseError, PROXY_PROTOCOL_V1_MAX_LINE, PROXY_PROTOCOL_V2_HEADER_LEN,
    PROXY_PROTOCOL_V2_MAX_PAYLOAD, PROXY_PROTOCOL_V2_SIGNATURE, parse_downstream_proxy_protocol_v1,
    parse_downstream_proxy_protocol_v2, proxy_protocol_v1_header, proxy_protocol_v2_header,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

mod copy;
mod selector;

pub use copy::{checked_stream_byte_count, copy_bidirectional_with_limits};
pub use selector::{StreamSelectedUpstream, StreamUpstreamSelector};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StreamSourcePolicy {
    allow: Arc<[StreamSourceMatcher]>,
    deny: Arc<[StreamSourceMatcher]>,
}

impl StreamSourcePolicy {
    pub fn from_route(route: &StreamRouteConfig) -> FluxResult<Self> {
        Ok(Self {
            allow: parse_stream_source_matchers(&route.allow_sources, "allow source")?.into(),
            deny: parse_stream_source_matchers(&route.deny_sources, "deny source")?.into(),
        })
    }

    pub fn source_allowed(&self, source: Option<SocketAddr>) -> bool {
        let Some(source) = source else {
            return self.allow.is_empty();
        };
        let source_ip = source.ip();
        if self.deny.iter().any(|matcher| matcher.matches(source_ip)) {
            return false;
        }
        self.allow.is_empty() || self.allow.iter().any(|matcher| matcher.matches(source_ip))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StreamSourceMatcher {
    Ip(IpAddr),
    Cidr { network: IpAddr, prefix: u8 },
}

impl StreamSourceMatcher {
    pub fn parse(value: &str, field: &'static str) -> FluxResult<Self> {
        if let Some((address, prefix)) = value.split_once('/') {
            let network = address.parse::<IpAddr>().map_err(|error| {
                FluxError::invalid_input(format!(
                    "invalid stream {field} network {value:?}: {error}"
                ))
            })?;
            let prefix = prefix.parse::<u8>().map_err(|error| {
                FluxError::invalid_input(format!(
                    "invalid stream {field} prefix {value:?}: {error}"
                ))
            })?;
            let max_prefix = match network {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max_prefix {
                return Err(FluxError::invalid_input(format!(
                    "invalid stream {field} prefix {value:?}: prefix exceeds address family width"
                )));
            }
            return Ok(Self::Cidr { network, prefix });
        }
        Ok(Self::Ip(value.parse::<IpAddr>().map_err(|error| {
            FluxError::invalid_input(format!("invalid stream {field} address {value:?}: {error}"))
        })?))
    }

    pub fn matches(&self, address: IpAddr) -> bool {
        match self {
            Self::Ip(trusted) => *trusted == address,
            Self::Cidr { network, prefix } => ip_in_prefix(address, *network, *prefix),
        }
    }
}

pub type StreamTrustedSource = StreamSourceMatcher;

pub fn parse_stream_trusted_sources(
    route: &StreamRouteConfig,
) -> FluxResult<Vec<StreamTrustedSource>> {
    if route.downstream_proxy_protocol == fluxheim_config::config::DownstreamProxyProtocol::Off {
        return Ok(Vec::new());
    }
    route
        .trusted_proxies
        .iter()
        .map(|source| StreamSourceMatcher::parse(source, "trusted proxy"))
        .collect::<FluxResult<Vec<_>>>()
}

fn parse_stream_source_matchers(
    values: &[String],
    field: &'static str,
) -> FluxResult<Vec<StreamSourceMatcher>> {
    values
        .iter()
        .map(|source| StreamSourceMatcher::parse(source, field))
        .collect::<FluxResult<Vec<_>>>()
}

pub fn stream_dns_resolved_address_allowed(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => stream_dns_resolved_ipv4_address_allowed(address),
        IpAddr::V6(address) => stream_dns_resolved_ipv6_address_allowed(address),
    }
}

fn stream_dns_resolved_ipv4_address_allowed(address: Ipv4Addr) -> bool {
    let [first, second, third, fourth] = address.octets();
    let ietf_protocol_assignment =
        first == 192 && second == 0 && third == 0 && !matches!(fourth, 9 | 10);
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_documentation()
        || ietf_protocol_assignment
        || first >= 240
        || first == 0
        || (first == 100 && (64..=127).contains(&second))
        || (first == 198 && matches!(second, 18 | 19)))
}

fn stream_dns_resolved_ipv6_address_allowed(address: Ipv6Addr) -> bool {
    if let Some(address) = address.to_ipv4() {
        return stream_dns_resolved_ipv4_address_allowed(address);
    }
    let segments = address.segments();
    let special_or_transition = (segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2..6].iter().all(|segment| *segment == 0))
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1)
        || (segments[0] == 0x0100
            && segments[1] == 0
            && segments[2] == 0
            && matches!(segments[3], 0 | 1))
        || (segments[0] == 0x2001 && segments[1] < 0x0200)
        || segments[0] == 0x2002
        || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
        || segments[0] == 0x5f00
        || (segments[0] & 0xffc0) == 0xfec0;
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        && !special_or_transition
}

pub fn stream_error_outcome(error: &FluxError) -> &'static str {
    let kind = match error {
        FluxError::Io { source, .. } | FluxError::WriteProxyHeader(source) => source.kind(),
        FluxError::Timeout { .. } => io::ErrorKind::TimedOut,
        FluxError::InvalidInput(_) | FluxError::InvalidInputMessage(_) => {
            io::ErrorKind::InvalidInput
        }
    };
    match kind {
        io::ErrorKind::Interrupted => "shutdown",
        io::ErrorKind::TimedOut => "timeout",
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::NotConnected => "connect_error",
        _ => "error",
    }
}

pub async fn write_upstream_proxy_protocol(
    upstream: &mut (impl AsyncWrite + Unpin),
    protocol: UpstreamProxyProtocol,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
    idle_timeout: Duration,
) -> FluxResult<()> {
    let header = match protocol {
        UpstreamProxyProtocol::Off => return Ok(()),
        UpstreamProxyProtocol::V1 => proxy_protocol_v1_header(source, destination),
        UpstreamProxyProtocol::V2 => proxy_protocol_v2_header(source, destination),
    };
    write_with_idle_timeout(upstream, &header, idle_timeout).await
}

pub async fn apply_downstream_proxy_protocol_to_stream(
    downstream: &mut (impl AsyncRead + Unpin),
    protocol: DownstreamProxyProtocol,
    trusted_sources: &[StreamTrustedSource],
    direct_source: Option<SocketAddr>,
    proxy_header_timeout: Duration,
) -> FluxResult<Option<SocketAddr>> {
    if protocol == DownstreamProxyProtocol::Off {
        return Ok(direct_source);
    }
    let Some(direct_source) = direct_source else {
        return Err(FluxError::InvalidInput(
            "stream downstream PROXY protocol requires a TCP peer address",
        ));
    };
    if !trusted_sources
        .iter()
        .any(|source| source.matches(direct_source.ip()))
    {
        return Err(FluxError::InvalidInput(
            "stream downstream PROXY protocol peer is not trusted",
        ));
    }
    let parse = async {
        match protocol {
            DownstreamProxyProtocol::Off => Ok(Some(direct_source)),
            DownstreamProxyProtocol::V1 => read_downstream_proxy_protocol_v1(downstream).await,
            DownstreamProxyProtocol::V2 => read_downstream_proxy_protocol_v2(downstream).await,
        }
    };
    tokio::time::timeout(proxy_header_timeout, parse)
        .await
        .map_err(|_| {
            FluxError::timeout(
                "stream PROXY header timeout",
                "complete PROXY header was not received before the deadline",
            )
        })?
}

async fn read_downstream_proxy_protocol_v1(
    downstream: &mut (impl AsyncRead + Unpin),
) -> FluxResult<Option<SocketAddr>> {
    let mut line = Vec::with_capacity(PROXY_PROTOCOL_V1_MAX_LINE);
    loop {
        let mut byte = [0u8; 1];
        let read = downstream
            .read(&mut byte)
            .await
            .map_err(|error| FluxError::io("read stream PROXY header", error))?;
        if read == 0 {
            return Err(FluxError::InvalidInput(
                "stream downstream PROXY protocol v1 header ended early",
            ));
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= PROXY_PROTOCOL_V1_MAX_LINE {
            return Err(FluxError::InvalidInput(
                "stream downstream PROXY protocol v1 header exceeds size limit",
            ));
        }
    }
    parse_downstream_proxy_protocol_v1(&line).map_err(proxy_protocol_parse_error)
}

async fn read_downstream_proxy_protocol_v2(
    downstream: &mut (impl AsyncRead + Unpin),
) -> FluxResult<Option<SocketAddr>> {
    let mut header = [0u8; PROXY_PROTOCOL_V2_HEADER_LEN];
    read_exact_proxy_header(downstream, &mut header).await?;
    if &header[..PROXY_PROTOCOL_V2_SIGNATURE.len()] != PROXY_PROTOCOL_V2_SIGNATURE {
        return Err(FluxError::InvalidInput(
            "stream downstream PROXY v2 header has invalid signature",
        ));
    }
    let payload_len = u16::from_be_bytes([header[14], header[15]]) as usize;
    if payload_len > PROXY_PROTOCOL_V2_MAX_PAYLOAD {
        return Err(FluxError::InvalidInput(
            "stream downstream PROXY v2 payload exceeds size limit",
        ));
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        read_exact_proxy_header(downstream, &mut payload).await?;
    }
    parse_downstream_proxy_protocol_v2(&header, &payload).map_err(proxy_protocol_parse_error)
}

async fn write_with_idle_timeout<W>(
    writer: &mut W,
    buffer: &[u8],
    idle_timeout: Duration,
) -> FluxResult<()>
where
    W: AsyncWrite + Unpin,
{
    match tokio::time::timeout(idle_timeout, writer.write_all(buffer)).await {
        Ok(result) => result.map_err(|error| FluxError::io("write stream", error)),
        Err(_) => Err(FluxError::timeout(
            "stream write timeout",
            "stream write timeout elapsed",
        )),
    }
}

async fn read_exact_proxy_header<R>(reader: &mut R, buffer: &mut [u8]) -> FluxResult<()>
where
    R: AsyncRead + Unpin,
{
    let mut offset = 0usize;
    while offset < buffer.len() {
        let read = reader
            .read(&mut buffer[offset..])
            .await
            .map_err(|error| FluxError::io("read stream PROXY header", error))?;
        if read == 0 {
            return Err(FluxError::InvalidInput(
                "stream downstream PROXY protocol header ended early",
            ));
        }
        offset = offset.checked_add(read).ok_or(FluxError::InvalidInput(
            "stream downstream PROXY protocol read offset overflowed",
        ))?;
    }
    Ok(())
}

fn proxy_protocol_parse_error(error: DownstreamProxyProtocolParseError) -> FluxError {
    FluxError::InvalidInput(error.as_static_str())
}

fn ip_in_prefix(address: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (address, network) {
        (IpAddr::V4(address), IpAddr::V4(network)) => {
            let mask = prefix_mask(prefix, 32) as u32;
            u32::from(address) & mask == u32::from(network) & mask
        }
        (IpAddr::V6(address), IpAddr::V6(network)) => {
            let mask = prefix_mask(prefix, 128);
            u128::from(address) & mask == u128::from(network) & mask
        }
        _ => false,
    }
}

fn prefix_mask(prefix: u8, bits: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << u32::from(bits.saturating_sub(prefix))
    }
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;

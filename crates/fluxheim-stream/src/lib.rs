#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::config::{DownstreamProxyProtocol, UpstreamProxyProtocol};
use fluxheim_config::config_stream::StreamRouteConfig;
use fluxheim_protocol::{proxy_protocol_v1_header, proxy_protocol_v2_header};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

pub const PROXY_PROTOCOL_V1_MAX_LINE: usize = 108;
pub const PROXY_PROTOCOL_V2_HEADER_LEN: usize = 16;
pub const PROXY_PROTOCOL_V2_MAX_PAYLOAD: usize = 4096;
pub const PROXY_PROTOCOL_V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

#[derive(Debug)]
pub struct StreamUpstreamSelector {
    upstreams: Arc<[RuntimeStreamUpstream]>,
    primary_indices: Arc<[usize]>,
    backup_indices: Arc<[usize]>,
    primary_weight_total: usize,
    next_upstream: AtomicUsize,
}

impl StreamUpstreamSelector {
    pub fn from_route(route: &StreamRouteConfig) -> FluxResult<Self> {
        let upstreams = runtime_stream_upstreams(route);
        if upstreams.is_empty() {
            return Err(FluxError::InvalidInput(
                "stream route requires at least one upstream",
            ));
        }
        let primary_indices = upstreams
            .iter()
            .enumerate()
            .filter_map(|(index, upstream)| {
                (!upstream.backup && !upstream.drained).then_some(index)
            })
            .collect::<Vec<_>>();
        if primary_indices.is_empty() {
            return Err(FluxError::InvalidInput(
                "stream route requires at least one selectable primary upstream",
            ));
        }
        let backup_indices = upstreams
            .iter()
            .enumerate()
            .filter_map(|(index, upstream)| (upstream.backup && !upstream.drained).then_some(index))
            .collect::<Vec<_>>();
        let primary_weight_total = primary_indices
            .iter()
            .map(|index| upstreams[*index].weight)
            .sum::<usize>()
            .max(1);

        Ok(Self {
            upstreams: upstreams.into(),
            primary_indices: primary_indices.into(),
            backup_indices: backup_indices.into(),
            primary_weight_total,
            next_upstream: AtomicUsize::new(0),
        })
    }

    pub fn select_candidates(&self) -> Vec<StreamSelectedUpstream> {
        let weighted_index =
            self.next_upstream.fetch_add(1, Ordering::Relaxed) % self.primary_weight_total;
        let first = self
            .primary_indices
            .iter()
            .copied()
            .scan(0usize, |seen, index| {
                *seen = seen.saturating_add(self.upstreams[index].weight);
                Some((index, *seen))
            })
            .find_map(|(index, seen)| (weighted_index < seen).then_some(index))
            .unwrap_or(self.primary_indices[0]);

        self.primary_indices
            .iter()
            .copied()
            .filter(move |index| *index == first)
            .chain(
                self.primary_indices
                    .iter()
                    .copied()
                    .filter(move |index| *index != first),
            )
            .chain(self.backup_indices.iter().copied())
            .map(|index| StreamSelectedUpstream {
                authority: self.upstreams[index].authority.clone(),
                alias: self.upstreams[index].alias.clone(),
                backup: self.upstreams[index].backup,
            })
            .collect()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct RuntimeStreamUpstream {
    authority: Arc<str>,
    alias: Option<Arc<str>>,
    weight: usize,
    backup: bool,
    drained: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StreamSelectedUpstream {
    pub authority: Arc<str>,
    pub alias: Option<Arc<str>>,
    pub backup: bool,
}

impl StreamSelectedUpstream {
    pub fn label(&self) -> &str {
        self.alias.as_deref().unwrap_or(self.authority.as_ref())
    }
}

fn runtime_stream_upstreams(route: &StreamRouteConfig) -> Vec<RuntimeStreamUpstream> {
    let backup = route
        .backup_upstreams
        .iter()
        .map(|upstream| upstream.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let drain = route
        .drain_upstreams
        .iter()
        .map(|upstream| upstream.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    route
        .upstreams()
        .enumerate()
        .map(|(index, authority)| {
            let normalized = authority.to_ascii_lowercase();
            RuntimeStreamUpstream {
                authority: Arc::from(authority),
                alias: route
                    .upstream_aliases
                    .get(index)
                    .map(|alias| Arc::<str>::from(alias.as_str())),
                weight: route.upstream_weights.get(index).copied().unwrap_or(1),
                backup: backup.contains(&normalized),
                drained: drain.contains(&normalized),
            }
        })
        .collect()
}

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
    let [first, second, ..] = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_documentation()
        || first >= 240
        || first == 0
        || (first == 100 && (64..=127).contains(&second))
        || (first == 198 && matches!(second, 18 | 19)))
}

fn stream_dns_resolved_ipv6_address_allowed(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
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

pub fn checked_stream_byte_count(
    current: u64,
    additional: u64,
    max_connection_bytes: Option<u64>,
) -> FluxResult<u64> {
    let next = current.checked_add(additional).ok_or_else(|| {
        FluxError::io(
            "count stream bytes",
            io::Error::new(
                io::ErrorKind::InvalidData,
                "stream copied byte counter overflowed",
            ),
        )
    })?;
    if max_connection_bytes.is_some_and(|limit| next > limit) {
        return Err(FluxError::io(
            "enforce stream byte limit",
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "stream max connection bytes exceeded",
            ),
        ));
    }
    Ok(next)
}

enum StreamCopyEvent {
    DownstreamTotal(u64),
    UpstreamTotal(u64),
    DownstreamEof,
    UpstreamEof,
}

pub async fn copy_bidirectional_with_limits(
    downstream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    upstream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    idle_timeout: Duration,
    max_connection_bytes: Option<u64>,
) -> FluxResult<(u64, u64)> {
    let (mut downstream_reader, mut downstream_writer) = tokio::io::split(downstream);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream);
    let mut downstream_buffer = [0u8; 16 * 1024];
    let mut upstream_buffer = [0u8; 16 * 1024];
    let mut downstream_to_upstream = 0u64;
    let mut upstream_to_downstream = 0u64;
    let mut downstream_eof = false;
    let mut upstream_eof = false;

    while !downstream_eof || !upstream_eof {
        let event = tokio::select! {
            result = async {
                let bytes = read_with_idle_timeout(
                    &mut downstream_reader,
                    &mut downstream_buffer,
                    idle_timeout,
                ).await?;
                if bytes == 0 {
                    shutdown_with_idle_timeout(&mut upstream_writer, idle_timeout).await?;
                    Ok::<_, FluxError>(StreamCopyEvent::DownstreamEof)
                } else {
                    let next = checked_stream_byte_count(
                        downstream_to_upstream,
                        bytes as u64,
                        max_connection_bytes,
                    )?;
                    write_with_idle_timeout(
                        &mut upstream_writer,
                        &downstream_buffer[..bytes],
                        idle_timeout,
                    ).await?;
                    Ok::<_, FluxError>(StreamCopyEvent::DownstreamTotal(next))
                }
            }, if !downstream_eof => result,
            result = async {
                let bytes = read_with_idle_timeout(
                    &mut upstream_reader,
                    &mut upstream_buffer,
                    idle_timeout,
                ).await?;
                if bytes == 0 {
                    shutdown_with_idle_timeout(&mut downstream_writer, idle_timeout).await?;
                    Ok::<_, FluxError>(StreamCopyEvent::UpstreamEof)
                } else {
                    let next = checked_stream_byte_count(
                        upstream_to_downstream,
                        bytes as u64,
                        max_connection_bytes,
                    )?;
                    write_with_idle_timeout(
                        &mut downstream_writer,
                        &upstream_buffer[..bytes],
                        idle_timeout,
                    ).await?;
                    Ok::<_, FluxError>(StreamCopyEvent::UpstreamTotal(next))
                }
            }, if !upstream_eof => result,
        }?;

        match event {
            StreamCopyEvent::DownstreamTotal(total) => downstream_to_upstream = total,
            StreamCopyEvent::UpstreamTotal(total) => upstream_to_downstream = total,
            StreamCopyEvent::DownstreamEof => downstream_eof = true,
            StreamCopyEvent::UpstreamEof => upstream_eof = true,
        }
    }

    Ok((downstream_to_upstream, upstream_to_downstream))
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
    idle_timeout: Duration,
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
    match protocol {
        DownstreamProxyProtocol::Off => Ok(Some(direct_source)),
        DownstreamProxyProtocol::V1 => {
            read_downstream_proxy_protocol_v1(downstream, idle_timeout).await
        }
        DownstreamProxyProtocol::V2 => {
            read_downstream_proxy_protocol_v2(downstream, idle_timeout).await
        }
    }
}

async fn read_downstream_proxy_protocol_v1(
    downstream: &mut (impl AsyncRead + Unpin),
    idle_timeout: Duration,
) -> FluxResult<Option<SocketAddr>> {
    let mut line = Vec::with_capacity(PROXY_PROTOCOL_V1_MAX_LINE);
    loop {
        let mut byte = [0u8; 1];
        let read = read_with_idle_timeout(downstream, &mut byte, idle_timeout).await?;
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
    parse_downstream_proxy_protocol_v1(&line)
}

pub fn parse_downstream_proxy_protocol_v1(line: &[u8]) -> FluxResult<Option<SocketAddr>> {
    let line = std::str::from_utf8(line)
        .map_err(|_| FluxError::InvalidInput("stream downstream PROXY v1 header is not UTF-8"))?;
    let line = line.strip_suffix("\r\n").ok_or(FluxError::InvalidInput(
        "stream downstream PROXY v1 header is missing CRLF",
    ))?;
    let mut fields = line.split_whitespace();
    if fields.next() != Some("PROXY") {
        return Err(FluxError::InvalidInput(
            "stream downstream PROXY v1 header is missing prefix",
        ));
    }
    let family = fields.next().ok_or(FluxError::InvalidInput(
        "stream downstream PROXY v1 header is missing family",
    ))?;
    if family == "UNKNOWN" {
        return Ok(None);
    }
    let source_addr = fields.next().ok_or(FluxError::InvalidInput(
        "stream downstream PROXY v1 header is missing source address",
    ))?;
    let destination_addr = fields.next().ok_or(FluxError::InvalidInput(
        "stream downstream PROXY v1 header is missing destination address",
    ))?;
    let source_port = fields.next().ok_or(FluxError::InvalidInput(
        "stream downstream PROXY v1 header is missing source port",
    ))?;
    let destination_port = fields.next().ok_or(FluxError::InvalidInput(
        "stream downstream PROXY v1 header is missing destination port",
    ))?;
    if fields.next().is_some() {
        return Err(FluxError::InvalidInput(
            "stream downstream PROXY v1 header has unexpected fields",
        ));
    }
    let source_ip = source_addr.parse::<IpAddr>().map_err(|_| {
        FluxError::InvalidInput("stream downstream PROXY v1 source address is invalid")
    })?;
    let destination_ip = destination_addr.parse::<IpAddr>().map_err(|_| {
        FluxError::InvalidInput("stream downstream PROXY v1 destination address is invalid")
    })?;
    match (family, source_ip, destination_ip) {
        ("TCP4", IpAddr::V4(_), IpAddr::V4(_)) | ("TCP6", IpAddr::V6(_), IpAddr::V6(_)) => {}
        _ => {
            return Err(FluxError::InvalidInput(
                "stream downstream PROXY v1 family does not match address types",
            ));
        }
    }
    let source_port = parse_proxy_protocol_port(source_port)?;
    let _destination_port = parse_proxy_protocol_port(destination_port)?;
    Ok(Some(SocketAddr::new(source_ip, source_port)))
}

async fn read_downstream_proxy_protocol_v2(
    downstream: &mut (impl AsyncRead + Unpin),
    idle_timeout: Duration,
) -> FluxResult<Option<SocketAddr>> {
    let mut header = [0u8; PROXY_PROTOCOL_V2_HEADER_LEN];
    read_exact_with_idle_timeout(downstream, &mut header, idle_timeout).await?;
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
        read_exact_with_idle_timeout(downstream, &mut payload, idle_timeout).await?;
    }
    parse_downstream_proxy_protocol_v2(&header, &payload)
}

pub fn parse_downstream_proxy_protocol_v2(
    header: &[u8; PROXY_PROTOCOL_V2_HEADER_LEN],
    payload: &[u8],
) -> FluxResult<Option<SocketAddr>> {
    if header[12] >> 4 != 0x2 {
        return Err(FluxError::InvalidInput(
            "stream downstream PROXY v2 header has invalid version",
        ));
    }
    match header[12] & 0x0f {
        0x00 => return Ok(None),
        0x01 => {}
        _ => {
            return Err(FluxError::InvalidInput(
                "stream downstream PROXY v2 header has invalid command",
            ));
        }
    }
    match header[13] {
        0x11 => {
            if payload.len() < 12 {
                return Err(FluxError::InvalidInput(
                    "stream downstream PROXY v2 TCP4 address is truncated",
                ));
            }
            let source = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let port = u16::from_be_bytes([payload[8], payload[9]]);
            Ok(Some(SocketAddr::new(IpAddr::V4(source), port)))
        }
        0x21 => {
            if payload.len() < 36 {
                return Err(FluxError::InvalidInput(
                    "stream downstream PROXY v2 TCP6 address is truncated",
                ));
            }
            let source = Ipv6Addr::from(<[u8; 16]>::try_from(&payload[0..16]).map_err(|_| {
                FluxError::InvalidInput("stream downstream PROXY v2 TCP6 source is invalid")
            })?);
            let port = u16::from_be_bytes([payload[32], payload[33]]);
            Ok(Some(SocketAddr::new(IpAddr::V6(source), port)))
        }
        0x00 => Ok(None),
        _ => Err(FluxError::InvalidInput(
            "stream downstream PROXY v2 address family is unsupported",
        )),
    }
}

async fn read_with_idle_timeout<R>(
    reader: &mut R,
    buffer: &mut [u8],
    idle_timeout: Duration,
) -> FluxResult<usize>
where
    R: AsyncRead + Unpin,
{
    match tokio::time::timeout(idle_timeout, reader.read(buffer)).await {
        Ok(result) => result.map_err(|error| FluxError::io("read stream", error)),
        Err(_) => Err(FluxError::timeout(
            "stream idle timeout",
            "stream idle timeout elapsed",
        )),
    }
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

async fn shutdown_with_idle_timeout<W>(writer: &mut W, idle_timeout: Duration) -> FluxResult<()>
where
    W: AsyncWrite + Unpin,
{
    match tokio::time::timeout(idle_timeout, writer.shutdown()).await {
        Ok(result) => result.map_err(|error| FluxError::io("shutdown stream", error)),
        Err(_) => Err(FluxError::timeout(
            "stream shutdown timeout",
            "stream shutdown timeout elapsed",
        )),
    }
}

async fn read_exact_with_idle_timeout<R>(
    reader: &mut R,
    buffer: &mut [u8],
    idle_timeout: Duration,
) -> FluxResult<()>
where
    R: AsyncRead + Unpin,
{
    let mut offset = 0usize;
    while offset < buffer.len() {
        let read = read_with_idle_timeout(reader, &mut buffer[offset..], idle_timeout).await?;
        if read == 0 {
            return Err(FluxError::InvalidInput(
                "stream downstream PROXY protocol header ended early",
            ));
        }
        offset = offset.saturating_add(read);
    }
    Ok(())
}

fn parse_proxy_protocol_port(value: &str) -> FluxResult<u16> {
    value
        .parse::<u16>()
        .map_err(|_| FluxError::InvalidInput("stream downstream PROXY port is invalid"))
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
mod tests {
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
            parse_downstream_proxy_protocol_v1(
                b"PROXY UNKNOWN 192.0.2.20 203.0.113.10 443 42300\r\n"
            )
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
}

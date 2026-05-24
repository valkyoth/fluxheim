// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The listening endpoints (TCP and TLS) and their configurations.
//!
//! This module provides the infrastructure for setting up network listeners
//! that accept incoming connections. It supports TCP, Unix domain sockets,
//! and TLS endpoints.
//!
//! # Connection Filtering
//!
//! With the `connection_filter` feature enabled, this module also provides
//! early connection filtering capabilities through the [`ConnectionFilter`] trait.
//! This allows dropping unwanted connections at the TCP level before any
//! expensive operations like TLS handshakes.
//!
//! ## Example with Connection Filtering
//!
//! ```rust,no_run
//! # #[cfg(feature = "connection_filter")]
//! # {
//! use pingora_core::listeners::{Listeners, ConnectionFilter};
//! use std::sync::Arc;
//!
//! // Create a custom filter
//! let filter = Arc::new(MyCustomFilter::new());
//!
//! // Apply to listeners
//! let mut listeners = Listeners::new();
//! listeners.set_connection_filter(filter);
//! listeners.add_tcp("0.0.0.0:8080");
//! # }
//! ```

mod l4;

#[cfg(feature = "connection_filter")]
pub mod connection_filter;

#[cfg(feature = "connection_filter")]
pub use connection_filter::{AcceptAllFilter, ConnectionFilter};

#[cfg(not(feature = "connection_filter"))]
#[derive(Debug, Clone)]
pub struct AcceptAllFilter;

#[cfg(not(feature = "connection_filter"))]
pub trait ConnectionFilter: std::fmt::Debug + Send + Sync {
    fn should_accept(&self, _addr: &std::net::SocketAddr) -> bool {
        true
    }
}

#[cfg(not(feature = "connection_filter"))]
impl ConnectionFilter for AcceptAllFilter {
    fn should_accept(&self, _addr: &std::net::SocketAddr) -> bool {
        true
    }
}
#[cfg(feature = "any_tls")]
pub mod tls;

#[cfg(not(feature = "any_tls"))]
pub use crate::tls::listeners as tls;

use crate::protocols::{l4::socket::SocketAddr, tls::TlsRef, GetSocketDigest, Stream};

#[cfg(unix)]
use crate::server::ListenFds;

use async_trait::async_trait;
use pingora_error::{Error, ErrorType, Result};
use std::{
    any::Any,
    fs::Permissions,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr as StdSocketAddr},
    sync::Arc,
};
use tokio::io::AsyncReadExt;

use l4::{ListenerEndpoint, Stream as L4Stream};
use tls::{Acceptor, TlsSettings};

pub use crate::protocols::tls::ALPN;
pub use l4::{ServerAddress, TcpSocketOptions};

const PROXY_PROTOCOL_V1_MAX_LINE: usize = 108;
const PROXY_PROTOCOL_V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const PROXY_PROTOCOL_V2_HEADER_LEN: usize = 16;
const PROXY_PROTOCOL_V2_MAX_PAYLOAD: usize = 4096;

#[derive(Clone, Debug)]
pub struct ProxyProtocolConfig {
    version: ProxyProtocolVersion,
    trusted_sources: Arc<[ProxyProtocolTrustedSource]>,
}

impl ProxyProtocolConfig {
    pub fn v1(trusted_sources: Vec<ProxyProtocolTrustedSource>) -> Self {
        Self {
            version: ProxyProtocolVersion::V1,
            trusted_sources: trusted_sources.into(),
        }
    }

    pub fn v2(trusted_sources: Vec<ProxyProtocolTrustedSource>) -> Self {
        Self {
            version: ProxyProtocolVersion::V2,
            trusted_sources: trusted_sources.into(),
        }
    }

    fn trusted(&self, address: &StdSocketAddr) -> bool {
        self.trusted_sources
            .iter()
            .any(|source| source.contains(address.ip()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyProtocolVersion {
    V1,
    V2,
}

#[derive(Clone, Debug)]
pub enum ProxyProtocolTrustedSource {
    Ip(IpAddr),
    Cidr { network: IpAddr, prefix: u8 },
}

impl ProxyProtocolTrustedSource {
    fn contains(&self, ip: IpAddr) -> bool {
        match self {
            Self::Ip(trusted) => *trusted == ip,
            Self::Cidr { network, prefix } => ip_in_prefix(ip, *network, *prefix),
        }
    }
}

fn ip_in_prefix(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(ip) & mask == u32::from(network) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(ip) & mask == u128::from(network) & mask
        }
        _ => false,
    }
}

/// The APIs to customize things like certificate during TLS server side handshake
#[async_trait]
pub trait TlsAccept {
    // TODO: return error?
    /// This function is called in the middle of a TLS handshake. Structs who
    /// implement this function should provide tls certificate and key to the
    /// [TlsRef] via `ssl_use_certificate` and `ssl_use_private_key`.
    /// Note. This is only supported for openssl and boringssl
    async fn certificate_callback(&self, _ssl: &mut TlsRef) -> () {
        // does nothing by default
    }

    /// This function is called after the TLS handshake is complete.
    ///
    /// Any value returned from this function (other than `None`) will be stored in the
    /// `extension` field of `SslDigest`. This allows you to attach custom application-specific
    /// data to the TLS connection, which will be accessible from the HTTP layer via the
    /// `SslDigest` attached to the session digest.
    async fn handshake_complete_callback(
        &self,
        _ssl: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        None
    }
}

pub type TlsAcceptCallbacks = Box<dyn TlsAccept + Send + Sync>;

struct TransportStackBuilder {
    l4: ServerAddress,
    tls: Option<TlsSettings>,
    proxy_protocol: Option<Arc<ProxyProtocolConfig>>,
    #[cfg(feature = "connection_filter")]
    connection_filter: Option<Arc<dyn ConnectionFilter>>,
}

impl TransportStackBuilder {
    pub async fn build(
        &mut self,
        #[cfg(unix)] upgrade_listeners: Option<ListenFds>,
    ) -> Result<TransportStack> {
        let mut builder = ListenerEndpoint::builder();

        builder.listen_addr(self.l4.clone());

        #[cfg(feature = "connection_filter")]
        if let Some(filter) = &self.connection_filter {
            builder.connection_filter(filter.clone());
        }

        #[cfg(unix)]
        let l4 = builder.listen(upgrade_listeners).await?;

        #[cfg(windows)]
        let l4 = builder.listen().await?;

        Ok(TransportStack {
            l4,
            tls: self.tls.take().map(|tls| Arc::new(tls.build())),
            proxy_protocol: self.proxy_protocol.clone(),
        })
    }
}

#[derive(Clone)]
pub(crate) struct TransportStack {
    l4: ListenerEndpoint,
    tls: Option<Arc<Acceptor>>,
    proxy_protocol: Option<Arc<ProxyProtocolConfig>>,
}

impl TransportStack {
    pub fn as_str(&self) -> &str {
        self.l4.as_str()
    }

    pub async fn accept(&self) -> Result<UninitializedStream> {
        let stream = self.l4.accept().await?;
        Ok(UninitializedStream {
            l4: stream,
            tls: self.tls.clone(),
            proxy_protocol: self.proxy_protocol.clone(),
        })
    }

    pub fn cleanup(&mut self) {
        // placeholder
    }
}

pub(crate) struct UninitializedStream {
    l4: L4Stream,
    tls: Option<Arc<Acceptor>>,
    proxy_protocol: Option<Arc<ProxyProtocolConfig>>,
}

impl UninitializedStream {
    pub async fn handshake(mut self) -> Result<Stream> {
        self.l4.set_buffer();
        if let Some(proxy_protocol) = &self.proxy_protocol {
            apply_proxy_protocol(&mut self.l4, proxy_protocol).await?;
        }
        if let Some(tls) = self.tls {
            let tls_stream = tls.tls_handshake(self.l4).await?;
            Ok(Box::new(tls_stream))
        } else {
            Ok(Box::new(self.l4))
        }
    }

    /// Get the peer address of the connection if available
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.l4
            .get_socket_digest()
            .and_then(|d| d.peer_addr().cloned())
    }
}

async fn apply_proxy_protocol(stream: &mut L4Stream, config: &ProxyProtocolConfig) -> Result<()> {
    let Some(digest) = stream.get_socket_digest() else {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "missing socket digest for PROXY protocol listener",
        );
    };
    let direct_peer = digest.peer_addr().and_then(|address| address.as_inet());
    let Some(direct_peer) = direct_peer else {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "PROXY protocol listener requires a TCP peer address",
        );
    };
    if !config.trusted(direct_peer) {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "PROXY protocol peer is not trusted",
        );
    }

    let parsed = match config.version {
        ProxyProtocolVersion::V1 => read_proxy_protocol_v1_header(stream).await?,
        ProxyProtocolVersion::V2 => read_proxy_protocol_v2_header(stream).await?,
    };
    if let Some(peer_addr) = parsed {
        stream.set_socket_digest(digest.clone_with_peer_addr(Some(SocketAddr::Inet(peer_addr))));
    }
    Ok(())
}

async fn read_proxy_protocol_v1_header(stream: &mut L4Stream) -> Result<Option<StdSocketAddr>> {
    let mut line = Vec::with_capacity(PROXY_PROTOCOL_V1_MAX_LINE);
    loop {
        let mut byte = [0u8; 1];
        match stream.read_exact(&mut byte).await {
            Ok(_) => {}
            Err(error) => {
                return Error::e_because(
                    ErrorType::ReadError,
                    "while reading PROXY protocol header",
                    error,
                );
            }
        }
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            break;
        }
        if line.len() >= PROXY_PROTOCOL_V1_MAX_LINE {
            return Error::e_explain(
                ErrorType::Custom("ProxyProtocolError"),
                "PROXY protocol header exceeds v1 size limit",
            );
        }
    }
    parse_proxy_protocol_v1_header(&line)
}

async fn read_proxy_protocol_v2_header(stream: &mut L4Stream) -> Result<Option<StdSocketAddr>> {
    let mut header = [0u8; PROXY_PROTOCOL_V2_HEADER_LEN];
    stream.read_exact(&mut header).await.map_err(|error| {
        Error::because(
            ErrorType::ReadError,
            "while reading PROXY protocol v2 header",
            error,
        )
    })?;
    let payload_len = u16::from_be_bytes([header[14], header[15]]) as usize;
    if payload_len > PROXY_PROTOCOL_V2_MAX_PAYLOAD {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "PROXY protocol v2 payload exceeds configured parser limit",
        );
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream.read_exact(&mut payload).await.map_err(|error| {
            Error::because(
                ErrorType::ReadError,
                "while reading PROXY protocol v2 payload",
                error,
            )
        })?;
    }
    parse_proxy_protocol_v2_header(&header, &payload)
}

fn parse_proxy_protocol_v2_header(
    header: &[u8; PROXY_PROTOCOL_V2_HEADER_LEN],
    payload: &[u8],
) -> Result<Option<StdSocketAddr>> {
    if &header[..PROXY_PROTOCOL_V2_SIGNATURE.len()] != PROXY_PROTOCOL_V2_SIGNATURE {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "invalid PROXY protocol v2 signature",
        );
    }
    let version = header[12] & 0xf0;
    let command = header[12] & 0x0f;
    if version != 0x20 {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "invalid PROXY protocol v2 version",
        );
    }
    if command == 0x00 {
        return Ok(None);
    }
    if command != 0x01 {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "invalid PROXY protocol v2 command",
        );
    }

    match header[13] {
        0x00 => Ok(None),
        0x11 => {
            if payload.len() < 12 {
                return Error::e_explain(
                    ErrorType::Custom("ProxyProtocolError"),
                    "truncated PROXY protocol v2 TCP4 address",
                );
            }
            let source = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let source_port = u16::from_be_bytes([payload[8], payload[9]]);
            Ok(Some(StdSocketAddr::new(
                IpAddr::V4(source),
                source_port,
            )))
        }
        0x21 => {
            if payload.len() < 36 {
                return Error::e_explain(
                    ErrorType::Custom("ProxyProtocolError"),
                    "truncated PROXY protocol v2 TCP6 address",
                );
            }
            let source = Ipv6Addr::from([
                payload[0],
                payload[1],
                payload[2],
                payload[3],
                payload[4],
                payload[5],
                payload[6],
                payload[7],
                payload[8],
                payload[9],
                payload[10],
                payload[11],
                payload[12],
                payload[13],
                payload[14],
                payload[15],
            ]);
            let source_port = u16::from_be_bytes([payload[32], payload[33]]);
            Ok(Some(StdSocketAddr::new(
                IpAddr::V6(source),
                source_port,
            )))
        }
        _ => Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "unsupported PROXY protocol v2 address family or transport",
        ),
    }
}

fn parse_proxy_protocol_v1_header(line: &[u8]) -> Result<Option<StdSocketAddr>> {
    let line = std::str::from_utf8(line).map_err(|error| {
        Error::because(
            ErrorType::Custom("ProxyProtocolError"),
            "PROXY protocol header is not ASCII/UTF-8",
            error,
        )
    })?;
    let line = line.strip_suffix("\r\n").ok_or_else(|| {
        Error::explain(
            ErrorType::Custom("ProxyProtocolError"),
            "PROXY protocol header is missing CRLF",
        )
    })?;
    if line == "PROXY UNKNOWN" {
        return Ok(None);
    }

    let mut fields = line.split(' ');
    if fields.next() != Some("PROXY") {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "missing PROXY protocol prefix",
        );
    }
    let Some(family) = fields.next() else {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "missing PROXY protocol family",
        );
    };
    let Some(source_ip) = fields.next() else {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "missing PROXY protocol source address",
        );
    };
    let Some(destination_ip) = fields.next() else {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "missing PROXY protocol destination address",
        );
    };
    let Some(source_port) = fields.next() else {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "missing PROXY protocol source port",
        );
    };
    let Some(destination_port) = fields.next() else {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "missing PROXY protocol destination port",
        );
    };
    if fields.next().is_some() {
        return Error::e_explain(
            ErrorType::Custom("ProxyProtocolError"),
            "unexpected PROXY protocol fields",
        );
    }

    let source_ip = source_ip.parse::<IpAddr>().map_err(|error| {
        Error::because(
            ErrorType::Custom("ProxyProtocolError"),
            "invalid PROXY protocol source address",
            error,
        )
    })?;
    let destination_ip = destination_ip.parse::<IpAddr>().map_err(|error| {
        Error::because(
            ErrorType::Custom("ProxyProtocolError"),
            "invalid PROXY protocol destination address",
            error,
        )
    })?;
    match (family, source_ip, destination_ip) {
        ("TCP4", IpAddr::V4(_), IpAddr::V4(_)) | ("TCP6", IpAddr::V6(_), IpAddr::V6(_)) => {}
        _ => {
            return Error::e_explain(
                ErrorType::Custom("ProxyProtocolError"),
                "PROXY protocol family does not match address types",
            );
        }
    }
    let source_port = parse_proxy_protocol_v1_port(source_port, "source")?;
    let _destination_port = parse_proxy_protocol_v1_port(destination_port, "destination")?;
    Ok(Some(StdSocketAddr::new(source_ip, source_port)))
}

fn parse_proxy_protocol_v1_port(value: &str, field: &'static str) -> Result<u16> {
    value.parse::<u16>().map_err(|error| {
        Error::because(
            ErrorType::Custom("ProxyProtocolError"),
            format!("invalid PROXY protocol {field} port"),
            error,
        )
    })
}

/// The struct to hold one more multiple listening endpoints
pub struct Listeners {
    stacks: Vec<TransportStackBuilder>,
    proxy_protocol: Option<Arc<ProxyProtocolConfig>>,
    #[cfg(feature = "connection_filter")]
    connection_filter: Option<Arc<dyn ConnectionFilter>>,
}

impl Listeners {
    /// Create a new [`Listeners`] with no listening endpoints.
    pub fn new() -> Self {
        Listeners {
            stacks: vec![],
            proxy_protocol: None,
            #[cfg(feature = "connection_filter")]
            connection_filter: None,
        }
    }
    /// Create a new [`Listeners`] with a TCP server endpoint from the given string.
    pub fn tcp(addr: &str) -> Self {
        let mut listeners = Self::new();
        listeners.add_tcp(addr);
        listeners
    }

    /// Create a new [`Listeners`] with a Unix domain socket endpoint from the given string.
    #[cfg(unix)]
    pub fn uds(addr: &str, perm: Option<Permissions>) -> Self {
        let mut listeners = Self::new();
        listeners.add_uds(addr, perm);
        listeners
    }

    /// Create a new [`Listeners`] with a TLS (TCP) endpoint with the given address string,
    /// and path to the certificate/private key pairs.
    /// This endpoint will adopt the [Mozilla Intermediate](https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28recommended.29)
    /// server side TLS settings.
    pub fn tls(addr: &str, cert_path: &str, key_path: &str) -> Result<Self> {
        let mut listeners = Self::new();
        listeners.add_tls(addr, cert_path, key_path)?;
        Ok(listeners)
    }

    /// Add a TCP endpoint to `self`.
    pub fn add_tcp(&mut self, addr: &str) {
        self.add_address(ServerAddress::Tcp(addr.into(), None));
    }

    /// Add a TCP endpoint to `self`, with the given [`TcpSocketOptions`].
    pub fn add_tcp_with_settings(&mut self, addr: &str, sock_opt: TcpSocketOptions) {
        self.add_address(ServerAddress::Tcp(addr.into(), Some(sock_opt)));
    }

    /// Add a Unix domain socket endpoint to `self`.
    #[cfg(unix)]
    pub fn add_uds(&mut self, addr: &str, perm: Option<Permissions>) {
        self.add_address(ServerAddress::Uds(addr.into(), perm));
    }

    /// Add a TLS endpoint to `self` with the [Mozilla Intermediate](https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28recommended.29)
    /// server side TLS settings.
    pub fn add_tls(&mut self, addr: &str, cert_path: &str, key_path: &str) -> Result<()> {
        self.add_tls_with_settings(addr, None, TlsSettings::intermediate(cert_path, key_path)?);
        Ok(())
    }

    /// Add a TLS endpoint to `self` with the given socket and server side TLS settings.
    /// See [`TlsSettings`] and [`TcpSocketOptions`] for more details.
    pub fn add_tls_with_settings(
        &mut self,
        addr: &str,
        sock_opt: Option<TcpSocketOptions>,
        settings: TlsSettings,
    ) {
        self.add_endpoint(ServerAddress::Tcp(addr.into(), sock_opt), Some(settings));
    }

    /// Add the given [`ServerAddress`] to `self`.
    pub fn add_address(&mut self, addr: ServerAddress) {
        self.add_endpoint(addr, None);
    }

    /// Set a connection filter for all endpoints in this listener collection
    #[cfg(feature = "connection_filter")]
    pub fn set_connection_filter(&mut self, filter: Arc<dyn ConnectionFilter>) {
        log::debug!("Setting connection filter on Listeners");

        // Store the filter for future endpoints
        self.connection_filter = Some(filter.clone());

        // Apply to existing stacks
        for stack in &mut self.stacks {
            stack.connection_filter = Some(filter.clone());
        }
    }

    /// Add the given [`ServerAddress`] to `self` with the given [`TlsSettings`] if provided
    pub fn add_endpoint(&mut self, l4: ServerAddress, tls: Option<TlsSettings>) {
        self.stacks.push(TransportStackBuilder {
            l4,
            tls,
            proxy_protocol: self.proxy_protocol.clone(),
            #[cfg(feature = "connection_filter")]
            connection_filter: self.connection_filter.clone(),
        })
    }

    /// Enable trusted PROXY protocol v1 receive on all listener endpoints.
    pub fn set_proxy_protocol_v1(&mut self, config: ProxyProtocolConfig) {
        let config = Arc::new(config);
        self.proxy_protocol = Some(config.clone());
        for stack in &mut self.stacks {
            stack.proxy_protocol = Some(config.clone());
        }
    }

    /// Enable trusted PROXY protocol v2 receive on all listener endpoints.
    pub fn set_proxy_protocol_v2(&mut self, config: ProxyProtocolConfig) {
        let config = Arc::new(config);
        self.proxy_protocol = Some(config.clone());
        for stack in &mut self.stacks {
            stack.proxy_protocol = Some(config.clone());
        }
    }

    pub(crate) async fn build(
        &mut self,
        #[cfg(unix)] upgrade_listeners: Option<ListenFds>,
    ) -> Result<Vec<TransportStack>> {
        let mut stacks = Vec::with_capacity(self.stacks.len());

        for b in self.stacks.iter_mut() {
            let new_stack = b
                .build(
                    #[cfg(unix)]
                    upgrade_listeners.clone(),
                )
                .await?;

            stacks.push(new_stack);
        }

        Ok(stacks)
    }

    pub(crate) fn cleanup(&self) {
        // placeholder
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "connection_filter")]
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[cfg(feature = "any_tls")]
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use tokio::time::{sleep, Duration};

    #[test]
    fn proxy_protocol_v1_parser_accepts_tcp4_and_unknown() {
        let parsed =
            parse_proxy_protocol_v1_header(b"PROXY TCP4 203.0.113.10 192.0.2.20 42300 443\r\n")
                .unwrap();
        assert_eq!(parsed, Some("203.0.113.10:42300".parse().unwrap()));
        assert_eq!(
            parse_proxy_protocol_v1_header(b"PROXY UNKNOWN\r\n").unwrap(),
            None
        );
    }

    #[test]
    fn proxy_protocol_v1_parser_rejects_mismatched_family() {
        assert!(
            parse_proxy_protocol_v1_header(
                b"PROXY TCP4 2001:db8::10 192.0.2.20 42300 443\r\n"
            )
            .is_err()
        );
    }

    #[test]
    fn proxy_protocol_v2_parser_accepts_tcp4_and_unspec() {
        let mut header = Vec::from(&PROXY_PROTOCOL_V2_SIGNATURE[..]);
        header.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
        header.extend_from_slice(&[203, 0, 113, 10, 192, 0, 2, 20]);
        header.extend_from_slice(&42300u16.to_be_bytes());
        header.extend_from_slice(&443u16.to_be_bytes());
        let parsed = parse_proxy_protocol_v2_header(
            header[..PROXY_PROTOCOL_V2_HEADER_LEN].try_into().unwrap(),
            &header[PROXY_PROTOCOL_V2_HEADER_LEN..],
        )
        .unwrap();
        assert_eq!(parsed, Some("203.0.113.10:42300".parse().unwrap()));

        let mut header = [0u8; PROXY_PROTOCOL_V2_HEADER_LEN];
        header[..PROXY_PROTOCOL_V2_SIGNATURE.len()].copy_from_slice(PROXY_PROTOCOL_V2_SIGNATURE);
        header[12] = 0x21;
        assert_eq!(parse_proxy_protocol_v2_header(&header, &[]).unwrap(), None);
    }

    #[test]
    fn proxy_protocol_v2_parser_rejects_truncated_tcp6() {
        let mut header = [0u8; PROXY_PROTOCOL_V2_HEADER_LEN];
        header[..PROXY_PROTOCOL_V2_SIGNATURE.len()].copy_from_slice(PROXY_PROTOCOL_V2_SIGNATURE);
        header[12] = 0x21;
        header[13] = 0x21;
        header[15] = 0x01;
        assert!(parse_proxy_protocol_v2_header(&header, &[0]).is_err());
    }

    #[test]
    fn proxy_protocol_trusted_sources_match_prefixes() {
        let source = ProxyProtocolTrustedSource::Cidr {
            network: "2001:db8::".parse().unwrap(),
            prefix: 32,
        };
        assert!(source.contains("2001:db8::1".parse().unwrap()));
        assert!(!source.contains("2001:db9::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_listen_tcp() {
        let addr1 = "127.0.0.1:7101";
        let addr2 = "127.0.0.1:7102";
        let mut listeners = Listeners::tcp(addr1);
        listeners.add_tcp(addr2);

        let listeners = listeners
            .build(
                #[cfg(unix)]
                None,
            )
            .await
            .unwrap();

        assert_eq!(listeners.len(), 2);
        for listener in listeners {
            tokio::spawn(async move {
                // just try to accept once
                let stream = listener.accept().await.unwrap();
                stream.handshake().await.unwrap();
            });
        }

        // make sure the above starts before the lines below
        sleep(Duration::from_millis(10)).await;

        TcpStream::connect(addr1).await.unwrap();
        TcpStream::connect(addr2).await.unwrap();
    }

    #[tokio::test]
    #[cfg(feature = "any_tls")]
    async fn test_listen_tls() {
        use tokio::io::AsyncReadExt;

        let addr = "127.0.0.1:7103";
        let cert_path = format!("{}/tests/keys/server.crt", env!("CARGO_MANIFEST_DIR"));
        let key_path = format!("{}/tests/keys/key.pem", env!("CARGO_MANIFEST_DIR"));
        let mut listeners = Listeners::tls(addr, &cert_path, &key_path).unwrap();
        let listener = listeners
            .build(
                #[cfg(unix)]
                None,
            )
            .await
            .unwrap()
            .pop()
            .unwrap();

        tokio::spawn(async move {
            // just try to accept once
            let stream = listener.accept().await.unwrap();
            let mut stream = stream.handshake().await.unwrap();
            let mut buf = [0; 1024];
            let _ = stream.read(&mut buf).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
                .await
                .unwrap();
        });
        // make sure the above starts before the lines below
        sleep(Duration::from_millis(10)).await;

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let res = client.get(format!("https://{addr}")).send().await.unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::OK);
    }

    #[cfg(feature = "connection_filter")]
    #[test]
    fn test_connection_filter_inheritance() {
        #[derive(Debug, Clone)]
        struct TestFilter {
            counter: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl ConnectionFilter for TestFilter {
            async fn should_accept(&self, _addr: Option<&std::net::SocketAddr>) -> bool {
                self.counter.fetch_add(1, Ordering::SeqCst);
                true
            }
        }

        let mut listeners = Listeners::new();

        // Add an endpoint before setting filter
        listeners.add_tcp("127.0.0.1:7104");

        // Set the connection filter
        let filter = Arc::new(TestFilter {
            counter: Arc::new(AtomicUsize::new(0)),
        });
        listeners.set_connection_filter(filter.clone());

        // Add endpoints after setting filter
        listeners.add_tcp("127.0.0.1:7105");
        #[cfg(feature = "any_tls")]
        {
            // Only test TLS if the feature is enabled
            if let Ok(tls_settings) = TlsSettings::intermediate(
                &format!("{}/tests/keys/server.crt", env!("CARGO_MANIFEST_DIR")),
                &format!("{}/tests/keys/key.pem", env!("CARGO_MANIFEST_DIR")),
            ) {
                listeners.add_tls_with_settings("127.0.0.1:7106", None, tls_settings);
            }
        }

        // Verify all stacks have the filter (only when feature is enabled)
        for stack in &listeners.stacks {
            assert!(
                stack.connection_filter.is_some(),
                "All stacks should have the connection filter set"
            );
        }
    }
}

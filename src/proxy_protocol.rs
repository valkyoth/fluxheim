use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pingora::prelude::{HttpPeer, Result};
use pingora::{Error, ErrorType};
use tokio::io::AsyncWriteExt as _;

use crate::config::UpstreamProxyProtocol;

pub(crate) fn apply_upstream_proxy_protocol(
    peer: &mut HttpPeer,
    protocol: UpstreamProxyProtocol,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
    connect_timeout: Option<Duration>,
) {
    let header = match protocol {
        UpstreamProxyProtocol::Off => return,
        UpstreamProxyProtocol::V1 => proxy_protocol_v1_header(source, destination),
        UpstreamProxyProtocol::V2 => proxy_protocol_v2_header(source, destination),
    };
    peer.options.custom_l4 = Some(Arc::new(ProxyProtocolConnector {
        header,
        connect_timeout,
    }));
}

pub(crate) fn proxy_protocol_v1_header(
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

pub(crate) fn proxy_protocol_v2_header(
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

#[derive(Debug)]
struct ProxyProtocolConnector {
    header: Vec<u8>,
    connect_timeout: Option<Duration>,
}

#[async_trait]
impl pingora::connectors::L4Connect for ProxyProtocolConnector {
    async fn connect(
        &self,
        addr: &pingora::protocols::l4::socket::SocketAddr,
    ) -> Result<pingora::protocols::l4::stream::Stream> {
        let connect = async {
            match addr {
                pingora::protocols::l4::socket::SocketAddr::Inet(addr) => {
                    tokio::net::TcpStream::connect(addr).await.map(Into::into)
                }
                #[cfg(unix)]
                pingora::protocols::l4::socket::SocketAddr::Unix(addr) => {
                    let path = addr.as_pathname().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "non-pathname Unix upstreams cannot use PROXY protocol",
                        )
                    })?;
                    tokio::net::UnixStream::connect(path).await.map(Into::into)
                }
            }
        };

        let mut stream: pingora::protocols::l4::stream::Stream = match self.connect_timeout {
            Some(timeout) => match tokio::time::timeout(timeout, connect).await {
                Ok(result) => result,
                Err(_) => {
                    return Error::e_explain(
                        ErrorType::ConnectTimedout,
                        format!("timeout {timeout:?} connecting to server {addr}"),
                    );
                }
            },
            None => connect.await,
        }
        .map_err(|error| Error::because(ErrorType::ConnectError, "upstream connect", error))?;

        stream
            .write_all(&self.header)
            .await
            .map_err(|error| Error::because(ErrorType::WriteError, "write PROXY header", error))?;
        Ok(stream)
    }
}

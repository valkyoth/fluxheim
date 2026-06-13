use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use pingora::ErrorType;
use pingora::prelude::{HttpPeer, Result};
use tokio::io::AsyncWriteExt as _;

use crate::config::UpstreamProxyProtocol;
use crate::flux_error::{FluxError, FluxErrorPingoraExt, FluxResult};
pub(crate) use fluxheim_protocol::{proxy_protocol_v1_header, proxy_protocol_v2_header};

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
        self.connect_with_proxy_protocol(addr)
            .await
            .map_err(|error| {
                let kind = match &error {
                    FluxError::InvalidInput(_) | FluxError::InvalidInputMessage(_) => {
                        ErrorType::ConnectError
                    }
                    FluxError::Timeout { .. } => ErrorType::ConnectTimedout,
                    FluxError::WriteProxyHeader(_) => ErrorType::WriteError,
                    FluxError::Io { .. } => ErrorType::ConnectError,
                };
                error.into_pingora(kind)
            })
    }
}

impl ProxyProtocolConnector {
    async fn connect_with_proxy_protocol(
        &self,
        addr: &pingora::protocols::l4::socket::SocketAddr,
    ) -> FluxResult<pingora::protocols::l4::stream::Stream> {
        let connect = async {
            match addr {
                pingora::protocols::l4::socket::SocketAddr::Inet(addr) => {
                    tokio::net::TcpStream::connect(addr)
                        .await
                        .map(Into::into)
                        .map_err(|error| FluxError::io("upstream connect", error))
                }
                #[cfg(unix)]
                pingora::protocols::l4::socket::SocketAddr::Unix(addr) => {
                    let path = addr.as_pathname().ok_or(FluxError::InvalidInput(
                        "non-pathname Unix upstreams cannot use PROXY protocol",
                    ))?;
                    tokio::net::UnixStream::connect(path)
                        .await
                        .map(Into::into)
                        .map_err(|error| FluxError::io("upstream connect", error))
                }
            }
        };

        let mut stream: pingora::protocols::l4::stream::Stream = match self.connect_timeout {
            Some(timeout) => match tokio::time::timeout(timeout, connect).await {
                Ok(result) => result,
                Err(_) => {
                    return Err(FluxError::timeout(
                        "upstream connect timeout",
                        format!("timeout {timeout:?} connecting to server {addr}"),
                    ));
                }
            },
            None => connect.await,
        }?;

        stream
            .write_all(&self.header)
            .await
            .map_err(FluxError::write_proxy_header)?;
        Ok(stream)
    }
}

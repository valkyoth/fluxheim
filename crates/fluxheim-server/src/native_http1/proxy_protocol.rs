use std::net::SocketAddr;

use fluxheim_protocol::{
    PROXY_PROTOCOL_V1_MAX_LINE, PROXY_PROTOCOL_V2_HEADER_LEN, PROXY_PROTOCOL_V2_MAX_PAYLOAD,
    parse_downstream_proxy_protocol_v1, parse_downstream_proxy_protocol_v2,
};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{NativeHttp1Error, ProxyProtocolPolicy};

pub(super) async fn read_proxy_protocol_source<S>(
    stream: &mut S,
    proxy_protocol: &ProxyProtocolPolicy,
    peer_addr: SocketAddr,
) -> Result<Option<SocketAddr>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    let trusted_sources = match proxy_protocol {
        ProxyProtocolPolicy::Off => return Ok(None),
        ProxyProtocolPolicy::V1 { trusted_sources }
        | ProxyProtocolPolicy::V2 { trusted_sources } => trusted_sources,
    };
    if !trusted_sources
        .iter()
        .any(|source| source.contains(peer_addr.ip()))
    {
        return Err(NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "untrusted PROXY protocol peer",
        )));
    }
    match proxy_protocol {
        ProxyProtocolPolicy::Off => Ok(None),
        ProxyProtocolPolicy::V1 { .. } => read_proxy_protocol_v1_source(stream).await,
        ProxyProtocolPolicy::V2 { .. } => read_proxy_protocol_v2_source(stream).await,
    }
}

async fn read_proxy_protocol_v1_source<S>(
    stream: &mut S,
) -> Result<Option<SocketAddr>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    while line.len() < PROXY_PROTOCOL_V1_MAX_LINE {
        let mut byte = [0u8; 1];
        if stream.read_exact(&mut byte).await.is_err() {
            return Err(NativeHttp1Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated PROXY protocol v1 header",
            )));
        }
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return parse_downstream_proxy_protocol_v1(&line).map_err(|error| {
                NativeHttp1Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    error.to_string(),
                ))
            });
        }
    }
    Err(NativeHttp1Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "PROXY protocol v1 header too large",
    )))
}

async fn read_proxy_protocol_v2_source<S>(
    stream: &mut S,
) -> Result<Option<SocketAddr>, NativeHttp1Error>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; PROXY_PROTOCOL_V2_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let payload_len = u16::from_be_bytes([header[14], header[15]]) as usize;
    if payload_len > PROXY_PROTOCOL_V2_MAX_PAYLOAD {
        return Err(NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PROXY protocol v2 payload too large",
        )));
    }
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;
    parse_downstream_proxy_protocol_v2(&header, &payload).map_err(|error| {
        NativeHttp1Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        ))
    })
}

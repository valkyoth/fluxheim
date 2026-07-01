use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::UpstreamProxyProtocol;
#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
use crate::stream_tls::StreamUpstreamTlsConnector;
use fluxheim_common::{FluxError, FluxResult};
use fluxheim_stream::{
    copy_bidirectional_with_limits, stream_dns_resolved_address_allowed,
    write_upstream_proxy_protocol,
};

use super::FluxStream;

pub(super) struct StreamProxyConnectionOptions {
    pub(super) connect_timeout: Duration,
    pub(super) idle_timeout: Duration,
    pub(super) max_connection_lifetime: Option<Duration>,
    pub(super) max_connection_bytes: Option<u64>,
    pub(super) upstream_proxy_protocol: UpstreamProxyProtocol,
    pub(super) upstream_tls: bool,
    pub(super) upstream_dns_allow_private_addresses: bool,
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
    pub(super) upstream_tls_connector: Option<StreamUpstreamTlsConnector>,
}

#[cfg(test)]
pub(super) async fn proxy_stream_connection(
    downstream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    upstream_authority: &str,
    options: StreamProxyConnectionOptions,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
) -> FluxResult<(u64, u64)> {
    let mut upstream = connect_upstream(upstream_authority, &options).await?;
    proxy_connected_stream_connection(downstream, &mut upstream, &options, source, destination)
        .await
}

pub(super) async fn proxy_connected_stream_connection(
    downstream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    upstream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    options: &StreamProxyConnectionOptions,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
) -> FluxResult<(u64, u64)> {
    write_upstream_proxy_protocol(
        upstream,
        options.upstream_proxy_protocol,
        source,
        destination,
        options.idle_timeout,
    )
    .await?;

    let copy = copy_bidirectional_with_limits(
        downstream,
        upstream,
        options.idle_timeout,
        options.max_connection_bytes,
    );
    if let Some(max_connection_lifetime) = options.max_connection_lifetime {
        match tokio::time::timeout(max_connection_lifetime, copy).await {
            Ok(result) => result,
            Err(_) => Err(FluxError::timeout(
                "stream connection lifetime",
                "stream max connection lifetime elapsed",
            )),
        }
    } else {
        copy.await
    }
}

pub(super) async fn connect_upstream(
    upstream_authority: &str,
    options: &StreamProxyConnectionOptions,
) -> FluxResult<FluxStream> {
    if options.upstream_tls {
        return connect_tls_upstream(upstream_authority, options).await;
    }

    match tokio::time::timeout(
        options.connect_timeout,
        connect_upstream_inner(
            upstream_authority,
            options.upstream_dns_allow_private_addresses,
        ),
    )
    .await
    {
        Ok(Ok(stream)) => Ok(Box::new(stream)),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(FluxError::timeout(
            "stream upstream connect timeout",
            "stream upstream connect timeout elapsed",
        )),
    }
}

async fn connect_tls_upstream(
    #[cfg_attr(
        not(any(feature = "tls-rustls-backend", feature = "tls-openssl")),
        allow(unused_variables)
    )]
    upstream_authority: &str,
    #[cfg_attr(
        not(any(feature = "tls-rustls-backend", feature = "tls-openssl")),
        allow(unused_variables)
    )]
    options: &StreamProxyConnectionOptions,
) -> FluxResult<FluxStream> {
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
    {
        let connect = async {
            let socket_addr = resolve_upstream_socket_addr(
                upstream_authority,
                options.upstream_dns_allow_private_addresses,
            )
            .await?;
            let Some(connector) = &options.upstream_tls_connector else {
                return Err(FluxError::InvalidInput(
                    "stream upstream TLS connector is not initialized",
                ));
            };
            connector.connect(upstream_authority, socket_addr).await
        };

        match tokio::time::timeout(options.connect_timeout, connect).await {
            Ok(result) => result,
            Err(_) => Err(FluxError::timeout(
                "stream upstream TLS connect timeout",
                "stream upstream TLS connect timeout elapsed",
            )),
        }
    }
    #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl")))]
    {
        Err(FluxError::InvalidInput(
            "stream upstream TLS requires a TLS backend feature",
        ))
    }
}

async fn connect_upstream_inner(
    upstream_authority: &str,
    allow_private_dns_addresses: bool,
) -> FluxResult<tokio::net::TcpStream> {
    let socket_addr =
        resolve_upstream_socket_addr(upstream_authority, allow_private_dns_addresses).await?;
    tokio::net::TcpStream::connect(socket_addr)
        .await
        .map_err(|error| FluxError::io("connect stream upstream", error))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) async fn resolve_upstream_socket_addr(
    upstream_authority: &str,
    allow_private_dns_addresses: bool,
) -> FluxResult<SocketAddr> {
    if let Ok(socket_addr) = upstream_authority.parse::<SocketAddr>() {
        return Ok(socket_addr);
    }

    let resolved = tokio::net::lookup_host(upstream_authority)
        .await
        .map_err(|error| FluxError::io("resolve stream upstream", error))?;
    let mut saw_rejected_address = false;
    for socket_addr in resolved {
        if allow_private_dns_addresses || stream_dns_resolved_address_allowed(socket_addr.ip()) {
            return Ok(socket_addr);
        }
        saw_rejected_address = true;
    }
    if saw_rejected_address {
        return Err(FluxError::InvalidInput(
            "stream upstream DNS resolved only to private or reserved addresses; set upstream_dns_allow_private_addresses = true for trusted internal DNS upstreams",
        ));
    }
    Err(FluxError::io(
        "resolve stream upstream",
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "stream upstream resolved to no socket addresses",
        ),
    ))
}

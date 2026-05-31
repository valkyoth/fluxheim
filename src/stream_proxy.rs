use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::apps::ServerApp;
#[cfg(any(
    feature = "tls-rustls-backend",
    feature = "tls-openssl",
    feature = "tls-boringssl",
    feature = "tls-s2n"
))]
use pingora::connectors::TransportConnector;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
#[cfg(any(
    feature = "tls-rustls-backend",
    feature = "tls-openssl",
    feature = "tls-boringssl",
    feature = "tls-s2n"
))]
use pingora::upstreams::peer::HttpPeer;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::config::{Config, DownstreamProxyProtocol, StreamRouteConfig, UpstreamProxyProtocol};
#[cfg(any(
    feature = "tls-rustls-backend",
    feature = "tls-openssl",
    feature = "tls-boringssl",
    feature = "tls-s2n"
))]
use crate::config_net::upstream_host;
use crate::config_stream::{StreamConnectionSlot, acquire_stream_connection_slot};
#[cfg(any(
    feature = "tls-rustls-backend",
    feature = "tls-openssl",
    feature = "tls-boringssl"
))]
use crate::upstream_tls::RuntimeUpstreamTls;

pub(crate) type StreamProxyService = pingora::services::listening::Service<StreamProxyApp>;

pub(crate) fn stream_services_from_config(config: &Config) -> io::Result<Vec<StreamProxyService>> {
    if !config.stream.enabled {
        return Ok(Vec::new());
    }

    config
        .stream
        .routes
        .iter()
        .map(stream_service_from_route)
        .collect()
}

fn stream_service_from_route(route: &StreamRouteConfig) -> io::Result<StreamProxyService> {
    let app = StreamProxyApp::from_config(route)?;
    let mut service =
        pingora::services::listening::Service::new(format!("Stream proxy {}", route.name), app);
    for listen in &route.listen {
        service.add_tcp(listen);
    }
    apply_stream_downstream_proxy_protocol(&mut service, route)?;
    Ok(service)
}

pub(crate) struct StreamProxyApp {
    name: Arc<str>,
    upstreams: Arc<[Arc<str>]>,
    connect_timeout: Duration,
    idle_timeout: Duration,
    max_connection_lifetime: Option<Duration>,
    max_connection_bytes: Option<u64>,
    max_connections: usize,
    active_connections: Arc<AtomicUsize>,
    next_upstream: AtomicUsize,
    upstream_proxy_protocol: UpstreamProxyProtocol,
    upstream_tls: bool,
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    ))]
    upstream_sni: Option<Arc<str>>,
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    ))]
    upstream_verify_cert: bool,
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    ))]
    upstream_verify_hostname: bool,
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    ))]
    upstream_alternative_cn: Option<Arc<str>>,
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl"
    ))]
    upstream_tls_material: RuntimeUpstreamTls,
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    ))]
    connector: Option<Arc<TransportConnector>>,
}

impl StreamProxyApp {
    fn from_config(route: &StreamRouteConfig) -> io::Result<Self> {
        let upstreams = route.upstreams().map(Arc::<str>::from).collect::<Vec<_>>();
        if upstreams.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stream route requires at least one upstream",
            ));
        }

        #[cfg(any(
            feature = "tls-rustls-backend",
            feature = "tls-openssl",
            feature = "tls-boringssl"
        ))]
        let upstream_tls_material = RuntimeUpstreamTls::from_paths(
            route.upstream_ca_path.as_deref(),
            route.upstream_client_cert_path.as_deref(),
            route.upstream_client_key_path.as_deref(),
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to load stream upstream TLS material for route {}: {error}",
                    route.name
                ),
            )
        })?;

        Ok(Self {
            name: Arc::from(route.name.as_str()),
            upstreams: upstreams.into(),
            connect_timeout: Duration::from_secs(route.connect_timeout_secs),
            idle_timeout: Duration::from_secs(route.idle_timeout_secs),
            max_connection_lifetime: route.max_connection_secs.map(Duration::from_secs),
            max_connection_bytes: route.max_connection_bytes,
            max_connections: route.max_connections,
            active_connections: Arc::new(AtomicUsize::new(0)),
            next_upstream: AtomicUsize::new(0),
            upstream_proxy_protocol: route.upstream_proxy_protocol,
            upstream_tls: route.upstream_tls,
            #[cfg(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl",
                feature = "tls-s2n"
            ))]
            upstream_sni: route.upstream_sni.as_deref().map(Arc::from),
            #[cfg(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl",
                feature = "tls-s2n"
            ))]
            upstream_verify_cert: route.upstream_verify_cert,
            #[cfg(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl",
                feature = "tls-s2n"
            ))]
            upstream_verify_hostname: route.upstream_verify_hostname,
            #[cfg(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl",
                feature = "tls-s2n"
            ))]
            upstream_alternative_cn: route.upstream_alternative_cn.as_deref().map(Arc::from),
            #[cfg(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl"
            ))]
            upstream_tls_material,
            #[cfg(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl",
                feature = "tls-s2n"
            ))]
            connector: route
                .upstream_tls
                .then(|| Arc::new(TransportConnector::new(None))),
        })
    }

    fn acquire_slot(&self) -> Option<StreamConnectionSlot> {
        acquire_stream_connection_slot(&self.active_connections, self.max_connections)
    }

    fn select_upstream(&self) -> &str {
        let index = self.next_upstream.fetch_add(1, Ordering::Relaxed) % self.upstreams.len();
        &self.upstreams[index]
    }
}

#[async_trait]
impl ServerApp for StreamProxyApp {
    async fn process_new(
        self: &Arc<Self>,
        mut downstream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        if *shutdown.borrow() {
            return None;
        }
        let Some(_slot) = self.acquire_slot() else {
            log::warn!(
                target: "fluxheim::stream",
                "stream route {} rejected connection: max_connections reached",
                self.name
            );
            record_stream_connection(self.name.as_ref(), "rejected");
            return None;
        };

        let source = downstream_peer_addr(&downstream);
        let destination = downstream_local_addr(&downstream);
        let upstream_authority = self.select_upstream().to_owned();
        let started = Instant::now();

        let result = proxy_stream_connection(
            &mut downstream,
            &upstream_authority,
            StreamProxyConnectionOptions {
                connect_timeout: self.connect_timeout,
                idle_timeout: self.idle_timeout,
                max_connection_lifetime: self.max_connection_lifetime,
                max_connection_bytes: self.max_connection_bytes,
                upstream_proxy_protocol: self.upstream_proxy_protocol,
                upstream_tls: self.upstream_tls,
                #[cfg(any(
                    feature = "tls-rustls-backend",
                    feature = "tls-openssl",
                    feature = "tls-boringssl",
                    feature = "tls-s2n"
                ))]
                upstream_sni: self.upstream_sni.clone(),
                #[cfg(any(
                    feature = "tls-rustls-backend",
                    feature = "tls-openssl",
                    feature = "tls-boringssl",
                    feature = "tls-s2n"
                ))]
                upstream_verify_cert: self.upstream_verify_cert,
                #[cfg(any(
                    feature = "tls-rustls-backend",
                    feature = "tls-openssl",
                    feature = "tls-boringssl",
                    feature = "tls-s2n"
                ))]
                upstream_verify_hostname: self.upstream_verify_hostname,
                #[cfg(any(
                    feature = "tls-rustls-backend",
                    feature = "tls-openssl",
                    feature = "tls-boringssl",
                    feature = "tls-s2n"
                ))]
                upstream_alternative_cn: self.upstream_alternative_cn.clone(),
                #[cfg(any(
                    feature = "tls-rustls-backend",
                    feature = "tls-openssl",
                    feature = "tls-boringssl"
                ))]
                upstream_tls_material: self.upstream_tls_material.clone(),
                #[cfg(any(
                    feature = "tls-rustls-backend",
                    feature = "tls-openssl",
                    feature = "tls-boringssl",
                    feature = "tls-s2n"
                ))]
                connector: self.connector.clone(),
            },
            source,
            destination,
        )
        .await;

        match result {
            Ok((downstream_to_upstream, upstream_to_downstream)) => {
                record_stream_connection(self.name.as_ref(), "completed");
                record_stream_bytes(
                    self.name.as_ref(),
                    "downstream_to_upstream",
                    downstream_to_upstream,
                );
                record_stream_bytes(
                    self.name.as_ref(),
                    "upstream_to_downstream",
                    upstream_to_downstream,
                );
                log::debug!(
                    target: "fluxheim::stream",
                    "stream route {} completed via {}; downstream_to_upstream={} upstream_to_downstream={} duration_ms={}",
                    self.name,
                    upstream_authority,
                    downstream_to_upstream,
                    upstream_to_downstream,
                    started.elapsed().as_millis()
                );
            }
            Err(error) => {
                record_stream_connection(self.name.as_ref(), stream_error_outcome(&error));
                log::warn!(
                    target: "fluxheim::stream",
                    "stream route {} failed via {} after {}ms: {}",
                    self.name,
                    upstream_authority,
                    started.elapsed().as_millis(),
                    error
                );
            }
        }

        None
    }
}

#[cfg(feature = "metrics")]
fn record_stream_connection(route: &str, outcome: &str) {
    crate::metrics::record_stream_connection(route, outcome);
}

#[cfg(not(feature = "metrics"))]
fn record_stream_connection(_route: &str, _outcome: &str) {}

#[cfg(feature = "metrics")]
fn record_stream_bytes(route: &str, direction: &str, bytes: u64) {
    crate::metrics::record_stream_bytes(route, direction, bytes);
}

#[cfg(not(feature = "metrics"))]
fn record_stream_bytes(_route: &str, _direction: &str, _bytes: u64) {}

fn stream_error_outcome(error: &io::Error) -> &'static str {
    match error.kind() {
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

async fn proxy_stream_connection(
    downstream: &mut Stream,
    upstream_authority: &str,
    options: StreamProxyConnectionOptions,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
) -> io::Result<(u64, u64)> {
    let mut upstream = connect_upstream(upstream_authority, &options).await?;
    write_upstream_proxy_protocol(
        &mut upstream,
        options.upstream_proxy_protocol,
        source,
        destination,
    )
    .await?;

    let copy = copy_bidirectional_with_limits(
        downstream,
        &mut upstream,
        options.idle_timeout,
        options.max_connection_bytes,
    );
    if let Some(max_connection_lifetime) = options.max_connection_lifetime {
        match tokio::time::timeout(max_connection_lifetime, copy).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "stream max connection lifetime elapsed",
            )),
        }
    } else {
        copy.await
    }
}

struct StreamProxyConnectionOptions {
    connect_timeout: Duration,
    idle_timeout: Duration,
    max_connection_lifetime: Option<Duration>,
    max_connection_bytes: Option<u64>,
    upstream_proxy_protocol: UpstreamProxyProtocol,
    upstream_tls: bool,
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    ))]
    upstream_sni: Option<Arc<str>>,
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    ))]
    upstream_verify_cert: bool,
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    ))]
    upstream_verify_hostname: bool,
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    ))]
    upstream_alternative_cn: Option<Arc<str>>,
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl"
    ))]
    upstream_tls_material: RuntimeUpstreamTls,
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    ))]
    connector: Option<Arc<TransportConnector>>,
}

enum StreamCopyEvent {
    DownstreamTotal(u64),
    UpstreamTotal(u64),
    DownstreamEof,
    UpstreamEof,
}

async fn copy_bidirectional_with_limits(
    downstream: &mut Stream,
    upstream: &mut Stream,
    idle_timeout: Duration,
    max_connection_bytes: Option<u64>,
) -> io::Result<(u64, u64)> {
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
                    upstream_writer.shutdown().await?;
                    Ok::<_, io::Error>(StreamCopyEvent::DownstreamEof)
                } else {
                    let next = checked_stream_byte_count(
                        downstream_to_upstream,
                        bytes as u64,
                        max_connection_bytes,
                    )?;
                    upstream_writer.write_all(&downstream_buffer[..bytes]).await?;
                    Ok::<_, io::Error>(StreamCopyEvent::DownstreamTotal(next))
                }
            }, if !downstream_eof => result,
            result = async {
                let bytes = read_with_idle_timeout(
                    &mut upstream_reader,
                    &mut upstream_buffer,
                    idle_timeout,
                ).await?;
                if bytes == 0 {
                    downstream_writer.shutdown().await?;
                    Ok::<_, io::Error>(StreamCopyEvent::UpstreamEof)
                } else {
                    let next = checked_stream_byte_count(
                        upstream_to_downstream,
                        bytes as u64,
                        max_connection_bytes,
                    )?;
                    downstream_writer.write_all(&upstream_buffer[..bytes]).await?;
                    Ok::<_, io::Error>(StreamCopyEvent::UpstreamTotal(next))
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

async fn read_with_idle_timeout<R>(
    reader: &mut R,
    buffer: &mut [u8],
    idle_timeout: Duration,
) -> io::Result<usize>
where
    R: tokio::io::AsyncRead + Unpin,
{
    match tokio::time::timeout(idle_timeout, reader.read(buffer)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "stream idle timeout elapsed",
        )),
    }
}

fn checked_stream_byte_count(
    current: u64,
    additional: u64,
    max_connection_bytes: Option<u64>,
) -> io::Result<u64> {
    let next = current.checked_add(additional).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "stream copied byte counter overflowed",
        )
    })?;
    if max_connection_bytes.is_some_and(|limit| next > limit) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "stream max connection bytes exceeded",
        ));
    }
    Ok(next)
}

async fn connect_upstream(
    upstream_authority: &str,
    options: &StreamProxyConnectionOptions,
) -> io::Result<Stream> {
    if options.upstream_tls {
        return connect_tls_upstream(upstream_authority, options).await;
    }

    match tokio::time::timeout(
        options.connect_timeout,
        connect_upstream_inner(upstream_authority),
    )
    .await
    {
        Ok(Ok(stream)) => Ok(Box::new(pingora::protocols::l4::stream::Stream::from(
            stream,
        ))),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "stream upstream connect timeout elapsed",
        )),
    }
}

async fn connect_tls_upstream(
    #[cfg_attr(
        not(any(
            feature = "tls-rustls-backend",
            feature = "tls-openssl",
            feature = "tls-boringssl",
            feature = "tls-s2n"
        )),
        allow(unused_variables)
    )]
    upstream_authority: &str,
    #[cfg_attr(
        not(any(
            feature = "tls-rustls-backend",
            feature = "tls-openssl",
            feature = "tls-boringssl",
            feature = "tls-s2n"
        )),
        allow(unused_variables)
    )]
    options: &StreamProxyConnectionOptions,
) -> io::Result<Stream> {
    #[cfg(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    ))]
    {
        let socket_addr = resolve_upstream_socket_addr(upstream_authority).await?;
        let sni = options
            .upstream_sni
            .as_deref()
            .map(str::to_owned)
            .or_else(|| upstream_host(upstream_authority))
            .unwrap_or_default();
        let mut peer = HttpPeer::new(socket_addr, true, sni);
        peer.options.connection_timeout = Some(options.connect_timeout);
        peer.options.total_connection_timeout = Some(options.connect_timeout);
        peer.options.verify_cert = options.upstream_verify_cert;
        peer.options.verify_hostname = options.upstream_verify_hostname;
        peer.options.alternative_cn = options
            .upstream_alternative_cn
            .as_deref()
            .map(str::to_owned);
        #[cfg(any(
            feature = "tls-rustls-backend",
            feature = "tls-openssl",
            feature = "tls-boringssl"
        ))]
        {
            peer.options.ca = options.upstream_tls_material.ca.clone();
            peer.client_cert_key = options.upstream_tls_material.client_cert_key.clone();
        }
        let Some(connector) = &options.connector else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stream upstream TLS connector is not initialized",
            ));
        };
        match tokio::time::timeout(options.connect_timeout, connector.get_stream(&peer)).await {
            Ok(Ok((stream, _reused))) => Ok(stream),
            Ok(Err(error)) => Err(io::Error::other(format!(
                "stream upstream TLS connect failed: {error}"
            ))),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "stream upstream TLS connect timeout elapsed",
            )),
        }
    }
    #[cfg(not(any(
        feature = "tls-rustls-backend",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    )))]
    {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stream upstream TLS requires a TLS backend feature",
        ))
    }
}

async fn connect_upstream_inner(upstream_authority: &str) -> io::Result<tokio::net::TcpStream> {
    let socket_addr = resolve_upstream_socket_addr(upstream_authority).await?;
    tokio::net::TcpStream::connect(socket_addr).await
}

async fn resolve_upstream_socket_addr(upstream_authority: &str) -> io::Result<SocketAddr> {
    if let Ok(socket_addr) = upstream_authority.parse::<SocketAddr>() {
        return Ok(socket_addr);
    }

    let resolved = tokio::net::lookup_host(upstream_authority).await?;
    resolved.into_iter().next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "stream upstream resolved to no socket addresses",
        )
    })
}

async fn write_upstream_proxy_protocol(
    upstream: &mut Stream,
    protocol: UpstreamProxyProtocol,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
) -> io::Result<()> {
    let header = match protocol {
        UpstreamProxyProtocol::Off => return Ok(()),
        UpstreamProxyProtocol::V1 => {
            crate::proxy_protocol::proxy_protocol_v1_header(source, destination)
        }
        UpstreamProxyProtocol::V2 => {
            crate::proxy_protocol::proxy_protocol_v2_header(source, destination)
        }
    };
    upstream.write_all(&header).await
}

fn downstream_peer_addr(downstream: &Stream) -> Option<SocketAddr> {
    downstream
        .get_socket_digest()
        .and_then(|digest| digest.peer_addr().and_then(|addr| addr.as_inet()).copied())
}

fn downstream_local_addr(downstream: &Stream) -> Option<SocketAddr> {
    downstream
        .get_socket_digest()
        .and_then(|digest| digest.local_addr().and_then(|addr| addr.as_inet()).copied())
}

fn apply_stream_downstream_proxy_protocol(
    service: &mut StreamProxyService,
    route: &StreamRouteConfig,
) -> io::Result<()> {
    if route.downstream_proxy_protocol == DownstreamProxyProtocol::Off {
        return Ok(());
    }
    let trusted_sources = route
        .trusted_proxies
        .iter()
        .map(|source| parse_stream_proxy_protocol_trusted_source(source))
        .collect::<io::Result<Vec<_>>>()?;
    log::info!(
        "stream route {} downstream PROXY protocol {:?} receive enabled for {} trusted source(s)",
        route.name,
        route.downstream_proxy_protocol,
        trusted_sources.len()
    );
    match route.downstream_proxy_protocol {
        DownstreamProxyProtocol::Off => {}
        DownstreamProxyProtocol::V1 => {
            service.set_proxy_protocol_v1(pingora::listeners::ProxyProtocolConfig::v1(
                trusted_sources,
            ));
        }
        DownstreamProxyProtocol::V2 => {
            service.set_proxy_protocol_v2(pingora::listeners::ProxyProtocolConfig::v2(
                trusted_sources,
            ));
        }
    }
    Ok(())
}

fn parse_stream_proxy_protocol_trusted_source(
    value: &str,
) -> io::Result<pingora::listeners::ProxyProtocolTrustedSource> {
    if let Some((address, prefix)) = value.split_once('/') {
        let network = address.parse::<IpAddr>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid stream trusted proxy network {value:?}: {error}"),
            )
        })?;
        let prefix = prefix.parse::<u8>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid stream trusted proxy prefix {value:?}: {error}"),
            )
        })?;
        return Ok(pingora::listeners::ProxyProtocolTrustedSource::Cidr { network, prefix });
    }
    Ok(pingora::listeners::ProxyProtocolTrustedSource::Ip(
        value.parse::<IpAddr>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid stream trusted proxy address {value:?}: {error}"),
            )
        })?,
    ))
}

#[cfg(test)]
mod tests {
    use super::{StreamProxyApp, proxy_stream_connection};
    use crate::config::{DownstreamProxyProtocol, StreamRouteConfig, UpstreamProxyProtocol};
    use pingora::protocols::Stream as AnyStream;
    use std::io;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn plain_options(
        idle_timeout: std::time::Duration,
        max_connection_bytes: Option<u64>,
    ) -> super::StreamProxyConnectionOptions {
        super::StreamProxyConnectionOptions {
            connect_timeout: std::time::Duration::from_secs(1),
            idle_timeout,
            max_connection_lifetime: None,
            max_connection_bytes,
            upstream_proxy_protocol: UpstreamProxyProtocol::Off,
            upstream_tls: false,
            #[cfg(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl",
                feature = "tls-s2n"
            ))]
            upstream_sni: None,
            #[cfg(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl",
                feature = "tls-s2n"
            ))]
            upstream_verify_cert: true,
            #[cfg(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl",
                feature = "tls-s2n"
            ))]
            upstream_verify_hostname: true,
            #[cfg(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl",
                feature = "tls-s2n"
            ))]
            upstream_alternative_cn: None,
            #[cfg(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl"
            ))]
            upstream_tls_material: crate::upstream_tls::RuntimeUpstreamTls::default(),
            #[cfg(any(
                feature = "tls-rustls-backend",
                feature = "tls-openssl",
                feature = "tls-boringssl",
                feature = "tls-s2n"
            ))]
            connector: None,
        }
    }

    #[test]
    fn stream_app_selects_upstreams_round_robin() {
        let app = StreamProxyApp::from_config(&StreamRouteConfig {
            name: "tcp".to_owned(),
            listen: vec!["127.0.0.1:12345".to_owned()],
            upstream: None,
            upstreams: vec!["127.0.0.1:5432".to_owned(), "127.0.0.1:6432".to_owned()],
            connect_timeout_secs: 1,
            idle_timeout_secs: 1,
            max_connection_secs: None,
            max_connection_bytes: None,
            max_connections: 0,
            downstream_proxy_protocol: DownstreamProxyProtocol::Off,
            trusted_proxies: Vec::new(),
            upstream_proxy_protocol: UpstreamProxyProtocol::Off,
            upstream_tls: false,
            upstream_sni: None,
            upstream_verify_cert: true,
            upstream_verify_hostname: true,
            upstream_alternative_cn: None,
            upstream_ca_path: None,
            upstream_client_cert_path: None,
            upstream_client_key_path: None,
        })
        .unwrap();

        assert_eq!(app.select_upstream(), "127.0.0.1:5432");
        assert_eq!(app.select_upstream(), "127.0.0.1:6432");
        assert_eq!(app.select_upstream(), "127.0.0.1:5432");
    }

    #[test]
    fn stream_proxy_copies_bytes_bidirectionally() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async {
            let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream_addr = upstream_listener.local_addr().unwrap();
            let upstream_task = tokio::spawn(async move {
                let (mut stream, _) = upstream_listener.accept().await.unwrap();
                let mut input = [0u8; 4];
                stream.read_exact(&mut input).await.unwrap();
                assert_eq!(&input, b"ping");
                stream.write_all(b"pong").await.unwrap();
            });

            let downstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let downstream_addr = downstream_listener.local_addr().unwrap();
            let proxy_task = tokio::spawn(async move {
                let (stream, _) = downstream_listener.accept().await.unwrap();
                let mut downstream: AnyStream =
                    Box::new(pingora::protocols::l4::stream::Stream::from(stream));
                proxy_stream_connection(
                    &mut downstream,
                    &upstream_addr.to_string(),
                    plain_options(std::time::Duration::from_secs(1), None),
                    None,
                    None,
                )
                .await
                .unwrap()
            });

            let mut client = tokio::net::TcpStream::connect(downstream_addr)
                .await
                .unwrap();
            client.write_all(b"ping").await.unwrap();
            client.shutdown().await.unwrap();
            let mut output = Vec::new();
            client.read_to_end(&mut output).await.unwrap();
            assert_eq!(output, b"pong");

            let copied = proxy_task.await.unwrap();
            assert_eq!(copied, (4, 4));
            upstream_task.await.unwrap();
        });
    }

    #[test]
    fn stream_proxy_rejects_connection_byte_overflow() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async {
            let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream_addr = upstream_listener.local_addr().unwrap();
            let upstream_task = tokio::spawn(async move {
                let (mut stream, _) = upstream_listener.accept().await.unwrap();
                let mut input = Vec::new();
                let _ = stream.read_to_end(&mut input).await;
            });

            let downstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let downstream_addr = downstream_listener.local_addr().unwrap();
            let proxy_task = tokio::spawn(async move {
                let (stream, _) = downstream_listener.accept().await.unwrap();
                let mut downstream: AnyStream =
                    Box::new(pingora::protocols::l4::stream::Stream::from(stream));
                proxy_stream_connection(
                    &mut downstream,
                    &upstream_addr.to_string(),
                    plain_options(std::time::Duration::from_secs(1), Some(3)),
                    None,
                    None,
                )
                .await
            });

            let mut client = tokio::net::TcpStream::connect(downstream_addr)
                .await
                .unwrap();
            client.write_all(b"ping").await.unwrap();
            let _ = client.shutdown().await;

            let error = proxy_task.await.unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            upstream_task.await.unwrap();
        });
    }

    #[test]
    fn stream_proxy_times_out_idle_connection_between_reads() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async {
            let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream_addr = upstream_listener.local_addr().unwrap();
            let upstream_task = tokio::spawn(async move {
                let (_stream, _) = upstream_listener.accept().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            });

            let downstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let downstream_addr = downstream_listener.local_addr().unwrap();
            let proxy_task = tokio::spawn(async move {
                let (stream, _) = downstream_listener.accept().await.unwrap();
                let mut downstream: AnyStream =
                    Box::new(pingora::protocols::l4::stream::Stream::from(stream));
                proxy_stream_connection(
                    &mut downstream,
                    &upstream_addr.to_string(),
                    plain_options(std::time::Duration::from_millis(50), None),
                    None,
                    None,
                )
                .await
            });

            let _client = tokio::net::TcpStream::connect(downstream_addr)
                .await
                .unwrap();

            let error = proxy_task.await.unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            upstream_task.abort();
        });
    }
}

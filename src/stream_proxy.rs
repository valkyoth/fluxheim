use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
#[cfg(unix)]
use pingora::server::ListenFds;
use pingora::server::ShutdownWatch;
use pingora::services::{ServiceReadyNotifier, ServiceWithDependents};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::config::{Config, DownstreamProxyProtocol, StreamRouteConfig, UpstreamProxyProtocol};
#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
use crate::stream_tls::StreamUpstreamTlsConnector;
use crate::{
    config_stream::{StreamConnectionSlot, acquire_stream_connection_slot},
    flux_error::{FluxError, FluxResult},
};

pub(crate) trait StreamIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> StreamIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(crate) type FluxStream = Box<dyn StreamIo>;

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
    StreamProxyService::from_config(route).map_err(FluxError::into_io)
}

pub(crate) struct StreamProxyService {
    name: String,
    listen: Arc<[String]>,
    app: Arc<StreamProxyApp>,
    downstream_proxy_protocol: DownstreamProxyProtocol,
    trusted_sources: Arc<[StreamTrustedSource]>,
}

impl StreamProxyService {
    fn from_config(route: &StreamRouteConfig) -> FluxResult<Self> {
        let trusted_sources = parse_stream_trusted_sources(route)?;
        if route.downstream_proxy_protocol != DownstreamProxyProtocol::Off {
            log::info!(
                "stream route {} downstream PROXY protocol {:?} receive enabled for {} trusted source(s)",
                route.name,
                route.downstream_proxy_protocol,
                trusted_sources.len()
            );
        }
        Ok(Self {
            name: format!("Stream proxy {}", route.name),
            listen: route.listen.clone().into(),
            app: Arc::new(StreamProxyApp::from_config(route)?),
            downstream_proxy_protocol: route.downstream_proxy_protocol,
            trusted_sources: trusted_sources.into(),
        })
    }

    async fn run_listener(
        app: Arc<StreamProxyApp>,
        listener: TcpListener,
        listen: String,
        downstream_proxy_protocol: DownstreamProxyProtocol,
        trusted_sources: Arc<[StreamTrustedSource]>,
        mut shutdown: ShutdownWatch,
    ) {
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((downstream, _peer)) => {
                            let app = app.clone();
                            let trusted_sources = trusted_sources.clone();
                            tokio::spawn(async move {
                                app.process_downstream(
                                    downstream,
                                    downstream_proxy_protocol,
                                    &trusted_sources,
                                ).await;
                            });
                        }
                        Err(error) => {
                            log::warn!(
                                target: "fluxheim::stream",
                                "stream listener {listen} failed to accept connection: {error}"
                            );
                        }
                    }
                }
            }
        }
        log::info!(target: "fluxheim::stream", "stream listener {listen} stopped");
    }
}

#[async_trait]
impl ServiceWithDependents for StreamProxyService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
        ready_notifier: ServiceReadyNotifier,
    ) {
        let mut listeners = Vec::with_capacity(self.listen.len());
        for listen in self.listen.iter() {
            match TcpListener::bind(listen).await {
                Ok(listener) => listeners.push((listen.clone(), listener)),
                Err(error) => {
                    log::error!(
                        target: "fluxheim::stream",
                        "failed to bind stream listener {listen}: {error}"
                    );
                    process::exit(1);
                }
            }
        }
        ready_notifier.notify_ready();
        if listeners.is_empty() {
            let _ = shutdown.changed().await;
            return;
        }
        let mut tasks = Vec::with_capacity(listeners.len());
        for (listen, listener) in listeners {
            tasks.push(tokio::spawn(Self::run_listener(
                self.app.clone(),
                listener,
                listen,
                self.downstream_proxy_protocol,
                self.trusted_sources.clone(),
                shutdown.clone(),
            )));
        }
        let _ = shutdown.changed().await;
        for task in tasks {
            task.abort();
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

pub(crate) struct StreamProxyApp {
    name: Arc<str>,
    upstreams: Arc<[RuntimeStreamUpstream]>,
    primary_indices: Arc<[usize]>,
    backup_indices: Arc<[usize]>,
    primary_weight_total: usize,
    connect_timeout: Duration,
    idle_timeout: Duration,
    max_connection_lifetime: Option<Duration>,
    max_connection_bytes: Option<u64>,
    max_connections: usize,
    active_connections: Arc<AtomicUsize>,
    next_upstream: AtomicUsize,
    source_allow: Arc<[StreamSourceMatcher]>,
    source_deny: Arc<[StreamSourceMatcher]>,
    upstream_proxy_protocol: UpstreamProxyProtocol,
    upstream_tls: bool,
    upstream_dns_allow_private_addresses: bool,
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
    upstream_tls_connector: Option<StreamUpstreamTlsConnector>,
}

impl StreamProxyApp {
    fn from_config(route: &StreamRouteConfig) -> FluxResult<Self> {
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
        let source_allow = parse_stream_source_matchers(&route.allow_sources, "allow source")?;
        let source_deny = parse_stream_source_matchers(&route.deny_sources, "deny source")?;

        #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
        let upstream_tls_connector = StreamUpstreamTlsConnector::from_route(route)?;

        Ok(Self {
            name: Arc::from(route.name.as_str()),
            upstreams: upstreams.into(),
            primary_indices: primary_indices.into(),
            backup_indices: backup_indices.into(),
            primary_weight_total,
            connect_timeout: Duration::from_secs(route.connect_timeout_secs),
            idle_timeout: Duration::from_secs(route.idle_timeout_secs),
            max_connection_lifetime: route.max_connection_secs.map(Duration::from_secs),
            max_connection_bytes: route.max_connection_bytes,
            max_connections: route.max_connections,
            active_connections: Arc::new(AtomicUsize::new(0)),
            next_upstream: AtomicUsize::new(0),
            source_allow: source_allow.into(),
            source_deny: source_deny.into(),
            upstream_proxy_protocol: route.upstream_proxy_protocol,
            upstream_tls: route.upstream_tls,
            upstream_dns_allow_private_addresses: route.upstream_dns_allow_private_addresses,
            #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
            upstream_tls_connector,
        })
    }

    fn acquire_slot(&self) -> Option<StreamConnectionSlot> {
        acquire_stream_connection_slot(&self.active_connections, self.max_connections)
    }

    fn select_upstream_candidates(&self) -> Vec<StreamSelectedUpstream> {
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

    fn connection_options(&self) -> StreamProxyConnectionOptions {
        StreamProxyConnectionOptions {
            connect_timeout: self.connect_timeout,
            idle_timeout: self.idle_timeout,
            max_connection_lifetime: self.max_connection_lifetime,
            max_connection_bytes: self.max_connection_bytes,
            upstream_proxy_protocol: self.upstream_proxy_protocol,
            upstream_tls: self.upstream_tls,
            upstream_dns_allow_private_addresses: self.upstream_dns_allow_private_addresses,
            #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
            upstream_tls_connector: self.upstream_tls_connector.clone(),
        }
    }

    fn source_allowed(&self, source: Option<SocketAddr>) -> bool {
        let Some(source) = source else {
            return self.source_allow.is_empty();
        };
        let source_ip = source.ip();
        if self
            .source_deny
            .iter()
            .any(|matcher| matcher.matches(source_ip))
        {
            return false;
        }
        self.source_allow.is_empty()
            || self
                .source_allow
                .iter()
                .any(|matcher| matcher.matches(source_ip))
    }

    async fn process_downstream(
        self: Arc<Self>,
        mut downstream: TcpStream,
        downstream_proxy_protocol: DownstreamProxyProtocol,
        trusted_sources: &[StreamTrustedSource],
    ) {
        let Some(_slot) = self.acquire_slot() else {
            log::warn!(
                target: "fluxheim::stream",
                "stream route {} rejected connection: max_connections reached",
                self.name
            );
            record_stream_connection(self.name.as_ref(), "rejected");
            return;
        };

        let direct_source = downstream.peer_addr().ok();
        let destination = downstream.local_addr().ok();
        let source = match apply_downstream_proxy_protocol_to_stream(
            &mut downstream,
            downstream_proxy_protocol,
            trusted_sources,
            direct_source,
            self.idle_timeout,
        )
        .await
        {
            Ok(source) => source,
            Err(error) => {
                record_stream_connection(self.name.as_ref(), stream_error_outcome(&error));
                log::warn!(
                    target: "fluxheim::stream",
                    "stream route {} rejected downstream PROXY protocol from {}: {}",
                    self.name,
                    direct_source
                        .map(|address| address.to_string())
                        .unwrap_or_else(|| "unknown".to_owned()),
                    error
                );
                return;
            }
        };
        if !self.source_allowed(source) {
            record_stream_connection(self.name.as_ref(), "rejected");
            log::warn!(
                target: "fluxheim::stream",
                "stream route {} rejected source {} by stream source policy",
                self.name,
                source
                    .map(|address| address.to_string())
                    .unwrap_or_else(|| "unknown".to_owned())
            );
            return;
        }
        let candidates = self.select_upstream_candidates();
        let options = self.connection_options();
        let started = Instant::now();

        let mut selected_upstream = None;
        let mut result = Err(FluxError::io(
            "select stream upstream",
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "stream route has no selectable upstream",
            ),
        ));
        for (attempt, candidate) in candidates.iter().enumerate() {
            match connect_upstream(&candidate.authority, &options).await {
                Ok(mut upstream) => {
                    selected_upstream = Some(candidate.clone());
                    result = proxy_connected_stream_connection(
                        &mut downstream,
                        &mut upstream,
                        &options,
                        source,
                        destination,
                    )
                    .await;
                    break;
                }
                Err(error) if attempt + 1 < candidates.len() => {
                    log::warn!(
                        target: "fluxheim::stream",
                        "stream route {} connect failed via {}{} after {}ms: {}; trying next upstream",
                        self.name,
                        candidate.label(),
                        if candidate.backup { " (backup)" } else { "" },
                        started.elapsed().as_millis(),
                        error
                    );
                    continue;
                }
                Err(error) => {
                    selected_upstream = Some(candidate.clone());
                    result = Err(error);
                    break;
                }
            }
        }

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
                    selected_upstream
                        .as_ref()
                        .map(StreamSelectedUpstream::label)
                        .unwrap_or(""),
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
                    selected_upstream
                        .as_ref()
                        .map(StreamSelectedUpstream::label)
                        .unwrap_or(""),
                    started.elapsed().as_millis(),
                    error
                );
            }
        }
    }
}

#[derive(Debug, Clone)]
struct RuntimeStreamUpstream {
    authority: Arc<str>,
    alias: Option<Arc<str>>,
    weight: usize,
    backup: bool,
    drained: bool,
}

#[derive(Debug, Clone)]
struct StreamSelectedUpstream {
    authority: Arc<str>,
    alias: Option<Arc<str>>,
    backup: bool,
}

impl StreamSelectedUpstream {
    fn label(&self) -> &str {
        self.alias.as_deref().unwrap_or(self.authority.as_ref())
    }
}

fn runtime_stream_upstreams(route: &StreamRouteConfig) -> Vec<RuntimeStreamUpstream> {
    let backup = route
        .backup_upstreams
        .iter()
        .map(|upstream| upstream.to_ascii_lowercase())
        .collect::<std::collections::HashSet<_>>();
    let drain = route
        .drain_upstreams
        .iter()
        .map(|upstream| upstream.to_ascii_lowercase())
        .collect::<std::collections::HashSet<_>>();
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

fn stream_error_outcome(error: &FluxError) -> &'static str {
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

#[cfg(test)]
async fn proxy_stream_connection(
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

async fn proxy_connected_stream_connection(
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

struct StreamProxyConnectionOptions {
    connect_timeout: Duration,
    idle_timeout: Duration,
    max_connection_lifetime: Option<Duration>,
    max_connection_bytes: Option<u64>,
    upstream_proxy_protocol: UpstreamProxyProtocol,
    upstream_tls: bool,
    upstream_dns_allow_private_addresses: bool,
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
    upstream_tls_connector: Option<StreamUpstreamTlsConnector>,
}

enum StreamCopyEvent {
    DownstreamTotal(u64),
    UpstreamTotal(u64),
    DownstreamEof,
    UpstreamEof,
}

async fn copy_bidirectional_with_limits(
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

fn checked_stream_byte_count(
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

async fn connect_upstream(
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

async fn resolve_upstream_socket_addr(
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

fn stream_dns_resolved_address_allowed(address: IpAddr) -> bool {
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

async fn write_upstream_proxy_protocol(
    upstream: &mut (impl AsyncWrite + Unpin),
    protocol: UpstreamProxyProtocol,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
    idle_timeout: Duration,
) -> FluxResult<()> {
    let header = match protocol {
        UpstreamProxyProtocol::Off => return Ok(()),
        UpstreamProxyProtocol::V1 => {
            crate::proxy_protocol::proxy_protocol_v1_header(source, destination)
        }
        UpstreamProxyProtocol::V2 => {
            crate::proxy_protocol::proxy_protocol_v2_header(source, destination)
        }
    };
    write_with_idle_timeout(upstream, &header, idle_timeout).await
}

#[derive(Debug, Clone)]
enum StreamSourceMatcher {
    Ip(IpAddr),
    Cidr { network: IpAddr, prefix: u8 },
}

impl StreamSourceMatcher {
    fn matches(&self, address: IpAddr) -> bool {
        match self {
            Self::Ip(trusted) => *trusted == address,
            Self::Cidr { network, prefix } => ip_in_prefix(address, *network, *prefix),
        }
    }
}

type StreamTrustedSource = StreamSourceMatcher;

const PROXY_PROTOCOL_V1_MAX_LINE: usize = 108;
const PROXY_PROTOCOL_V2_HEADER_LEN: usize = 16;
const PROXY_PROTOCOL_V2_MAX_PAYLOAD: usize = 4096;
const PROXY_PROTOCOL_V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

fn parse_stream_trusted_sources(route: &StreamRouteConfig) -> FluxResult<Vec<StreamTrustedSource>> {
    if route.downstream_proxy_protocol == DownstreamProxyProtocol::Off {
        return Ok(Vec::new());
    }
    route
        .trusted_proxies
        .iter()
        .map(|source| parse_stream_source_matcher(source, "trusted proxy"))
        .collect::<FluxResult<Vec<_>>>()
}

fn parse_stream_source_matchers(
    values: &[String],
    field: &'static str,
) -> FluxResult<Vec<StreamSourceMatcher>> {
    values
        .iter()
        .map(|source| parse_stream_source_matcher(source, field))
        .collect::<FluxResult<Vec<_>>>()
}

fn parse_stream_source_matcher(
    value: &str,
    field: &'static str,
) -> FluxResult<StreamSourceMatcher> {
    if let Some((address, prefix)) = value.split_once('/') {
        let network = address.parse::<IpAddr>().map_err(|error| {
            FluxError::invalid_input(format!("invalid stream {field} network {value:?}: {error}"))
        })?;
        let prefix = prefix.parse::<u8>().map_err(|error| {
            FluxError::invalid_input(format!("invalid stream {field} prefix {value:?}: {error}"))
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
        return Ok(StreamSourceMatcher::Cidr { network, prefix });
    }
    Ok(StreamSourceMatcher::Ip(value.parse::<IpAddr>().map_err(
        |error| {
            FluxError::invalid_input(format!("invalid stream {field} address {value:?}: {error}"))
        },
    )?))
}

async fn apply_downstream_proxy_protocol_to_stream(
    downstream: &mut TcpStream,
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
    downstream: &mut TcpStream,
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

fn parse_downstream_proxy_protocol_v1(line: &[u8]) -> FluxResult<Option<SocketAddr>> {
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
    downstream: &mut TcpStream,
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

fn parse_downstream_proxy_protocol_v2(
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
    use super::{StreamProxyApp, proxy_stream_connection};
    use crate::config::{DownstreamProxyProtocol, StreamRouteConfig, UpstreamProxyProtocol};
    use std::io;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn plain_options(
        idle_timeout: std::time::Duration,
        max_connection_bytes: Option<u64>,
    ) -> super::StreamProxyConnectionOptions {
        plain_options_with_lifetime(idle_timeout, None, max_connection_bytes)
    }

    fn plain_options_with_lifetime(
        idle_timeout: std::time::Duration,
        max_connection_lifetime: Option<std::time::Duration>,
        max_connection_bytes: Option<u64>,
    ) -> super::StreamProxyConnectionOptions {
        super::StreamProxyConnectionOptions {
            connect_timeout: std::time::Duration::from_secs(1),
            idle_timeout,
            max_connection_lifetime,
            max_connection_bytes,
            upstream_proxy_protocol: UpstreamProxyProtocol::Off,
            upstream_tls: false,
            upstream_dns_allow_private_addresses: false,
            #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
            upstream_tls_connector: None,
        }
    }

    #[test]
    fn stream_app_selects_upstreams_round_robin() {
        let app = StreamProxyApp::from_config(&StreamRouteConfig {
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
            app.select_upstream_candidates()[0].authority.as_ref(),
            "127.0.0.1:5432"
        );
        assert_eq!(
            app.select_upstream_candidates()[0].authority.as_ref(),
            "127.0.0.1:6432"
        );
        assert_eq!(
            app.select_upstream_candidates()[0].authority.as_ref(),
            "127.0.0.1:5432"
        );
    }

    #[test]
    fn stream_app_respects_weights_and_drained_upstreams() {
        let app = StreamProxyApp::from_config(&StreamRouteConfig {
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

        let first = app.select_upstream_candidates();
        let second = app.select_upstream_candidates();
        let third = app.select_upstream_candidates();

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
        let exact = super::parse_stream_source_matcher("127.0.0.1", "trusted proxy").unwrap();
        assert!(exact.matches("127.0.0.1".parse().unwrap()));
        assert!(!exact.matches("127.0.0.2".parse().unwrap()));

        let cidr = super::parse_stream_source_matcher("10.0.0.0/24", "trusted proxy").unwrap();
        assert!(cidr.matches("10.0.0.42".parse().unwrap()));
        assert!(!cidr.matches("10.0.1.42".parse().unwrap()));

        assert!(super::parse_stream_source_matcher("10.0.0.0/64", "trusted proxy").is_err());
    }

    #[test]
    fn stream_source_policy_denies_before_allowing() {
        let app = StreamProxyApp::from_config(&StreamRouteConfig {
            name: "tcp".to_owned(),
            listen: vec!["127.0.0.1:12345".to_owned()],
            upstream: Some("127.0.0.1:5432".to_owned()),
            allow_sources: vec!["10.0.0.0/8".to_owned()],
            deny_sources: vec!["10.0.0.13".to_owned()],
            ..StreamRouteConfig::default()
        })
        .unwrap();

        assert!(app.source_allowed(Some("10.0.0.12:1234".parse().unwrap())));
        assert!(!app.source_allowed(Some("10.0.0.13:1234".parse().unwrap())));
        assert!(!app.source_allowed(Some("192.0.2.10:1234".parse().unwrap())));
        assert!(!app.source_allowed(None));

        let app = StreamProxyApp::from_config(&StreamRouteConfig {
            name: "tcp".to_owned(),
            listen: vec!["127.0.0.1:12345".to_owned()],
            upstream: Some("127.0.0.1:5432".to_owned()),
            deny_sources: vec!["192.0.2.0/24".to_owned()],
            ..StreamRouteConfig::default()
        })
        .unwrap();
        assert!(app.source_allowed(None));
        assert!(app.source_allowed(Some("10.0.0.12:1234".parse().unwrap())));
        assert!(!app.source_allowed(Some("192.0.2.10:1234".parse().unwrap())));
    }

    #[test]
    fn stream_dns_rebind_guard_rejects_private_resolved_addresses() {
        assert!(!super::stream_dns_resolved_address_allowed(
            "127.0.0.1".parse().unwrap()
        ));
        assert!(!super::stream_dns_resolved_address_allowed(
            "10.0.0.1".parse().unwrap()
        ));
        assert!(!super::stream_dns_resolved_address_allowed(
            "169.254.169.254".parse().unwrap()
        ));
        assert!(!super::stream_dns_resolved_address_allowed(
            "100.64.0.1".parse().unwrap()
        ));
        assert!(!super::stream_dns_resolved_address_allowed(
            "198.18.0.1".parse().unwrap()
        ));
        assert!(!super::stream_dns_resolved_address_allowed(
            "240.0.0.1".parse().unwrap()
        ));
        assert!(!super::stream_dns_resolved_address_allowed(
            "::1".parse().unwrap()
        ));
        assert!(!super::stream_dns_resolved_address_allowed(
            "fc00::1".parse().unwrap()
        ));
        assert!(!super::stream_dns_resolved_address_allowed(
            "2001:db8::1".parse().unwrap()
        ));
        assert!(super::stream_dns_resolved_address_allowed(
            "1.1.1.1".parse().unwrap()
        ));
        assert!(super::stream_dns_resolved_address_allowed(
            "2606:4700:4700::1111".parse().unwrap()
        ));
    }

    #[test]
    fn stream_dns_rebind_guard_allows_explicit_ip_literal_upstreams() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();

        runtime.block_on(async {
            assert_eq!(
                super::resolve_upstream_socket_addr("127.0.0.1:5432", false)
                    .await
                    .unwrap(),
                "127.0.0.1:5432".parse().unwrap()
            );
        });
    }

    #[test]
    fn stream_downstream_proxy_protocol_v1_parser_extracts_source() {
        let parsed = super::parse_downstream_proxy_protocol_v1(
            b"PROXY TCP4 203.0.113.10 192.0.2.20 42300 443\r\n",
        )
        .unwrap();

        assert_eq!(parsed, Some("203.0.113.10:42300".parse().unwrap()));
        assert_eq!(
            super::parse_downstream_proxy_protocol_v1(b"PROXY UNKNOWN\r\n").unwrap(),
            None
        );
        assert_eq!(
            super::parse_downstream_proxy_protocol_v1(
                b"PROXY UNKNOWN 192.0.2.20 203.0.113.10 443 42300\r\n"
            )
            .unwrap(),
            None
        );
        assert!(
            super::parse_downstream_proxy_protocol_v1(
                b"PROXY TCP4 2001:db8::10 192.0.2.20 42300 443\r\n"
            )
            .is_err()
        );
    }

    #[test]
    fn stream_downstream_proxy_protocol_v2_parser_extracts_source() {
        let mut header = [0u8; super::PROXY_PROTOCOL_V2_HEADER_LEN];
        header[..super::PROXY_PROTOCOL_V2_SIGNATURE.len()]
            .copy_from_slice(super::PROXY_PROTOCOL_V2_SIGNATURE);
        header[12] = 0x21;
        header[13] = 0x11;
        header[14..16].copy_from_slice(&12u16.to_be_bytes());
        let mut payload = Vec::new();
        payload.extend_from_slice(&[203, 0, 113, 10]);
        payload.extend_from_slice(&[192, 0, 2, 20]);
        payload.extend_from_slice(&42300u16.to_be_bytes());
        payload.extend_from_slice(&443u16.to_be_bytes());

        assert_eq!(
            super::parse_downstream_proxy_protocol_v2(&header, &payload).unwrap(),
            Some("203.0.113.10:42300".parse().unwrap())
        );

        header[12] = 0x20;
        header[13] = 0x00;
        header[14..16].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            super::parse_downstream_proxy_protocol_v2(&header, &[]).unwrap(),
            None
        );
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
                let (mut downstream, _) = downstream_listener.accept().await.unwrap();
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
                let (mut downstream, _) = downstream_listener.accept().await.unwrap();
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
            assert_eq!(error.into_io().kind(), io::ErrorKind::PermissionDenied);
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
                let (mut downstream, _) = downstream_listener.accept().await.unwrap();
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
            assert_eq!(error.into_io().kind(), io::ErrorKind::TimedOut);
            upstream_task.abort();
        });
    }

    #[test]
    fn stream_proxy_enforces_connection_lifetime() {
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
                let (mut downstream, _) = downstream_listener.accept().await.unwrap();
                proxy_stream_connection(
                    &mut downstream,
                    &upstream_addr.to_string(),
                    plain_options_with_lifetime(
                        std::time::Duration::from_secs(1),
                        Some(std::time::Duration::from_millis(50)),
                        None,
                    ),
                    None,
                    None,
                )
                .await
            });

            let _client = tokio::net::TcpStream::connect(downstream_addr)
                .await
                .unwrap();

            let error = proxy_task.await.unwrap().unwrap_err();
            assert_eq!(error.into_io().kind(), io::ErrorKind::TimedOut);
            upstream_task.abort();
        });
    }

    #[test]
    fn stream_proxy_writes_upstream_proxy_protocol_v2() {
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
                let mut header = [0u8; 28];
                stream.read_exact(&mut header).await.unwrap();
                assert_eq!(&header[..12], b"\r\n\r\n\0\r\nQUIT\n");
                assert_eq!(&header[12..16], &[0x21, 0x11, 0x00, 0x0c]);

                let mut input = [0u8; 4];
                stream.read_exact(&mut input).await.unwrap();
                assert_eq!(&input, b"ping");
                stream.write_all(b"pong").await.unwrap();
            });

            let downstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let downstream_addr = downstream_listener.local_addr().unwrap();
            let proxy_task = tokio::spawn(async move {
                let (mut downstream, _) = downstream_listener.accept().await.unwrap();
                let mut options = plain_options(std::time::Duration::from_secs(1), None);
                options.upstream_proxy_protocol = UpstreamProxyProtocol::V2;
                proxy_stream_connection(
                    &mut downstream,
                    &upstream_addr.to_string(),
                    options,
                    Some("127.0.0.1:50000".parse().unwrap()),
                    Some("127.0.0.1:50001".parse().unwrap()),
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
}

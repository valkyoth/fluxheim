use std::io;
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

use crate::background::{FluxBackgroundReady, FluxBackgroundTask, FluxShutdown};
use crate::config::{Config, DownstreamProxyProtocol, StreamRouteConfig, UpstreamProxyProtocol};
#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
use crate::stream_tls::StreamUpstreamTlsConnector;
use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::config_stream::{StreamConnectionSlot, acquire_stream_connection_slot};
use fluxheim_stream::{
    StreamSelectedUpstream, StreamSourcePolicy, StreamTrustedSource, StreamUpstreamSelector,
    apply_downstream_proxy_protocol_to_stream, parse_stream_trusted_sources, stream_error_outcome,
};

mod connect;
use connect::{StreamProxyConnectionOptions, connect_upstream, proxy_connected_stream_connection};
#[cfg(test)]
use connect::{proxy_stream_connection, resolve_upstream_socket_addr};

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

pub(crate) fn stream_background_services_from_config(
    config: &Config,
) -> io::Result<Vec<crate::background::FluxBackgroundService<StreamProxyTask>>> {
    if !config.stream.enabled {
        return Ok(Vec::new());
    }

    config
        .stream
        .routes
        .iter()
        .map(stream_background_service_from_route)
        .collect()
}

fn stream_service_from_route(route: &StreamRouteConfig) -> io::Result<StreamProxyService> {
    StreamProxyService::from_config(route).map_err(FluxError::into_io)
}

fn stream_background_service_from_route(
    route: &StreamRouteConfig,
) -> io::Result<crate::background::FluxBackgroundService<StreamProxyTask>> {
    StreamProxyService::from_config(route)
        .map(StreamProxyService::into_background_service)
        .map_err(FluxError::into_io)
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

    fn into_background_service(self) -> crate::background::FluxBackgroundService<StreamProxyTask> {
        crate::background::FluxBackgroundService::new(
            self.name,
            StreamProxyTask {
                listen: self.listen,
                app: self.app,
                downstream_proxy_protocol: self.downstream_proxy_protocol,
                trusted_sources: self.trusted_sources,
            },
        )
    }
}

pub(crate) struct StreamProxyTask {
    listen: Arc<[String]>,
    app: Arc<StreamProxyApp>,
    downstream_proxy_protocol: DownstreamProxyProtocol,
    trusted_sources: Arc<[StreamTrustedSource]>,
}

impl StreamProxyTask {
    async fn run_listener(
        app: Arc<StreamProxyApp>,
        listener: TcpListener,
        listen: String,
        downstream_proxy_protocol: DownstreamProxyProtocol,
        trusted_sources: Arc<[StreamTrustedSource]>,
        mut shutdown: FluxShutdown,
    ) {
        loop {
            if shutdown.is_shutdown() {
                break;
            }
            tokio::select! {
                requested = shutdown.wait_for_shutdown() => {
                    if requested {
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
impl FluxBackgroundTask for StreamProxyTask {
    async fn start(&self, shutdown: FluxShutdown, mut ready: FluxBackgroundReady) {
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
        ready.notify_ready();
        if listeners.is_empty() {
            let mut shutdown = shutdown;
            let _ = shutdown.wait_for_shutdown().await;
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
        let mut shutdown = shutdown;
        let _ = shutdown.wait_for_shutdown().await;
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

pub(crate) struct StreamProxyApp {
    name: Arc<str>,
    upstream_selector: StreamUpstreamSelector,
    connect_timeout: Duration,
    idle_timeout: Duration,
    max_connection_lifetime: Option<Duration>,
    max_connection_bytes: Option<u64>,
    max_connections: usize,
    active_connections: Arc<AtomicUsize>,
    source_policy: StreamSourcePolicy,
    upstream_proxy_protocol: UpstreamProxyProtocol,
    upstream_tls: bool,
    upstream_dns_allow_private_addresses: bool,
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
    upstream_tls_connector: Option<StreamUpstreamTlsConnector>,
}

impl StreamProxyApp {
    fn from_config(route: &StreamRouteConfig) -> FluxResult<Self> {
        let upstream_selector = StreamUpstreamSelector::from_route(route)?;
        let source_policy = StreamSourcePolicy::from_route(route)?;

        #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
        let upstream_tls_connector = StreamUpstreamTlsConnector::from_route(route)?;

        Ok(Self {
            name: Arc::from(route.name.as_str()),
            upstream_selector,
            connect_timeout: Duration::from_secs(route.connect_timeout_secs),
            idle_timeout: Duration::from_secs(route.idle_timeout_secs),
            max_connection_lifetime: route.max_connection_secs.map(Duration::from_secs),
            max_connection_bytes: route.max_connection_bytes,
            max_connections: route.max_connections,
            active_connections: Arc::new(AtomicUsize::new(0)),
            source_policy,
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
        self.upstream_selector.select_candidates()
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
        self.source_policy.source_allowed(source)
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

#[cfg(test)]
mod tests;

use std::io;
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use async_trait::async_trait;
#[cfg(unix)]
use pingora::server::ListenFds;
use pingora::server::ShutdownWatch;
use pingora::services::{ServiceReadyNotifier, ServiceWithDependents};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

use crate::background::{FluxBackgroundReady, FluxBackgroundTask, FluxShutdown};
use crate::config::{Config, DownstreamProxyProtocol, StreamRouteConfig, UpstreamProxyProtocol};
#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
use crate::stream_tls::StreamUpstreamTlsConnector;
use crate::{
    config_stream::{StreamConnectionSlot, acquire_stream_connection_slot},
    flux_error::{FluxError, FluxResult},
};
use fluxheim_stream::{
    StreamSelectedUpstream, StreamSourcePolicy, StreamTrustedSource, StreamUpstreamSelector,
    apply_downstream_proxy_protocol_to_stream, copy_bidirectional_with_limits,
    parse_stream_trusted_sources, stream_dns_resolved_address_allowed, stream_error_outcome,
    write_upstream_proxy_protocol,
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

#[async_trait]
impl ServiceWithDependents for StreamProxyService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<ListenFds>,
        shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
        ready_notifier: ServiceReadyNotifier,
    ) {
        let task = StreamProxyTask {
            listen: self.listen.clone(),
            app: self.app.clone(),
            downstream_proxy_protocol: self.downstream_proxy_protocol,
            trusted_sources: self.trusted_sources.clone(),
        };
        task.start(
            fluxheim_runtime::FluxShutdown::new(shutdown),
            fluxheim_runtime::FluxBackgroundReady::new(move || ready_notifier.notify_ready()),
        )
        .await;
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
        let exact =
            fluxheim_stream::StreamSourceMatcher::parse("127.0.0.1", "trusted proxy").unwrap();
        assert!(exact.matches("127.0.0.1".parse().unwrap()));
        assert!(!exact.matches("127.0.0.2".parse().unwrap()));

        let cidr =
            fluxheim_stream::StreamSourceMatcher::parse("10.0.0.0/24", "trusted proxy").unwrap();
        assert!(cidr.matches("10.0.0.42".parse().unwrap()));
        assert!(!cidr.matches("10.0.1.42".parse().unwrap()));

        assert!(
            fluxheim_stream::StreamSourceMatcher::parse("10.0.0.0/64", "trusted proxy").is_err()
        );
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
        assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
            "127.0.0.1".parse().unwrap()
        ));
        assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
            "10.0.0.1".parse().unwrap()
        ));
        assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
            "169.254.169.254".parse().unwrap()
        ));
        assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
            "100.64.0.1".parse().unwrap()
        ));
        assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
            "198.18.0.1".parse().unwrap()
        ));
        assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
            "240.0.0.1".parse().unwrap()
        ));
        assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
            "::1".parse().unwrap()
        ));
        assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
            "fc00::1".parse().unwrap()
        ));
        assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
            "2001:db8::1".parse().unwrap()
        ));
        assert!(fluxheim_stream::stream_dns_resolved_address_allowed(
            "1.1.1.1".parse().unwrap()
        ));
        assert!(fluxheim_stream::stream_dns_resolved_address_allowed(
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

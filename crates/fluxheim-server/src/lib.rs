#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use fluxheim_config::{AcmeAutomationMode, Config, DownstreamProxyProtocol};
use fluxheim_runtime::{BackgroundTaskSpec, ShutdownView};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerProtocol {
    AdminHttp,
    Http,
    Https,
    MetricsHttp,
    StreamTcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceKind {
    AdminControlPlane,
    AdminOpsSocket,
    MetricsHttp,
    ProxyHttp,
    StreamProxy,
    UdpProxy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceSpec {
    name: &'static str,
    kind: ServiceKind,
}

impl ServiceSpec {
    pub const fn new(name: &'static str, kind: ServiceKind) -> Self {
        Self { name, kind }
    }

    pub const fn name(self) -> &'static str {
        self.name
    }

    pub const fn kind(self) -> ServiceKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerSpec {
    addr: SocketAddr,
    protocol: ListenerProtocol,
    proxy_protocol: bool,
}

impl ListenerSpec {
    pub const fn new(addr: SocketAddr, protocol: ListenerProtocol) -> Self {
        Self {
            addr,
            protocol,
            proxy_protocol: false,
        }
    }

    pub const fn with_proxy_protocol(mut self, enabled: bool) -> Self {
        self.proxy_protocol = enabled;
        self
    }

    pub const fn addr(self) -> SocketAddr {
        self.addr
    }

    pub const fn protocol(self) -> ListenerProtocol {
        self.protocol
    }

    pub const fn proxy_protocol_enabled(self) -> bool {
        self.proxy_protocol
    }

    pub fn is_loopback(self) -> bool {
        self.addr.ip().is_loopback()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerPlan {
    process: ProcessSpec,
    listeners: Vec<ListenerSpec>,
    services: Vec<ServiceSpec>,
    background_tasks: Vec<BackgroundTaskSpec>,
}

impl ServerPlan {
    pub fn new(listeners: Vec<ListenerSpec>, background_tasks: Vec<BackgroundTaskSpec>) -> Self {
        Self {
            process: ProcessSpec::default(),
            listeners,
            services: Vec::new(),
            background_tasks,
        }
    }

    pub fn with_process(
        process: ProcessSpec,
        listeners: Vec<ListenerSpec>,
        services: Vec<ServiceSpec>,
        background_tasks: Vec<BackgroundTaskSpec>,
    ) -> Self {
        Self {
            process,
            listeners,
            services,
            background_tasks,
        }
    }

    pub fn process(&self) -> &ProcessSpec {
        &self.process
    }

    pub fn listeners(&self) -> &[ListenerSpec] {
        &self.listeners
    }

    pub fn services(&self) -> &[ServiceSpec] {
        &self.services
    }

    pub fn has_service(&self, kind: ServiceKind) -> bool {
        self.services.iter().any(|service| service.kind() == kind)
    }

    pub fn background_tasks(&self) -> &[BackgroundTaskSpec] {
        &self.background_tasks
    }

    pub fn has_background_task(&self, kind: fluxheim_runtime::BackgroundTaskKind) -> bool {
        self.background_tasks.iter().any(|task| task.kind() == kind)
    }

    pub fn has_public_listener(&self) -> bool {
        self.listeners
            .iter()
            .any(|listener| !listener.is_loopback())
    }

    pub fn from_config(config: &Config) -> Result<Self, ServerPlanError> {
        let mut listeners = Vec::new();
        let proxy_protocol = config.server.proxy_protocol != DownstreamProxyProtocol::Off;

        for listen in &config.server.listen {
            listeners.push(
                ListenerSpec::new(parse_listener(listen)?, ListenerProtocol::Http)
                    .with_proxy_protocol(proxy_protocol),
            );
        }
        for listen in &config.server.tls_listen {
            listeners.push(
                ListenerSpec::new(parse_listener(listen)?, ListenerProtocol::Https)
                    .with_proxy_protocol(proxy_protocol),
            );
        }
        if config.admin.enabled {
            listeners.push(ListenerSpec::new(
                parse_listener(&config.admin.listen)?,
                ListenerProtocol::AdminHttp,
            ));
        }
        if config.metrics.enabled {
            listeners.push(ListenerSpec::new(
                parse_listener(&config.metrics.listen)?,
                ListenerProtocol::MetricsHttp,
            ));
        }
        if config.stream.enabled {
            for route in &config.stream.routes {
                for listen in &route.listen {
                    listeners.push(ListenerSpec::new(
                        parse_listener(listen)?,
                        ListenerProtocol::StreamTcp,
                    ));
                }
            }
        }
        if config.udp.enabled {
            for route in &config.udp.routes {
                for listen in &route.listen {
                    listeners.push(ListenerSpec::new(
                        parse_listener(listen)?,
                        ListenerProtocol::Udp,
                    ));
                }
            }
        }

        Ok(Self {
            process: ProcessSpec::from_config(config),
            listeners,
            services: service_specs_from_config(config),
            background_tasks: background_task_specs_from_config(config),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessSpec {
    daemon: bool,
    error_log: Option<PathBuf>,
    pid_file: PathBuf,
    upgrade_sock: PathBuf,
    threads: usize,
    listener_tasks_per_fd: usize,
    work_stealing: bool,
    upstream_keepalive_pool_size: usize,
    max_retries: usize,
    grace_period_seconds: Option<u64>,
    graceful_shutdown_timeout_seconds: Option<u64>,
}

impl Default for ProcessSpec {
    fn default() -> Self {
        Self {
            daemon: false,
            error_log: None,
            pid_file: PathBuf::from("/run/fluxheim/fluxheim.pid"),
            upgrade_sock: PathBuf::from("/run/fluxheim/fluxheim-upgrade.sock"),
            threads: 1,
            listener_tasks_per_fd: 1,
            work_stealing: true,
            upstream_keepalive_pool_size: 128,
            max_retries: 16,
            grace_period_seconds: None,
            graceful_shutdown_timeout_seconds: None,
        }
    }
}

impl ProcessSpec {
    fn from_config(config: &Config) -> Self {
        let process = &config.server.process;
        Self {
            daemon: process.daemon,
            error_log: process.error_log.clone(),
            pid_file: process.pid_file.clone(),
            upgrade_sock: process.upgrade_sock.clone(),
            threads: process.threads,
            listener_tasks_per_fd: process.listener_tasks_per_fd,
            work_stealing: process.work_stealing,
            upstream_keepalive_pool_size: process.upstream_keepalive_pool_size,
            max_retries: process.max_retries,
            grace_period_seconds: process.grace_period_seconds,
            graceful_shutdown_timeout_seconds: process.graceful_shutdown_timeout_seconds,
        }
    }

    pub const fn daemon(&self) -> bool {
        self.daemon
    }

    pub fn error_log(&self) -> Option<&Path> {
        self.error_log.as_deref()
    }

    pub fn pid_file(&self) -> &Path {
        &self.pid_file
    }

    pub fn upgrade_sock(&self) -> &Path {
        &self.upgrade_sock
    }

    pub const fn threads(&self) -> usize {
        self.threads
    }

    pub const fn listener_tasks_per_fd(&self) -> usize {
        self.listener_tasks_per_fd
    }

    pub const fn work_stealing(&self) -> bool {
        self.work_stealing
    }

    pub const fn upstream_keepalive_pool_size(&self) -> usize {
        self.upstream_keepalive_pool_size
    }

    pub const fn max_retries(&self) -> usize {
        self.max_retries
    }

    pub const fn grace_period_seconds(&self) -> Option<u64> {
        self.grace_period_seconds
    }

    pub const fn graceful_shutdown_timeout_seconds(&self) -> Option<u64> {
        self.graceful_shutdown_timeout_seconds
    }
}

pub trait ServerRunner {
    type Error;

    fn run(&self, plan: ServerPlan, shutdown: &dyn ShutdownView) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerPlanError {
    InvalidListenerAddress { address: String },
}

impl std::fmt::Display for ServerPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidListenerAddress { address } => {
                write!(formatter, "invalid listener address {address:?}")
            }
        }
    }
}

impl std::error::Error for ServerPlanError {}

fn parse_listener(value: &str) -> Result<SocketAddr, ServerPlanError> {
    value
        .parse::<SocketAddr>()
        .map_err(|_| ServerPlanError::InvalidListenerAddress {
            address: value.to_owned(),
        })
}

fn service_specs_from_config(config: &Config) -> Vec<ServiceSpec> {
    let mut services = Vec::new();

    if !config.server.listen.is_empty() || !config.server.tls_listen.is_empty() {
        services.push(ServiceSpec::new(
            "Fluxheim HTTP Proxy",
            ServiceKind::ProxyHttp,
        ));
    }
    if config.admin.enabled {
        services.push(ServiceSpec::new(
            "Fluxheim Admin Control Plane",
            ServiceKind::AdminControlPlane,
        ));
        if config.admin.ops_socket.enabled {
            services.push(ServiceSpec::new(
                "Fluxheim Local Ops Socket",
                ServiceKind::AdminOpsSocket,
            ));
        }
    }
    if config.metrics.enabled {
        services.push(ServiceSpec::new(
            "Fluxheim Metrics HTTP",
            ServiceKind::MetricsHttp,
        ));
    }
    if config.stream.enabled {
        services.push(ServiceSpec::new(
            "Fluxheim Stream Proxy",
            ServiceKind::StreamProxy,
        ));
    }
    if config.udp.enabled {
        services.push(ServiceSpec::new(
            "Fluxheim UDP Proxy",
            ServiceKind::UdpProxy,
        ));
    }

    services
}

fn background_task_specs_from_config(config: &Config) -> Vec<BackgroundTaskSpec> {
    let mut tasks = Vec::new();

    if config.cache_purger.enabled {
        tasks.push(BackgroundTaskSpec::new(
            "Cache stale disk purger",
            fluxheim_runtime::BackgroundTaskKind::CacheStalePurge,
        ));
    }
    if config.metrics.enabled {
        if any_cache_policy_enabled(config) {
            tasks.push(BackgroundTaskSpec::new(
                "Cache runtime metrics",
                fluxheim_runtime::BackgroundTaskKind::CacheMetrics,
            ));
        }
        if config.metrics.otlp.enabled {
            tasks.push(BackgroundTaskSpec::new(
                "OTLP metrics export",
                fluxheim_runtime::BackgroundTaskKind::MetricsExport,
            ));
        }
    }
    if config.tls.acme.enabled
        && config.tls.acme.automation == AcmeAutomationMode::Background
        && config.tls.acme.renewal.enabled
    {
        tasks.push(BackgroundTaskSpec::new(
            "ACME renewal",
            fluxheim_runtime::BackgroundTaskKind::AcmeRenewal,
        ));
    }
    if config.tls.acme.enabled && config.tls.acme.renewal.reload_after_renewal {
        tasks.push(BackgroundTaskSpec::new(
            "Certificate reload control socket",
            fluxheim_runtime::BackgroundTaskKind::CertificateReload,
        ));
    }

    tasks
}

fn any_cache_policy_enabled(config: &Config) -> bool {
    config.cache.enabled
        || config
            .vhosts
            .iter()
            .any(|vhost| vhost.cache.enabled || vhost.routes.iter().any(route_cache_enabled))
}

fn route_cache_enabled(route: &fluxheim_config::RouteConfig) -> bool {
    route.cache.as_ref().is_some_and(|cache| cache.enabled)
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

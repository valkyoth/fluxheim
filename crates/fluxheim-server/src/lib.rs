#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::net::SocketAddr;

use fluxheim_config::{AcmeAutomationMode, Config, DownstreamProxyProtocol};
use fluxheim_runtime::{BackgroundTaskSpec, ShutdownView};

mod control;
mod http2;
mod listener;
mod process;
mod proxy_protocol;
mod service;
#[cfg(unix)]
mod unix_listener;

pub use control::CertificateReloadControlPlan;
pub use http2::DownstreamHttp2Policy;
pub use listener::{ListenerProtocol, ListenerSpec};
pub use process::ProcessSpec;
pub use proxy_protocol::{ProxyProtocolPolicy, ProxyProtocolTrustedSource};
pub use service::{ServiceKind, ServiceSpec};
#[cfg(unix)]
pub use unix_listener::replace_private_unix_listener;

use proxy_protocol::proxy_protocol_policy_from_config;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAdapterKind {
    PingoraCompatibility,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerPlan {
    runtime_adapter: RuntimeAdapterKind,
    process: ProcessSpec,
    proxy_protocol: ProxyProtocolPolicy,
    downstream_http2: DownstreamHttp2Policy,
    certificate_reload_control: Option<CertificateReloadControlPlan>,
    listeners: Vec<ListenerSpec>,
    services: Vec<ServiceSpec>,
    background_tasks: Vec<BackgroundTaskSpec>,
}

impl ServerPlan {
    pub fn new(listeners: Vec<ListenerSpec>, background_tasks: Vec<BackgroundTaskSpec>) -> Self {
        Self {
            runtime_adapter: RuntimeAdapterKind::PingoraCompatibility,
            process: ProcessSpec::default(),
            proxy_protocol: ProxyProtocolPolicy::Off,
            downstream_http2: DownstreamHttp2Policy::default(),
            certificate_reload_control: None,
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
            runtime_adapter: RuntimeAdapterKind::PingoraCompatibility,
            process,
            proxy_protocol: ProxyProtocolPolicy::Off,
            downstream_http2: DownstreamHttp2Policy::default(),
            certificate_reload_control: None,
            listeners,
            services,
            background_tasks,
        }
    }

    pub fn process(&self) -> &ProcessSpec {
        &self.process
    }

    pub const fn runtime_adapter(&self) -> RuntimeAdapterKind {
        self.runtime_adapter
    }

    pub fn proxy_protocol(&self) -> &ProxyProtocolPolicy {
        &self.proxy_protocol
    }

    pub const fn downstream_http2(&self) -> &DownstreamHttp2Policy {
        &self.downstream_http2
    }

    pub fn certificate_reload_control(&self) -> Option<&CertificateReloadControlPlan> {
        self.certificate_reload_control.as_ref()
    }

    pub fn listeners(&self) -> &[ListenerSpec] {
        &self.listeners
    }

    pub fn listeners_for(
        &self,
        protocol: ListenerProtocol,
    ) -> impl Iterator<Item = &ListenerSpec> + '_ {
        self.listeners
            .iter()
            .filter(move |listener| listener.protocol() == protocol)
    }

    pub fn listener_addrs(&self, protocol: ListenerProtocol) -> Vec<String> {
        self.listeners_for(protocol)
            .map(|listener| listener.addr().to_string())
            .collect()
    }

    pub fn services(&self) -> &[ServiceSpec] {
        &self.services
    }

    pub fn service(&self, kind: ServiceKind) -> Option<ServiceSpec> {
        self.services
            .iter()
            .copied()
            .find(|service| service.kind() == kind)
    }

    pub fn has_service(&self, kind: ServiceKind) -> bool {
        self.service(kind).is_some()
    }

    pub fn background_tasks(&self) -> &[BackgroundTaskSpec] {
        &self.background_tasks
    }

    pub fn background_task(
        &self,
        kind: fluxheim_runtime::BackgroundTaskKind,
    ) -> Option<BackgroundTaskSpec> {
        self.background_tasks
            .iter()
            .copied()
            .find(|task| task.kind() == kind)
    }

    pub fn has_background_task(&self, kind: fluxheim_runtime::BackgroundTaskKind) -> bool {
        self.background_task(kind).is_some()
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

        let process = ProcessSpec::from_config(config);
        let certificate_reload_control =
            certificate_reload_control_plan_from_config(config, &process);

        Ok(Self {
            runtime_adapter: RuntimeAdapterKind::PingoraCompatibility,
            process,
            proxy_protocol: proxy_protocol_policy_from_config(config)?,
            downstream_http2: DownstreamHttp2Policy::default(),
            certificate_reload_control,
            listeners,
            services: service_specs_from_config(config),
            background_tasks: background_task_specs_from_config(config),
        })
    }
}

fn certificate_reload_control_plan_from_config(
    config: &Config,
    process: &ProcessSpec,
) -> Option<CertificateReloadControlPlan> {
    if config.tls.acme.enabled && config.tls.acme.renewal.reload_after_renewal {
        return Some(CertificateReloadControlPlan::new(
            process.certificate_reload_sock().to_path_buf(),
        ));
    }
    None
}

pub trait ServerRunner {
    type Error;

    fn run(&self, plan: ServerPlan, shutdown: &dyn ShutdownView) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerPlanError {
    InvalidListenerAddress { address: String },
    InvalidProxyProtocolTrustedSource { source: String, reason: String },
}

impl std::fmt::Display for ServerPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidListenerAddress { address } => {
                write!(formatter, "invalid listener address {address:?}")
            }
            Self::InvalidProxyProtocolTrustedSource { source, reason } => {
                write!(
                    formatter,
                    "invalid PROXY protocol trusted source {source:?}: {reason}"
                )
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

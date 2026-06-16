#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use fluxheim_config::Config;
use fluxheim_runtime::{BackgroundTaskSpec, ShutdownView};

mod background;
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

use control::certificate_reload_control_plan_from_config;
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

    pub fn service_listener_addrs(&self, kind: ServiceKind) -> Vec<String> {
        let Some(service) = self.service(kind) else {
            return Vec::new();
        };
        service
            .listener_protocols()
            .iter()
            .flat_map(|protocol| self.listeners_for(*protocol))
            .map(|listener| listener.addr().to_string())
            .collect()
    }

    pub fn service_listener_addrs_for_protocol(
        &self,
        kind: ServiceKind,
        protocol: ListenerProtocol,
    ) -> Vec<String> {
        let Some(service) = self.service(kind) else {
            return Vec::new();
        };
        if !service.listener_protocols().contains(&protocol) {
            return Vec::new();
        }
        self.listener_addrs(protocol)
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
        let process = ProcessSpec::from_config(config);
        let certificate_reload_control =
            certificate_reload_control_plan_from_config(config, &process);

        Ok(Self {
            runtime_adapter: RuntimeAdapterKind::PingoraCompatibility,
            process,
            proxy_protocol: proxy_protocol_policy_from_config(config)?,
            downstream_http2: DownstreamHttp2Policy::default(),
            certificate_reload_control,
            listeners: listener::listener_specs_from_config(config)?,
            services: service::service_specs_from_config(config),
            background_tasks: background::background_task_specs_from_config(config),
        })
    }
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

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "server_unix_tests.rs"]
mod unix_tests;

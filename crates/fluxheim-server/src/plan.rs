use fluxheim_config::Config;
use fluxheim_runtime::BackgroundTaskSpec;

use crate::{
    CertificateReloadControlPlan, DownstreamHttp1Policy, DownstreamHttp2Policy, ListenerProtocol,
    ListenerSpec, NativeHttp1ProxyCandidate, NativeHttp1ProxyCutoverSummary, NativeHttp2Preview,
    ProcessSpec, ProxyProtocolPolicy, ServerPlanError, ServiceKind, ServiceSpec, background,
    control::certificate_reload_control_plan_from_config, listener, native_http1_plan,
    proxy_protocol, service,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAdapterKind {
    PingoraCompatibility,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerPlan {
    runtime_adapter: RuntimeAdapterKind,
    process: ProcessSpec,
    proxy_protocol: ProxyProtocolPolicy,
    downstream_http1: DownstreamHttp1Policy,
    downstream_http2: DownstreamHttp2Policy,
    native_http2_preview: NativeHttp2Preview,
    certificate_reload_control: Option<CertificateReloadControlPlan>,
    admin_ops_socket: Option<service::AdminOpsSocketPlan>,
    native_http1_proxy_candidates: Vec<NativeHttp1ProxyCandidate>,
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
            downstream_http1: DownstreamHttp1Policy::default(),
            downstream_http2: DownstreamHttp2Policy::default(),
            native_http2_preview: NativeHttp2Preview::from_downstream_policy(
                DownstreamHttp2Policy::default(),
            ),
            certificate_reload_control: None,
            admin_ops_socket: None,
            native_http1_proxy_candidates: Vec::new(),
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
            downstream_http1: DownstreamHttp1Policy::default(),
            downstream_http2: DownstreamHttp2Policy::default(),
            native_http2_preview: NativeHttp2Preview::from_downstream_policy(
                DownstreamHttp2Policy::default(),
            ),
            certificate_reload_control: None,
            admin_ops_socket: None,
            native_http1_proxy_candidates: Vec::new(),
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

    pub const fn downstream_http1(&self) -> &DownstreamHttp1Policy {
        &self.downstream_http1
    }

    pub const fn downstream_http2(&self) -> &DownstreamHttp2Policy {
        &self.downstream_http2
    }

    pub const fn native_http2_preview(&self) -> &NativeHttp2Preview {
        &self.native_http2_preview
    }

    pub fn certificate_reload_control(&self) -> Option<&CertificateReloadControlPlan> {
        self.certificate_reload_control.as_ref()
    }

    pub fn admin_ops_socket(&self) -> Option<&service::AdminOpsSocketPlan> {
        self.admin_ops_socket.as_ref()
    }

    pub fn native_http1_proxy_candidates(&self) -> &[NativeHttp1ProxyCandidate] {
        &self.native_http1_proxy_candidates
    }

    pub fn native_http1_proxy_cutover_summary(&self) -> NativeHttp1ProxyCutoverSummary {
        NativeHttp1ProxyCutoverSummary::from_candidates(&self.native_http1_proxy_candidates)
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

    pub fn service_listeners(&self, kind: ServiceKind) -> impl Iterator<Item = &ListenerSpec> + '_ {
        let listener_protocols = self
            .service(kind)
            .map(ServiceSpec::listener_protocols)
            .unwrap_or(&[]);
        listener_protocols
            .iter()
            .flat_map(|protocol| self.listeners_for(*protocol))
    }

    pub fn service_listeners_for_protocol(
        &self,
        kind: ServiceKind,
        protocol: ListenerProtocol,
    ) -> impl Iterator<Item = &ListenerSpec> + '_ {
        let service_owns_protocol = self
            .service(kind)
            .is_some_and(|service| service.listener_protocols().contains(&protocol));
        self.listeners_for(protocol)
            .filter(move |_| service_owns_protocol)
    }

    pub fn service_listener_addrs(&self, kind: ServiceKind) -> Vec<String> {
        self.service_listeners(kind)
            .map(|listener| listener.addr().to_string())
            .collect()
    }

    pub fn first_service_listener_addr(&self, kind: ServiceKind) -> Option<String> {
        self.service_listeners(kind)
            .map(|listener| listener.addr().to_string())
            .next()
    }

    pub fn service_listener_addrs_for_protocol(
        &self,
        kind: ServiceKind,
        protocol: ListenerProtocol,
    ) -> Vec<String> {
        self.service_listeners_for_protocol(kind, protocol)
            .map(|listener| listener.addr().to_string())
            .collect()
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
        let upstream_keepalive_pool_size = process.upstream_keepalive_pool_size();
        let certificate_reload_control =
            certificate_reload_control_plan_from_config(config, &process);
        let downstream_http1 = DownstreamHttp1Policy::from_server_limits(config.server.limits);

        let downstream_http2 = DownstreamHttp2Policy::from_server_limits(config.server.limits);

        Ok(Self {
            runtime_adapter: RuntimeAdapterKind::PingoraCompatibility,
            process,
            proxy_protocol: proxy_protocol::proxy_protocol_policy_from_config(config)?,
            downstream_http1,
            downstream_http2,
            native_http2_preview: NativeHttp2Preview::from_downstream_policy(downstream_http2),
            certificate_reload_control,
            admin_ops_socket: service::admin_ops_socket_plan_from_config(config),
            native_http1_proxy_candidates:
                native_http1_plan::native_http1_proxy_candidates_from_config(
                    config,
                    downstream_http1,
                    upstream_keepalive_pool_size,
                ),
            listeners: listener::listener_specs_from_config(config)?,
            services: service::service_specs_from_config(config),
            background_tasks: background::background_task_specs_from_config(config),
        })
    }
}

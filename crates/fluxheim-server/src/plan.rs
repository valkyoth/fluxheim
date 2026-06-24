use fluxheim_config::Config;
use fluxheim_runtime::BackgroundTaskSpec;

use crate::{
    CertificateReloadControlPlan, DownstreamHttp1Policy, DownstreamHttp2Policy, ListenerProtocol,
    ListenerSpec, NativeHttp1ProxyCandidate, NativeHttp1ProxyCutoverSummary, NativeHttp2Preview,
    NativeRuntimeLaunchPlan, NativeRuntimeLaunchPlanError, NativeRuntimeManifest,
    NativeRuntimeManifestError, ProcessSpec, ProxyProtocolPolicy, ServerPlanError, ServiceKind,
    ServiceSpec, background, control::certificate_reload_control_plan_from_config, listener,
    native_http1_plan, proxy_protocol, service,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAdapterKind {
    PingoraCompatibility,
    NativeRuntime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRuntimeCutoverBlocker {
    NativeHttp1Proxy,
    NativeHttp2,
    AdminControlPlane,
    AdminOpsSocket,
    MetricsHttp,
    StreamProxy,
    UdpProxy,
}

impl NativeRuntimeCutoverBlocker {
    pub const ALL: [Self; 7] = [
        Self::NativeHttp1Proxy,
        Self::NativeHttp2,
        Self::AdminControlPlane,
        Self::AdminOpsSocket,
        Self::MetricsHttp,
        Self::StreamProxy,
        Self::UdpProxy,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::NativeHttp1Proxy => "native-http1-proxy",
            Self::NativeHttp2 => "native-http2",
            Self::AdminControlPlane => "admin-control-plane",
            Self::AdminOpsSocket => "admin-ops-socket",
            Self::MetricsHttp => "metrics-http",
            Self::StreamProxy => "stream-proxy",
            Self::UdpProxy => "udp-proxy",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeHttp1Proxy => "native HTTP/1 proxy parity",
            Self::NativeHttp2 => "native HTTP/2 downstream parity",
            Self::AdminControlPlane => "native admin control plane",
            Self::AdminOpsSocket => "native admin ops socket service",
            Self::MetricsHttp => "native metrics HTTP service",
            Self::StreamProxy => "native stream proxy service",
            Self::UdpProxy => "native UDP proxy service",
        }
    }

    pub const fn target_release(self) -> &'static str {
        match self {
            Self::AdminControlPlane | Self::AdminOpsSocket | Self::MetricsHttp => "1.6.22",
            Self::StreamProxy | Self::UdpProxy => "1.6.23",
            Self::NativeHttp2 => "1.6.24",
            Self::NativeHttp1Proxy => "1.6.32",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRuntimeCutoverSummary {
    blockers: Vec<NativeRuntimeCutoverBlocker>,
}

impl NativeRuntimeCutoverSummary {
    fn from_plan(plan: &ServerPlan) -> Self {
        let mut blockers = Vec::new();
        let http1_summary = plan.native_http1_proxy_cutover_summary();
        if plan.has_service(ServiceKind::ProxyHttp)
            && !matches!(
                http1_summary.status(),
                crate::NativeHttp1ProxyCutoverStatus::NoProxy
                    | crate::NativeHttp1ProxyCutoverStatus::NativeReady
            )
        {
            blockers.push(NativeRuntimeCutoverBlocker::NativeHttp1Proxy);
        }
        if plan.has_service(ServiceKind::ProxyHttp)
            && !plan.native_http2_preview().is_cutover_ready()
        {
            blockers.push(NativeRuntimeCutoverBlocker::NativeHttp2);
        }
        for (kind, native_ready, blocker) in [
            (
                ServiceKind::AdminControlPlane,
                plan.native_admin_control_plane_ready,
                NativeRuntimeCutoverBlocker::AdminControlPlane,
            ),
            (
                ServiceKind::AdminOpsSocket,
                plan.native_admin_ops_socket_ready,
                NativeRuntimeCutoverBlocker::AdminOpsSocket,
            ),
            (
                ServiceKind::MetricsHttp,
                plan.native_metrics_http_ready,
                NativeRuntimeCutoverBlocker::MetricsHttp,
            ),
            (
                ServiceKind::StreamProxy,
                plan.native_stream_proxy_ready,
                NativeRuntimeCutoverBlocker::StreamProxy,
            ),
            (
                ServiceKind::UdpProxy,
                plan.native_udp_proxy_ready,
                NativeRuntimeCutoverBlocker::UdpProxy,
            ),
        ] {
            if plan.has_service(kind) && !native_ready {
                blockers.push(blocker);
            }
        }
        Self { blockers }
    }

    pub fn blockers(&self) -> &[NativeRuntimeCutoverBlocker] {
        &self.blockers
    }

    pub fn is_ready(&self) -> bool {
        self.blockers.is_empty()
    }

    pub fn to_tsv(&self) -> String {
        let mut report = String::from("blocker\tdescription\ttarget_release\n");
        for blocker in &self.blockers {
            report.push_str(blocker.key());
            report.push('\t');
            report.push_str(blocker.as_str());
            report.push('\t');
            report.push_str(blocker.target_release());
            report.push('\n');
        }
        report
    }
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
    native_admin_control_plane_ready: bool,
    native_admin_ops_socket_ready: bool,
    native_metrics_http_ready: bool,
    native_stream_proxy_ready: bool,
    native_udp_proxy_ready: bool,
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
            native_admin_control_plane_ready: false,
            native_admin_ops_socket_ready: false,
            native_metrics_http_ready: false,
            native_stream_proxy_ready: false,
            native_udp_proxy_ready: false,
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
            native_admin_control_plane_ready: false,
            native_admin_ops_socket_ready: false,
            native_metrics_http_ready: false,
            native_stream_proxy_ready: false,
            native_udp_proxy_ready: false,
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

    pub fn native_runtime_target_adapter(&self) -> RuntimeAdapterKind {
        if self.native_runtime_cutover_summary().is_ready() {
            RuntimeAdapterKind::NativeRuntime
        } else {
            RuntimeAdapterKind::PingoraCompatibility
        }
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

    pub const fn native_admin_control_plane_ready(&self) -> bool {
        self.native_admin_control_plane_ready
    }

    pub const fn native_admin_ops_socket_ready(&self) -> bool {
        self.native_admin_ops_socket_ready
    }

    pub const fn native_metrics_http_ready(&self) -> bool {
        self.native_metrics_http_ready
    }

    pub const fn native_stream_proxy_ready(&self) -> bool {
        self.native_stream_proxy_ready
    }

    pub const fn native_udp_proxy_ready(&self) -> bool {
        self.native_udp_proxy_ready
    }

    pub fn native_http1_proxy_candidates(&self) -> &[NativeHttp1ProxyCandidate] {
        &self.native_http1_proxy_candidates
    }

    pub fn native_http1_proxy_cutover_summary(&self) -> NativeHttp1ProxyCutoverSummary {
        NativeHttp1ProxyCutoverSummary::from_candidates(&self.native_http1_proxy_candidates)
    }

    pub fn native_runtime_cutover_summary(&self) -> NativeRuntimeCutoverSummary {
        NativeRuntimeCutoverSummary::from_plan(self)
    }

    pub fn native_runtime_manifest(
        &self,
    ) -> Result<NativeRuntimeManifest, NativeRuntimeManifestError> {
        NativeRuntimeManifest::from_plan(self)
    }

    pub fn native_runtime_launch_plan(
        &self,
    ) -> Result<NativeRuntimeLaunchPlan, NativeRuntimeLaunchPlanError> {
        NativeRuntimeLaunchPlan::from_plan(self)
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
            native_admin_control_plane_ready: config.admin.enabled,
            native_admin_ops_socket_ready: native_admin_ops_socket_ready(config),
            native_metrics_http_ready: config.metrics.enabled,
            native_stream_proxy_ready: config.stream.enabled,
            native_udp_proxy_ready: config.udp.enabled,
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

#[cfg(unix)]
fn native_admin_ops_socket_ready(config: &Config) -> bool {
    config.admin.enabled && config.admin.ops_socket.enabled
}

#[cfg(not(unix))]
fn native_admin_ops_socket_ready(_config: &Config) -> bool {
    false
}

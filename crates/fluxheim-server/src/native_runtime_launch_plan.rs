use crate::{
    DownstreamHttp1Policy, DownstreamHttp2Policy, ListenerProtocol, NativeRuntimeCutoverBlocker,
    NativeRuntimeManifest, NativeRuntimeManifestError, NativeRuntimeServiceManifest, ProcessSpec,
    ProxyProtocolPolicy, ServerPlan, ServiceKind, ServiceSpec,
};
use fluxheim_runtime::{BackgroundTaskKind, BackgroundTaskSpec};
use std::{collections::BTreeMap, net::SocketAddr};

#[path = "native_runtime_launch_plan_report.rs"]
mod native_runtime_launch_plan_report;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRuntimeLaunchPlan {
    process: ProcessSpec,
    proxy_protocol: ProxyProtocolPolicy,
    downstream_http1: DownstreamHttp1Policy,
    downstream_http2: DownstreamHttp2Policy,
    metrics_bearer_token_required: bool,
    manifest: NativeRuntimeManifest,
    listeners: Vec<NativeRuntimeLaunchListener>,
    background_tasks: Vec<NativeRuntimeLaunchBackgroundTask>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRuntimeLaunchListener {
    service: ServiceSpec,
    listener: crate::ListenerSpec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRuntimeLaunchBackgroundTask {
    task: BackgroundTaskSpec,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NativeRuntimeListenerTransport {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeRuntimeLaunchPlanError {
    Blocked {
        blockers: Vec<NativeRuntimeCutoverBlocker>,
    },
    DuplicateService {
        kind: ServiceKind,
        first_name: &'static str,
        second_name: &'static str,
    },
    DuplicateListener {
        transport: NativeRuntimeListenerTransport,
        address: SocketAddr,
        first_service: ServiceKind,
        second_service: ServiceKind,
    },
    DuplicateBackgroundTask {
        kind: BackgroundTaskKind,
        first_name: &'static str,
        second_name: &'static str,
    },
}

impl std::fmt::Display for NativeRuntimeLaunchPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocked { blockers } => {
                write!(
                    formatter,
                    "native runtime launch plan blocked by {} cutover blockers",
                    blockers.len()
                )
            }
            Self::DuplicateService {
                kind,
                first_name,
                second_name,
            } => {
                write!(
                    formatter,
                    "native runtime launch plan has duplicate {kind:?} service for {first_name:?} and {second_name:?}"
                )
            }
            Self::DuplicateListener {
                transport,
                address,
                first_service,
                second_service,
            } => {
                write!(
                    formatter,
                    "native runtime launch plan has duplicate {transport} listener {address} for {first_service:?} and {second_service:?}"
                )
            }
            Self::DuplicateBackgroundTask {
                kind,
                first_name,
                second_name,
            } => {
                write!(
                    formatter,
                    "native runtime launch plan has duplicate {kind:?} background task for {first_name:?} and {second_name:?}"
                )
            }
        }
    }
}

impl std::error::Error for NativeRuntimeLaunchPlanError {}

impl NativeRuntimeLaunchPlan {
    pub(crate) fn from_plan(plan: &ServerPlan) -> Result<Self, NativeRuntimeLaunchPlanError> {
        let manifest = plan
            .native_runtime_manifest()
            .map_err(NativeRuntimeLaunchPlanError::from)?;
        validate_services(manifest.services())?;
        let listeners: Vec<_> = manifest
            .services()
            .iter()
            .flat_map(|service| {
                service.listeners().iter().copied().map(move |listener| {
                    NativeRuntimeLaunchListener {
                        service: service.service(),
                        listener,
                    }
                })
            })
            .collect();
        validate_listener_bindings(&listeners)?;
        let background_tasks: Vec<_> = manifest
            .background_tasks()
            .iter()
            .copied()
            .map(|task| NativeRuntimeLaunchBackgroundTask { task })
            .collect();
        validate_background_tasks(&background_tasks)?;
        Ok(Self {
            process: plan.process().clone(),
            proxy_protocol: plan.proxy_protocol().clone(),
            downstream_http1: *plan.downstream_http1(),
            downstream_http2: *plan.downstream_http2(),
            metrics_bearer_token_required: plan.native_metrics_http_auth_required(),
            manifest,
            listeners,
            background_tasks,
        })
    }

    pub const fn process(&self) -> &ProcessSpec {
        &self.process
    }

    pub const fn proxy_protocol(&self) -> &ProxyProtocolPolicy {
        &self.proxy_protocol
    }

    pub const fn downstream_http1(&self) -> DownstreamHttp1Policy {
        self.downstream_http1
    }

    pub const fn downstream_http2(&self) -> DownstreamHttp2Policy {
        self.downstream_http2
    }

    pub const fn metrics_bearer_token_required(&self) -> bool {
        self.metrics_bearer_token_required
    }

    pub const fn manifest(&self) -> &NativeRuntimeManifest {
        &self.manifest
    }

    pub fn listeners(&self) -> &[NativeRuntimeLaunchListener] {
        &self.listeners
    }

    pub fn background_tasks(&self) -> &[NativeRuntimeLaunchBackgroundTask] {
        &self.background_tasks
    }
}

impl NativeRuntimeLaunchListener {
    pub const fn service(&self) -> ServiceSpec {
        self.service
    }

    pub const fn service_kind(&self) -> ServiceKind {
        self.service.kind()
    }

    pub const fn service_name(&self) -> &'static str {
        self.service.name()
    }

    pub const fn listener(&self) -> crate::ListenerSpec {
        self.listener
    }

    pub const fn listener_protocol(&self) -> crate::ListenerProtocol {
        self.listener.protocol()
    }

    pub const fn listener_addr(&self) -> std::net::SocketAddr {
        self.listener.addr()
    }

    pub const fn proxy_protocol_enabled(&self) -> bool {
        self.listener.proxy_protocol_enabled()
    }

    pub const fn transport(&self) -> NativeRuntimeListenerTransport {
        NativeRuntimeListenerTransport::from_protocol(self.listener_protocol())
    }
}

impl NativeRuntimeLaunchBackgroundTask {
    pub const fn spec(&self) -> BackgroundTaskSpec {
        self.task
    }

    pub const fn kind(&self) -> BackgroundTaskKind {
        self.task.kind()
    }

    pub const fn name(&self) -> &'static str {
        self.task.name()
    }

    pub const fn is_critical(&self) -> bool {
        self.task.is_critical()
    }
}

impl From<NativeRuntimeManifestError> for NativeRuntimeLaunchPlanError {
    fn from(error: NativeRuntimeManifestError) -> Self {
        match error {
            NativeRuntimeManifestError::Blocked { blockers } => Self::Blocked { blockers },
        }
    }
}

impl NativeRuntimeListenerTransport {
    pub const fn from_protocol(protocol: ListenerProtocol) -> Self {
        match protocol {
            ListenerProtocol::Udp => Self::Udp,
            ListenerProtocol::AdminHttp
            | ListenerProtocol::Http
            | ListenerProtocol::Https
            | ListenerProtocol::MetricsHttp
            | ListenerProtocol::StreamTcp => Self::Tcp,
        }
    }
}

impl std::fmt::Display for NativeRuntimeListenerTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => formatter.write_str("TCP"),
            Self::Udp => formatter.write_str("UDP"),
        }
    }
}

fn validate_listener_bindings(
    listeners: &[NativeRuntimeLaunchListener],
) -> Result<(), NativeRuntimeLaunchPlanError> {
    let mut seen = BTreeMap::new();
    for listener in listeners {
        let key = (listener.transport(), listener.listener_addr());
        if let Some(first_service) = seen.insert(key, listener.service_kind()) {
            return Err(NativeRuntimeLaunchPlanError::DuplicateListener {
                transport: listener.transport(),
                address: listener.listener_addr(),
                first_service,
                second_service: listener.service_kind(),
            });
        }
    }
    Ok(())
}

fn validate_services(
    services: &[NativeRuntimeServiceManifest],
) -> Result<(), NativeRuntimeLaunchPlanError> {
    let mut seen = Vec::new();
    for service in services {
        if let Some((_, first_name)) = seen
            .iter()
            .find(|(kind, _)| *kind == service.kind())
            .copied()
        {
            return Err(NativeRuntimeLaunchPlanError::DuplicateService {
                kind: service.kind(),
                first_name,
                second_name: service.name(),
            });
        }
        seen.push((service.kind(), service.name()));
    }
    Ok(())
}

fn validate_background_tasks(
    tasks: &[NativeRuntimeLaunchBackgroundTask],
) -> Result<(), NativeRuntimeLaunchPlanError> {
    let mut seen = Vec::new();
    for task in tasks {
        if let Some((_, first_name)) = seen.iter().find(|(kind, _)| *kind == task.kind()).copied() {
            return Err(NativeRuntimeLaunchPlanError::DuplicateBackgroundTask {
                kind: task.kind(),
                first_name,
                second_name: task.name(),
            });
        }
        seen.push((task.kind(), task.name()));
    }
    Ok(())
}

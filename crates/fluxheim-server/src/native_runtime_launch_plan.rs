use crate::{
    DownstreamHttp1Policy, DownstreamHttp2Policy, ListenerProtocol, NativeRuntimeCutoverBlocker,
    NativeRuntimeManifest, NativeRuntimeManifestError, ProcessSpec, ProxyProtocolPolicy,
    ServerPlan, ServiceKind, ServiceSpec,
};
use fluxheim_runtime::{BackgroundTaskKind, BackgroundTaskSpec};
use std::{collections::BTreeMap, net::SocketAddr};

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

    pub fn to_tsv(&self) -> String {
        let mut report = format!(
            "native-runtime-launch-plan\tstatus\tservices\tlisteners\tbackground_tasks\tproxy_protocol\n\
             native-runtime-launch-plan\tready\t{}\t{}\t{}\t{}\n",
            self.manifest.services().len(),
            self.listeners.len(),
            self.background_tasks.len(),
            proxy_protocol_label(&self.proxy_protocol),
        );
        report.push_str("native-runtime-launch-policy\tprotocol\tfield\tvalue\n");
        push_launch_policy_row(
            &mut report,
            "http1",
            "max_body_bytes",
            self.downstream_http1.max_body_bytes().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "max_connections",
            self.downstream_http1.max_connections().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "max_head_bytes",
            self.downstream_http1.max_head_bytes().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "max_header_count",
            self.downstream_http1.max_header_count().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "max_header_line_bytes",
            self.downstream_http1.max_header_line_bytes().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "max_start_line_bytes",
            self.downstream_http1.max_start_line_bytes().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "request_body_timeout_ms",
            self.downstream_http1
                .request_body_timeout()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "request_head_timeout_ms",
            self.downstream_http1
                .request_head_timeout()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http1",
            "tls_handshake_timeout_ms",
            self.downstream_http1
                .tls_handshake_timeout()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_header_list_size",
            self.downstream_http2.max_header_list_size().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_header_count",
            self.downstream_http2.max_header_count().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_uri_bytes",
            self.downstream_http2.max_uri_bytes().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_body_bytes",
            self.downstream_http2.max_body_bytes().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "request_body_timeout_ms",
            self.downstream_http2
                .request_body_timeout()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "response_body_timeout_ms",
            self.downstream_http2
                .response_body_timeout()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "handler_timeout_ms",
            self.downstream_http2
                .handler_timeout()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "response_write_lifetime_ms",
            self.downstream_http2
                .response_write_lifetime()
                .as_millis()
                .to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_concurrent_streams",
            self.downstream_http2.max_concurrent_streams().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "initial_window_size",
            self.downstream_http2.initial_window_size().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_frame_size",
            self.downstream_http2.max_frame_size().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_send_buffer_size",
            self.downstream_http2.max_send_buffer_size().to_string(),
        );
        push_launch_policy_row(
            &mut report,
            "http2",
            "max_pending_accept_reset_streams",
            self.downstream_http2
                .max_pending_accept_reset_streams()
                .to_string(),
        );
        report.push_str("native-runtime-launch-service-policy\tkind\tfield\tvalue\n");
        if self.manifest.service(ServiceKind::MetricsHttp).is_some() {
            push_launch_service_policy_row(
                &mut report,
                "MetricsHttp",
                "bearer_token_required",
                self.metrics_bearer_token_required.to_string(),
            );
        }
        report.push_str(
            "native-runtime-launch-listener\tkind\tname\tprotocol\taddress\tproxy_protocol\n",
        );
        for listener in &self.listeners {
            report.push_str("native-runtime-launch-listener\t");
            report.push_str(&format!("{:?}", listener.service_kind()));
            report.push('\t');
            report.push_str(&launch_tsv_field(listener.service_name()));
            report.push('\t');
            report.push_str(&format!("{:?}", listener.listener_protocol()));
            report.push('\t');
            report.push_str(&listener.listener_addr().to_string());
            report.push('\t');
            report.push_str(if listener.proxy_protocol_enabled() {
                "true"
            } else {
                "false"
            });
            report.push('\n');
        }
        report.push_str("native-runtime-launch-background-task\tkind\tname\tcritical\n");
        for task in &self.background_tasks {
            report.push_str("native-runtime-launch-background-task\t");
            report.push_str(&format!("{:?}", task.kind()));
            report.push('\t');
            report.push_str(&launch_tsv_field(task.name()));
            report.push('\t');
            report.push_str(if task.is_critical() { "true" } else { "false" });
            report.push('\n');
        }
        report
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

fn push_launch_policy_row(report: &mut String, protocol: &str, field: &str, value: String) {
    report.push_str("native-runtime-launch-policy\t");
    report.push_str(protocol);
    report.push('\t');
    report.push_str(field);
    report.push('\t');
    report.push_str(&value);
    report.push('\n');
}

fn push_launch_service_policy_row(report: &mut String, kind: &str, field: &str, value: String) {
    report.push_str("native-runtime-launch-service-policy\t");
    report.push_str(kind);
    report.push('\t');
    report.push_str(field);
    report.push('\t');
    report.push_str(&value);
    report.push('\n');
}

fn proxy_protocol_label(proxy_protocol: &ProxyProtocolPolicy) -> &'static str {
    match proxy_protocol {
        ProxyProtocolPolicy::Off => "off",
        ProxyProtocolPolicy::V1 { .. } => "v1",
        ProxyProtocolPolicy::V2 { .. } => "v2",
    }
}

fn launch_tsv_field(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\t' | '\n' | '\r' => ' ',
            character => character,
        })
        .collect()
}

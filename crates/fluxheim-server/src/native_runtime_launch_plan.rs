use crate::{
    DownstreamHttp1Policy, DownstreamHttp2Policy, NativeRuntimeCutoverBlocker,
    NativeRuntimeManifest, NativeRuntimeManifestError, ProcessSpec, ProxyProtocolPolicy,
    ServerPlan, ServiceKind, ServiceSpec,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRuntimeLaunchPlan {
    process: ProcessSpec,
    proxy_protocol: ProxyProtocolPolicy,
    downstream_http1: DownstreamHttp1Policy,
    downstream_http2: DownstreamHttp2Policy,
    manifest: NativeRuntimeManifest,
    listeners: Vec<NativeRuntimeLaunchListener>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRuntimeLaunchListener {
    service: ServiceSpec,
    listener: crate::ListenerSpec,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeRuntimeLaunchPlanError {
    Blocked {
        blockers: Vec<NativeRuntimeCutoverBlocker>,
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
        }
    }
}

impl std::error::Error for NativeRuntimeLaunchPlanError {}

impl NativeRuntimeLaunchPlan {
    pub(crate) fn from_plan(plan: &ServerPlan) -> Result<Self, NativeRuntimeLaunchPlanError> {
        let manifest = plan
            .native_runtime_manifest()
            .map_err(NativeRuntimeLaunchPlanError::from)?;
        let listeners = manifest
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
        Ok(Self {
            process: plan.process().clone(),
            proxy_protocol: plan.proxy_protocol().clone(),
            downstream_http1: *plan.downstream_http1(),
            downstream_http2: *plan.downstream_http2(),
            manifest,
            listeners,
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

    pub const fn manifest(&self) -> &NativeRuntimeManifest {
        &self.manifest
    }

    pub fn listeners(&self) -> &[NativeRuntimeLaunchListener] {
        &self.listeners
    }

    pub fn to_tsv(&self) -> String {
        let mut report = format!(
            "native-runtime-launch-plan\tstatus\tservices\tlisteners\tbackground_tasks\tproxy_protocol\n\
             native-runtime-launch-plan\tready\t{}\t{}\t{}\t{}\n",
            self.manifest.services().len(),
            self.listeners.len(),
            self.manifest.background_tasks().len(),
            proxy_protocol_label(&self.proxy_protocol),
        );
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
}

impl From<NativeRuntimeManifestError> for NativeRuntimeLaunchPlanError {
    fn from(error: NativeRuntimeManifestError) -> Self {
        match error {
            NativeRuntimeManifestError::Blocked { blockers } => Self::Blocked { blockers },
        }
    }
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

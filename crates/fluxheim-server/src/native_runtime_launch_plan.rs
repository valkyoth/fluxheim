use crate::{
    DownstreamHttp1Policy, DownstreamHttp2Policy, NativeRuntimeCutoverBlocker,
    NativeRuntimeManifest, NativeRuntimeManifestError, ProcessSpec, ProxyProtocolPolicy,
    ServerPlan,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRuntimeLaunchPlan {
    process: ProcessSpec,
    proxy_protocol: ProxyProtocolPolicy,
    downstream_http1: DownstreamHttp1Policy,
    downstream_http2: DownstreamHttp2Policy,
    manifest: NativeRuntimeManifest,
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
        Ok(Self {
            process: plan.process().clone(),
            proxy_protocol: plan.proxy_protocol().clone(),
            downstream_http1: *plan.downstream_http1(),
            downstream_http2: *plan.downstream_http2(),
            manifest,
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

    pub fn to_tsv(&self) -> String {
        let listener_count: usize = self
            .manifest
            .services()
            .iter()
            .map(|service| service.listeners().len())
            .sum();
        format!(
            "native-runtime-launch-plan\tstatus\tservices\tlisteners\tbackground_tasks\tproxy_protocol\n\
             native-runtime-launch-plan\tready\t{}\t{}\t{}\t{}\n",
            self.manifest.services().len(),
            listener_count,
            self.manifest.background_tasks().len(),
            proxy_protocol_label(&self.proxy_protocol),
        )
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

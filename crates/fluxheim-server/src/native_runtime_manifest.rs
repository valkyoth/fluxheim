use fluxheim_runtime::BackgroundTaskSpec;

use crate::{ListenerSpec, NativeRuntimeCutoverBlocker, ServerPlan, ServiceKind, ServiceSpec};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRuntimeManifest {
    services: Vec<NativeRuntimeServiceManifest>,
    background_tasks: Vec<BackgroundTaskSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRuntimeServiceManifest {
    service: ServiceSpec,
    listeners: Vec<ListenerSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeRuntimeManifestError {
    Blocked {
        blockers: Vec<NativeRuntimeCutoverBlocker>,
    },
}

impl std::fmt::Display for NativeRuntimeManifestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocked { blockers } => {
                write!(
                    formatter,
                    "native runtime manifest blocked by {} cutover blockers",
                    blockers.len()
                )
            }
        }
    }
}

impl std::error::Error for NativeRuntimeManifestError {}

impl NativeRuntimeManifest {
    pub(crate) fn from_plan(plan: &ServerPlan) -> Result<Self, NativeRuntimeManifestError> {
        let blockers = plan.native_runtime_cutover_summary().blockers().to_vec();
        if !blockers.is_empty() {
            return Err(NativeRuntimeManifestError::Blocked { blockers });
        }

        Ok(Self {
            services: plan
                .services()
                .iter()
                .copied()
                .map(|service| NativeRuntimeServiceManifest {
                    service,
                    listeners: plan.service_listeners(service.kind()).copied().collect(),
                })
                .collect(),
            background_tasks: plan.background_tasks().to_vec(),
        })
    }

    pub fn services(&self) -> &[NativeRuntimeServiceManifest] {
        &self.services
    }

    pub fn background_tasks(&self) -> &[BackgroundTaskSpec] {
        &self.background_tasks
    }

    pub fn service(&self, kind: ServiceKind) -> Option<&NativeRuntimeServiceManifest> {
        self.services.iter().find(|service| service.kind() == kind)
    }

    pub fn to_tsv(&self) -> String {
        let mut report = String::from("native-runtime-manifest-service\tkind\tname\tlisteners\n");
        for service in &self.services {
            report.push_str("native-runtime-manifest-service\t");
            report.push_str(&format!("{:?}", service.kind()));
            report.push('\t');
            report.push_str(&manifest_tsv_field(service.name()));
            report.push('\t');
            let listeners = service
                .listeners()
                .iter()
                .map(|listener| format!("{:?}@{}", listener.protocol(), listener.addr()))
                .collect::<Vec<_>>()
                .join(",");
            report.push_str(&manifest_tsv_field(&listeners));
            report.push('\n');
        }
        report.push_str("native-runtime-manifest-background-task\tkind\tname\tcritical\n");
        for task in &self.background_tasks {
            report.push_str("native-runtime-manifest-background-task\t");
            report.push_str(&format!("{:?}", task.kind()));
            report.push('\t');
            report.push_str(&manifest_tsv_field(task.name()));
            report.push('\t');
            report.push_str(if task.is_critical() { "true" } else { "false" });
            report.push('\n');
        }
        report
    }
}

impl NativeRuntimeServiceManifest {
    pub const fn service(&self) -> ServiceSpec {
        self.service
    }

    pub const fn kind(&self) -> ServiceKind {
        self.service.kind()
    }

    pub const fn name(&self) -> &'static str {
        self.service.name()
    }

    pub fn listeners(&self) -> &[ListenerSpec] {
        &self.listeners
    }
}

fn manifest_tsv_field(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\t' | '\n' | '\r' => ' ',
            character => character,
        })
        .collect()
}

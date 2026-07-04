use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use fluxheim_config::{Config, WasmAttachmentConfig, WasmPluginFailMode, WasmPluginPhase};
use fluxheim_wasm::{
    FluxWasmAdmissionController, FluxWasmRuntime, LoadedWasmPlugin, WasmAccessDecision,
    WasmAccessDeny, WasmExecutionError, WasmPluginLoadError, load_plugin_from_manifest,
};

use crate::native_http1_proxy_metrics::{
    record_native_wasm_admission_rejection, record_native_wasm_execution,
};

const ACCESS_DECISION_PHASE: &str = "access-decision";
const ACCESS_DECISION_FUNCTION: &str = "fluxheim_access_decision";

#[derive(Clone, Debug)]
pub(crate) struct NativeWasmHookRegistry {
    attachments: Vec<NativeWasmAttachment>,
    admission: FluxWasmAdmissionController,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NativeWasmHooks {
    access_decision: Vec<NativeWasmHook>,
}

#[derive(Clone, Debug)]
struct NativeWasmAttachment {
    plugin: Arc<NativeWasmPlugin>,
    vhost: String,
    route: Option<String>,
    phases: Vec<WasmPluginPhase>,
    admission: FluxWasmAdmissionController,
}

#[derive(Debug)]
struct NativeWasmPlugin {
    name: String,
    loaded: LoadedWasmPlugin,
    runtime: FluxWasmRuntime,
    fail_mode: WasmPluginFailMode,
    admission: FluxWasmAdmissionController,
}

#[derive(Clone, Debug)]
struct NativeWasmHook {
    plugin: Arc<NativeWasmPlugin>,
    phase: WasmPluginPhase,
    global_admission: FluxWasmAdmissionController,
    attachment_admission: FluxWasmAdmissionController,
}

#[derive(Debug)]
pub(crate) enum NativeWasmAccessOutcome {
    Allow,
    Deny { status: u16, reason: String },
}

#[derive(Debug)]
pub(crate) enum NativeWasmHookError {
    Admission(NativeWasmAdmissionScope),
    Execution(WasmExecutionError),
    Join,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeWasmAdmissionScope {
    Global,
    Plugin,
    Attachment,
}

impl PartialEq for NativeWasmHooks {
    fn eq(&self, other: &Self) -> bool {
        self.access_decision == other.access_decision
    }
}

impl Eq for NativeWasmHooks {}

impl PartialEq for NativeWasmHook {
    fn eq(&self, other: &Self) -> bool {
        self.plugin.name == other.plugin.name && self.phase == other.phase
    }
}

impl Eq for NativeWasmHook {}

impl NativeWasmHookRegistry {
    pub(crate) fn from_config(config: &Config) -> Result<Option<Self>, NativeWasmRegistryError> {
        if !config.wasm.enabled {
            return Ok(None);
        }
        let admission = FluxWasmAdmissionController::new(
            usize::try_from(config.wasm.max_total_concurrent_executions)
                .map_err(|_| NativeWasmRegistryError::AdmissionLimit)?,
        )
        .map_err(|_| NativeWasmRegistryError::AdmissionLimit)?;

        let manifests = config
            .wasm
            .plugin_manifests()
            .map_err(|_| NativeWasmRegistryError::Config)?;
        let mut plugins = HashMap::with_capacity(manifests.len());
        for manifest in manifests {
            let loaded = load_plugin_from_manifest(
                manifest,
                &config.wasm.plugin_roots,
                config.wasm.allow_preview_abi,
            )?;
            let runtime = FluxWasmRuntime::new(loaded.manifest().limits())
                .map_err(|_| NativeWasmRegistryError::Runtime)?;
            let name = loaded.manifest().name().to_owned();
            let plugin_config = config
                .wasm
                .plugins
                .iter()
                .find(|plugin| plugin.name == name)
                .ok_or(NativeWasmRegistryError::Config)?;
            plugins.insert(
                name.clone(),
                Arc::new(NativeWasmPlugin {
                    name,
                    fail_mode: plugin_config.fail_mode,
                    admission: admission_controller(
                        plugin_config
                            .admission
                            .unwrap_or(config.wasm.default_admission),
                    )?,
                    loaded,
                    runtime,
                }),
            );
        }

        let mut attachments = Vec::with_capacity(config.wasm.attachments.len());
        for attachment in config.wasm.ordered_attachments() {
            let plugin = plugins
                .get(&attachment.plugin)
                .cloned()
                .ok_or(NativeWasmRegistryError::Config)?;
            let plugin_config = config
                .wasm
                .plugins
                .iter()
                .find(|plugin| plugin.name == attachment.plugin)
                .ok_or(NativeWasmRegistryError::Config)?;
            attachments.push(NativeWasmAttachment {
                phases: attachment_phases(attachment, &plugin_config.phases),
                plugin,
                vhost: attachment.vhost.clone(),
                route: attachment.route.clone(),
                admission: admission_controller(
                    attachment
                        .admission
                        .unwrap_or(config.wasm.default_admission),
                )?,
            });
        }

        Ok(Some(Self {
            attachments,
            admission,
        }))
    }

    pub(crate) fn hooks_for(&self, vhost: &str, route: Option<&str>) -> NativeWasmHooks {
        let access_decision = self
            .attachments
            .iter()
            .filter(|attachment| attachment.matches(vhost, route))
            .filter(|attachment| attachment.phases.contains(&WasmPluginPhase::AccessDecision))
            .map(|attachment| NativeWasmHook {
                plugin: attachment.plugin.clone(),
                phase: WasmPluginPhase::AccessDecision,
                global_admission: self.admission.clone(),
                attachment_admission: attachment.admission.clone(),
            })
            .collect();
        NativeWasmHooks { access_decision }
    }
}

impl NativeWasmHooks {
    pub(crate) fn is_empty(&self) -> bool {
        self.access_decision.is_empty()
    }

    pub(crate) async fn access_decision(&self) -> NativeWasmAccessOutcome {
        if self.access_decision.is_empty() {
            return NativeWasmAccessOutcome::Allow;
        }
        for hook in &self.access_decision {
            match hook.run_access_decision().await {
                WasmAccessDecision::Continue | WasmAccessDecision::Allow => {}
                WasmAccessDecision::Deny(deny) => {
                    return NativeWasmAccessOutcome::Deny {
                        status: deny.status,
                        reason: deny.reason,
                    };
                }
            }
        }
        NativeWasmAccessOutcome::Allow
    }
}

impl NativeWasmAttachment {
    fn matches(&self, vhost: &str, route: Option<&str>) -> bool {
        self.vhost == vhost && (self.route.is_none() || self.route.as_deref() == route)
    }
}

impl NativeWasmHook {
    async fn run_access_decision(&self) -> WasmAccessDecision {
        match self
            .run_i32(ACCESS_DECISION_PHASE, ACCESS_DECISION_FUNCTION)
            .await
        {
            Ok(0) => WasmAccessDecision::Continue,
            Ok(1) => WasmAccessDecision::Allow,
            Ok(2) => WasmAccessDecision::Deny(WasmAccessDeny {
                status: 403,
                reason: "wasm access denied".to_owned(),
            }),
            Ok(_) => self.failed_access_decision("error"),
            Err(error) => {
                let outcome = match error {
                    NativeWasmHookError::Admission(_) => "fail_closed",
                    NativeWasmHookError::Execution(WasmExecutionError::Trap(_)) => "trap",
                    NativeWasmHookError::Execution(WasmExecutionError::CompileTimeout {
                        ..
                    }) => "timeout",
                    NativeWasmHookError::Execution(_) | NativeWasmHookError::Join => "error",
                };
                self.failed_access_decision(outcome)
            }
        }
    }

    async fn run_i32(
        &self,
        phase_label: &'static str,
        function: &'static str,
    ) -> Result<i32, NativeWasmHookError> {
        let plugin = self.plugin.clone();
        let global_admission = self.global_admission.clone();
        let attachment_admission = self.attachment_admission.clone();
        let started = Instant::now();
        let plugin_name = plugin.name.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _global_permit = global_admission
                .try_acquire()
                .map_err(|_| NativeWasmHookError::Admission(NativeWasmAdmissionScope::Global))?;
            let _plugin_permit = plugin
                .admission
                .try_acquire()
                .map_err(|_| NativeWasmHookError::Admission(NativeWasmAdmissionScope::Plugin))?;
            let _attachment_permit = attachment_admission.try_acquire().map_err(|_| {
                NativeWasmHookError::Admission(NativeWasmAdmissionScope::Attachment)
            })?;
            plugin
                .runtime
                .run_i32_no_args(plugin.loaded.file(), function)
                .map(|outcome| outcome.result)
                .map_err(NativeWasmHookError::Execution)
        })
        .await
        .map_err(|_| NativeWasmHookError::Join)
        .and_then(|result| result);

        match &result {
            Ok(0) => record_native_wasm_execution(
                &plugin_name,
                phase_label,
                "continue",
                started.elapsed(),
            ),
            Ok(1) => {
                record_native_wasm_execution(&plugin_name, phase_label, "allow", started.elapsed())
            }
            Ok(2) => {
                record_native_wasm_execution(&plugin_name, phase_label, "deny", started.elapsed())
            }
            Ok(_) => {
                record_native_wasm_execution(&plugin_name, phase_label, "error", started.elapsed())
            }
            Err(NativeWasmHookError::Admission(scope)) => {
                record_native_wasm_admission_rejection(&plugin_name, phase_label, scope.as_label());
                record_native_wasm_execution(
                    &plugin_name,
                    phase_label,
                    "fail_closed",
                    started.elapsed(),
                );
            }
            Err(NativeWasmHookError::Execution(WasmExecutionError::Trap(_))) => {
                record_native_wasm_execution(&plugin_name, phase_label, "trap", started.elapsed());
            }
            Err(NativeWasmHookError::Execution(WasmExecutionError::CompileTimeout { .. })) => {
                record_native_wasm_execution(
                    &plugin_name,
                    phase_label,
                    "timeout",
                    started.elapsed(),
                );
            }
            Err(NativeWasmHookError::Execution(_)) | Err(NativeWasmHookError::Join) => {
                record_native_wasm_execution(&plugin_name, phase_label, "error", started.elapsed());
            }
        }
        result
    }

    fn failed_access_decision(&self, outcome: &'static str) -> WasmAccessDecision {
        match self.plugin.fail_mode {
            WasmPluginFailMode::FailOpen => WasmAccessDecision::Continue,
            WasmPluginFailMode::FailClosed => WasmAccessDecision::Deny(WasmAccessDeny {
                status: 503,
                reason: format!("wasm access decision {outcome}"),
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) enum NativeWasmRegistryError {
    AdmissionLimit,
    Config,
    Load,
    Runtime,
}

impl From<WasmPluginLoadError> for NativeWasmRegistryError {
    fn from(_error: WasmPluginLoadError) -> Self {
        Self::Load
    }
}

fn attachment_phases(
    attachment: &WasmAttachmentConfig,
    plugin_phases: &[WasmPluginPhase],
) -> Vec<WasmPluginPhase> {
    if attachment.phases.is_empty() {
        plugin_phases.to_vec()
    } else {
        attachment.phases.clone()
    }
}

fn admission_controller(
    budget: fluxheim_config::WasmAdmissionBudgetConfig,
) -> Result<FluxWasmAdmissionController, NativeWasmRegistryError> {
    FluxWasmAdmissionController::new(
        usize::try_from(budget.max_concurrent_executions)
            .map_err(|_| NativeWasmRegistryError::AdmissionLimit)?,
    )
    .map_err(|_| NativeWasmRegistryError::AdmissionLimit)
}

impl NativeWasmAdmissionScope {
    fn as_label(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Plugin => "plugin",
            Self::Attachment => "attachment",
        }
    }
}

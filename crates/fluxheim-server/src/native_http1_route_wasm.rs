use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use fluxheim_config::{Config, WasmAttachmentConfig, WasmPluginFailMode, WasmPluginPhase};
use fluxheim_wasm::{
    FluxWasmAdmissionController, FluxWasmCompiledModule, FluxWasmRuntime, WasmAccessDecision,
    WasmAccessDeny, WasmExecutionError, WasmI32HostFunction, WasmPluginLoadError,
    load_plugin_from_manifest,
};

use crate::native_http1_proxy_metrics::{
    record_native_wasm_admission_rejection, record_native_wasm_execution,
};
use crate::native_http1_route_proxy::{NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute};
use crate::native_http1_route_rewrite::request_path_and_query;
use crate::{NativeHttp1Request, NativeHttp1Response};

const ACCESS_DECISION_PHASE: &str = "access-decision";
const ACCESS_DECISION_FUNCTION: &str = "fluxheim_access_decision";
const REQUEST_HEADERS_PHASE: &str = "request-headers";
const REQUEST_HEADERS_FUNCTION: &str = "fluxheim_request_headers";
const RESPONSE_HEADERS_PHASE: &str = "response-headers";
const RESPONSE_HEADERS_FUNCTION: &str = "fluxheim_response_headers";
const WASM_HOST_MODULE: &str = "fluxheim_policy_v1";
const MAX_WASM_HEADER_MUTATIONS: usize = 16;

const HOST_CONTEXT_PATH_CLASS: i32 = 1;
const HEADER_X_POLICY_TIER: i32 = 1;
const HEADER_X_FLUXHEIM_POLICY_BRANCH: i32 = 2;
const HEADER_X_POWERED_BY: i32 = 3;
const VALUE_STANDARD: i32 = 1;
const VALUE_API: i32 = 2;
const VALUE_STATIC: i32 = 3;
const VALUE_GOLD: i32 = 4;
const PATH_CLASS_OTHER: i32 = 0;
const PATH_CLASS_API: i32 = 1;
const PATH_CLASS_STATIC: i32 = 2;
const PATH_CLASS_GOLD: i32 = 3;

#[derive(Clone, Debug)]
pub(crate) struct NativeWasmHookRegistry {
    attachments: Vec<NativeWasmAttachment>,
    admission: FluxWasmAdmissionController,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NativeWasmHooks {
    access_decision: Vec<NativeWasmHook>,
    request_headers: Vec<NativeWasmHook>,
    response_headers: Vec<NativeWasmHook>,
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
    runtime: FluxWasmRuntime,
    module: FluxWasmCompiledModule,
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
            && self.request_headers == other.request_headers
            && self.response_headers == other.response_headers
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
            let module = runtime
                .compile_plugin_module(loaded.file())
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
                    runtime,
                    module,
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
        let request_headers = self
            .attachments
            .iter()
            .filter(|attachment| attachment.matches(vhost, route))
            .filter(|attachment| attachment.phases.contains(&WasmPluginPhase::RequestHeaders))
            .map(|attachment| NativeWasmHook {
                plugin: attachment.plugin.clone(),
                phase: WasmPluginPhase::RequestHeaders,
                global_admission: self.admission.clone(),
                attachment_admission: attachment.admission.clone(),
            })
            .collect();
        let response_headers = self
            .attachments
            .iter()
            .filter(|attachment| attachment.matches(vhost, route))
            .filter(|attachment| {
                attachment
                    .phases
                    .contains(&WasmPluginPhase::ResponseHeaders)
            })
            .map(|attachment| NativeWasmHook {
                plugin: attachment.plugin.clone(),
                phase: WasmPluginPhase::ResponseHeaders,
                global_admission: self.admission.clone(),
                attachment_admission: attachment.admission.clone(),
            })
            .collect();
        NativeWasmHooks {
            access_decision,
            request_headers,
            response_headers,
        }
    }
}

impl NativeWasmHooks {
    pub(crate) fn is_empty(&self) -> bool {
        self.access_decision.is_empty()
            && self.request_headers.is_empty()
            && self.response_headers.is_empty()
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

    pub(crate) async fn apply_request_headers(
        &self,
        request: &mut NativeHttp1Request,
    ) -> Result<(), NativeWasmHeaderError> {
        if self.request_headers.is_empty() {
            return Ok(());
        }
        let context = NativeWasmHeaderContext::from_request(request);
        for hook in &self.request_headers {
            let mutations = hook
                .run_header_mutations(
                    REQUEST_HEADERS_PHASE,
                    REQUEST_HEADERS_FUNCTION,
                    context,
                    NativeWasmHeaderPhase::Request,
                )
                .await?;
            mutations.apply_request(request);
        }
        Ok(())
    }

    pub(crate) async fn apply_response_headers(
        &self,
        context: NativeWasmHeaderContext,
        response: &mut NativeHttp1Response,
    ) -> Result<(), NativeWasmHeaderError> {
        if self.response_headers.is_empty() {
            return Ok(());
        }
        for hook in &self.response_headers {
            let mutations = hook
                .run_header_mutations(
                    RESPONSE_HEADERS_PHASE,
                    RESPONSE_HEADERS_FUNCTION,
                    context,
                    NativeWasmHeaderPhase::Response,
                )
                .await?;
            mutations.apply_response(response);
        }
        Ok(())
    }
}

pub(crate) async fn wasm_access_rejection(
    proxy: &NativeHttp1RouteProxy,
    route: Option<&NativeHttp1RouteProxyRoute>,
) -> Option<NativeHttp1Response> {
    wasm_access_rejection_status(proxy, route)
        .await
        .map(|(status, reason)| {
            NativeHttp1Response::new(status, status_reason(status), reason.into_bytes())
                .close_connection()
        })
}

pub(crate) async fn wasm_access_rejection_status(
    proxy: &NativeHttp1RouteProxy,
    route: Option<&NativeHttp1RouteProxyRoute>,
) -> Option<(u16, String)> {
    let hooks = route
        .map(|route| &route.wasm_hooks)
        .filter(|hooks| !hooks.is_empty())
        .unwrap_or(&proxy.wasm_hooks);
    match hooks.access_decision().await {
        NativeWasmAccessOutcome::Allow => None,
        NativeWasmAccessOutcome::Deny { status, reason } => Some((status, format!("{reason}\n"))),
    }
}

pub(crate) async fn wasm_request_header_rejection(
    hooks: &NativeWasmHooks,
    request: &mut NativeHttp1Request,
) -> Option<NativeHttp1Response> {
    match hooks.apply_request_headers(request).await {
        Ok(()) => None,
        Err(NativeWasmHeaderError::Failed(phase, outcome)) => Some(
            NativeHttp1Response::new(
                503,
                "Service Unavailable",
                format!("wasm {phase} {outcome}\n").into_bytes(),
            )
            .close_connection(),
        ),
    }
}

pub(crate) async fn wasm_response_header_failure(
    hooks: &NativeWasmHooks,
    context: NativeWasmHeaderContext,
    response: &mut NativeHttp1Response,
) -> Option<NativeHttp1Response> {
    match hooks.apply_response_headers(context, response).await {
        Ok(()) => None,
        Err(NativeWasmHeaderError::Failed(phase, outcome)) => Some(
            NativeHttp1Response::new(
                503,
                "Service Unavailable",
                format!("wasm {phase} {outcome}\n").into_bytes(),
            )
            .close_connection(),
        ),
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
                    NativeWasmHookError::Execution(WasmExecutionError::ExecutionTimeout {
                        ..
                    }) => "timeout",
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
        self.run_i32_with_hosts(phase_label, function, Vec::new())
            .await
    }

    async fn run_i32_with_hosts(
        &self,
        phase_label: &'static str,
        function: &'static str,
        host_functions: Vec<WasmI32HostFunction>,
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
                .run_compiled_i32_no_args_with_hosts(&plugin.module, function, host_functions)
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
            Err(NativeWasmHookError::Execution(WasmExecutionError::ExecutionTimeout {
                ..
            })) => {
                record_native_wasm_execution(
                    &plugin_name,
                    phase_label,
                    "timeout",
                    started.elapsed(),
                );
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

    async fn run_header_mutations(
        &self,
        phase_label: &'static str,
        function: &'static str,
        context: NativeWasmHeaderContext,
        phase: NativeWasmHeaderPhase,
    ) -> Result<NativeWasmHeaderMutations, NativeWasmHeaderError> {
        let state = Arc::new(Mutex::new(NativeWasmHeaderMutations::default()));
        let host_functions = wasm_header_host_functions(context, phase, Arc::clone(&state));
        match self
            .run_i32_with_hosts(phase_label, function, host_functions)
            .await
        {
            Ok(0) => state
                .lock()
                .map(|state| state.clone())
                .map_err(|_| NativeWasmHeaderError::Failed(phase_label, "error")),
            Ok(_) => self.failed_header_mutation(phase_label, "error"),
            Err(error) => {
                let outcome = match error {
                    NativeWasmHookError::Admission(_) => "fail_closed",
                    NativeWasmHookError::Execution(WasmExecutionError::Trap(_)) => "trap",
                    NativeWasmHookError::Execution(WasmExecutionError::ExecutionTimeout {
                        ..
                    }) => "timeout",
                    NativeWasmHookError::Execution(WasmExecutionError::CompileTimeout {
                        ..
                    }) => "timeout",
                    NativeWasmHookError::Execution(_) | NativeWasmHookError::Join => "error",
                };
                self.failed_header_mutation(phase_label, outcome)
            }
        }
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

    fn failed_header_mutation(
        &self,
        phase: &'static str,
        outcome: &'static str,
    ) -> Result<NativeWasmHeaderMutations, NativeWasmHeaderError> {
        match self.plugin.fail_mode {
            WasmPluginFailMode::FailOpen => Ok(NativeWasmHeaderMutations::default()),
            WasmPluginFailMode::FailClosed => Err(NativeWasmHeaderError::Failed(phase, outcome)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeWasmHeaderError {
    Failed(&'static str, &'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeWasmHeaderContext {
    path_class: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeWasmHeaderPhase {
    Request,
    Response,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct NativeWasmHeaderMutations {
    set: Vec<(String, String)>,
    remove: Vec<String>,
}

impl NativeWasmHeaderContext {
    pub(crate) fn from_request(request: &NativeHttp1Request) -> Self {
        let path_class = request_path_and_query(request)
            .map(|(path, _)| wasm_path_class(&path))
            .unwrap_or(PATH_CLASS_OTHER);
        Self { path_class }
    }
}

impl NativeWasmHeaderMutations {
    fn push_set(&mut self, name: String, value: String) -> Result<i32, String> {
        if self.set.len() + self.remove.len() >= MAX_WASM_HEADER_MUTATIONS {
            return Err("wasm header mutation limit reached".to_owned());
        }
        self.set.push((name, value));
        Ok(0)
    }

    fn push_remove(&mut self, name: String) -> Result<i32, String> {
        if self.set.len() + self.remove.len() >= MAX_WASM_HEADER_MUTATIONS {
            return Err("wasm header mutation limit reached".to_owned());
        }
        self.remove.push(name);
        Ok(0)
    }

    fn apply_request(&self, request: &mut NativeHttp1Request) {
        for name in &self.remove {
            request
                .headers
                .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
        }
        for (name, value) in &self.set {
            request
                .headers
                .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
            request.headers.push((name.clone(), value.clone()));
        }
    }

    fn apply_response(&self, response: &mut NativeHttp1Response) {
        for name in &self.remove {
            response.remove_header(name);
        }
        for (name, value) in &self.set {
            response.remove_header(name);
            response.push_header(name.clone(), value.clone());
        }
    }
}

fn wasm_header_host_functions(
    context: NativeWasmHeaderContext,
    phase: NativeWasmHeaderPhase,
    state: Arc<Mutex<NativeWasmHeaderMutations>>,
) -> Vec<WasmI32HostFunction> {
    let context_function = WasmI32HostFunction::new(
        WASM_HOST_MODULE,
        "context",
        move |kind, _unused| match kind {
            HOST_CONTEXT_PATH_CLASS => Ok(context.path_class),
            _ => Err("unknown wasm context field".to_owned()),
        },
    );
    let set_request_state = Arc::clone(&state);
    let set_request_function = WasmI32HostFunction::new(
        WASM_HOST_MODULE,
        "set_request_header",
        move |name_id, value_id| {
            if phase != NativeWasmHeaderPhase::Request {
                return Err("request header mutation used outside request phase".to_owned());
            }
            let (name, value) = wasm_request_header_mutation(name_id, value_id)?;
            set_request_state
                .lock()
                .map_err(|_| "wasm header mutation lock poisoned".to_owned())?
                .push_set(name.to_owned(), value.to_owned())
        },
    );
    let set_response_state = Arc::clone(&state);
    let set_response_function = WasmI32HostFunction::new(
        WASM_HOST_MODULE,
        "set_response_header",
        move |name_id, value_id| {
            if phase != NativeWasmHeaderPhase::Response {
                return Err("response header mutation used outside response phase".to_owned());
            }
            let (name, value) = wasm_response_header_mutation(name_id, value_id)?;
            set_response_state
                .lock()
                .map_err(|_| "wasm header mutation lock poisoned".to_owned())?
                .push_set(name.to_owned(), value.to_owned())
        },
    );
    let remove_response_function = WasmI32HostFunction::new(
        WASM_HOST_MODULE,
        "remove_response_header",
        move |name_id, _unused| {
            if phase != NativeWasmHeaderPhase::Response {
                return Err("response header removal used outside response phase".to_owned());
            }
            let name = wasm_response_removable_header(name_id)?;
            state
                .lock()
                .map_err(|_| "wasm header mutation lock poisoned".to_owned())?
                .push_remove(name.to_owned())
        },
    );
    vec![
        context_function,
        set_request_function,
        set_response_function,
        remove_response_function,
    ]
}

fn wasm_path_class(path: &str) -> i32 {
    if path == "/gold" || path.starts_with("/gold/") {
        PATH_CLASS_GOLD
    } else if path == "/api" || path.starts_with("/api/") {
        PATH_CLASS_API
    } else if path == "/static" || path.starts_with("/static/") {
        PATH_CLASS_STATIC
    } else {
        PATH_CLASS_OTHER
    }
}

fn wasm_request_header_mutation(
    name_id: i32,
    value_id: i32,
) -> Result<(&'static str, &'static str), String> {
    match (name_id, value_id) {
        (HEADER_X_POLICY_TIER, VALUE_STANDARD) => Ok(("x-policy-tier", "standard")),
        (HEADER_X_POLICY_TIER, VALUE_API) => Ok(("x-policy-tier", "api")),
        (HEADER_X_POLICY_TIER, VALUE_STATIC) => Ok(("x-policy-tier", "static")),
        (HEADER_X_POLICY_TIER, VALUE_GOLD) => Ok(("x-policy-tier", "gold")),
        _ => Err("forbidden wasm request header mutation".to_owned()),
    }
}

fn wasm_response_header_mutation(
    name_id: i32,
    value_id: i32,
) -> Result<(&'static str, &'static str), String> {
    match (name_id, value_id) {
        (HEADER_X_FLUXHEIM_POLICY_BRANCH, VALUE_STANDARD) => {
            Ok(("x-fluxheim-policy-branch", "standard"))
        }
        (HEADER_X_FLUXHEIM_POLICY_BRANCH, VALUE_API) => Ok(("x-fluxheim-policy-branch", "api")),
        (HEADER_X_FLUXHEIM_POLICY_BRANCH, VALUE_STATIC) => {
            Ok(("x-fluxheim-policy-branch", "static"))
        }
        (HEADER_X_FLUXHEIM_POLICY_BRANCH, VALUE_GOLD) => Ok(("x-fluxheim-policy-branch", "gold")),
        _ => Err("forbidden wasm response header mutation".to_owned()),
    }
}

fn wasm_response_removable_header(name_id: i32) -> Result<&'static str, String> {
    match name_id {
        HEADER_X_POWERED_BY => Ok("x-powered-by"),
        _ => Err("forbidden wasm response header removal".to_owned()),
    }
}

pub(crate) const fn status_reason(status: u16) -> &'static str {
    match status {
        403 => "Forbidden",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
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

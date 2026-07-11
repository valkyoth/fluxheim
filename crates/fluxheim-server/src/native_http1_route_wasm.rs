use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fluxheim_config::{Config, WasmAttachmentConfig, WasmPluginFailMode, WasmPluginPhase};
use fluxheim_wasm::{
    FluxWasmAdmissionController, FluxWasmCompiledModule, FluxWasmCompiledModuleIdentity,
    FluxWasmRuntime, ValidatedWasmPluginManifest, WasmAccessDecision, WasmAccessDeny,
    WasmExecutionError, WasmHostCallNamespace, WasmI32HostFunction, WasmPluginLoadError,
    load_plugin_from_manifest,
};

use crate::native_http1_proxy_memory_cache::{
    NativeProxyCacheKeyComponent, NativeProxyCacheStoreMetadata,
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
const ROUTE_DECISION_PHASE: &str = "route-decision";
const ROUTE_DECISION_FUNCTION: &str = "fluxheim_route_decision";
const CACHE_LOOKUP_PHASE: &str = "cache-lookup";
const CACHE_LOOKUP_FUNCTION: &str = "fluxheim_cache_lookup";
const CACHE_STORE_PHASE: &str = "cache-store";
const CACHE_STORE_FUNCTION: &str = "fluxheim_cache_store";
const WASM_HOST_MODULE: &str = "fluxheim_policy_v1";
#[cfg(feature = "wasm-proxy-abi")]
const PROXY_WASM_HOST_MODULE: &str = "env";
const MAX_WASM_HEADER_MUTATIONS: usize = 16;
const MAX_WASM_CACHE_KEY_COMPONENTS: usize = 4;
const MAX_WASM_CACHE_TAGS: usize = 4;
const MAX_WASM_CACHE_STORE_HEADER_MUTATIONS: usize = 4;

const HOST_CONTEXT_PATH_CLASS: i32 = 1;
const HOST_CONTEXT_CANARY_HEADER: i32 = 2;
const HOST_CONTEXT_MIRROR_HEADER: i32 = 3;
const HOST_CONTEXT_RESPONSE_STATUS: i32 = 4;
const HOST_CONTEXT_DEVICE_CLASS_HEADER: i32 = 5;
const HOST_CONTEXT_RESPONSE_CONTENT_TYPE_CLASS: i32 = 6;
const HEADER_X_POLICY_TIER: i32 = 1;
const HEADER_X_FLUXHEIM_POLICY_BRANCH: i32 = 2;
const HEADER_X_POWERED_BY: i32 = 3;
const CACHE_KEY_DEVICE_CLASS: i32 = 1;
const CACHE_TTL_SHORT: i32 = 1;
const CACHE_TTL_MEDIUM: i32 = 2;
const CACHE_TAG_WASM_POLICY: i32 = 1;
const CACHE_TAG_WASM_GOLD: i32 = 2;
const CACHE_STORE_HEADER_POLICY: i32 = 1;
const CACHE_STORE_HEADER_VALUE_WASM: i32 = 1;
const CACHE_STORE_HEADER_VALUE_GOLD: i32 = 2;
const VALUE_STANDARD: i32 = 1;
const VALUE_API: i32 = 2;
const VALUE_STATIC: i32 = 3;
const VALUE_GOLD: i32 = 4;
const VALUE_MOBILE: i32 = 5;
const VALUE_DESKTOP: i32 = 6;
const VALUE_CONTENT_TYPE_IMAGE: i32 = 7;
const VALUE_CONTENT_TYPE_HTML: i32 = 8;
const VALUE_CONTENT_TYPE_JSON: i32 = 9;
const VALUE_CONTENT_TYPE_TEXT: i32 = 10;
const PATH_CLASS_OTHER: i32 = 0;
const PATH_CLASS_API: i32 = 1;
const PATH_CLASS_STATIC: i32 = 2;
const PATH_CLASS_GOLD: i32 = 3;
const ROUTE_DECISION_CONTINUE: i32 = 0;
const ROUTE_DECISION_CANARY: i32 = 1;
const ROUTE_DECISION_DENY: i32 = 2;
const ROUTE_DECISION_MIRROR: i32 = 3;
const CACHE_LOOKUP_CONTINUE: i32 = 0;
const CACHE_LOOKUP_PASS: i32 = 1;
const CACHE_LOOKUP_BYPASS: i32 = 2;
const CACHE_LOOKUP_DENY: i32 = 3;
const CACHE_STORE_CONTINUE: i32 = 0;
const CACHE_STORE_SKIP: i32 = 1;
const CACHE_STORE_DENY: i32 = 2;

#[derive(Clone, Debug)]
pub(crate) struct NativeWasmHookRegistry {
    attachments: Vec<NativeWasmAttachment>,
    admission: FluxWasmAdmissionController,
    preview_admission: FluxWasmAdmissionController,
    cache_admission: FluxWasmAdmissionController,
    cache_vhost_admissions: HashMap<String, FluxWasmAdmissionController>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NativeWasmHooks {
    access_decision: Vec<NativeWasmHook>,
    request_headers: Vec<NativeWasmHook>,
    response_headers: Vec<NativeWasmHook>,
    route_decision: Vec<NativeWasmHook>,
    cache_lookup: Vec<NativeWasmHook>,
    cache_store: Vec<NativeWasmHook>,
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
    host_call_namespace: WasmHostCallNamespace,
    admission: FluxWasmAdmissionController,
}

#[derive(Clone, Debug)]
struct NativeWasmHook {
    plugin: Arc<NativeWasmPlugin>,
    phase: WasmPluginPhase,
    global_admission: FluxWasmAdmissionController,
    global_admission_scope: NativeWasmAdmissionScope,
    vhost_admission: Option<FluxWasmAdmissionController>,
    attachment_admission: FluxWasmAdmissionController,
}

#[derive(Debug)]
pub(crate) enum NativeWasmAccessOutcome {
    Allow,
    Deny { status: u16, reason: String },
}

#[derive(Debug)]
pub(crate) enum NativeWasmRouteOutcome {
    Continue,
    Select { route_name: &'static str },
    Deny { status: u16, reason: String },
}

#[derive(Debug)]
pub(crate) enum NativeWasmCacheLookupOutcome {
    Continue,
    Pass(&'static str),
    Bypass(&'static str),
    Deny { status: u16, reason: String },
}

#[derive(Debug)]
pub(crate) struct NativeWasmCacheLookupDecision {
    pub(crate) outcome: NativeWasmCacheLookupOutcome,
    pub(crate) key_components: Vec<NativeProxyCacheKeyComponent>,
}

#[derive(Debug)]
pub(crate) enum NativeWasmCacheStoreOutcome {
    Continue,
    Skip(&'static str),
    Deny { status: u16, reason: String },
}

#[derive(Debug)]
pub(crate) struct NativeWasmCacheStoreDecision {
    pub(crate) outcome: NativeWasmCacheStoreOutcome,
    pub(crate) metadata: NativeProxyCacheStoreMetadata,
}

#[derive(Debug)]
pub(crate) enum NativeWasmHookError {
    Admission(NativeWasmAdmissionScope),
    Execution(WasmExecutionError),
    Join,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeWasmAdmissionScope {
    BlockingWork,
    Global,
    PreviewGlobal,
    CacheGlobal,
    CacheVhost,
    Plugin,
    Attachment,
}

impl PartialEq for NativeWasmHooks {
    fn eq(&self, other: &Self) -> bool {
        self.access_decision == other.access_decision
            && self.request_headers == other.request_headers
            && self.response_headers == other.response_headers
            && self.route_decision == other.route_decision
            && self.cache_lookup == other.cache_lookup
            && self.cache_store == other.cache_store
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
        let preview_admission = FluxWasmAdmissionController::new(
            usize::try_from(config.wasm.max_total_preview_concurrent_executions)
                .map_err(|_| NativeWasmRegistryError::AdmissionLimit)?,
        )
        .map_err(|_| NativeWasmRegistryError::AdmissionLimit)?;
        let cache_total_concurrent =
            usize::try_from(config.wasm.max_total_cache_concurrent_executions)
                .map_err(|_| NativeWasmRegistryError::AdmissionLimit)?;
        let cache_admission = FluxWasmAdmissionController::new(cache_total_concurrent)
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
            let cache_identity = FluxWasmCompiledModuleIdentity::for_loaded_plugin(
                &loaded,
                native_wasm_module_feature_set(loaded.manifest()),
            );
            let module = runtime
                .compile_plugin_module_with_identity(loaded.file(), cache_identity)
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
                    host_call_namespace: loaded.manifest().host_call_namespace(),
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

        let cache_vhosts = attachments
            .iter()
            .filter(|attachment| attachment_has_cache_phase(&attachment.phases))
            .map(|attachment| attachment.vhost.clone())
            .collect::<HashSet<_>>();
        let cache_vhost_limit =
            cache_vhost_admission_limit(cache_total_concurrent, cache_vhosts.len());
        let mut cache_vhost_admissions = HashMap::with_capacity(cache_vhosts.len());
        for vhost in cache_vhosts {
            cache_vhost_admissions.insert(
                vhost,
                FluxWasmAdmissionController::new(cache_vhost_limit)
                    .map_err(|_| NativeWasmRegistryError::AdmissionLimit)?,
            );
        }

        Ok(Some(Self {
            attachments,
            admission,
            preview_admission,
            cache_admission,
            cache_vhost_admissions,
        }))
    }

    pub(crate) fn hooks_for(&self, vhost: &str, route: Option<&str>) -> NativeWasmHooks {
        let access_decision = self
            .attachments
            .iter()
            .filter(|attachment| attachment.matches(vhost, route))
            .filter(|attachment| attachment.phases.contains(&WasmPluginPhase::AccessDecision))
            .map(|attachment| {
                let (global_admission, global_admission_scope) =
                    self.access_admission(attachment.plugin.host_call_namespace);
                NativeWasmHook {
                    plugin: attachment.plugin.clone(),
                    phase: WasmPluginPhase::AccessDecision,
                    global_admission,
                    global_admission_scope,
                    vhost_admission: None,
                    attachment_admission: attachment.admission.clone(),
                }
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
                global_admission_scope: NativeWasmAdmissionScope::Global,
                vhost_admission: None,
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
                global_admission_scope: NativeWasmAdmissionScope::Global,
                vhost_admission: None,
                attachment_admission: attachment.admission.clone(),
            })
            .collect();
        let route_decision = self
            .attachments
            .iter()
            .filter(|attachment| attachment.matches(vhost, route))
            .filter(|attachment| attachment.phases.contains(&WasmPluginPhase::RouteDecision))
            .map(|attachment| NativeWasmHook {
                plugin: attachment.plugin.clone(),
                phase: WasmPluginPhase::RouteDecision,
                global_admission: self.admission.clone(),
                global_admission_scope: NativeWasmAdmissionScope::Global,
                vhost_admission: None,
                attachment_admission: attachment.admission.clone(),
            })
            .collect();
        let cache_lookup = self
            .attachments
            .iter()
            .filter(|attachment| attachment.matches(vhost, route))
            .filter(|attachment| attachment.phases.contains(&WasmPluginPhase::CacheLookup))
            .map(|attachment| NativeWasmHook {
                plugin: attachment.plugin.clone(),
                phase: WasmPluginPhase::CacheLookup,
                global_admission: self.cache_admission.clone(),
                global_admission_scope: NativeWasmAdmissionScope::CacheGlobal,
                vhost_admission: self.cache_vhost_admissions.get(&attachment.vhost).cloned(),
                attachment_admission: attachment.admission.clone(),
            })
            .collect();
        let cache_store = self
            .attachments
            .iter()
            .filter(|attachment| attachment.matches(vhost, route))
            .filter(|attachment| attachment.phases.contains(&WasmPluginPhase::CacheStore))
            .map(|attachment| NativeWasmHook {
                plugin: attachment.plugin.clone(),
                phase: WasmPluginPhase::CacheStore,
                global_admission: self.cache_admission.clone(),
                global_admission_scope: NativeWasmAdmissionScope::CacheGlobal,
                vhost_admission: self.cache_vhost_admissions.get(&attachment.vhost).cloned(),
                attachment_admission: attachment.admission.clone(),
            })
            .collect();
        NativeWasmHooks {
            access_decision,
            request_headers,
            response_headers,
            route_decision,
            cache_lookup,
            cache_store,
        }
    }

    fn access_admission(
        &self,
        namespace: WasmHostCallNamespace,
    ) -> (FluxWasmAdmissionController, NativeWasmAdmissionScope) {
        match namespace {
            WasmHostCallNamespace::FluxheimPolicyV1 => {
                (self.admission.clone(), NativeWasmAdmissionScope::Global)
            }
            WasmHostCallNamespace::ProxyWasmPreview | WasmHostCallNamespace::WasiPreview => (
                self.preview_admission.clone(),
                NativeWasmAdmissionScope::PreviewGlobal,
            ),
        }
    }
}

fn native_wasm_module_feature_set(manifest: &ValidatedWasmPluginManifest) -> String {
    let mut phases = manifest
        .phases()
        .iter()
        .map(wasm_phase_name)
        .collect::<Vec<_>>();
    phases.sort_unstable();
    format!(
        "native-http1:{}:{}",
        wasm_host_call_namespace_name(manifest.host_call_namespace()),
        phases.join("+")
    )
}

fn wasm_host_call_namespace_name(namespace: WasmHostCallNamespace) -> &'static str {
    match namespace {
        WasmHostCallNamespace::FluxheimPolicyV1 => "fluxheim-policy-v1",
        WasmHostCallNamespace::ProxyWasmPreview => "proxy-wasm-preview",
        WasmHostCallNamespace::WasiPreview => "wasi-preview",
    }
}

fn wasm_phase_name(phase: &fluxheim_wasm::WasmPluginPhase) -> &'static str {
    match phase {
        fluxheim_wasm::WasmPluginPhase::RequestHeaders => REQUEST_HEADERS_PHASE,
        fluxheim_wasm::WasmPluginPhase::ResponseHeaders => RESPONSE_HEADERS_PHASE,
        fluxheim_wasm::WasmPluginPhase::AccessDecision => ACCESS_DECISION_PHASE,
        fluxheim_wasm::WasmPluginPhase::RouteDecision => ROUTE_DECISION_PHASE,
        fluxheim_wasm::WasmPluginPhase::CacheLookup => CACHE_LOOKUP_PHASE,
        fluxheim_wasm::WasmPluginPhase::CacheStore => CACHE_STORE_PHASE,
    }
}

fn with_namespace_host_functions(
    mut namespace_functions: Vec<WasmI32HostFunction>,
    host_functions: Vec<WasmI32HostFunction>,
) -> Vec<WasmI32HostFunction> {
    namespace_functions.extend(host_functions);
    namespace_functions
}

fn scoped_phase_host_functions(
    namespace: WasmHostCallNamespace,
    namespace_functions: Vec<WasmI32HostFunction>,
    phase_functions: Vec<WasmI32HostFunction>,
) -> Vec<WasmI32HostFunction> {
    match namespace {
        WasmHostCallNamespace::FluxheimPolicyV1 => {
            with_namespace_host_functions(namespace_functions, phase_functions)
        }
        WasmHostCallNamespace::ProxyWasmPreview | WasmHostCallNamespace::WasiPreview => {
            namespace_functions
        }
    }
}

fn wasm_host_call_namespace_functions(
    namespace: WasmHostCallNamespace,
) -> Vec<WasmI32HostFunction> {
    match namespace {
        WasmHostCallNamespace::FluxheimPolicyV1 => Vec::new(),
        WasmHostCallNamespace::ProxyWasmPreview => wasm_proxy_preview_host_functions(),
        WasmHostCallNamespace::WasiPreview => Vec::new(),
    }
}

#[cfg(feature = "wasm-proxy-abi")]
fn wasm_proxy_preview_host_functions() -> Vec<WasmI32HostFunction> {
    vec![WasmI32HostFunction::new_i32x3(
        PROXY_WASM_HOST_MODULE,
        "proxy_log",
        |_level, _message_data, _message_size| {
            Err("unsupported proxy-wasm preview host call: env.proxy_log".to_owned())
        },
    )]
}

#[cfg(not(feature = "wasm-proxy-abi"))]
fn wasm_proxy_preview_host_functions() -> Vec<WasmI32HostFunction> {
    Vec::new()
}

impl NativeWasmHooks {
    pub(crate) fn is_empty(&self) -> bool {
        self.access_decision.is_empty()
            && self.request_headers.is_empty()
            && self.response_headers.is_empty()
            && self.route_decision.is_empty()
            && self.cache_lookup.is_empty()
            && self.cache_store.is_empty()
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

    pub(crate) async fn route_decision(
        &self,
        context: NativeWasmRouteContext,
    ) -> NativeWasmRouteOutcome {
        if self.route_decision.is_empty() {
            return NativeWasmRouteOutcome::Continue;
        }
        let mut selected_route = None;
        for hook in &self.route_decision {
            match hook.run_route_decision(context).await {
                NativeWasmRouteOutcome::Continue => {}
                NativeWasmRouteOutcome::Select { route_name } => {
                    selected_route.get_or_insert(route_name);
                }
                NativeWasmRouteOutcome::Deny { status, reason } => {
                    return NativeWasmRouteOutcome::Deny { status, reason };
                }
            }
        }
        selected_route
            .map(|route_name| NativeWasmRouteOutcome::Select { route_name })
            .unwrap_or(NativeWasmRouteOutcome::Continue)
    }

    pub(crate) fn has_route_decision(&self) -> bool {
        !self.route_decision.is_empty()
    }

    pub(crate) async fn cache_lookup_decision(
        &self,
        context: NativeWasmCacheLookupContext,
    ) -> NativeWasmCacheLookupDecision {
        if self.cache_lookup.is_empty() {
            return NativeWasmCacheLookupDecision {
                outcome: NativeWasmCacheLookupOutcome::Continue,
                key_components: Vec::new(),
            };
        }
        let mut selected = NativeWasmCacheLookupOutcome::Continue;
        let mut key_components = Vec::new();
        for hook in &self.cache_lookup {
            let decision = hook.run_cache_lookup(context).await;
            if let Err(reason) =
                merge_wasm_cache_key_components(&mut key_components, decision.key_components)
            {
                return NativeWasmCacheLookupDecision {
                    outcome: NativeWasmCacheLookupOutcome::Deny {
                        status: 503,
                        reason,
                    },
                    key_components: Vec::new(),
                };
            }
            match decision.outcome {
                NativeWasmCacheLookupOutcome::Continue => {}
                NativeWasmCacheLookupOutcome::Pass(reason) => {
                    if matches!(selected, NativeWasmCacheLookupOutcome::Continue) {
                        selected = NativeWasmCacheLookupOutcome::Pass(reason);
                    }
                }
                NativeWasmCacheLookupOutcome::Bypass(reason) => {
                    if matches!(selected, NativeWasmCacheLookupOutcome::Continue) {
                        selected = NativeWasmCacheLookupOutcome::Bypass(reason);
                    }
                }
                NativeWasmCacheLookupOutcome::Deny { status, reason } => {
                    return NativeWasmCacheLookupDecision {
                        outcome: NativeWasmCacheLookupOutcome::Deny { status, reason },
                        key_components: Vec::new(),
                    };
                }
            }
        }
        NativeWasmCacheLookupDecision {
            outcome: selected,
            key_components,
        }
    }

    pub(crate) async fn cache_store_decision(
        &self,
        context: NativeWasmCacheStoreContext,
    ) -> NativeWasmCacheStoreDecision {
        if self.cache_store.is_empty() {
            return NativeWasmCacheStoreDecision {
                outcome: NativeWasmCacheStoreOutcome::Continue,
                metadata: NativeProxyCacheStoreMetadata::default(),
            };
        }
        let mut selected = NativeWasmCacheStoreOutcome::Continue;
        let mut selected_metadata = NativeProxyCacheStoreMetadata::default();
        for hook in &self.cache_store {
            let decision = hook.run_cache_store(context).await;
            match decision.outcome {
                NativeWasmCacheStoreOutcome::Continue => {
                    merge_wasm_cache_store_metadata(&mut selected_metadata, decision.metadata);
                }
                NativeWasmCacheStoreOutcome::Skip(reason) => {
                    if matches!(selected, NativeWasmCacheStoreOutcome::Continue) {
                        selected = NativeWasmCacheStoreOutcome::Skip(reason);
                    }
                }
                NativeWasmCacheStoreOutcome::Deny { status, reason } => {
                    return NativeWasmCacheStoreDecision {
                        outcome: NativeWasmCacheStoreOutcome::Deny { status, reason },
                        metadata: NativeProxyCacheStoreMetadata::default(),
                    };
                }
            }
        }
        NativeWasmCacheStoreDecision {
            outcome: selected,
            metadata: selected_metadata,
        }
    }

    pub(crate) async fn apply_request_headers(
        &self,
        request: &mut NativeHttp1Request,
        context: NativeWasmHeaderContext,
    ) -> Result<(), NativeWasmHeaderError> {
        if self.request_headers.is_empty() {
            return Ok(());
        }
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
    context: NativeWasmHeaderContext,
) -> Option<NativeHttp1Response> {
    match hooks.apply_request_headers(request, context).await {
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
        self.run_i32_with_hosts(
            phase_label,
            function,
            self.host_call_namespace_functions(),
            wasm_default_outcome_label,
        )
        .await
    }

    async fn run_i32_with_hosts(
        &self,
        phase_label: &'static str,
        function: &'static str,
        host_functions: Vec<WasmI32HostFunction>,
        outcome_label: fn(i32) -> &'static str,
    ) -> Result<i32, NativeWasmHookError> {
        let plugin = self.plugin.clone();
        let global_admission = self.global_admission.clone();
        let global_admission_scope = self.global_admission_scope;
        let vhost_admission = self.vhost_admission.clone();
        let attachment_admission = self.attachment_admission.clone();
        let started = Instant::now();
        let plugin_name = plugin.name.clone();
        let blocking_work_class = match plugin.host_call_namespace {
            WasmHostCallNamespace::FluxheimPolicyV1 => {
                crate::blocking_work::NativeBlockingWorkClass::Wasm
            }
            WasmHostCallNamespace::ProxyWasmPreview | WasmHostCallNamespace::WasiPreview => {
                crate::blocking_work::NativeBlockingWorkClass::WasmPreview
            }
        };
        // Acquire the narrowest budgets first so a saturated plugin or attachment cannot
        // reserve process-wide capacity while it waits for its own policy limit.
        let permits = async {
            let attachment = attachment_admission.acquire().await.map_err(|_| {
                NativeWasmHookError::Admission(NativeWasmAdmissionScope::Attachment)
            })?;
            let plugin_permit =
                plugin.admission.acquire().await.map_err(|_| {
                    NativeWasmHookError::Admission(NativeWasmAdmissionScope::Plugin)
                })?;
            let vhost = match vhost_admission {
                Some(admission) => Some(admission.acquire().await.map_err(|_| {
                    NativeWasmHookError::Admission(NativeWasmAdmissionScope::CacheVhost)
                })?),
                None => None,
            };
            let global = global_admission
                .acquire()
                .await
                .map_err(|_| NativeWasmHookError::Admission(global_admission_scope))?;
            let blocking =
                crate::blocking_work::try_acquire_request_blocking_work(blocking_work_class)
                    .map_err(|_| {
                        NativeWasmHookError::Admission(NativeWasmAdmissionScope::BlockingWork)
                    })?;
            Ok::<_, NativeWasmHookError>((attachment, plugin_permit, vhost, global, blocking))
        }
        .await;
        let permits = match permits {
            Ok(permits) => permits,
            Err(error) => {
                record_native_wasm_admission_rejection(
                    &plugin_name,
                    phase_label,
                    match error {
                        NativeWasmHookError::Admission(scope) => scope.as_label(),
                        NativeWasmHookError::Execution(_) | NativeWasmHookError::Join => "global",
                    },
                );
                record_native_wasm_execution(
                    &plugin_name,
                    phase_label,
                    "fail_closed",
                    started.elapsed(),
                );
                return Err(error);
            }
        };
        let result = tokio::task::spawn_blocking(move || {
            let _permits = permits;
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
            Ok(value) => record_native_wasm_execution(
                &plugin_name,
                phase_label,
                outcome_label(*value),
                started.elapsed(),
            ),
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

    fn host_call_namespace_functions(&self) -> Vec<WasmI32HostFunction> {
        wasm_host_call_namespace_functions(self.plugin.host_call_namespace)
    }

    fn phase_host_functions(
        &self,
        phase_functions: Vec<WasmI32HostFunction>,
    ) -> Vec<WasmI32HostFunction> {
        scoped_phase_host_functions(
            self.plugin.host_call_namespace,
            self.host_call_namespace_functions(),
            phase_functions,
        )
    }

    async fn run_header_mutations(
        &self,
        phase_label: &'static str,
        function: &'static str,
        context: NativeWasmHeaderContext,
        phase: NativeWasmHeaderPhase,
    ) -> Result<NativeWasmHeaderMutations, NativeWasmHeaderError> {
        let state = Arc::new(Mutex::new(NativeWasmHeaderMutations::default()));
        let host_functions = self.phase_host_functions(wasm_header_host_functions(
            context,
            phase,
            Arc::clone(&state),
        ));
        match self
            .run_i32_with_hosts(
                phase_label,
                function,
                host_functions,
                wasm_header_outcome_label,
            )
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

    async fn run_route_decision(&self, context: NativeWasmRouteContext) -> NativeWasmRouteOutcome {
        let host_functions = self.phase_host_functions(wasm_route_host_functions(context));
        match self
            .run_i32_with_hosts(
                ROUTE_DECISION_PHASE,
                ROUTE_DECISION_FUNCTION,
                host_functions,
                wasm_route_outcome_label,
            )
            .await
        {
            Ok(ROUTE_DECISION_CONTINUE) => NativeWasmRouteOutcome::Continue,
            Ok(ROUTE_DECISION_CANARY) => NativeWasmRouteOutcome::Select {
                route_name: "canary",
            },
            Ok(ROUTE_DECISION_DENY) => NativeWasmRouteOutcome::Deny {
                status: 403,
                reason: "wasm route decision denied".to_owned(),
            },
            Ok(ROUTE_DECISION_MIRROR) => NativeWasmRouteOutcome::Select {
                route_name: "mirror",
            },
            Ok(_) => self.failed_route_decision("error"),
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
                self.failed_route_decision(outcome)
            }
        }
    }

    async fn run_cache_lookup(
        &self,
        context: NativeWasmCacheLookupContext,
    ) -> NativeWasmCacheLookupDecision {
        let key_components = Arc::new(Mutex::new(Vec::new()));
        let host_functions = self.phase_host_functions(wasm_cache_lookup_host_functions(
            context,
            Arc::clone(&key_components),
        ));
        match self
            .run_i32_with_hosts(
                CACHE_LOOKUP_PHASE,
                CACHE_LOOKUP_FUNCTION,
                host_functions,
                wasm_cache_lookup_outcome_label,
            )
            .await
        {
            Ok(CACHE_LOOKUP_CONTINUE) => NativeWasmCacheLookupDecision {
                outcome: NativeWasmCacheLookupOutcome::Continue,
                key_components: locked_wasm_cache_key_components(&key_components),
            },
            Ok(CACHE_LOOKUP_PASS) => NativeWasmCacheLookupDecision {
                outcome: NativeWasmCacheLookupOutcome::Pass("wasm-pass"),
                key_components: Vec::new(),
            },
            Ok(CACHE_LOOKUP_BYPASS) => NativeWasmCacheLookupDecision {
                outcome: NativeWasmCacheLookupOutcome::Bypass("wasm-bypass"),
                key_components: Vec::new(),
            },
            Ok(CACHE_LOOKUP_DENY) => NativeWasmCacheLookupDecision {
                outcome: NativeWasmCacheLookupOutcome::Deny {
                    status: 403,
                    reason: "wasm cache lookup denied".to_owned(),
                },
                key_components: Vec::new(),
            },
            Ok(_) => self.failed_cache_lookup("error"),
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
                self.failed_cache_lookup(outcome)
            }
        }
    }

    async fn run_cache_store(
        &self,
        context: NativeWasmCacheStoreContext,
    ) -> NativeWasmCacheStoreDecision {
        let metadata = Arc::new(Mutex::new(NativeProxyCacheStoreMetadata::default()));
        let host_functions = self.phase_host_functions(wasm_cache_store_host_functions(
            context,
            Arc::clone(&metadata),
        ));
        match self
            .run_i32_with_hosts(
                CACHE_STORE_PHASE,
                CACHE_STORE_FUNCTION,
                host_functions,
                wasm_cache_store_outcome_label,
            )
            .await
        {
            Ok(CACHE_STORE_CONTINUE) => NativeWasmCacheStoreDecision {
                outcome: NativeWasmCacheStoreOutcome::Continue,
                metadata: locked_wasm_cache_store_metadata(&metadata),
            },
            Ok(CACHE_STORE_SKIP) => NativeWasmCacheStoreDecision {
                outcome: NativeWasmCacheStoreOutcome::Skip("wasm-store-skip"),
                metadata: NativeProxyCacheStoreMetadata::default(),
            },
            Ok(CACHE_STORE_DENY) => NativeWasmCacheStoreDecision {
                outcome: NativeWasmCacheStoreOutcome::Deny {
                    status: 403,
                    reason: "wasm cache store denied".to_owned(),
                },
                metadata: NativeProxyCacheStoreMetadata::default(),
            },
            Ok(_) => self.failed_cache_store("error"),
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
                self.failed_cache_store(outcome)
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

    fn failed_route_decision(&self, outcome: &'static str) -> NativeWasmRouteOutcome {
        match self.plugin.fail_mode {
            WasmPluginFailMode::FailOpen => NativeWasmRouteOutcome::Continue,
            WasmPluginFailMode::FailClosed => NativeWasmRouteOutcome::Deny {
                status: 503,
                reason: format!("wasm route decision {outcome}"),
            },
        }
    }

    fn failed_cache_lookup(&self, outcome: &'static str) -> NativeWasmCacheLookupDecision {
        let outcome = match self.plugin.fail_mode {
            WasmPluginFailMode::FailOpen => NativeWasmCacheLookupOutcome::Continue,
            WasmPluginFailMode::FailClosed => NativeWasmCacheLookupOutcome::Deny {
                status: 503,
                reason: format!("wasm cache lookup {outcome}"),
            },
        };
        NativeWasmCacheLookupDecision {
            outcome,
            key_components: Vec::new(),
        }
    }

    fn failed_cache_store(&self, outcome: &'static str) -> NativeWasmCacheStoreDecision {
        let outcome = match self.plugin.fail_mode {
            WasmPluginFailMode::FailOpen => NativeWasmCacheStoreOutcome::Continue,
            WasmPluginFailMode::FailClosed => NativeWasmCacheStoreOutcome::Deny {
                status: 503,
                reason: format!("wasm cache store {outcome}"),
            },
        };
        NativeWasmCacheStoreDecision {
            outcome,
            metadata: NativeProxyCacheStoreMetadata::default(),
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
pub(crate) struct NativeWasmRouteContext {
    path_class: i32,
    canary_header: i32,
    mirror_header: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeWasmCacheLookupContext {
    path_class: i32,
    device_class_header: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeWasmCacheStoreContext {
    path_class: i32,
    response_status: i32,
    response_content_type_class: i32,
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
    pub(crate) fn from_path(path: &str) -> Self {
        Self {
            path_class: wasm_path_class(path),
        }
    }

    pub(crate) fn from_request(request: &NativeHttp1Request) -> Self {
        let path_class = request_path_and_query(request)
            .map(|(path, _)| wasm_path_class(&path))
            .unwrap_or(PATH_CLASS_OTHER);
        Self { path_class }
    }
}

impl NativeWasmRouteContext {
    pub(crate) fn from_request_path(request: &NativeHttp1Request, path: &str) -> Self {
        let canary_header = i32::from(request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("x-canary") && value.trim().eq_ignore_ascii_case("1")
        }));
        let mirror_header = i32::from(request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("x-mirror") && value.trim().eq_ignore_ascii_case("1")
        }));
        Self {
            path_class: wasm_path_class(path),
            canary_header,
            mirror_header,
        }
    }
}

impl NativeWasmCacheLookupContext {
    pub(crate) fn from_request(request: &NativeHttp1Request) -> Self {
        let path_class = request_path_and_query(request)
            .map(|(path, _)| wasm_path_class(&path))
            .unwrap_or(PATH_CLASS_OTHER);
        let device_class_header = wasm_device_class_header(request);
        Self {
            path_class,
            device_class_header,
        }
    }
}

impl NativeWasmCacheStoreContext {
    pub(crate) fn from_request_response(
        request: &NativeHttp1Request,
        response: &NativeHttp1Response,
    ) -> Self {
        let path_class = request_path_and_query(request)
            .map(|(path, _)| wasm_path_class(&path))
            .unwrap_or(PATH_CLASS_OTHER);
        Self {
            path_class,
            response_status: i32::from(response.status()),
            response_content_type_class: wasm_response_content_type_class(response),
        }
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

fn wasm_route_host_functions(context: NativeWasmRouteContext) -> Vec<WasmI32HostFunction> {
    vec![WasmI32HostFunction::new(
        WASM_HOST_MODULE,
        "context",
        move |kind, _unused| match kind {
            HOST_CONTEXT_PATH_CLASS => Ok(context.path_class),
            HOST_CONTEXT_CANARY_HEADER => Ok(context.canary_header),
            HOST_CONTEXT_MIRROR_HEADER => Ok(context.mirror_header),
            _ => Err("unknown wasm context field".to_owned()),
        },
    )]
}

fn wasm_cache_lookup_host_functions(
    context: NativeWasmCacheLookupContext,
    state: Arc<Mutex<Vec<NativeProxyCacheKeyComponent>>>,
) -> Vec<WasmI32HostFunction> {
    let context_function = WasmI32HostFunction::new(
        WASM_HOST_MODULE,
        "context",
        move |kind, _unused| match kind {
            HOST_CONTEXT_PATH_CLASS => Ok(context.path_class),
            HOST_CONTEXT_DEVICE_CLASS_HEADER => Ok(context.device_class_header),
            _ => Err("unknown wasm context field".to_owned()),
        },
    );
    let set_key_component_function = WasmI32HostFunction::new(
        WASM_HOST_MODULE,
        "set_cache_key_component",
        move |label_id, value_id| {
            let component = wasm_cache_key_component(label_id, value_id)?;
            let mut state = state
                .lock()
                .map_err(|_| "wasm cache key component lock poisoned".to_owned())?;
            if state.len() >= MAX_WASM_CACHE_KEY_COMPONENTS {
                return Err("wasm cache key component limit reached".to_owned());
            }
            if state
                .iter()
                .any(|existing| existing.label == component.label)
            {
                return Err("duplicate wasm cache key component".to_owned());
            }
            state.push(component);
            Ok(0)
        },
    );
    vec![context_function, set_key_component_function]
}

fn wasm_cache_store_host_functions(
    context: NativeWasmCacheStoreContext,
    state: Arc<Mutex<NativeProxyCacheStoreMetadata>>,
) -> Vec<WasmI32HostFunction> {
    let context_function = WasmI32HostFunction::new(
        WASM_HOST_MODULE,
        "context",
        move |kind, _unused| match kind {
            HOST_CONTEXT_PATH_CLASS => Ok(context.path_class),
            HOST_CONTEXT_RESPONSE_STATUS => Ok(context.response_status),
            HOST_CONTEXT_RESPONSE_CONTENT_TYPE_CLASS => Ok(context.response_content_type_class),
            _ => Err("unknown wasm context field".to_owned()),
        },
    );
    let ttl_state = Arc::clone(&state);
    let set_ttl_function =
        WasmI32HostFunction::new(WASM_HOST_MODULE, "set_cache_ttl", move |ttl_id, _unused| {
            let ttl = wasm_cache_ttl(ttl_id)?;
            let mut state = ttl_state
                .lock()
                .map_err(|_| "wasm cache store metadata lock poisoned".to_owned())?;
            if state.ttl_override.is_some() {
                return Err("duplicate wasm cache ttl override".to_owned());
            }
            state.ttl_override = Some(ttl);
            Ok(0)
        });
    let tag_state = Arc::clone(&state);
    let add_tag_function =
        WasmI32HostFunction::new(WASM_HOST_MODULE, "add_cache_tag", move |tag_id, _unused| {
            let tag = wasm_cache_tag(tag_id)?;
            let mut state = tag_state
                .lock()
                .map_err(|_| "wasm cache store metadata lock poisoned".to_owned())?;
            if state.cache_tags.len() >= MAX_WASM_CACHE_TAGS {
                return Err("wasm cache tag limit reached".to_owned());
            }
            if !state.cache_tags.contains(&tag) {
                state.cache_tags.push(tag);
            }
            Ok(0)
        });
    let header_state = Arc::clone(&state);
    let set_store_header_function = WasmI32HostFunction::new(
        WASM_HOST_MODULE,
        "set_cache_store_header",
        move |name_id, value_id| {
            let header = wasm_cache_store_header(name_id, value_id)?;
            let mut state = header_state
                .lock()
                .map_err(|_| "wasm cache store metadata lock poisoned".to_owned())?;
            if state.response_headers.len() >= MAX_WASM_CACHE_STORE_HEADER_MUTATIONS {
                return Err("wasm cache store header mutation limit reached".to_owned());
            }
            if state
                .response_headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(header.0))
            {
                return Err("duplicate wasm cache store header mutation".to_owned());
            }
            state.response_headers.push(header);
            Ok(0)
        },
    );
    vec![
        context_function,
        set_ttl_function,
        add_tag_function,
        set_store_header_function,
    ]
}

fn wasm_default_outcome_label(value: i32) -> &'static str {
    match value {
        0 => "continue",
        1 => "allow",
        2 => "deny",
        _ => "error",
    }
}

fn wasm_header_outcome_label(value: i32) -> &'static str {
    match value {
        0 => "continue",
        _ => "error",
    }
}

fn wasm_route_outcome_label(value: i32) -> &'static str {
    match value {
        ROUTE_DECISION_CONTINUE => "continue",
        ROUTE_DECISION_CANARY => "select",
        ROUTE_DECISION_DENY => "deny",
        ROUTE_DECISION_MIRROR => "select",
        _ => "error",
    }
}

fn wasm_cache_lookup_outcome_label(value: i32) -> &'static str {
    match value {
        CACHE_LOOKUP_CONTINUE => "continue",
        CACHE_LOOKUP_PASS => "pass",
        CACHE_LOOKUP_BYPASS => "bypass",
        CACHE_LOOKUP_DENY => "deny",
        _ => "error",
    }
}

fn wasm_cache_store_outcome_label(value: i32) -> &'static str {
    match value {
        CACHE_STORE_CONTINUE => "continue",
        CACHE_STORE_SKIP => "skip",
        CACHE_STORE_DENY => "deny",
        _ => "error",
    }
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

fn wasm_cache_key_component(
    label_id: i32,
    value_id: i32,
) -> Result<NativeProxyCacheKeyComponent, String> {
    match (label_id, value_id) {
        (CACHE_KEY_DEVICE_CLASS, VALUE_MOBILE) => Ok(NativeProxyCacheKeyComponent {
            label: "wasm-device-class",
            value: "mobile",
        }),
        (CACHE_KEY_DEVICE_CLASS, VALUE_DESKTOP) => Ok(NativeProxyCacheKeyComponent {
            label: "wasm-device-class",
            value: "desktop",
        }),
        _ => Err("forbidden wasm cache key component".to_owned()),
    }
}

fn wasm_device_class_header(request: &NativeHttp1Request) -> i32 {
    request
        .headers
        .iter()
        .find_map(|(name, value)| {
            if !name.eq_ignore_ascii_case("x-device-class") {
                return None;
            }
            match value.trim().to_ascii_lowercase().as_str() {
                "mobile" => Some(VALUE_MOBILE),
                "desktop" => Some(VALUE_DESKTOP),
                _ => Some(0),
            }
        })
        .unwrap_or(0)
}

fn wasm_response_content_type_class(response: &NativeHttp1Response) -> i32 {
    let Some((_, value)) = response
        .headers()
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
    else {
        return 0;
    };
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media_type.starts_with("image/") {
        VALUE_CONTENT_TYPE_IMAGE
    } else if media_type == "text/html" || media_type == "application/xhtml+xml" {
        VALUE_CONTENT_TYPE_HTML
    } else if media_type == "application/json" || media_type.ends_with("+json") {
        VALUE_CONTENT_TYPE_JSON
    } else if media_type.starts_with("text/") {
        VALUE_CONTENT_TYPE_TEXT
    } else {
        0
    }
}

fn locked_wasm_cache_key_components(
    state: &Arc<Mutex<Vec<NativeProxyCacheKeyComponent>>>,
) -> Vec<NativeProxyCacheKeyComponent> {
    match state.lock() {
        Ok(components) => components.clone(),
        Err(error) => {
            log::error!(
                target: "fluxheim::security",
                "wasm cache key component lock poisoned: {error}"
            );
            std::process::abort();
        }
    }
}

fn merge_wasm_cache_key_components(
    target: &mut Vec<NativeProxyCacheKeyComponent>,
    source: Vec<NativeProxyCacheKeyComponent>,
) -> Result<(), String> {
    for component in source {
        if target.len() >= MAX_WASM_CACHE_KEY_COMPONENTS {
            return Err("wasm cache key component limit reached".to_owned());
        }
        if target
            .iter()
            .any(|existing| existing.label == component.label)
        {
            return Err("duplicate wasm cache key component".to_owned());
        }
        target.push(component);
    }
    Ok(())
}

fn wasm_cache_ttl(ttl_id: i32) -> Result<Duration, String> {
    match ttl_id {
        CACHE_TTL_SHORT => Ok(Duration::from_secs(1)),
        CACHE_TTL_MEDIUM => Ok(Duration::from_secs(300)),
        _ => Err("forbidden wasm cache ttl override".to_owned()),
    }
}

fn wasm_cache_tag(tag_id: i32) -> Result<&'static str, String> {
    match tag_id {
        CACHE_TAG_WASM_POLICY => Ok("wasm-policy"),
        CACHE_TAG_WASM_GOLD => Ok("wasm-gold"),
        _ => Err("forbidden wasm cache tag".to_owned()),
    }
}

fn wasm_cache_store_header(
    name_id: i32,
    value_id: i32,
) -> Result<(&'static str, &'static str), String> {
    match (name_id, value_id) {
        (CACHE_STORE_HEADER_POLICY, CACHE_STORE_HEADER_VALUE_WASM) => {
            Ok(("x-fluxheim-cache-policy", "wasm"))
        }
        (CACHE_STORE_HEADER_POLICY, CACHE_STORE_HEADER_VALUE_GOLD) => {
            Ok(("x-fluxheim-cache-policy", "gold"))
        }
        _ => Err("forbidden wasm cache store header mutation".to_owned()),
    }
}

fn locked_wasm_cache_store_metadata(
    state: &Arc<Mutex<NativeProxyCacheStoreMetadata>>,
) -> NativeProxyCacheStoreMetadata {
    match state.lock() {
        Ok(metadata) => metadata.clone(),
        Err(error) => {
            log::error!(
                target: "fluxheim::security",
                "wasm cache store metadata lock poisoned: {error}"
            );
            std::process::abort();
        }
    }
}

fn merge_wasm_cache_store_metadata(
    target: &mut NativeProxyCacheStoreMetadata,
    source: NativeProxyCacheStoreMetadata,
) {
    if target.ttl_override.is_none() {
        target.ttl_override = source.ttl_override;
    }
    for tag in source.cache_tags {
        if target.cache_tags.len() >= MAX_WASM_CACHE_TAGS {
            break;
        }
        if !target.cache_tags.contains(&tag) {
            target.cache_tags.push(tag);
        }
    }
    for header in source.response_headers {
        if target.response_headers.len() >= MAX_WASM_CACHE_STORE_HEADER_MUTATIONS {
            break;
        }
        if !target
            .response_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(header.0))
        {
            target.response_headers.push(header);
        }
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

fn attachment_has_cache_phase(phases: &[WasmPluginPhase]) -> bool {
    phases.iter().any(|phase| {
        matches!(
            phase,
            WasmPluginPhase::CacheLookup | WasmPluginPhase::CacheStore
        )
    })
}

fn cache_vhost_admission_limit(total_concurrent: usize, cache_vhost_count: usize) -> usize {
    if cache_vhost_count == 0 {
        return total_concurrent.max(1);
    }
    total_concurrent.div_ceil(cache_vhost_count).max(1)
}

fn admission_controller(
    budget: fluxheim_config::WasmAdmissionBudgetConfig,
) -> Result<FluxWasmAdmissionController, NativeWasmRegistryError> {
    FluxWasmAdmissionController::new_with_queue(
        usize::try_from(budget.max_concurrent_executions)
            .map_err(|_| NativeWasmRegistryError::AdmissionLimit)?,
        usize::try_from(budget.queue_limit).map_err(|_| NativeWasmRegistryError::AdmissionLimit)?,
    )
    .map_err(|_| NativeWasmRegistryError::AdmissionLimit)
}

impl NativeWasmAdmissionScope {
    fn as_label(self) -> &'static str {
        match self {
            Self::BlockingWork => "blocking-work",
            Self::Global => "global",
            Self::PreviewGlobal => "preview-global",
            Self::CacheGlobal => "cache-global",
            Self::CacheVhost => "cache-vhost",
            Self::Plugin => "plugin",
            Self::Attachment => "attachment",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn wasm_guest_id_decoders_are_total(first in any::<i32>(), second in any::<i32>()) {
            let _ = wasm_request_header_mutation(first, second);
            let _ = wasm_response_header_mutation(first, second);
            let _ = wasm_response_removable_header(first);
            let _ = wasm_cache_key_component(first, second);
            let _ = wasm_cache_ttl(first);
            let _ = wasm_cache_tag(first);
            let _ = wasm_cache_store_header(first, second);
        }
    }

    #[test]
    fn proxy_preview_namespace_does_not_receive_native_phase_functions() {
        let namespace_functions = vec![WasmI32HostFunction::new_i32x3(
            "env",
            "proxy_log",
            |_first, _second, _third| Ok(0),
        )];
        let phase_functions = vec![WasmI32HostFunction::new(
            WASM_HOST_MODULE,
            "context",
            |_first, _second| Ok(0),
        )];

        let scoped = scoped_phase_host_functions(
            WasmHostCallNamespace::ProxyWasmPreview,
            namespace_functions,
            phase_functions,
        );

        assert_eq!(scoped.len(), 1);
    }

    #[test]
    fn native_namespace_receives_native_phase_functions() {
        let phase_functions = vec![WasmI32HostFunction::new(
            WASM_HOST_MODULE,
            "context",
            |_first, _second| Ok(0),
        )];

        let scoped = scoped_phase_host_functions(
            WasmHostCallNamespace::FluxheimPolicyV1,
            Vec::new(),
            phase_functions,
        );

        assert_eq!(scoped.len(), 1);
    }

    #[test]
    fn preview_admission_isolated_from_native_policy_admission() {
        let registry = NativeWasmHookRegistry {
            attachments: Vec::new(),
            admission: FluxWasmAdmissionController::new(1).unwrap(),
            preview_admission: FluxWasmAdmissionController::new(1).unwrap(),
            cache_admission: FluxWasmAdmissionController::new(1).unwrap(),
            cache_vhost_admissions: HashMap::new(),
        };
        let (preview, preview_scope) =
            registry.access_admission(WasmHostCallNamespace::WasiPreview);
        let (native, native_scope) =
            registry.access_admission(WasmHostCallNamespace::FluxheimPolicyV1);
        let _preview_permit = preview.try_acquire().unwrap();

        assert_eq!(preview_scope, NativeWasmAdmissionScope::PreviewGlobal);
        assert_eq!(native_scope, NativeWasmAdmissionScope::Global);
        assert!(preview.try_acquire().is_err());
        assert!(native.try_acquire().is_ok());
    }

    #[test]
    fn cache_vhost_admission_limit_splits_global_budget() {
        assert_eq!(cache_vhost_admission_limit(8, 0), 8);
        assert_eq!(cache_vhost_admission_limit(8, 1), 8);
        assert_eq!(cache_vhost_admission_limit(8, 2), 4);
        assert_eq!(cache_vhost_admission_limit(8, 3), 3);
        assert_eq!(cache_vhost_admission_limit(1, 8), 1);
    }

    #[tokio::test]
    async fn configured_wasm_queue_limit_bounds_async_waiters() {
        let controller = admission_controller(fluxheim_config::WasmAdmissionBudgetConfig {
            max_concurrent_executions: 1,
            queue_limit: 1,
        })
        .unwrap();
        let active = controller.try_acquire().unwrap();
        let queued_controller = controller.clone();
        let queued = tokio::spawn(async move { queued_controller.acquire().await });
        while controller.queued_executions() == 0 {
            tokio::task::yield_now().await;
        }

        assert!(controller.acquire().await.is_err());
        drop(active);
        let admitted = queued.await.unwrap().unwrap();
        drop(admitted);
        assert_eq!(controller.active_executions(), 0);
        assert_eq!(controller.queued_executions(), 0);
    }

    #[test]
    fn cache_key_component_merge_rejects_aggregate_limit() {
        let mut target = vec![
            NativeProxyCacheKeyComponent {
                label: "one",
                value: "1",
            },
            NativeProxyCacheKeyComponent {
                label: "two",
                value: "2",
            },
            NativeProxyCacheKeyComponent {
                label: "three",
                value: "3",
            },
            NativeProxyCacheKeyComponent {
                label: "four",
                value: "4",
            },
        ];
        let source = vec![NativeProxyCacheKeyComponent {
            label: "five",
            value: "5",
        }];

        let error = merge_wasm_cache_key_components(&mut target, source).unwrap_err();

        assert_eq!(error, "wasm cache key component limit reached");
        assert_eq!(target.len(), MAX_WASM_CACHE_KEY_COMPONENTS);
        assert!(!target.iter().any(|component| component.label == "five"));
    }

    #[test]
    fn cache_store_metadata_merge_caps_tags_without_dropping_headers() {
        let mut target = NativeProxyCacheStoreMetadata {
            ttl_override: None,
            cache_tags: vec!["one", "two", "three", "four"],
            response_headers: Vec::new(),
        };
        let source = NativeProxyCacheStoreMetadata {
            ttl_override: Some(Duration::from_secs(1)),
            cache_tags: vec!["five"],
            response_headers: vec![("x-fluxheim-cache-policy", "wasm")],
        };

        merge_wasm_cache_store_metadata(&mut target, source);

        assert_eq!(target.ttl_override, Some(Duration::from_secs(1)));
        assert_eq!(target.cache_tags.len(), MAX_WASM_CACHE_TAGS);
        assert!(!target.cache_tags.contains(&"five"));
        assert_eq!(
            target.response_headers,
            vec![("x-fluxheim-cache-policy", "wasm")]
        );
    }

    #[test]
    fn cache_store_metadata_merge_caps_stored_headers_without_dropping_tags() {
        let mut target = NativeProxyCacheStoreMetadata {
            ttl_override: None,
            cache_tags: Vec::new(),
            response_headers: vec![
                ("x-one", "1"),
                ("x-two", "2"),
                ("x-three", "3"),
                ("x-four", "4"),
            ],
        };
        let source = NativeProxyCacheStoreMetadata {
            ttl_override: Some(Duration::from_secs(1)),
            cache_tags: vec!["wasm-policy"],
            response_headers: vec![("x-five", "5")],
        };

        merge_wasm_cache_store_metadata(&mut target, source);

        assert_eq!(target.ttl_override, Some(Duration::from_secs(1)));
        assert_eq!(target.cache_tags, vec!["wasm-policy"]);
        assert_eq!(
            target.response_headers.len(),
            MAX_WASM_CACHE_STORE_HEADER_MUTATIONS
        );
        assert!(
            !target
                .response_headers
                .iter()
                .any(|(name, _)| *name == "x-five")
        );
    }

    #[test]
    fn cache_store_metadata_merge_keeps_first_ttl_override() {
        let mut target = NativeProxyCacheStoreMetadata {
            ttl_override: Some(Duration::from_secs(1)),
            cache_tags: Vec::new(),
            response_headers: Vec::new(),
        };
        let source = NativeProxyCacheStoreMetadata {
            ttl_override: Some(Duration::from_secs(300)),
            cache_tags: vec!["wasm-policy"],
            response_headers: vec![("x-fluxheim-cache-policy", "wasm")],
        };

        merge_wasm_cache_store_metadata(&mut target, source);

        assert_eq!(target.ttl_override, Some(Duration::from_secs(1)));
        assert_eq!(target.cache_tags, vec!["wasm-policy"]);
        assert_eq!(
            target.response_headers,
            vec![("x-fluxheim-cache-policy", "wasm")]
        );
    }
}

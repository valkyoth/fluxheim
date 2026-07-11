use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
#[cfg(feature = "wasm")]
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{ByteSize, ConfigError, validate_config_list_len};

pub const MAX_WASM_PLUGIN_ROOTS: usize = 32;
pub const MAX_WASM_PLUGINS: usize = 128;
pub const MAX_WASM_ATTACHMENTS: usize = 64;
pub const MAX_WASM_PLUGIN_NAME_BYTES: usize = 64;
pub const MAX_WASM_PLUGIN_PHASES: usize = 16;
pub const MAX_WASM_MAX_CONCURRENT_EXECUTIONS: u32 = 256;
pub const MAX_WASM_MAX_TOTAL_PREVIEW_CONCURRENT_EXECUTIONS: u32 = 32;
pub const MAX_WASM_QUEUE_LIMIT: u32 = 256;
pub const MAX_WASM_ATTACHMENT_PRIORITY: u32 = 1_000_000;

const DEFAULT_WASM_MAX_MODULE_BYTES: u64 = 1_048_576;
const DEFAULT_WASM_MAX_MEMORY_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_WASM_MAX_TABLE_ELEMENTS: u32 = 10_000;
const DEFAULT_WASM_FUEL: u64 = 5_000_000;
const DEFAULT_WASM_TIMEOUT_MS: u64 = 50;
const DEFAULT_WASM_COMPILE_TIMEOUT_MS: u64 = 500;
const DEFAULT_WASM_MAX_CONCURRENT_EXECUTIONS: u32 = 64;
const DEFAULT_WASM_MAX_TOTAL_CONCURRENT_EXECUTIONS: u32 = 256;
const DEFAULT_WASM_MAX_TOTAL_PREVIEW_CONCURRENT_EXECUTIONS: u32 = 32;
const DEFAULT_WASM_MAX_TOTAL_CACHE_CONCURRENT_EXECUTIONS: u32 = 256;
const DEFAULT_WASM_QUEUE_LIMIT: u32 = 0;
const DEFAULT_WASM_ATTACHMENT_PRIORITY: u32 = 1000;
const MIN_WASM_PLUGIN_ROOT_COMPONENTS: usize = 3;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WasmConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_preview_abi: bool,
    #[serde(default)]
    pub plugin_roots: Vec<PathBuf>,
    #[serde(default)]
    pub default_limits: WasmSandboxLimitsConfig,
    #[serde(default)]
    pub default_admission: WasmAdmissionBudgetConfig,
    #[serde(default = "default_wasm_max_total_concurrent_executions")]
    pub max_total_concurrent_executions: u32,
    #[serde(default = "default_wasm_max_total_preview_concurrent_executions")]
    pub max_total_preview_concurrent_executions: u32,
    #[serde(default = "default_wasm_max_total_cache_concurrent_executions")]
    pub max_total_cache_concurrent_executions: u32,
    #[serde(default)]
    pub plugins: Vec<WasmPluginConfig>,
    #[serde(default)]
    pub attachments: Vec<WasmAttachmentConfig>,
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_preview_abi: false,
            plugin_roots: Vec::new(),
            default_limits: WasmSandboxLimitsConfig::default(),
            default_admission: WasmAdmissionBudgetConfig::default(),
            max_total_concurrent_executions: default_wasm_max_total_concurrent_executions(),
            max_total_preview_concurrent_executions:
                default_wasm_max_total_preview_concurrent_executions(),
            max_total_cache_concurrent_executions:
                default_wasm_max_total_cache_concurrent_executions(),
            plugins: Vec::new(),
            attachments: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WasmConfigFragment {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    allow_preview_abi: Option<bool>,
    #[serde(default)]
    plugin_roots: Option<Vec<PathBuf>>,
    #[serde(default)]
    default_limits: Option<WasmSandboxLimitsConfig>,
    #[serde(default)]
    default_admission: Option<WasmAdmissionBudgetConfig>,
    #[serde(default)]
    max_total_concurrent_executions: Option<u32>,
    #[serde(default)]
    max_total_preview_concurrent_executions: Option<u32>,
    #[serde(default)]
    max_total_cache_concurrent_executions: Option<u32>,
    #[serde(default)]
    plugins: Option<Vec<WasmPluginConfig>>,
    #[serde(default)]
    attachments: Option<Vec<WasmAttachmentConfig>>,
}

impl WasmConfigFragment {
    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(plugin_roots) = &mut self.plugin_roots {
            for root in plugin_roots {
                if root.is_relative() {
                    *root = base_dir.join(&root);
                }
            }
        }
        if let Some(plugins) = &mut self.plugins {
            for plugin in plugins {
                if plugin.path.is_relative() {
                    plugin.path = base_dir.join(&plugin.path);
                }
            }
        }
    }
}

impl WasmConfig {
    pub(crate) fn merge(&mut self, fragment: WasmConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(allow_preview_abi) = fragment.allow_preview_abi {
            self.allow_preview_abi = allow_preview_abi;
        }
        if let Some(plugin_roots) = fragment.plugin_roots {
            self.plugin_roots.extend(plugin_roots);
        }
        if let Some(default_limits) = fragment.default_limits {
            self.default_limits = default_limits;
        }
        if let Some(default_admission) = fragment.default_admission {
            self.default_admission = default_admission;
        }
        if let Some(max_total_concurrent_executions) = fragment.max_total_concurrent_executions {
            self.max_total_concurrent_executions = max_total_concurrent_executions;
        }
        if let Some(max_total_preview_concurrent_executions) =
            fragment.max_total_preview_concurrent_executions
        {
            self.max_total_preview_concurrent_executions = max_total_preview_concurrent_executions;
        }
        if let Some(max_total_cache_concurrent_executions) =
            fragment.max_total_cache_concurrent_executions
        {
            self.max_total_cache_concurrent_executions = max_total_cache_concurrent_executions;
        }
        if let Some(plugins) = fragment.plugins {
            self.plugins.extend(plugins);
        }
        if let Some(attachments) = fragment.attachments {
            self.attachments.extend(attachments);
        }
    }

    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        for root in &mut self.plugin_roots {
            if root.is_relative() {
                *root = base_dir.join(&root);
            }
        }
        for plugin in &mut self.plugins {
            if plugin.path.is_relative() {
                plugin.path = base_dir.join(&plugin.path);
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        #[cfg(not(feature = "wasm"))]
        if self.enabled
            || !self.plugin_roots.is_empty()
            || !self.plugins.is_empty()
            || !self.attachments.is_empty()
        {
            return Err(ConfigError::WasmNotCompiled);
        }

        validate_config_list_len(
            "wasm.plugin_roots",
            self.plugin_roots.len(),
            MAX_WASM_PLUGIN_ROOTS,
        )?;
        validate_config_list_len("wasm.plugins", self.plugins.len(), MAX_WASM_PLUGINS)?;
        if !self.enabled
            && (!self.plugins.is_empty()
                || !self.plugin_roots.is_empty()
                || !self.attachments.is_empty())
        {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: "wasm".to_owned(),
                field: "enabled",
                reason: "plugin roots, plugin declarations, or plugin attachments require wasm.enabled = true",
            });
        }
        if self.enabled && !self.plugins.is_empty() && self.plugin_roots.is_empty() {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: "wasm".to_owned(),
                field: "plugin_roots",
                reason: "plugin declarations require at least one wasm.plugin_roots entry",
            });
        }
        for root in &self.plugin_roots {
            validate_wasm_root_path("wasm.plugin_roots", root)?;
        }
        self.default_limits.validate("wasm.default_limits")?;
        self.default_admission.validate("wasm.default_admission")?;
        validate_wasm_total_admission_budget(
            "max_total_concurrent_executions",
            self.max_total_concurrent_executions,
        )?;
        validate_wasm_preview_admission_budget(
            "max_total_preview_concurrent_executions",
            self.max_total_preview_concurrent_executions,
        )?;
        validate_wasm_total_admission_budget(
            "max_total_cache_concurrent_executions",
            self.max_total_cache_concurrent_executions,
        )?;
        validate_config_list_len(
            "wasm.attachments",
            self.attachments.len(),
            MAX_WASM_ATTACHMENTS,
        )?;

        let mut names = HashSet::new();
        for plugin in &self.plugins {
            plugin.validate(self.allow_preview_abi)?;
            validate_wasm_plugin_path_under_roots(plugin, &self.plugin_roots)?;
            if !names.insert(plugin.name.clone()) {
                return Err(ConfigError::DuplicateWasmPluginName {
                    name: plugin.name.clone(),
                });
            }
        }

        Ok(())
    }

    pub(crate) fn plugin_map(&self) -> HashMap<&str, &WasmPluginConfig> {
        self.plugins
            .iter()
            .map(|plugin| (plugin.name.as_str(), plugin))
            .collect()
    }

    pub fn ordered_attachments(&self) -> Vec<&WasmAttachmentConfig> {
        let mut attachments = self.attachments.iter().enumerate().collect::<Vec<_>>();
        attachments.sort_by(|(left_index, left), (right_index, right)| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left_index.cmp(right_index))
        });
        attachments
            .into_iter()
            .map(|(_, attachment)| attachment)
            .collect()
    }

    #[cfg(feature = "wasm")]
    pub fn plugin_manifests(&self) -> Result<Vec<fluxheim_wasm::WasmPluginManifest>, ConfigError> {
        self.plugins
            .iter()
            .map(|plugin| plugin.to_wasm_manifest(&self.default_limits))
            .collect()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WasmPluginConfig {
    pub name: String,
    pub path: PathBuf,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub abi: WasmPluginAbi,
    #[serde(default)]
    pub host_call_namespace: WasmHostCallNamespace,
    #[serde(default)]
    pub wasi: WasmWasiCapabilitiesConfig,
    #[serde(default)]
    pub phases: Vec<WasmPluginPhase>,
    #[serde(default)]
    pub fail_mode: WasmPluginFailMode,
    #[serde(default)]
    pub limits: Option<WasmSandboxLimitsConfig>,
    #[serde(default)]
    pub admission: Option<WasmAdmissionBudgetConfig>,
}

impl WasmPluginConfig {
    fn validate(&self, allow_preview_abi: bool) -> Result<(), ConfigError> {
        validate_wasm_plugin_name("wasm.plugins.name", &self.name)?;
        validate_wasm_path("wasm.plugins.path", &self.path)?;
        if let Some(sha256) = &self.sha256 {
            validate_wasm_sha256(sha256)?;
        }
        if self.sha256.is_none() && wasm_phases_include_security_decision(&self.phases) {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: format!("wasm plugin {:?}", self.name),
                field: "sha256",
                reason: "security decision phases require a pinned sha256 digest",
            });
        }
        if self.abi.is_preview() && !allow_preview_abi {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: format!("wasm plugin {:?}", self.name),
                field: "abi",
                reason: "preview ABI requires wasm.allow_preview_abi = true",
            });
        }
        if self.host_call_namespace.requires_fluxheim_policy_v1()
            && self.abi != WasmPluginAbi::FluxheimPolicyV1
        {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: format!("wasm plugin {:?}", self.name),
                field: "host_call_namespace",
                reason: "fluxheim-policy-v1 host calls require abi = \"fluxheim-policy-v1\"",
            });
        }
        if self.host_call_namespace.requires_proxy_wasm_preview()
            && self.abi != WasmPluginAbi::ProxyWasmPreview
        {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: format!("wasm plugin {:?}", self.name),
                field: "host_call_namespace",
                reason: "proxy-wasm-preview host calls require abi = \"proxy-wasm-preview\"",
            });
        }
        if self.host_call_namespace.requires_wasi_preview()
            && self.abi != WasmPluginAbi::WasiPreview
        {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: format!("wasm plugin {:?}", self.name),
                field: "host_call_namespace",
                reason: "wasi-preview host calls require abi = \"wasi-preview\"",
            });
        }
        if self.host_call_namespace.requires_wasi_preview() && !cfg!(feature = "wasm-wasi") {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: format!("wasm plugin {:?}", self.name),
                field: "host_call_namespace",
                reason: "wasi-preview host calls require the wasm-wasi feature",
            });
        }
        if self.host_call_namespace.requires_wasi_preview()
            && self
                .phases
                .iter()
                .any(|phase| *phase != WasmPluginPhase::AccessDecision)
        {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: format!("wasm plugin {:?}", self.name),
                field: "phases",
                reason: "wasi-preview currently supports only the access-decision phase",
            });
        }
        if self.abi != WasmPluginAbi::WasiPreview && !self.wasi.is_empty() {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: format!("wasm plugin {:?}", self.name),
                field: "wasi",
                reason: "WASI capability grants require abi = \"wasi-preview\"",
            });
        }
        if self.host_call_namespace.requires_proxy_wasm_preview()
            && !cfg!(feature = "wasm-proxy-abi")
        {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: format!("wasm plugin {:?}", self.name),
                field: "host_call_namespace",
                reason: "proxy-wasm-preview host calls require the wasm-proxy-abi feature",
            });
        }
        if self.host_call_namespace.requires_proxy_wasm_preview()
            && self
                .phases
                .iter()
                .any(|phase| *phase != WasmPluginPhase::AccessDecision)
        {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: format!("wasm plugin {:?}", self.name),
                field: "phases",
                reason: "proxy-wasm-preview currently supports only the access-decision phase",
            });
        }
        validate_wasm_phases(&self.phases, &format!("wasm plugin {:?}", self.name))?;
        validate_wasm_fail_mode(
            self.fail_mode,
            &self.phases,
            &format!("wasm plugin {:?}", self.name),
        )?;
        if let Some(limits) = &self.limits {
            limits.validate("wasm.plugins.limits")?;
        }
        if let Some(admission) = &self.admission {
            admission.validate("wasm.plugins.admission")?;
        }
        Ok(())
    }

    #[cfg(feature = "wasm")]
    pub fn to_wasm_manifest(
        &self,
        default_limits: &WasmSandboxLimitsConfig,
    ) -> Result<fluxheim_wasm::WasmPluginManifest, ConfigError> {
        let limits = self.limits.unwrap_or(*default_limits).to_wasm_limits()?;
        Ok(fluxheim_wasm::WasmPluginManifest {
            name: self.name.clone(),
            path: self.path.clone(),
            expected_sha256: self.sha256.clone(),
            abi: self.abi.to_wasm_abi(),
            host_call_namespace: self.host_call_namespace.to_wasm_host_call_namespace(),
            wasi_capabilities: self.wasi.to_wasm_capabilities(),
            phases: self
                .phases
                .iter()
                .copied()
                .map(WasmPluginPhase::to_wasm_phase)
                .collect(),
            limits,
            fail_mode: self.fail_mode.to_wasm_fail_mode(),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WasmAttachmentConfig {
    pub plugin: String,
    pub vhost: String,
    #[serde(default)]
    pub route: Option<String>,
    #[serde(default)]
    pub phases: Vec<WasmPluginPhase>,
    #[serde(default = "default_wasm_attachment_priority")]
    pub priority: u32,
    #[serde(default)]
    pub admission: Option<WasmAdmissionBudgetConfig>,
}

impl WasmAttachmentConfig {
    pub(crate) fn validate(
        &self,
        scope: &str,
        plugins: &HashMap<&str, &WasmPluginConfig>,
    ) -> Result<(), ConfigError> {
        validate_wasm_plugin_name("wasm attachment plugin", &self.plugin)?;
        let Some(plugin) = plugins.get(self.plugin.as_str()) else {
            return Err(ConfigError::UnknownWasmPlugin {
                scope: scope.to_owned(),
                plugin: self.plugin.clone(),
            });
        };
        let phases = if self.phases.is_empty() {
            plugin.phases.as_slice()
        } else {
            validate_wasm_phases(&self.phases, scope)?;
            self.phases.as_slice()
        };
        for phase in phases {
            if !plugin.phases.contains(phase) {
                return Err(ConfigError::InvalidWasmPolicy {
                    scope: scope.to_owned(),
                    field: "wasm.phases",
                    reason: "attachment phase must be declared by the referenced plugin",
                });
            }
        }
        if let Some(admission) = &self.admission {
            admission.validate("wasm attachment admission")?;
        }
        validate_wasm_attachment_priority(self.priority)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WasmPluginAbi {
    #[default]
    FluxheimPolicyV1,
    ProxyWasmPreview,
    WasiPreview,
}

impl WasmPluginAbi {
    fn is_preview(self) -> bool {
        !matches!(self, Self::FluxheimPolicyV1)
    }

    #[cfg(feature = "wasm")]
    fn to_wasm_abi(self) -> fluxheim_wasm::WasmPluginAbi {
        match self {
            Self::FluxheimPolicyV1 => fluxheim_wasm::WasmPluginAbi::FluxheimPolicyV1,
            Self::ProxyWasmPreview => fluxheim_wasm::WasmPluginAbi::ProxyWasmPreview,
            Self::WasiPreview => fluxheim_wasm::WasmPluginAbi::WasiPreview,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WasmPluginPhase {
    RequestHeaders,
    ResponseHeaders,
    AccessDecision,
    RouteDecision,
    CacheLookup,
    CacheStore,
}

#[cfg(feature = "wasm")]
impl WasmPluginPhase {
    fn to_wasm_phase(self) -> fluxheim_wasm::WasmPluginPhase {
        match self {
            Self::RequestHeaders => fluxheim_wasm::WasmPluginPhase::RequestHeaders,
            Self::ResponseHeaders => fluxheim_wasm::WasmPluginPhase::ResponseHeaders,
            Self::AccessDecision => fluxheim_wasm::WasmPluginPhase::AccessDecision,
            Self::RouteDecision => fluxheim_wasm::WasmPluginPhase::RouteDecision,
            Self::CacheLookup => fluxheim_wasm::WasmPluginPhase::CacheLookup,
            Self::CacheStore => fluxheim_wasm::WasmPluginPhase::CacheStore,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WasmPluginFailMode {
    #[default]
    FailClosed,
    FailOpen,
}

#[cfg(feature = "wasm")]
impl WasmPluginFailMode {
    fn to_wasm_fail_mode(self) -> fluxheim_wasm::WasmPluginFailMode {
        match self {
            Self::FailClosed => fluxheim_wasm::WasmPluginFailMode::FailClosed,
            Self::FailOpen => fluxheim_wasm::WasmPluginFailMode::FailOpen,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WasmHostCallNamespace {
    #[default]
    FluxheimPolicyV1,
    ProxyWasmPreview,
    WasiPreview,
}

impl WasmHostCallNamespace {
    fn requires_fluxheim_policy_v1(self) -> bool {
        matches!(self, Self::FluxheimPolicyV1)
    }

    fn requires_proxy_wasm_preview(self) -> bool {
        matches!(self, Self::ProxyWasmPreview)
    }

    fn requires_wasi_preview(self) -> bool {
        matches!(self, Self::WasiPreview)
    }

    #[cfg(feature = "wasm")]
    fn to_wasm_host_call_namespace(self) -> fluxheim_wasm::WasmHostCallNamespace {
        match self {
            Self::FluxheimPolicyV1 => fluxheim_wasm::WasmHostCallNamespace::FluxheimPolicyV1,
            Self::ProxyWasmPreview => fluxheim_wasm::WasmHostCallNamespace::ProxyWasmPreview,
            Self::WasiPreview => fluxheim_wasm::WasmHostCallNamespace::WasiPreview,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WasmWasiCapabilitiesConfig {
    #[serde(default)]
    pub clocks: bool,
    #[serde(default)]
    pub randomness: bool,
}

impl WasmWasiCapabilitiesConfig {
    fn is_empty(self) -> bool {
        !self.clocks && !self.randomness
    }

    #[cfg(feature = "wasm")]
    fn to_wasm_capabilities(self) -> fluxheim_wasm::WasmWasiCapabilities {
        fluxheim_wasm::WasmWasiCapabilities {
            clocks: self.clocks,
            randomness: self.randomness,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WasmSandboxLimitsConfig {
    #[serde(default = "default_wasm_max_module_bytes")]
    pub max_module_bytes: ByteSize,
    #[serde(default = "default_wasm_max_memory_bytes")]
    pub max_memory_bytes: ByteSize,
    #[serde(default = "default_wasm_max_table_elements")]
    pub max_table_elements: u32,
    #[serde(default = "default_wasm_fuel")]
    pub fuel: u64,
    #[serde(default = "default_wasm_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_wasm_compile_timeout_ms")]
    pub compile_timeout_ms: u64,
}

impl Default for WasmSandboxLimitsConfig {
    fn default() -> Self {
        Self {
            max_module_bytes: default_wasm_max_module_bytes(),
            max_memory_bytes: default_wasm_max_memory_bytes(),
            max_table_elements: default_wasm_max_table_elements(),
            fuel: default_wasm_fuel(),
            timeout_ms: default_wasm_timeout_ms(),
            compile_timeout_ms: default_wasm_compile_timeout_ms(),
        }
    }
}

impl WasmSandboxLimitsConfig {
    fn validate(&self, field: &'static str) -> Result<(), ConfigError> {
        if self.max_module_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: field.to_owned(),
                field: "max_module_bytes",
                reason: "must be greater than zero",
            });
        }
        if self.max_memory_bytes.as_u64() == 0 {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: field.to_owned(),
                field: "max_memory_bytes",
                reason: "must be greater than zero",
            });
        }
        if self.max_table_elements == 0 {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: field.to_owned(),
                field: "max_table_elements",
                reason: "must be greater than zero",
            });
        }
        if self.fuel == 0 {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: field.to_owned(),
                field: "fuel",
                reason: "must be greater than zero",
            });
        }
        if self.timeout_ms == 0 {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: field.to_owned(),
                field: "timeout_ms",
                reason: "must be greater than zero",
            });
        }
        if self.compile_timeout_ms == 0 {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: field.to_owned(),
                field: "compile_timeout_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }

    #[cfg(feature = "wasm")]
    fn to_wasm_limits(self) -> Result<fluxheim_wasm::WasmSandboxLimits, ConfigError> {
        let max_memory_bytes = usize::try_from(self.max_memory_bytes.as_u64()).map_err(|_| {
            ConfigError::InvalidWasmPolicy {
                scope: "wasm sandbox limits".to_owned(),
                field: "max_memory_bytes",
                reason: "value is too large for this platform",
            }
        })?;
        let max_table_elements = usize::try_from(self.max_table_elements).map_err(|_| {
            ConfigError::InvalidWasmPolicy {
                scope: "wasm sandbox limits".to_owned(),
                field: "max_table_elements",
                reason: "value is too large for this platform",
            }
        })?;

        Ok(fluxheim_wasm::WasmSandboxLimits {
            max_module_bytes: self.max_module_bytes.as_u64(),
            max_memory_bytes,
            max_table_elements,
            fuel: self.fuel,
            timeout: Duration::from_millis(self.timeout_ms),
            compile_timeout: Duration::from_millis(self.compile_timeout_ms),
        })
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WasmAdmissionBudgetConfig {
    #[serde(default = "default_wasm_max_concurrent_executions")]
    pub max_concurrent_executions: u32,
    #[serde(default = "default_wasm_queue_limit")]
    pub queue_limit: u32,
}

impl Default for WasmAdmissionBudgetConfig {
    fn default() -> Self {
        Self {
            max_concurrent_executions: default_wasm_max_concurrent_executions(),
            queue_limit: default_wasm_queue_limit(),
        }
    }
}

impl WasmAdmissionBudgetConfig {
    fn validate(&self, field: &'static str) -> Result<(), ConfigError> {
        if self.max_concurrent_executions == 0
            || self.max_concurrent_executions > MAX_WASM_MAX_CONCURRENT_EXECUTIONS
        {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: field.to_owned(),
                field: "max_concurrent_executions",
                reason: "must be within the supported execution budget range",
            });
        }
        if self.queue_limit > MAX_WASM_QUEUE_LIMIT {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: field.to_owned(),
                field: "queue_limit",
                reason: "must be within the supported execution budget range",
            });
        }
        Ok(())
    }
}

fn validate_wasm_total_admission_budget(
    field: &'static str,
    budget: u32,
) -> Result<(), ConfigError> {
    if budget == 0 || budget > MAX_WASM_MAX_CONCURRENT_EXECUTIONS {
        return Err(ConfigError::InvalidWasmPolicy {
            scope: "wasm".to_owned(),
            field,
            reason: "must be within the supported process-wide execution budget range",
        });
    }
    Ok(())
}

fn validate_wasm_preview_admission_budget(
    field: &'static str,
    budget: u32,
) -> Result<(), ConfigError> {
    if budget == 0 || budget > MAX_WASM_MAX_TOTAL_PREVIEW_CONCURRENT_EXECUTIONS {
        return Err(ConfigError::InvalidWasmPolicy {
            scope: "wasm".to_owned(),
            field,
            reason: "must be within the supported preview execution budget range",
        });
    }
    Ok(())
}

fn validate_wasm_attachment_priority(priority: u32) -> Result<(), ConfigError> {
    if priority > MAX_WASM_ATTACHMENT_PRIORITY {
        return Err(ConfigError::InvalidWasmPolicy {
            scope: "wasm.attachments".to_owned(),
            field: "priority",
            reason: "must be within the supported attachment priority range",
        });
    }
    Ok(())
}

pub(crate) fn validate_wasm_attachments(
    attachments: &[WasmAttachmentConfig],
    scope: &str,
    plugins: &HashMap<&str, &WasmPluginConfig>,
) -> Result<(), ConfigError> {
    validate_config_list_len(scope, attachments.len(), MAX_WASM_ATTACHMENTS)?;
    let mut names = HashSet::new();
    for attachment in attachments {
        attachment.validate(scope, plugins)?;
        let key = (
            attachment.plugin.clone(),
            attachment.vhost.clone(),
            attachment.route.clone(),
        );
        if !names.insert(key) {
            return Err(ConfigError::DuplicateWasmAttachment {
                scope: scope.to_owned(),
                plugin: attachment.plugin.clone(),
            });
        }
    }
    Ok(())
}

fn validate_wasm_plugin_name(field: &'static str, name: &str) -> Result<(), ConfigError> {
    if name.is_empty() {
        return Err(ConfigError::InvalidWasmPolicy {
            scope: field.to_owned(),
            field,
            reason: "plugin name cannot be empty",
        });
    }
    if name.len() > MAX_WASM_PLUGIN_NAME_BYTES {
        return Err(ConfigError::InvalidConfigNameLength {
            field,
            max: MAX_WASM_PLUGIN_NAME_BYTES,
        });
    }
    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(ConfigError::InvalidWasmPolicy {
            scope: field.to_owned(),
            field,
            reason: "plugin name may contain only ASCII letters, digits, '-', '_', or '.'",
        });
    }
    Ok(())
}

fn validate_wasm_plugin_path_under_roots(
    plugin: &WasmPluginConfig,
    plugin_roots: &[PathBuf],
) -> Result<(), ConfigError> {
    if plugin_roots
        .iter()
        .any(|root| plugin.path.starts_with(root.as_path()))
    {
        Ok(())
    } else {
        Err(ConfigError::InvalidWasmPolicy {
            scope: format!("wasm plugin {:?}", plugin.name),
            field: "path",
            reason: "plugin path must be located under one of wasm.plugin_roots",
        })
    }
}

fn validate_wasm_path(field: &'static str, path: &Path) -> Result<(), ConfigError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ConfigError::InvalidWasmPolicy {
            scope: field.to_owned(),
            field,
            reason: "path must be absolute and must not contain '.' or '..' components",
        });
    }
    Ok(())
}

fn validate_wasm_root_path(field: &'static str, path: &Path) -> Result<(), ConfigError> {
    validate_wasm_path(field, path)?;
    if normal_component_count(path) < MIN_WASM_PLUGIN_ROOT_COMPONENTS {
        return Err(ConfigError::InvalidWasmPolicy {
            scope: field.to_owned(),
            field,
            reason: "plugin root must be a scoped directory, not the filesystem root or a top-level system directory",
        });
    }
    Ok(())
}

fn normal_component_count(path: &Path) -> usize {
    path.components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count()
}

fn validate_wasm_phases(phases: &[WasmPluginPhase], scope: &str) -> Result<(), ConfigError> {
    if phases.is_empty() {
        return Err(ConfigError::InvalidWasmPolicy {
            scope: scope.to_owned(),
            field: "phases",
            reason: "at least one phase is required",
        });
    }
    validate_config_list_len(
        format!("{scope}.phases"),
        phases.len(),
        MAX_WASM_PLUGIN_PHASES,
    )?;
    let mut seen = HashSet::new();
    for phase in phases {
        if !seen.insert(*phase) {
            return Err(ConfigError::InvalidWasmPolicy {
                scope: scope.to_owned(),
                field: "phases",
                reason: "duplicate phases are not allowed",
            });
        }
    }
    Ok(())
}

fn wasm_phases_include_security_decision(phases: &[WasmPluginPhase]) -> bool {
    phases.iter().any(|phase| {
        matches!(
            phase,
            WasmPluginPhase::AccessDecision
                | WasmPluginPhase::RouteDecision
                | WasmPluginPhase::CacheStore
        )
    })
}

fn validate_wasm_fail_mode(
    fail_mode: WasmPluginFailMode,
    phases: &[WasmPluginPhase],
    scope: &str,
) -> Result<(), ConfigError> {
    if fail_mode == WasmPluginFailMode::FailOpen
        && phases.iter().any(|phase| {
            matches!(
                phase,
                WasmPluginPhase::AccessDecision
                    | WasmPluginPhase::RouteDecision
                    | WasmPluginPhase::CacheStore
            )
        })
    {
        return Err(ConfigError::InvalidWasmPolicy {
            scope: scope.to_owned(),
            field: "fail_mode",
            reason: "fail_open is not allowed for security decision phases",
        });
    }
    Ok(())
}

fn validate_wasm_sha256(value: &str) -> Result<(), ConfigError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigError::InvalidWasmPolicy {
            scope: "wasm.plugins.sha256".to_owned(),
            field: "sha256",
            reason: "expected a 64-character hexadecimal SHA-256 digest",
        });
    }
    Ok(())
}

const fn default_wasm_max_module_bytes() -> ByteSize {
    ByteSize::from_bytes(DEFAULT_WASM_MAX_MODULE_BYTES)
}

const fn default_wasm_max_memory_bytes() -> ByteSize {
    ByteSize::from_bytes(DEFAULT_WASM_MAX_MEMORY_BYTES)
}

const fn default_wasm_max_table_elements() -> u32 {
    DEFAULT_WASM_MAX_TABLE_ELEMENTS
}

const fn default_wasm_fuel() -> u64 {
    DEFAULT_WASM_FUEL
}

const fn default_wasm_timeout_ms() -> u64 {
    DEFAULT_WASM_TIMEOUT_MS
}

const fn default_wasm_compile_timeout_ms() -> u64 {
    DEFAULT_WASM_COMPILE_TIMEOUT_MS
}

const fn default_wasm_max_concurrent_executions() -> u32 {
    DEFAULT_WASM_MAX_CONCURRENT_EXECUTIONS
}

const fn default_wasm_max_total_concurrent_executions() -> u32 {
    DEFAULT_WASM_MAX_TOTAL_CONCURRENT_EXECUTIONS
}

const fn default_wasm_max_total_preview_concurrent_executions() -> u32 {
    DEFAULT_WASM_MAX_TOTAL_PREVIEW_CONCURRENT_EXECUTIONS
}

const fn default_wasm_max_total_cache_concurrent_executions() -> u32 {
    DEFAULT_WASM_MAX_TOTAL_CACHE_CONCURRENT_EXECUTIONS
}

const fn default_wasm_queue_limit() -> u32 {
    DEFAULT_WASM_QUEUE_LIMIT
}

const fn default_wasm_attachment_priority() -> u32 {
    DEFAULT_WASM_ATTACHMENT_PRIORITY
}

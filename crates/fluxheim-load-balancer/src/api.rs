use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};

use fluxheim_config::{
    LoadBalanceHealthCheckExpectedStatusRange, LoadBalanceHealthCheckProtocol,
    LoadBalancePassiveHealthConfig, LoadBalancePersistenceConfig, LoadBalancePersistenceMode,
    LoadBalanceQueueConfig, LoadBalanceRetryConfig, LoadBalanceSelection,
    LoadBalanceSlowStartConfig, ProxyConfig,
};

use super::MAX_RUNTIME_BACKEND_WEIGHT;
pub use super::api_selection::{
    LoadBalancedUpstreamOutcome, LoadBalancerPersistenceOutcome, LoadBalancerQueueOutcome,
    LoadBalancerSelectionResult, SelectedUpstream,
};
use super::backend::FluxBackendDiscoveryRuntimeStatus;
use super::persistence::LoadBalancerPersistenceSnapshot;
use super::policy::RuntimeBackendPolicySnapshot;

#[derive(Clone, Debug)]
pub(crate) struct LoadBalancerMetricLabels {
    pub(crate) vhost: Arc<str>,
    pub(crate) route: Option<Arc<str>>,
}

impl LoadBalancerMetricLabels {
    pub(crate) fn new(vhost: &str, route: Option<&str>) -> Self {
        Self {
            vhost: Arc::from(vhost),
            route: route.map(Arc::from),
        }
    }

    #[cfg(feature = "metrics")]
    pub(crate) fn vhost(&self) -> &str {
        &self.vhost
    }

    #[cfg(feature = "metrics")]
    pub(crate) fn route(&self) -> Option<&str> {
        self.route.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerRuntimeBackendState {
    Normal,
    Drained,
    Disabled,
    ForcedDown,
    ManualResume,
}

impl LoadBalancerRuntimeBackendState {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "normal" | "enable" | "enabled" => Some(Self::Normal),
            "drain" | "drained" => Some(Self::Drained),
            "disable" | "disabled" => Some(Self::Disabled),
            "down" | "force-down" | "force_down" | "forced-down" | "forced_down" => {
                Some(Self::ForcedDown)
            }
            "resume" | "resumed" | "manual-resume" | "manual_resume" => Some(Self::ManualResume),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Drained => "drained",
            Self::Disabled => "disabled",
            Self::ForcedDown => "forced_down",
            Self::ManualResume => "manual_resume",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LoadBalancerRuntimeBackendMutation {
    pub member: String,
    pub state: LoadBalancerRuntimeBackendState,
    pub persistent: bool,
    #[cfg(not(feature = "privacy-mode"))]
    pub address: String,
    pub alias: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LoadBalancerRuntimeBackendWeightMutation {
    pub member: String,
    pub configured_weight: usize,
    pub effective_weight: usize,
    pub runtime_weight_override: Option<usize>,
    pub persistent: bool,
    #[cfg(not(feature = "privacy-mode"))]
    pub address: String,
    pub alias: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerRuntimeBackendSetOperation {
    Added,
    Removed,
    Updated,
}

impl LoadBalancerRuntimeBackendSetOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Updated => "updated",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LoadBalancerRuntimeBackendSetMutation {
    pub member: String,
    pub operation: LoadBalancerRuntimeBackendSetOperation,
    pub configured_weight: usize,
    pub backend_count: usize,
    pub persistent: bool,
    #[cfg(not(feature = "privacy-mode"))]
    pub address: String,
    #[cfg(not(feature = "privacy-mode"))]
    pub previous_address: Option<String>,
    pub alias: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerCircuitState {
    Closed,
    Open,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerDiscoveryMode {
    Static,
    File,
    Http,
    Dns,
}

impl LoadBalancerDiscoveryMode {
    pub(super) fn from_config(config: &ProxyConfig) -> Self {
        if config.upstreams_file.is_some() {
            Self::File
        } else if config.upstreams_http_url.is_some() {
            Self::Http
        } else if config.upstream_dns_refresh_secs.is_some() {
            Self::Dns
        } else {
            Self::Static
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerRuntimeStats {
    pub vhosts: Vec<LoadBalancerVhostRuntimeStats>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerVhostRuntimeStats {
    pub name: String,
    pub pool: Option<LoadBalancerPoolRuntimeStats>,
    pub routes: Vec<LoadBalancerRouteRuntimeStats>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerRouteRuntimeStats {
    pub name: String,
    pub pool: LoadBalancerPoolRuntimeStats,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadBalancerMemberStateRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub member: &'a str,
    pub state: LoadBalancerRuntimeBackendState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LoadBalancerMemberStateResult {
    pub vhost: String,
    pub route: Option<String>,
    pub member: String,
    pub state: LoadBalancerRuntimeBackendState,
    pub persistent: bool,
    #[cfg(not(feature = "privacy-mode"))]
    pub address: String,
    pub alias: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadBalancerMemberWeightRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub member: &'a str,
    pub weight: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LoadBalancerMemberWeightResult {
    pub vhost: String,
    pub route: Option<String>,
    pub member: String,
    pub configured_weight: usize,
    pub effective_weight: usize,
    pub runtime_weight_override: Option<usize>,
    pub persistent: bool,
    #[cfg(not(feature = "privacy-mode"))]
    pub address: String,
    pub alias: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadBalancerMemberAddRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub member: &'a str,
    pub weight: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadBalancerMemberRemoveRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub member: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadBalancerMemberUpdateRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
    pub member: &'a str,
    pub updated_member: Option<&'a str>,
    pub weight: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LoadBalancerMemberSetMutationResult {
    pub vhost: String,
    pub route: Option<String>,
    pub member: String,
    pub operation: LoadBalancerRuntimeBackendSetOperation,
    pub configured_weight: usize,
    pub backend_count: usize,
    pub persistent: bool,
    #[cfg(not(feature = "privacy-mode"))]
    pub address: String,
    #[cfg(not(feature = "privacy-mode"))]
    pub previous_address: Option<String>,
    pub alias: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadBalancerPersistenceClearRequest<'a> {
    pub vhost: &'a str,
    pub route: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LoadBalancerPersistenceClearResult {
    pub vhost: String,
    pub route: Option<String>,
    pub cleared_entries: usize,
    pub persistent: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerPoolRuntimeStats {
    pub discovery_mode: LoadBalancerDiscoveryMode,
    pub discovery: LoadBalancerDiscoveryRuntimeStats,
    pub selection: LoadBalanceSelection,
    pub backend_count: usize,
    pub ready_backend_count: usize,
    pub available_backend_count: usize,
    pub primary_available_backend_count: usize,
    pub backup_available_backend_count: usize,
    pub drained_backend_count: usize,
    pub disabled_backend_count: usize,
    pub runtime_overridden_backend_count: usize,
    pub runtime_drained_backend_count: usize,
    pub runtime_disabled_backend_count: usize,
    pub runtime_forced_down_backend_count: usize,
    pub passive_ejected_backend_count: usize,
    pub circuit_open_backend_count: usize,
    pub saturated_backend_count: usize,
    pub max_iterations: usize,
    pub all_down_status: u16,
    pub health_check_enabled: bool,
    pub health_check_protocol: Option<LoadBalanceHealthCheckProtocol>,
    pub health_check_frequency_secs: Option<u64>,
    pub parallel_health_check: bool,
    pub passive_health_enabled: bool,
    pub slow_start_enabled: bool,
    pub persistence_enabled: bool,
    pub passive_health: LoadBalancePassiveHealthConfig,
    pub slow_start: LoadBalanceSlowStartConfig,
    pub persistence: LoadBalancerPersistenceRuntimeStats,
    pub queue: LoadBalancerQueueRuntimeStats,
    pub retry: LoadBalancerRetryRuntimeStats,
    pub backends: Vec<LoadBalancerBackendRuntimeStats>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerDiscoveryRuntimeStats {
    pub mode: LoadBalancerDiscoveryMode,
    pub refresh_enabled: bool,
    pub update_frequency_secs: Option<u64>,
    pub success_count: u64,
    pub failure_count: u64,
    pub last_success_unix_secs: Option<u64>,
    pub last_failure_unix_secs: Option<u64>,
    pub last_error: Option<String>,
}

impl LoadBalancerDiscoveryRuntimeStats {
    pub(super) fn from_runtime_status(
        mode: LoadBalancerDiscoveryMode,
        status: FluxBackendDiscoveryRuntimeStatus,
    ) -> Self {
        Self {
            mode,
            refresh_enabled: status.refresh_enabled,
            update_frequency_secs: status.update_frequency_secs,
            success_count: status.success_count,
            failure_count: status.failure_count,
            last_success_unix_secs: status.last_success_unix_secs,
            last_failure_unix_secs: status.last_failure_unix_secs,
            last_error: status.last_error,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerRetryRuntimeStats {
    pub enabled: bool,
    pub max_retries: u8,
    pub methods: Vec<String>,
    pub statuses: Vec<u16>,
    pub status_ranges: Vec<LoadBalanceHealthCheckExpectedStatusRange>,
    pub budget_per_window: u32,
    pub budget_window_secs: u64,
}

impl LoadBalancerRetryRuntimeStats {
    pub(super) fn from_config(config: &LoadBalanceRetryConfig) -> Self {
        Self {
            enabled: config.enabled,
            max_retries: config.max_retries,
            methods: config.methods.clone(),
            statuses: config.statuses.clone(),
            status_ranges: config.status_ranges.clone(),
            budget_per_window: config.budget_per_window,
            budget_window_secs: config.budget_window_secs,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerPersistenceRuntimeStats {
    pub enabled: bool,
    pub mode: LoadBalancePersistenceMode,
    pub header: Option<String>,
    pub cookie: Option<String>,
    pub ttl_secs: u64,
    pub table_max_entries: usize,
    pub entry_count: usize,
}

impl LoadBalancerPersistenceRuntimeStats {
    pub(super) fn from_policy(
        persistence: Option<&super::persistence::LoadBalancerPersistenceState>,
        config: &LoadBalancePersistenceConfig,
        entry_count: usize,
    ) -> Self {
        Self {
            enabled: persistence.is_some(),
            mode: config.mode,
            header: config.header.clone(),
            cookie: config.cookie.clone(),
            ttl_secs: config.ttl_secs,
            table_max_entries: config.table_max_entries,
            entry_count,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerQueueRuntimeStats {
    pub enabled: bool,
    pub max_waiting: usize,
    pub timeout_ms: u64,
    pub retry_interval_ms: u64,
    pub waiting: usize,
}

impl LoadBalancerQueueRuntimeStats {
    pub(super) fn from_policy(config: &LoadBalanceQueueConfig, waiting: &AtomicUsize) -> Self {
        Self {
            enabled: config.enabled(),
            max_waiting: config.max_waiting,
            timeout_ms: config.timeout_ms,
            retry_interval_ms: config.retry_interval_ms,
            waiting: waiting.load(Ordering::Acquire),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct LoadBalancerRuntimeStateSnapshot {
    pub(crate) version: u16,
    pub(crate) runtime_overrides: RuntimeBackendPolicySnapshot,
    pub(crate) persistence: Option<LoadBalancerPersistenceSnapshot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadBalancerRuntimeStateRestore {
    pub persistence_entries: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoadBalancerBackendRuntimeStats {
    pub address: Option<String>,
    pub alias: Option<String>,
    pub tags: Vec<String>,
    pub weight: usize,
    pub effective_weight: usize,
    pub health_weight_percent: Option<u8>,
    pub runtime_weight_override: Option<usize>,
    pub runtime_weight_changed_at_unix_secs: Option<u64>,
    pub locality: Option<String>,
    pub locality_preferred: bool,
    pub ready: bool,
    pub backup: bool,
    pub drained: bool,
    pub disabled: bool,
    pub runtime_state_override: Option<LoadBalancerRuntimeBackendState>,
    pub runtime_state_changed_at_unix_secs: Option<u64>,
    pub persistence_entry_count: usize,
    pub priority_group: Option<u16>,
    pub max_in_flight: Option<usize>,
    pub in_flight: usize,
    pub passive_ejected: bool,
    pub circuit_state: LoadBalancerCircuitState,
    pub passive_consecutive_failures: Option<usize>,
    pub passive_ejection_remaining_secs: Option<u64>,
    pub slow_start_permitting: bool,
    pub latency_micros: Option<u64>,
}

pub fn parse_load_balancer_runtime_weight(value: &str) -> Result<Option<usize>, &'static str> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("default")
        || value.eq_ignore_ascii_case("reset")
        || value.eq_ignore_ascii_case("clear")
        || value.eq_ignore_ascii_case("configured")
    {
        return Ok(None);
    }
    let Ok(weight) = value.parse::<usize>() else {
        return Err(
            "load balancer weight must be a number or one of default/reset/clear/configured",
        );
    };
    if weight == 0 || weight > MAX_RUNTIME_BACKEND_WEIGHT {
        return Err("load balancer weight must be between 1 and 1000");
    }
    Ok(Some(weight))
}

pub fn parse_load_balancer_member_weight(value: &str) -> Result<usize, &'static str> {
    let value = value.trim();
    let Ok(weight) = value.parse::<usize>() else {
        return Err("load balancer member weight must be a number");
    };
    if weight == 0 || weight > MAX_RUNTIME_BACKEND_WEIGHT {
        return Err("load balancer member weight must be between 1 and 1000");
    }
    Ok(weight)
}

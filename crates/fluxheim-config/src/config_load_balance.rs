use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[path = "config_load_balance_impl.rs"]
mod config_load_balance_impl;
#[path = "config_load_balance_selection.rs"]
mod config_load_balance_selection;

pub use crate::config_load_balance_health::{
    LoadBalanceHealthCheckConfig, LoadBalanceHealthCheckConfigFragment,
    LoadBalanceHealthCheckExpectedHeader, LoadBalanceHealthCheckExpectedJson,
    LoadBalanceHealthCheckExpectedStatusRange, LoadBalanceHealthCheckProtocol,
    LoadBalanceHealthCheckRequestHeader,
};
pub use crate::config_load_balance_passive_health::{
    LoadBalancePassiveHealthConfig, LoadBalancePassiveHealthConfigFragment,
};
pub use crate::config_load_balance_persistence::{
    LoadBalanceManagedCookieSameSite, LoadBalancePersistenceConfig,
    LoadBalancePersistenceConfigFragment, LoadBalancePersistenceMode,
};
pub use crate::config_load_balance_queue::{
    LoadBalanceQueueConfig, LoadBalanceQueueConfigFragment,
};
pub use crate::config_load_balance_retry::{
    LB_SAFE_RETRY_METHODS, LoadBalanceRetryConfig, LoadBalanceRetryConfigFragment,
};
pub use crate::config_load_balance_slow_start::{
    LoadBalanceSlowStartConfig, LoadBalanceSlowStartConfigFragment,
};
pub use config_load_balance_selection::LoadBalanceSelection;

const MIN_BOUNDED_LOAD_FACTOR_PER_MILLE: u16 = 1000;
const MAX_BOUNDED_LOAD_FACTOR_PER_MILLE: u16 = 10000;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceConfig {
    #[serde(default)]
    pub selection: LoadBalanceSelection,
    #[serde(default)]
    pub hash_header: Option<String>,
    #[serde(default)]
    pub hash_cookie: Option<String>,
    #[serde(default = "default_lb_max_iterations")]
    pub max_iterations: usize,
    #[serde(default = "default_lb_all_down_status")]
    pub all_down_status: u16,
    #[serde(default = "default_bounded_load_factor_per_mille")]
    pub bounded_load_factor_per_mille: u16,
    #[serde(default)]
    pub health_check: LoadBalanceHealthCheckConfig,
    #[serde(default)]
    pub passive_health: LoadBalancePassiveHealthConfig,
    #[serde(default)]
    pub slow_start: LoadBalanceSlowStartConfig,
    #[serde(default)]
    pub retry: LoadBalanceRetryConfig,
    #[serde(default)]
    pub persistence: LoadBalancePersistenceConfig,
    #[serde(default)]
    pub runtime_state_file: Option<PathBuf>,
    #[serde(default)]
    pub queue: LoadBalanceQueueConfig,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalanceConfigFragment {
    selection: Option<LoadBalanceSelection>,
    hash_header: Option<String>,
    hash_cookie: Option<String>,
    max_iterations: Option<usize>,
    all_down_status: Option<u16>,
    bounded_load_factor_per_mille: Option<u16>,
    health_check: Option<LoadBalanceHealthCheckConfigFragment>,
    passive_health: Option<LoadBalancePassiveHealthConfigFragment>,
    slow_start: Option<LoadBalanceSlowStartConfigFragment>,
    retry: Option<LoadBalanceRetryConfigFragment>,
    persistence: Option<LoadBalancePersistenceConfigFragment>,
    runtime_state_file: Option<PathBuf>,
    queue: Option<LoadBalanceQueueConfigFragment>,
}

impl LoadBalanceConfigFragment {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.runtime_state_file
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }
}

impl Default for LoadBalanceConfig {
    fn default() -> Self {
        Self {
            selection: LoadBalanceSelection::default(),
            hash_header: None,
            hash_cookie: None,
            max_iterations: default_lb_max_iterations(),
            all_down_status: default_lb_all_down_status(),
            bounded_load_factor_per_mille: default_bounded_load_factor_per_mille(),
            health_check: LoadBalanceHealthCheckConfig::default(),
            passive_health: LoadBalancePassiveHealthConfig::default(),
            slow_start: LoadBalanceSlowStartConfig::default(),
            retry: LoadBalanceRetryConfig::default(),
            persistence: LoadBalancePersistenceConfig::default(),
            runtime_state_file: None,
            queue: LoadBalanceQueueConfig::default(),
        }
    }
}

fn default_lb_max_iterations() -> usize {
    256
}

fn default_lb_all_down_status() -> u16 {
    502
}

pub fn default_bounded_load_factor_per_mille() -> u16 {
    1250
}

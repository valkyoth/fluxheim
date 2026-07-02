use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[path = "config_load_balance_impl.rs"]
mod config_load_balance_impl;

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

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalanceSelection {
    #[default]
    RoundRobin,
    #[serde(
        alias = "weighted-least-connections",
        alias = "ratio-least-connections"
    )]
    LeastConnections,
    #[serde(alias = "least-session")]
    LeastSessions,
    LeastTime,
    #[serde(
        alias = "power-of-two-choices",
        alias = "two-choice",
        alias = "weighted-two-choice",
        alias = "weighted-random-two-choice"
    )]
    PowerOfTwo,
    SourceHash,
    UriHash,
    HeaderHash,
    CookieHash,
    ConsistentSourceHash,
    ConsistentUriHash,
    ConsistentHeaderHash,
    ConsistentCookieHash,
    #[serde(
        alias = "ketama",
        alias = "ketama-source-hash",
        alias = "nginx-consistent-hash"
    )]
    NginxConsistentSourceHash,
    #[serde(alias = "ketama-uri-hash")]
    NginxConsistentUriHash,
    #[serde(alias = "ketama-header-hash")]
    NginxConsistentHeaderHash,
    #[serde(alias = "ketama-cookie-hash")]
    NginxConsistentCookieHash,
    BoundedLoadConsistentSourceHash,
    BoundedLoadConsistentUriHash,
    BoundedLoadConsistentHeaderHash,
    BoundedLoadConsistentCookieHash,
    #[serde(alias = "maglev", alias = "maglev-hash")]
    MaglevSourceHash,
    MaglevUriHash,
    MaglevHeaderHash,
    MaglevCookieHash,
}

impl LoadBalanceSelection {
    pub fn requires_hash_header(self) -> bool {
        matches!(
            self,
            Self::HeaderHash
                | Self::ConsistentHeaderHash
                | Self::NginxConsistentHeaderHash
                | Self::BoundedLoadConsistentHeaderHash
                | Self::MaglevHeaderHash
        )
    }

    pub fn requires_hash_cookie(self) -> bool {
        matches!(
            self,
            Self::CookieHash
                | Self::ConsistentCookieHash
                | Self::NginxConsistentCookieHash
                | Self::BoundedLoadConsistentCookieHash
                | Self::MaglevCookieHash
        )
    }

    pub fn uses_bounded_load(self) -> bool {
        matches!(
            self,
            Self::BoundedLoadConsistentSourceHash
                | Self::BoundedLoadConsistentUriHash
                | Self::BoundedLoadConsistentHeaderHash
                | Self::BoundedLoadConsistentCookieHash
        )
    }

    pub fn uses_maglev(self) -> bool {
        matches!(
            self,
            Self::MaglevSourceHash
                | Self::MaglevUriHash
                | Self::MaglevHeaderHash
                | Self::MaglevCookieHash
        )
    }

    pub fn uses_static_ring(self) -> bool {
        matches!(
            self,
            Self::NginxConsistentSourceHash
                | Self::NginxConsistentUriHash
                | Self::NginxConsistentHeaderHash
                | Self::NginxConsistentCookieHash
                | Self::MaglevSourceHash
                | Self::MaglevUriHash
                | Self::MaglevHeaderHash
                | Self::MaglevCookieHash
        )
    }

    pub fn metric_label(self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::LeastConnections => "least_connections",
            Self::LeastSessions => "least_sessions",
            Self::LeastTime => "least_time",
            Self::PowerOfTwo => "power_of_two",
            Self::SourceHash => "source_hash",
            Self::UriHash => "uri_hash",
            Self::HeaderHash => "header_hash",
            Self::CookieHash => "cookie_hash",
            Self::ConsistentSourceHash => "consistent_source_hash",
            Self::ConsistentUriHash => "consistent_uri_hash",
            Self::ConsistentHeaderHash => "consistent_header_hash",
            Self::ConsistentCookieHash => "consistent_cookie_hash",
            Self::NginxConsistentSourceHash => "nginx_consistent_source_hash",
            Self::NginxConsistentUriHash => "nginx_consistent_uri_hash",
            Self::NginxConsistentHeaderHash => "nginx_consistent_header_hash",
            Self::NginxConsistentCookieHash => "nginx_consistent_cookie_hash",
            Self::BoundedLoadConsistentSourceHash => "bounded_load_consistent_source_hash",
            Self::BoundedLoadConsistentUriHash => "bounded_load_consistent_uri_hash",
            Self::BoundedLoadConsistentHeaderHash => "bounded_load_consistent_header_hash",
            Self::BoundedLoadConsistentCookieHash => "bounded_load_consistent_cookie_hash",
            Self::MaglevSourceHash => "maglev_source_hash",
            Self::MaglevUriHash => "maglev_uri_hash",
            Self::MaglevHeaderHash => "maglev_header_hash",
            Self::MaglevCookieHash => "maglev_cookie_hash",
        }
    }

    #[cfg(feature = "load-balancer")]
    pub fn supports_runtime_weight_override(self) -> bool {
        matches!(
            self,
            Self::RoundRobin | Self::LeastConnections | Self::LeastSessions | Self::LeastTime
        )
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

#[cfg(test)]
mod tests {
    use super::LoadBalanceSelection;

    #[test]
    fn load_balance_selection_metric_labels_are_stable() {
        assert_eq!(
            LoadBalanceSelection::BoundedLoadConsistentSourceHash.metric_label(),
            "bounded_load_consistent_source_hash"
        );
        assert_eq!(
            LoadBalanceSelection::BoundedLoadConsistentUriHash.metric_label(),
            "bounded_load_consistent_uri_hash"
        );
        assert_eq!(
            LoadBalanceSelection::BoundedLoadConsistentHeaderHash.metric_label(),
            "bounded_load_consistent_header_hash"
        );
        assert_eq!(
            LoadBalanceSelection::BoundedLoadConsistentCookieHash.metric_label(),
            "bounded_load_consistent_cookie_hash"
        );
        assert_eq!(
            LoadBalanceSelection::NginxConsistentSourceHash.metric_label(),
            "nginx_consistent_source_hash"
        );
        assert_eq!(
            LoadBalanceSelection::NginxConsistentUriHash.metric_label(),
            "nginx_consistent_uri_hash"
        );
        assert_eq!(
            LoadBalanceSelection::NginxConsistentHeaderHash.metric_label(),
            "nginx_consistent_header_hash"
        );
        assert_eq!(
            LoadBalanceSelection::NginxConsistentCookieHash.metric_label(),
            "nginx_consistent_cookie_hash"
        );
        assert_eq!(
            LoadBalanceSelection::MaglevSourceHash.metric_label(),
            "maglev_source_hash"
        );
        assert_eq!(
            LoadBalanceSelection::MaglevUriHash.metric_label(),
            "maglev_uri_hash"
        );
        assert_eq!(
            LoadBalanceSelection::MaglevHeaderHash.metric_label(),
            "maglev_header_hash"
        );
        assert_eq!(
            LoadBalanceSelection::MaglevCookieHash.metric_label(),
            "maglev_cookie_hash"
        );
    }
}

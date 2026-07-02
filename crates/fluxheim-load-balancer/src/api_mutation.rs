use serde::{Deserialize, Serialize};

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

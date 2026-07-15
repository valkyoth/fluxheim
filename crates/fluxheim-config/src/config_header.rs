use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
pub use crate::config_header_cors::{CorsPolicyConfig, CorsPolicyOverlayConfig};
pub use crate::config_header_hardening::{
    CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy, CrossOriginResourcePolicy,
    PermittedCrossDomainPolicies, ResponseHardeningConfig, ResponseHardeningProfile,
    ResponsePermissionsPolicyConfig, ResponsePermissionsPolicyProfile,
};
pub use crate::config_header_metadata::{ResponseMetadataConfig, ResponseMetadataOverlayConfig};
pub use crate::config_header_response::{
    ResponseHeaderPolicyConfig, ResponseHeaderPolicyOverlayConfig, ResponseHeaderRewriteConfig,
    ResponseHeaderRewriteRuleConfig, ResponseHstsConfig,
};
pub use crate::config_header_validation::*;

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderPolicyConfig {
    #[serde(default)]
    pub request: RequestHeaderPolicyConfig,
    #[serde(default)]
    pub response: ResponseHeaderPolicyConfig,
    #[serde(default)]
    pub cors: CorsPolicyConfig,
}

impl HeaderPolicyConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.request.validate()?;
        self.response.validate()?;
        self.cors.validate("headers.cors")
    }

    pub fn with_vhost_overlay(&self, overlay: &VhostHeaderPolicyConfig) -> Self {
        let mut policy = self.clone();
        policy.request.apply_overlay(&overlay.request);
        policy.response.apply_overlay(&overlay.response);
        policy.cors.apply_overlay(&overlay.cors);
        policy
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostHeaderPolicyConfig {
    #[serde(default)]
    pub request: RequestHeaderPolicyOverlayConfig,
    #[serde(default)]
    pub response: ResponseHeaderPolicyOverlayConfig,
    #[serde(default)]
    pub cors: CorsPolicyOverlayConfig,
}

impl VhostHeaderPolicyConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.request.validate()?;
        self.response.validate()?;
        self.cors.validate("vhosts.headers.cors")
    }
}

pub const MAX_HEADER_MUTATION_NAMES: usize = 128;
pub const MAX_HEADER_APPEND_VALUES: usize = 32;
pub const MAX_RESPONSE_HEADER_REWRITE_RULES: usize = 32;

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestHeaderPolicyOverlayConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub strip_inbound_client_ip_headers: Option<bool>,
    #[serde(default)]
    pub x_forwarded_for: Option<ForwardedClientIpHeaderMode>,
    #[serde(default)]
    pub x_real_ip: Option<bool>,
    #[serde(default)]
    pub x_forwarded_host: Option<bool>,
    #[serde(default)]
    pub x_forwarded_proto: Option<bool>,
    #[serde(default)]
    pub forwarded: Option<bool>,
    #[serde(default)]
    pub unset: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub add: BTreeMap<String, String>,
    #[serde(default)]
    pub append: BTreeMap<String, HeaderValues>,
    #[serde(default)]
    pub operations: HeaderOperationsConfig,
}

impl RequestHeaderPolicyOverlayConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_header_add_aliases(
            "vhosts.headers.request",
            &self.set,
            &self.add,
            &self.operations.add,
        )?;
        let unset = combined_header_unset(&self.unset, &self.remove, &self.operations.remove);
        let set = combined_header_set(&self.set, &self.add, &self.operations.add);
        validate_header_mutations("vhosts.headers.request", &unset, &set, &self.append)?;
        validate_no_tls_header_append("vhosts.headers.request", &self.append)
    }

    pub fn effective_unset(&self) -> Vec<String> {
        combined_header_unset(&self.unset, &self.remove, &self.operations.remove)
    }

    pub fn effective_set(&self) -> BTreeMap<String, String> {
        combined_header_set(&self.set, &self.add, &self.operations.add)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestHeaderPolicyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub strip_inbound_client_ip_headers: bool,
    #[serde(default)]
    pub x_forwarded_for: ForwardedClientIpHeaderMode,
    #[serde(default = "default_true")]
    pub x_real_ip: bool,
    #[serde(default = "default_true")]
    pub x_forwarded_host: bool,
    #[serde(default = "default_true")]
    pub x_forwarded_proto: bool,
    #[serde(default)]
    pub forwarded: bool,
    #[serde(default)]
    pub unset: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub add: BTreeMap<String, String>,
    #[serde(default)]
    pub append: BTreeMap<String, HeaderValues>,
    #[serde(default)]
    pub operations: HeaderOperationsConfig,
}

impl Default for RequestHeaderPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strip_inbound_client_ip_headers: true,
            #[cfg(not(feature = "privacy-mode"))]
            x_forwarded_for: ForwardedClientIpHeaderMode::Replace,
            #[cfg(feature = "privacy-mode")]
            x_forwarded_for: ForwardedClientIpHeaderMode::Off,
            x_real_ip: true,
            x_forwarded_host: true,
            x_forwarded_proto: true,
            forwarded: false,
            unset: Vec::new(),
            remove: Vec::new(),
            set: BTreeMap::new(),
            add: BTreeMap::new(),
            append: BTreeMap::new(),
            operations: HeaderOperationsConfig::default(),
        }
    }
}

impl RequestHeaderPolicyConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_header_add_aliases(
            "headers.request",
            &self.set,
            &self.add,
            &self.operations.add,
        )?;
        let unset = self.effective_unset();
        let set = self.effective_set();
        validate_header_mutations("headers.request", &unset, &set, &self.append)?;
        validate_no_tls_header_append("headers.request", &self.append)
    }

    pub fn effective_unset(&self) -> Vec<String> {
        combined_header_unset(&self.unset, &self.remove, &self.operations.remove)
    }

    pub fn effective_set(&self) -> BTreeMap<String, String> {
        combined_header_set(&self.set, &self.add, &self.operations.add)
    }

    fn apply_overlay(&mut self, overlay: &RequestHeaderPolicyOverlayConfig) {
        if let Some(enabled) = overlay.enabled {
            self.enabled = enabled;
        }
        if let Some(strip) = overlay.strip_inbound_client_ip_headers {
            self.strip_inbound_client_ip_headers = strip;
        }
        if let Some(mode) = overlay.x_forwarded_for {
            self.x_forwarded_for = mode;
        }
        if let Some(enabled) = overlay.x_real_ip {
            self.x_real_ip = enabled;
        }
        if let Some(enabled) = overlay.x_forwarded_host {
            self.x_forwarded_host = enabled;
        }
        if let Some(enabled) = overlay.x_forwarded_proto {
            self.x_forwarded_proto = enabled;
        }
        if let Some(enabled) = overlay.forwarded {
            self.forwarded = enabled;
        }
        merge_header_mutations(
            &mut self.unset,
            &mut self.set,
            &mut self.append,
            &overlay.effective_unset(),
            &overlay.effective_set(),
            &overlay.append,
        );
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForwardedClientIpHeaderMode {
    Off,
    #[default]
    Replace,
    Append,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderOperationsConfig {
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub add: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum HeaderValues {
    One(String),
    Many(Vec<String>),
}

impl HeaderValues {
    pub fn iter(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        match self {
            Self::One(value) => Box::new(std::iter::once(value.as_str())),
            Self::Many(values) => Box::new(values.iter().map(String::as_str)),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(values) => values.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::One(value) => value.is_empty(),
            Self::Many(values) => values.is_empty(),
        }
    }

    pub fn extend(&mut self, extra: &Self) {
        let mut values = self.iter().map(str::to_owned).collect::<Vec<_>>();
        values.extend(extra.iter().map(str::to_owned));
        *self = Self::Many(values);
    }
}

fn default_true() -> bool {
    true
}

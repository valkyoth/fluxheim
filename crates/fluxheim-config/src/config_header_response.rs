use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_header::{HeaderOperationsConfig, HeaderValues};
use crate::config_header_hardening::{
    CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy, CrossOriginResourcePolicy,
    PermittedCrossDomainPolicies, ResponseHardeningConfig, ResponsePermissionsPolicyConfig,
    validate_reporting_endpoints,
};
use crate::config_header_metadata::{ResponseMetadataConfig, ResponseMetadataOverlayConfig};
use crate::config_header_validation::{
    combined_header_set, combined_header_unset, merge_header_mutations,
    validate_cookie_domain_rewrite_rules, validate_cookie_path_rewrite_rules,
    validate_header_add_aliases, validate_header_mutations, validate_optional_header_value,
    validate_response_header_rewrite_rules,
};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeaderPolicyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub hardening: ResponseHardeningConfig,
    #[serde(default)]
    pub metadata: ResponseMetadataConfig,
    #[serde(default)]
    pub strict_transport_security: Option<String>,
    #[serde(default)]
    pub hsts: Option<ResponseHstsConfig>,
    #[serde(default)]
    pub content_security_policy: Option<String>,
    #[serde(default)]
    pub content_security_policy_report_only: Option<String>,
    #[serde(default)]
    pub permissions_policy: Option<ResponsePermissionsPolicyConfig>,
    #[serde(default)]
    pub cross_origin_opener_policy: Option<CrossOriginOpenerPolicy>,
    #[serde(default)]
    pub cross_origin_resource_policy: Option<CrossOriginResourcePolicy>,
    #[serde(default)]
    pub cross_origin_embedder_policy: Option<CrossOriginEmbedderPolicy>,
    #[serde(default)]
    pub x_permitted_cross_domain_policies: Option<PermittedCrossDomainPolicies>,
    #[serde(default)]
    pub reporting_endpoints: BTreeMap<String, String>,
    #[serde(default = "default_x_content_type_options")]
    pub x_content_type_options: Option<String>,
    #[serde(default = "default_x_frame_options")]
    pub x_frame_options: Option<String>,
    #[serde(default = "default_referrer_policy")]
    pub referrer_policy: Option<String>,
    #[serde(default = "default_response_unset_headers")]
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
    #[serde(default)]
    pub rewrite: ResponseHeaderRewriteConfig,
}

impl Default for ResponseHeaderPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hardening: ResponseHardeningConfig::default(),
            metadata: ResponseMetadataConfig::default(),
            strict_transport_security: None,
            hsts: None,
            content_security_policy: None,
            content_security_policy_report_only: None,
            permissions_policy: None,
            cross_origin_opener_policy: None,
            cross_origin_resource_policy: None,
            cross_origin_embedder_policy: None,
            x_permitted_cross_domain_policies: None,
            reporting_endpoints: BTreeMap::new(),
            x_content_type_options: default_x_content_type_options(),
            x_frame_options: default_x_frame_options(),
            referrer_policy: default_referrer_policy(),
            unset: default_response_unset_headers(),
            remove: Vec::new(),
            set: BTreeMap::new(),
            add: BTreeMap::new(),
            append: BTreeMap::new(),
            operations: HeaderOperationsConfig::default(),
            rewrite: ResponseHeaderRewriteConfig::default(),
        }
    }
}

impl ResponseHeaderPolicyConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        self.metadata.validate("headers.response.metadata")?;
        validate_optional_header_value(
            "headers.response.strict_transport_security",
            self.strict_transport_security.as_deref(),
        )?;
        if self.strict_transport_security.is_some() && self.hsts.is_some() {
            return Err(ConfigError::InvalidResponseHeaderValue {
                field: "headers.response.hsts",
            });
        }
        if let Some(hsts) = &self.hsts {
            hsts.validate("headers.response.hsts")?;
        }
        validate_optional_header_value(
            "headers.response.content_security_policy",
            self.content_security_policy.as_deref(),
        )?;
        validate_optional_header_value(
            "headers.response.content_security_policy_report_only",
            self.content_security_policy_report_only.as_deref(),
        )?;
        validate_reporting_endpoints(
            "headers.response.reporting_endpoints",
            &self.reporting_endpoints,
        )?;
        validate_optional_header_value(
            "headers.response.x_content_type_options",
            self.x_content_type_options.as_deref(),
        )?;
        validate_optional_header_value(
            "headers.response.x_frame_options",
            self.x_frame_options.as_deref(),
        )?;
        validate_optional_header_value(
            "headers.response.referrer_policy",
            self.referrer_policy.as_deref(),
        )?;
        validate_header_add_aliases(
            "headers.response",
            &self.set,
            &self.add,
            &self.operations.add,
        )?;
        let unset = self.effective_unset();
        let set = self.effective_set();
        validate_header_mutations("headers.response", &unset, &set, &self.append)?;
        self.rewrite.validate("headers.response.rewrite")?;

        Ok(())
    }

    pub fn effective_unset(&self) -> Vec<String> {
        combined_header_unset(&self.unset, &self.remove, &self.operations.remove)
    }

    pub fn effective_set(&self) -> BTreeMap<String, String> {
        combined_header_set(&self.set, &self.add, &self.operations.add)
    }

    pub(crate) fn apply_overlay(&mut self, overlay: &ResponseHeaderPolicyOverlayConfig) {
        if let Some(enabled) = overlay.enabled {
            self.enabled = enabled;
        }
        if let Some(hardening) = &overlay.hardening {
            self.hardening = hardening.clone();
        }
        self.metadata.apply_overlay(&overlay.metadata);
        if let Some(value) = &overlay.strict_transport_security {
            self.strict_transport_security = value.clone();
        }
        if let Some(value) = &overlay.hsts {
            self.hsts = value.clone();
        }
        if let Some(value) = &overlay.content_security_policy {
            self.content_security_policy = value.clone();
        }
        if let Some(value) = &overlay.content_security_policy_report_only {
            self.content_security_policy_report_only = value.clone();
        }
        if let Some(value) = &overlay.permissions_policy {
            self.permissions_policy = value.clone();
        }
        if let Some(value) = overlay.cross_origin_opener_policy {
            self.cross_origin_opener_policy = value;
        }
        if let Some(value) = overlay.cross_origin_resource_policy {
            self.cross_origin_resource_policy = value;
        }
        if let Some(value) = overlay.cross_origin_embedder_policy {
            self.cross_origin_embedder_policy = value;
        }
        if let Some(value) = overlay.x_permitted_cross_domain_policies {
            self.x_permitted_cross_domain_policies = value;
        }
        if let Some(value) = &overlay.reporting_endpoints {
            self.reporting_endpoints = value.clone();
        }
        if let Some(value) = &overlay.x_content_type_options {
            self.x_content_type_options = value.clone();
        }
        if let Some(value) = &overlay.x_frame_options {
            self.x_frame_options = value.clone();
        }
        if let Some(value) = &overlay.referrer_policy {
            self.referrer_policy = value.clone();
        }
        merge_header_mutations(
            &mut self.unset,
            &mut self.set,
            &mut self.append,
            &overlay.effective_unset(),
            &overlay.effective_set(),
            &overlay.append,
        );
        self.rewrite.merge(&overlay.rewrite);
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeaderRewriteConfig {
    #[serde(default)]
    pub location: Vec<ResponseHeaderRewriteRuleConfig>,
    #[serde(default)]
    pub refresh: Vec<ResponseHeaderRewriteRuleConfig>,
    #[serde(default)]
    pub cookie_domain: Vec<ResponseHeaderRewriteRuleConfig>,
    #[serde(default)]
    pub cookie_path: Vec<ResponseHeaderRewriteRuleConfig>,
}

impl ResponseHeaderRewriteConfig {
    fn validate(&self, field: &'static str) -> Result<(), ConfigError> {
        validate_response_header_rewrite_rules(field, "location", &self.location)?;
        validate_response_header_rewrite_rules(field, "refresh", &self.refresh)?;
        validate_cookie_domain_rewrite_rules(field, &self.cookie_domain)?;
        validate_cookie_path_rewrite_rules(field, &self.cookie_path)
    }

    fn merge(&mut self, overlay: &Self) {
        self.location.extend(overlay.location.iter().cloned());
        self.refresh.extend(overlay.refresh.iter().cloned());
        self.cookie_domain
            .extend(overlay.cookie_domain.iter().cloned());
        self.cookie_path.extend(overlay.cookie_path.iter().cloned());
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeaderRewriteRuleConfig {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHstsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_hsts_max_age_secs")]
    pub max_age_secs: u64,
    #[serde(default)]
    pub include_subdomains: bool,
    #[serde(default)]
    pub preload: bool,
}

impl Default for ResponseHstsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_age_secs: default_hsts_max_age_secs(),
            include_subdomains: false,
            preload: false,
        }
    }
}

impl ResponseHstsConfig {
    fn validate(&self, field: &'static str) -> Result<(), ConfigError> {
        if self.enabled && self.max_age_secs == 0 {
            return Err(ConfigError::InvalidResponseHeaderValue { field });
        }
        Ok(())
    }

    pub fn header_value(&self) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let mut value = format!("max-age={}", self.max_age_secs);
        if self.include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if self.preload {
            value.push_str("; preload");
        }
        Some(value)
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeaderPolicyOverlayConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub hardening: Option<ResponseHardeningConfig>,
    #[serde(default)]
    pub metadata: ResponseMetadataOverlayConfig,
    #[serde(default)]
    pub strict_transport_security: Option<Option<String>>,
    #[serde(default)]
    pub hsts: Option<Option<ResponseHstsConfig>>,
    #[serde(default)]
    pub content_security_policy: Option<Option<String>>,
    #[serde(default)]
    pub content_security_policy_report_only: Option<Option<String>>,
    #[serde(default)]
    pub permissions_policy: Option<Option<ResponsePermissionsPolicyConfig>>,
    #[serde(default)]
    pub cross_origin_opener_policy: Option<Option<CrossOriginOpenerPolicy>>,
    #[serde(default)]
    pub cross_origin_resource_policy: Option<Option<CrossOriginResourcePolicy>>,
    #[serde(default)]
    pub cross_origin_embedder_policy: Option<Option<CrossOriginEmbedderPolicy>>,
    #[serde(default)]
    pub x_permitted_cross_domain_policies: Option<Option<PermittedCrossDomainPolicies>>,
    #[serde(default)]
    pub reporting_endpoints: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub x_content_type_options: Option<Option<String>>,
    #[serde(default)]
    pub x_frame_options: Option<Option<String>>,
    #[serde(default)]
    pub referrer_policy: Option<Option<String>>,
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
    #[serde(default)]
    pub rewrite: ResponseHeaderRewriteConfig,
}

impl ResponseHeaderPolicyOverlayConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        self.metadata.validate("vhosts.headers.response.metadata")?;
        validate_optional_header_value(
            "vhosts.headers.response.strict_transport_security",
            self.strict_transport_security
                .as_ref()
                .and_then(Option::as_deref),
        )?;
        if self.strict_transport_security.is_some() && self.hsts.is_some() {
            return Err(ConfigError::InvalidResponseHeaderValue {
                field: "vhosts.headers.response.hsts",
            });
        }
        if let Some(Some(hsts)) = &self.hsts {
            hsts.validate("vhosts.headers.response.hsts")?;
        }
        validate_optional_header_value(
            "vhosts.headers.response.content_security_policy",
            self.content_security_policy
                .as_ref()
                .and_then(Option::as_deref),
        )?;
        validate_optional_header_value(
            "vhosts.headers.response.content_security_policy_report_only",
            self.content_security_policy_report_only
                .as_ref()
                .and_then(Option::as_deref),
        )?;
        if let Some(reporting_endpoints) = &self.reporting_endpoints {
            validate_reporting_endpoints(
                "vhosts.headers.response.reporting_endpoints",
                reporting_endpoints,
            )?;
        }
        validate_optional_header_value(
            "vhosts.headers.response.x_content_type_options",
            self.x_content_type_options
                .as_ref()
                .and_then(Option::as_deref),
        )?;
        validate_optional_header_value(
            "vhosts.headers.response.x_frame_options",
            self.x_frame_options.as_ref().and_then(Option::as_deref),
        )?;
        validate_optional_header_value(
            "vhosts.headers.response.referrer_policy",
            self.referrer_policy.as_ref().and_then(Option::as_deref),
        )?;
        validate_header_add_aliases(
            "vhosts.headers.response",
            &self.set,
            &self.add,
            &self.operations.add,
        )?;
        let unset = self.effective_unset();
        let set = self.effective_set();
        validate_header_mutations("vhosts.headers.response", &unset, &set, &self.append)?;
        self.rewrite.validate("vhosts.headers.response.rewrite")
    }

    pub fn effective_unset(&self) -> Vec<String> {
        combined_header_unset(&self.unset, &self.remove, &self.operations.remove)
    }

    pub fn effective_set(&self) -> BTreeMap<String, String> {
        combined_header_set(&self.set, &self.add, &self.operations.add)
    }
}

fn default_true() -> bool {
    true
}

fn default_hsts_max_age_secs() -> u64 {
    63_072_000
}

fn default_x_content_type_options() -> Option<String> {
    Some("nosniff".to_owned())
}

fn default_x_frame_options() -> Option<String> {
    Some("DENY".to_owned())
}

fn default_referrer_policy() -> Option<String> {
    Some("no-referrer".to_owned())
}

fn default_response_unset_headers() -> Vec<String> {
    vec!["x-powered-by".to_owned()]
}

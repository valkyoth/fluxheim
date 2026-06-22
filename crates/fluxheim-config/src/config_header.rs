use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::{
    ConfigError, MAX_ROUTE_REGEX_CAPTURE_NAME_BYTES, MAX_ROUTE_REGEX_CAPTURE_VALUES,
};

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderPolicyConfig {
    #[serde(default)]
    pub request: RequestHeaderPolicyConfig,
    #[serde(default)]
    pub response: ResponseHeaderPolicyConfig,
}

impl HeaderPolicyConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.request.validate()?;
        self.response.validate()
    }

    pub fn with_vhost_overlay(&self, overlay: &VhostHeaderPolicyConfig) -> Self {
        let mut policy = self.clone();
        policy.request.apply_overlay(&overlay.request);
        policy.response.apply_overlay(&overlay.response);
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
}

impl VhostHeaderPolicyConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.request.validate()?;
        self.response.validate()
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

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeaderPolicyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub strict_transport_security: Option<String>,
    #[serde(default)]
    pub hsts: Option<ResponseHstsConfig>,
    #[serde(default)]
    pub content_security_policy: Option<String>,
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
            strict_transport_security: None,
            hsts: None,
            content_security_policy: None,
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
    fn validate(&self) -> Result<(), ConfigError> {
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

    fn apply_overlay(&mut self, overlay: &ResponseHeaderPolicyOverlayConfig) {
        if let Some(enabled) = overlay.enabled {
            self.enabled = enabled;
        }
        if let Some(value) = &overlay.strict_transport_security {
            self.strict_transport_security = value.clone();
        }
        if let Some(value) = &overlay.hsts {
            self.hsts = value.clone();
        }
        if let Some(value) = &overlay.content_security_policy {
            self.content_security_policy = value.clone();
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
    pub strict_transport_security: Option<Option<String>>,
    #[serde(default)]
    pub hsts: Option<Option<ResponseHstsConfig>>,
    #[serde(default)]
    pub content_security_policy: Option<Option<String>>,
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
    fn validate(&self) -> Result<(), ConfigError> {
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

pub fn validate_optional_header_value(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ConfigError> {
    let Some(value) = value else {
        return Ok(());
    };

    if value.trim().is_empty() || header_value_contains_disallowed_control(value) {
        return Err(ConfigError::InvalidResponseHeaderValue { field });
    }

    Ok(())
}

pub fn validate_header_mutations(
    field: &'static str,
    unset: &[String],
    set: &BTreeMap<String, String>,
    append: &BTreeMap<String, HeaderValues>,
) -> Result<(), ConfigError> {
    validate_header_mutation_len(field, "unset", unset.len(), MAX_HEADER_MUTATION_NAMES)?;
    validate_header_mutation_len(field, "set", set.len(), MAX_HEADER_MUTATION_NAMES)?;
    validate_header_mutation_len(field, "append", append.len(), MAX_HEADER_MUTATION_NAMES)?;

    for name in unset {
        validate_header_name(field, name)?;
    }
    for (name, value) in set {
        validate_header_name(field, name)?;
        validate_header_mutation_value(field, name, value)?;
    }
    for (name, values) in append {
        validate_header_name(field, name)?;
        validate_header_mutation_len(
            field,
            "append values",
            values.len(),
            MAX_HEADER_APPEND_VALUES,
        )?;
        for value in values.iter() {
            validate_header_mutation_value(field, name, value)?;
        }
    }

    Ok(())
}

pub fn validate_no_tls_header_append(
    field: &'static str,
    append: &BTreeMap<String, HeaderValues>,
) -> Result<(), ConfigError> {
    for (name, values) in append {
        if values.iter().any(header_value_uses_tls_template) {
            return Err(ConfigError::UnsafeTlsHeaderAppend {
                field,
                name: name.clone(),
            });
        }
    }
    Ok(())
}

pub fn validate_response_header_rewrite_rules(
    field: &'static str,
    header: &'static str,
    rules: &[ResponseHeaderRewriteRuleConfig],
) -> Result<(), ConfigError> {
    validate_header_mutation_len(
        field,
        header,
        rules.len(),
        MAX_RESPONSE_HEADER_REWRITE_RULES,
    )?;

    let mut seen = std::collections::BTreeSet::new();
    for rule in rules {
        validate_response_header_rewrite_endpoint(field, header, "from", &rule.from)?;
        validate_response_header_rewrite_endpoint(field, header, "to", &rule.to)?;
        if !seen.insert(rule.from.as_str()) {
            return Err(ConfigError::ConflictingHeaderAdd {
                field,
                name: format!("{header}.from"),
            });
        }
    }

    Ok(())
}

pub fn validate_cookie_domain_rewrite_rules(
    field: &'static str,
    rules: &[ResponseHeaderRewriteRuleConfig],
) -> Result<(), ConfigError> {
    validate_header_mutation_len(
        field,
        "cookie_domain",
        rules.len(),
        MAX_RESPONSE_HEADER_REWRITE_RULES,
    )?;

    let mut seen = std::collections::BTreeSet::new();
    for rule in rules {
        validate_cookie_domain_rewrite_endpoint(field, "from", &rule.from)?;
        validate_cookie_domain_rewrite_endpoint(field, "to", &rule.to)?;
        if !seen.insert(rule.from.to_ascii_lowercase()) {
            return Err(ConfigError::ConflictingHeaderAdd {
                field,
                name: "cookie_domain.from".to_owned(),
            });
        }
    }

    Ok(())
}

pub fn validate_cookie_path_rewrite_rules(
    field: &'static str,
    rules: &[ResponseHeaderRewriteRuleConfig],
) -> Result<(), ConfigError> {
    validate_header_mutation_len(
        field,
        "cookie_path",
        rules.len(),
        MAX_RESPONSE_HEADER_REWRITE_RULES,
    )?;

    let mut seen = std::collections::BTreeSet::new();
    for rule in rules {
        validate_cookie_path_rewrite_endpoint(field, "from", &rule.from)?;
        validate_cookie_path_rewrite_endpoint(field, "to", &rule.to)?;
        if !seen.insert(rule.from.as_str()) {
            return Err(ConfigError::ConflictingHeaderAdd {
                field,
                name: "cookie_path.from".to_owned(),
            });
        }
    }

    Ok(())
}

pub fn validate_header_add_aliases(
    field: &'static str,
    set: &BTreeMap<String, String>,
    add: &BTreeMap<String, String>,
    operations_add: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    let mut seen = std::collections::BTreeSet::new();
    for name in set.keys() {
        seen.insert(name.to_ascii_lowercase());
    }
    for name in add.keys().chain(operations_add.keys()) {
        let normalized = name.to_ascii_lowercase();
        if !seen.insert(normalized) {
            return Err(ConfigError::ConflictingHeaderAdd {
                field,
                name: name.clone(),
            });
        }
    }

    Ok(())
}

pub fn combined_header_unset(
    unset: &[String],
    remove: &[String],
    operations_remove: &[String],
) -> Vec<String> {
    let mut combined = Vec::with_capacity(unset.len() + remove.len() + operations_remove.len());
    combined.extend(unset.iter().cloned());
    combined.extend(remove.iter().cloned());
    combined.extend(operations_remove.iter().cloned());
    combined
}

pub fn combined_header_set(
    set: &BTreeMap<String, String>,
    add: &BTreeMap<String, String>,
    operations_add: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut combined = set.clone();
    combined.extend(
        add.iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    combined.extend(
        operations_add
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    combined
}

pub fn merge_header_mutations(
    unset: &mut Vec<String>,
    set: &mut BTreeMap<String, String>,
    append: &mut BTreeMap<String, HeaderValues>,
    overlay_unset: &[String],
    overlay_set: &BTreeMap<String, String>,
    overlay_append: &BTreeMap<String, HeaderValues>,
) {
    unset.extend(overlay_unset.iter().cloned());
    for (name, value) in overlay_set {
        set.insert(name.clone(), value.clone());
    }
    for (name, values) in overlay_append {
        append
            .entry(name.clone())
            .and_modify(|existing| existing.extend(values))
            .or_insert_with(|| values.clone());
    }
}

pub fn validate_header_name(field: &'static str, name: &str) -> Result<(), ConfigError> {
    let normalized = name.trim();
    if normalized != name || !valid_http_header_name(name) {
        return Err(ConfigError::InvalidHeaderName {
            field,
            name: name.to_owned(),
        });
    }

    Ok(())
}

pub fn validate_dynamic_header_template(
    field: &'static str,
    name: &str,
    value: &str,
) -> Result<(), ConfigError> {
    let mut rest = value;
    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return Err(ConfigError::InvalidHeaderTemplate {
                field,
                name: name.to_owned(),
                variable: after_open.to_owned(),
            });
        };
        let variable = &after_open[..close];
        if !valid_dynamic_header_variable(variable) {
            return Err(ConfigError::InvalidHeaderTemplate {
                field,
                name: name.to_owned(),
                variable: variable.to_owned(),
            });
        }
        rest = &after_open[close + 1..];
    }

    if let Some(variable) = rest.split_once('}').map(|(before, _)| before) {
        return Err(ConfigError::InvalidHeaderTemplate {
            field,
            name: name.to_owned(),
            variable: variable.to_owned(),
        });
    }

    Ok(())
}

pub fn valid_dynamic_header_variable(variable: &str) -> bool {
    matches!(
        variable,
        "host"
            | "remote_addr"
            | "scheme"
            | "uri"
            | "path"
            | "query"
            | "request_id"
            | "tls.cipher"
            | "tls.version"
            | "tls.client_cert_organization"
            | "tls.client_cert_serial"
            | "tls.client_cert_sha256"
    ) || variable
        .strip_prefix("route.regex.")
        .is_some_and(valid_route_regex_capture_variable)
        || variable
            .strip_prefix("http.")
            .is_some_and(valid_http_header_name)
}

pub fn valid_route_regex_capture_variable(value: &str) -> bool {
    if value
        .parse::<usize>()
        .is_ok_and(|index| index < MAX_ROUTE_REGEX_CAPTURE_VALUES)
    {
        return true;
    }
    value.len() <= MAX_ROUTE_REGEX_CAPTURE_NAME_BYTES
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub fn valid_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
                    | b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
            )
        })
}

fn header_value_uses_tls_template(value: &str) -> bool {
    let mut rest = value;
    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return false;
        };
        if after_open[..close].starts_with("tls.") {
            return true;
        }
        rest = &after_open[close + 1..];
    }
    false
}

fn validate_header_mutation_value(
    field: &'static str,
    name: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.trim().is_empty() || header_value_contains_disallowed_control(value) {
        return Err(ConfigError::InvalidHeaderValue {
            field,
            name: name.to_owned(),
        });
    }

    validate_dynamic_header_template(field, name, value)?;
    Ok(())
}

fn header_value_contains_disallowed_control(value: &str) -> bool {
    value
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, 0x00..=0x1f | 0x7f))
}

fn validate_response_header_rewrite_endpoint(
    field: &'static str,
    header: &'static str,
    side: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    let valid_prefix =
        value.starts_with("http://") || value.starts_with("https://") || value.starts_with('/');
    let valid_path_prefix = !value.starts_with("//");
    if value.is_empty()
        || value.len() > 2048
        || !valid_prefix
        || !valid_path_prefix
        || header_value_contains_disallowed_control(value)
    {
        return Err(ConfigError::InvalidHeaderValue {
            field,
            name: format!("{header}.{side}"),
        });
    }

    Ok(())
}

fn validate_cookie_domain_rewrite_endpoint(
    field: &'static str,
    side: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed != value
        || value.len() > 255
        || value.starts_with('-')
        || value.ends_with('-')
        || value.contains("..")
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.')))
    {
        return Err(ConfigError::InvalidHeaderValue {
            field,
            name: format!("cookie_domain.{side}"),
        });
    }

    Ok(())
}

fn validate_cookie_path_rewrite_endpoint(
    field: &'static str,
    side: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 2048
        || !value.starts_with('/')
        || value.starts_with("//")
        || value
            .bytes()
            .any(|byte| matches!(byte, 0x00..=0x20 | 0x7f | b';'))
    {
        return Err(ConfigError::InvalidHeaderValue {
            field,
            name: format!("cookie_path.{side}"),
        });
    }

    Ok(())
}

fn validate_header_mutation_len(
    field: &'static str,
    operation: &'static str,
    len: usize,
    max: usize,
) -> Result<(), ConfigError> {
    if len > max {
        return Err(ConfigError::InvalidHeaderMutationLength {
            field,
            operation,
            max,
        });
    }
    Ok(())
}

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, valid_http_token};
use crate::config_header_validation::valid_http_header_name;
use crate::config_http::valid_http_base_url;

const MAX_CORS_ORIGINS: usize = 64;
const MAX_CORS_METHODS: usize = 32;
const MAX_CORS_HEADERS: usize = 64;
const MAX_CORS_MAX_AGE_SECS: u64 = 86_400;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorsPolicyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_origins: Vec<String>,
    #[serde(default = "default_cors_methods")]
    pub allow_methods: Vec<String>,
    #[serde(default)]
    pub allow_headers: Vec<String>,
    #[serde(default)]
    pub expose_headers: Vec<String>,
    #[serde(default)]
    pub allow_credentials: bool,
    #[serde(default)]
    pub max_age_secs: Option<u64>,
}

impl Default for CorsPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_origins: Vec::new(),
            allow_methods: default_cors_methods(),
            allow_headers: Vec::new(),
            expose_headers: Vec::new(),
            allow_credentials: false,
            max_age_secs: None,
        }
    }
}

impl CorsPolicyConfig {
    pub(crate) fn validate(&self, field: &'static str) -> Result<(), ConfigError> {
        if self.allow_origins.len() > MAX_CORS_ORIGINS
            || self.allow_methods.len() > MAX_CORS_METHODS
            || self.allow_headers.len() > MAX_CORS_HEADERS
            || self.expose_headers.len() > MAX_CORS_HEADERS
            || self
                .max_age_secs
                .is_some_and(|value| value > MAX_CORS_MAX_AGE_SECS)
        {
            return Err(ConfigError::InvalidResponseHeaderValue { field });
        }
        if self.enabled && (self.allow_origins.is_empty() || self.allow_methods.is_empty()) {
            return Err(ConfigError::InvalidResponseHeaderValue { field });
        }
        let wildcard = self.allow_origins.iter().any(|origin| origin == "*");
        if (wildcard && self.allow_origins.len() != 1)
            || (wildcard && self.allow_credentials)
            || self
                .allow_origins
                .iter()
                .any(|origin| origin != "*" && !valid_cors_origin(origin))
            || self.allow_methods.iter().any(|method| {
                !valid_http_token(method) || method.bytes().any(|byte| byte.is_ascii_lowercase())
            })
            || self
                .allow_headers
                .iter()
                .chain(self.expose_headers.iter())
                .any(|name| !valid_http_header_name(name))
        {
            return Err(ConfigError::InvalidResponseHeaderValue { field });
        }
        reject_case_insensitive_duplicates(field, &self.allow_origins)?;
        reject_case_insensitive_duplicates(field, &self.allow_methods)?;
        reject_case_insensitive_duplicates(field, &self.allow_headers)?;
        reject_case_insensitive_duplicates(field, &self.expose_headers)
    }

    pub(crate) fn apply_overlay(&mut self, overlay: &CorsPolicyOverlayConfig) {
        if let Some(enabled) = overlay.enabled {
            self.enabled = enabled;
        }
        if let Some(values) = &overlay.allow_origins {
            self.allow_origins = values.clone();
        }
        if let Some(values) = &overlay.allow_methods {
            self.allow_methods = values.clone();
        }
        if let Some(values) = &overlay.allow_headers {
            self.allow_headers = values.clone();
        }
        if let Some(values) = &overlay.expose_headers {
            self.expose_headers = values.clone();
        }
        if let Some(value) = overlay.allow_credentials {
            self.allow_credentials = value;
        }
        if let Some(value) = overlay.max_age_secs {
            self.max_age_secs = value;
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CorsPolicyOverlayConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub allow_origins: Option<Vec<String>>,
    #[serde(default)]
    pub allow_methods: Option<Vec<String>>,
    #[serde(default)]
    pub allow_headers: Option<Vec<String>>,
    #[serde(default)]
    pub expose_headers: Option<Vec<String>>,
    #[serde(default)]
    pub allow_credentials: Option<bool>,
    #[serde(default)]
    pub max_age_secs: Option<Option<u64>>,
}

impl CorsPolicyOverlayConfig {
    pub(crate) fn validate(&self, field: &'static str) -> Result<(), ConfigError> {
        if self
            .allow_origins
            .as_ref()
            .is_some_and(|values| values.len() > MAX_CORS_ORIGINS)
            || self
                .allow_methods
                .as_ref()
                .is_some_and(|values| values.len() > MAX_CORS_METHODS)
            || self
                .allow_headers
                .as_ref()
                .is_some_and(|values| values.len() > MAX_CORS_HEADERS)
            || self
                .expose_headers
                .as_ref()
                .is_some_and(|values| values.len() > MAX_CORS_HEADERS)
            || self
                .max_age_secs
                .flatten()
                .is_some_and(|value| value > MAX_CORS_MAX_AGE_SECS)
        {
            return Err(ConfigError::InvalidResponseHeaderValue { field });
        }
        if let Some(origins) = &self.allow_origins {
            let wildcard = origins.iter().any(|origin| origin == "*");
            if (wildcard && origins.len() != 1)
                || (wildcard && self.allow_credentials == Some(true))
                || origins
                    .iter()
                    .any(|origin| origin != "*" && !valid_cors_origin(origin))
            {
                return Err(ConfigError::InvalidResponseHeaderValue { field });
            }
            reject_case_insensitive_duplicates(field, origins)?;
        }
        if let Some(methods) = &self.allow_methods {
            if methods.iter().any(|method| {
                !valid_http_token(method) || method.bytes().any(|byte| byte.is_ascii_lowercase())
            }) {
                return Err(ConfigError::InvalidResponseHeaderValue { field });
            }
            reject_case_insensitive_duplicates(field, methods)?;
        }
        for headers in [&self.allow_headers, &self.expose_headers]
            .into_iter()
            .flatten()
        {
            if headers.iter().any(|name| !valid_http_header_name(name)) {
                return Err(ConfigError::InvalidResponseHeaderValue { field });
            }
            reject_case_insensitive_duplicates(field, headers)?;
        }
        Ok(())
    }
}

pub fn valid_cors_origin(origin: &str) -> bool {
    let authority = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"));
    origin.len() <= 2048
        && !origin.ends_with('/')
        && !origin.contains(['?', '#'])
        && authority.is_some_and(|authority| !authority.contains('/'))
        && valid_http_base_url(origin)
}

fn reject_case_insensitive_duplicates(
    field: &'static str,
    values: &[String],
) -> Result<(), ConfigError> {
    let mut seen = std::collections::BTreeSet::new();
    if values
        .iter()
        .any(|value| !seen.insert(value.to_ascii_lowercase()))
    {
        return Err(ConfigError::InvalidResponseHeaderValue { field });
    }
    Ok(())
}

fn default_cors_methods() -> Vec<String> {
    vec!["GET".to_owned(), "HEAD".to_owned(), "POST".to_owned()]
}

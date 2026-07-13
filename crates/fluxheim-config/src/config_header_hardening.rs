use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_header_validation::validate_optional_header_value;
use crate::config_http::valid_http_endpoint_url;

const MAX_REPORTING_ENDPOINTS: usize = 16;
const MAX_REPORTING_ENDPOINT_NAME_BYTES: usize = 64;
const MAX_REPORTING_ENDPOINTS_HEADER_BYTES: usize = 16_384;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseHardeningProfile {
    #[default]
    Off,
    Baseline,
    CrossOriginIsolated,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHardeningConfig {
    #[serde(default)]
    pub profile: ResponseHardeningProfile,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponsePermissionsPolicyProfile {
    #[default]
    DenySensitive,
    DenyAll,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePermissionsPolicyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub profile: ResponsePermissionsPolicyProfile,
}

impl Default for ResponsePermissionsPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            profile: ResponsePermissionsPolicyProfile::default(),
        }
    }
}

impl ResponsePermissionsPolicyConfig {
    pub fn header_value(&self) -> Option<&'static str> {
        if !self.enabled {
            return None;
        }
        Some(match self.profile {
            ResponsePermissionsPolicyProfile::DenySensitive => {
                "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
            }
            ResponsePermissionsPolicyProfile::DenyAll => {
                "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), identity-credentials-get=(), idle-detection=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), otp-credentials=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), storage-access=(), usb=(), web-share=(), window-management=(), xr-spatial-tracking=()"
            }
        })
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrossOriginOpenerPolicy {
    UnsafeNone,
    SameOriginAllowPopups,
    SameOrigin,
}

impl CrossOriginOpenerPolicy {
    pub const fn header_value(self) -> &'static str {
        match self {
            Self::UnsafeNone => "unsafe-none",
            Self::SameOriginAllowPopups => "same-origin-allow-popups",
            Self::SameOrigin => "same-origin",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrossOriginResourcePolicy {
    SameSite,
    SameOrigin,
    CrossOrigin,
}

impl CrossOriginResourcePolicy {
    pub const fn header_value(self) -> &'static str {
        match self {
            Self::SameSite => "same-site",
            Self::SameOrigin => "same-origin",
            Self::CrossOrigin => "cross-origin",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrossOriginEmbedderPolicy {
    UnsafeNone,
    RequireCorp,
    Credentialless,
}

impl CrossOriginEmbedderPolicy {
    pub const fn header_value(self) -> &'static str {
        match self {
            Self::UnsafeNone => "unsafe-none",
            Self::RequireCorp => "require-corp",
            Self::Credentialless => "credentialless",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermittedCrossDomainPolicies {
    None,
    MasterOnly,
    ByContentType,
    All,
}

impl PermittedCrossDomainPolicies {
    pub const fn header_value(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MasterOnly => "master-only",
            Self::ByContentType => "by-content-type",
            Self::All => "all",
        }
    }
}

pub(crate) fn validate_reporting_endpoints(
    field: &'static str,
    endpoints: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    if endpoints.len() > MAX_REPORTING_ENDPOINTS {
        return Err(ConfigError::InvalidResponseHeaderValue { field });
    }
    for (name, endpoint) in endpoints {
        if !valid_structured_field_key(name)
            || !endpoint.starts_with("https://")
            || !valid_http_endpoint_url(endpoint)
            || serialize_sf_string(endpoint).is_none()
        {
            return Err(ConfigError::InvalidHeaderValue {
                field,
                name: name.clone(),
            });
        }
        validate_optional_header_value(field, Some(endpoint))?;
    }
    if reporting_endpoints_header_value(endpoints).is_none() && !endpoints.is_empty() {
        return Err(ConfigError::InvalidResponseHeaderValue { field });
    }
    Ok(())
}

pub fn reporting_endpoints_header_value(endpoints: &BTreeMap<String, String>) -> Option<String> {
    if endpoints.is_empty() {
        return None;
    }
    let mut serialized = String::new();
    for (name, endpoint) in endpoints {
        if !valid_structured_field_key(name)
            || !endpoint.starts_with("https://")
            || !valid_http_endpoint_url(endpoint)
        {
            return None;
        }
        let endpoint = serialize_sf_string(endpoint)?;
        let separator_bytes = usize::from(!serialized.is_empty()) * 2;
        let additional_bytes = separator_bytes
            .checked_add(name.len())?
            .checked_add(1)?
            .checked_add(endpoint.len())?;
        if serialized.len().checked_add(additional_bytes)? > MAX_REPORTING_ENDPOINTS_HEADER_BYTES {
            return None;
        }
        if !serialized.is_empty() {
            serialized.push_str(", ");
        }
        serialized.push_str(name);
        serialized.push('=');
        serialized.push_str(&endpoint);
    }
    Some(serialized)
}

fn valid_structured_field_key(name: &str) -> bool {
    if name.len() > MAX_REPORTING_ENDPOINT_NAME_BYTES {
        return false;
    }
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'*'))
        && bytes.all(|byte| {
            matches!(
                byte,
                b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'*'
            )
        })
}

fn serialize_sf_string(value: &str) -> Option<String> {
    if !value.is_ascii() || value.bytes().any(|byte| !(0x20..=0x7e).contains(&byte)) {
        return None;
    }
    let escaped_bytes = value
        .bytes()
        .filter(|byte| matches!(byte, b'"' | b'\\'))
        .count();
    let capacity = value.len().checked_add(escaped_bytes)?.checked_add(2)?;
    let mut serialized = String::with_capacity(capacity);
    serialized.push('"');
    for character in value.chars() {
        if matches!(character, '"' | '\\') {
            serialized.push('\\');
        }
        serialized.push(character);
    }
    serialized.push('"');
    Some(serialized)
}

fn default_true() -> bool {
    true
}

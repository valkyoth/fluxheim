use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_header_validation::{valid_http_header_name, validate_optional_header_value};
use crate::config_http::valid_http_endpoint_url;

const MAX_REPORTING_ENDPOINTS: usize = 16;

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
        if !valid_http_header_name(name) || !valid_http_endpoint_url(endpoint) {
            return Err(ConfigError::InvalidHeaderValue {
                field,
                name: name.clone(),
            });
        }
        validate_optional_header_value(field, Some(endpoint))?;
    }
    Ok(())
}

pub fn reporting_endpoints_header_value(endpoints: &BTreeMap<String, String>) -> Option<String> {
    if endpoints.is_empty() {
        return None;
    }
    Some(
        endpoints
            .iter()
            .map(|(name, endpoint)| format!("{name}=\"{endpoint}\""))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

fn default_true() -> bool {
    true
}

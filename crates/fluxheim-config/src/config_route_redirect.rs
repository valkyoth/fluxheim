use serde::{Deserialize, Serialize};

use crate::config::{AccessPolicyConfig, ConcurrencyLimitConfig, ConfigError, RateLimitConfig};
use crate::config_header::VhostHeaderPolicyConfig;
use crate::config_net::valid_http_authority;
use crate::config_route::{GrpcRouteConfig, RouteConfig};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRedirectConfig {
    pub to: String,
    #[serde(default = "default_route_redirect_status")]
    pub status: u16,
}

impl RouteRedirectConfig {
    pub(crate) fn validate(&self, vhost: &str, route: &str) -> Result<(), ConfigError> {
        if !matches!(self.status, 301 | 302 | 307 | 308) {
            return Err(ConfigError::InvalidRouteRedirectStatus {
                vhost: vhost.to_owned(),
                route: route.to_owned(),
                status: self.status,
            });
        }
        if !valid_redirect_target_template(&self.to) {
            return Err(ConfigError::InvalidRouteRedirectTarget {
                vhost: vhost.to_owned(),
                route: route.to_owned(),
            });
        }
        Ok(())
    }
}

fn default_route_redirect_status() -> u16 {
    308
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostRedirectConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default = "default_route_redirect_status")]
    pub status: u16,
}

impl Default for VhostRedirectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            to: None,
            status: default_route_redirect_status(),
        }
    }
}

impl VhostRedirectConfig {
    pub fn validate(&self, vhost: &str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        let Some(to) = &self.to else {
            return Err(ConfigError::MissingVhostRedirectTarget {
                vhost: vhost.to_owned(),
            });
        };
        RouteRedirectConfig {
            to: to.clone(),
            status: self.status,
        }
        .validate(vhost, "vhost-redirect")
    }

    pub fn route_config(&self) -> Option<RouteConfig> {
        if !self.enabled {
            return None;
        }
        let to = self.to.clone()?;

        Some(RouteConfig {
            name: "vhost-redirect".to_owned(),
            path_exact: None,
            path_prefix: None,
            path_regex: None,
            methods: Vec::new(),
            fallback: true,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: AccessPolicyConfig::default(),
            rate_limit: RateLimitConfig::default(),
            concurrency: ConcurrencyLimitConfig::default(),
            grpc: GrpcRouteConfig::default(),
            redirect: Some(RouteRedirectConfig {
                to,
                status: self.status,
            }),
            proxy: None,
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
        })
    }
}

pub fn valid_redirect_target_template(value: &str) -> bool {
    let value = value.trim();
    if !(value.starts_with("https://") || value.starts_with("http://"))
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || redirect_template_authority_contains(value, "{query}")
        || redirect_template_path_contains(value, "/{path}")
        || redirect_template_path_contains(value, "/{uri}")
    {
        return false;
    }

    let expanded = value
        .replace("{uri}", "/")
        .replace("{path}", "/")
        .replace("{query}", "");
    if expanded.contains('{') || expanded.contains('}') {
        return false;
    }
    if expanded.contains("\\") {
        return false;
    }

    let Some(rest) = expanded
        .strip_prefix("https://")
        .or_else(|| expanded.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    valid_http_authority(authority) && redirect_template_path_safe(&expanded)
}

fn redirect_template_authority_contains(value: &str, needle: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    authority.contains(needle)
}

fn redirect_template_path_contains(value: &str, needle: &str) -> bool {
    redirect_template_path(value).is_some_and(|path| path.contains(needle))
}

fn redirect_template_path_safe(value: &str) -> bool {
    let Some(path) = redirect_template_path(value) else {
        return false;
    };
    !path.contains("//") && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}

fn redirect_template_path(value: &str) -> Option<&str> {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))?;
    let path_and_tail = rest
        .find('/')
        .map(|path_start| &rest[path_start..])
        .unwrap_or_default();
    let path_end = path_and_tail
        .find(['?', '#'])
        .unwrap_or(path_and_tail.len());
    Some(&path_and_tail[..path_end])
}

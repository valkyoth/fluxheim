use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{
    AccessPolicyConfig, ByteSize, CacheConfig, CompressionConfig, ConcurrencyLimitConfig,
    ConfigError, MAX_ROUTE_NAME_BYTES, MAX_ROUTE_REGEX_PROGRAM_BYTES, PhpConfig, ProxyConfig,
    RateLimitConfig, UpstreamHttpVersion, VhostHeaderPolicyConfig, WebConfig, valid_http_token,
};
use crate::config_header::valid_route_regex_capture_variable;
use crate::config_net::valid_http_authority;

const MAX_ROUTE_METHODS: usize = 16;
const MAX_ROUTE_REGEX_BYTES: usize = 4096;

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcRouteConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub require_content_type: bool,
}

impl Default for GrpcRouteConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_content_type: true,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub name: String,
    #[serde(default)]
    pub path_exact: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub path_regex: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub fallback: bool,
    #[serde(default)]
    pub https_redirect_exempt: bool,
    #[serde(default)]
    pub strip_prefix: Option<String>,
    #[serde(default)]
    pub rewrite_prefix: Option<String>,
    #[serde(default)]
    pub rewrite_template: Option<String>,
    #[serde(default)]
    pub max_request_body_bytes: Option<ByteSize>,
    #[serde(default)]
    pub access: AccessPolicyConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub concurrency: ConcurrencyLimitConfig,
    #[serde(default)]
    pub grpc: GrpcRouteConfig,
    #[serde(default)]
    pub redirect: Option<RouteRedirectConfig>,
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,
    #[serde(default)]
    pub web: Option<WebConfig>,
    #[serde(default)]
    pub php: Option<PhpConfig>,
    #[serde(default)]
    pub cache: Option<CacheConfig>,
    #[serde(default)]
    pub compression: Option<CompressionConfig>,
    #[serde(default)]
    pub headers: VhostHeaderPolicyConfig,
}

impl RouteConfig {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(proxy) = &mut self.proxy {
            proxy.resolve_relative_paths(base_dir);
        }
        if let Some(web) = &mut self.web {
            web.resolve_relative_paths(base_dir);
        }
        if let Some(php) = &mut self.php {
            php.resolve_relative_paths(base_dir);
        }
        if let Some(cache) = &mut self.cache {
            cache.resolve_relative_paths(base_dir);
        }
    }

    pub fn validate(&self, vhost: &str, regex_enabled: bool) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::EmptyRouteName {
                vhost: vhost.to_owned(),
            });
        }
        if self.name.len() > MAX_ROUTE_NAME_BYTES {
            return Err(ConfigError::InvalidConfigNameLength {
                field: "vhosts.routes.name",
                max: MAX_ROUTE_NAME_BYTES,
            });
        }

        let matcher_count = usize::from(self.path_exact.is_some())
            + usize::from(self.path_prefix.is_some())
            + usize::from(self.path_regex.is_some())
            + usize::from(self.fallback);
        if matcher_count != 1 {
            return Err(ConfigError::InvalidRouteMatcher {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
            });
        }

        if let Some(path) = &self.path_exact {
            validate_route_path("vhosts.routes.path_exact", path, false).map_err(|_| {
                ConfigError::InvalidRouteMatcher {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                }
            })?;
        }
        if let Some(path) = &self.path_prefix {
            validate_route_path("vhosts.routes.path_prefix", path, true).map_err(|_| {
                ConfigError::InvalidRouteMatcher {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                }
            })?;
        }
        if let Some(pattern) = &self.path_regex {
            if !regex_enabled {
                return Err(ConfigError::RouteRegexDisabled {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                });
            }
            validate_route_regex(pattern).map_err(|_| ConfigError::InvalidRouteRegex {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
            })?;
        }
        validate_route_methods(vhost, &self.name, &self.methods)?;
        if let Some(path) = &self.strip_prefix {
            validate_route_path("vhosts.routes.strip_prefix", path, true).map_err(|_| {
                ConfigError::InvalidRouteStripPrefix {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                }
            })?;
            let Some(prefix) = &self.path_prefix else {
                return Err(ConfigError::InvalidRouteStripPrefix {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                });
            };
            if !prefix.starts_with(path) && !path.starts_with(prefix) {
                return Err(ConfigError::InvalidRouteStripPrefix {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                });
            }
        }
        if let Some(path) = &self.rewrite_prefix {
            validate_route_rewrite_prefix_path(path).map_err(|_| {
                ConfigError::InvalidRouteRewritePrefix {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                }
            })?;
            if self.strip_prefix.is_none() {
                return Err(ConfigError::InvalidRouteRewritePrefix {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                });
            }
        }
        if let Some(template) = &self.rewrite_template {
            validate_route_rewrite_template_path(template).map_err(|_| {
                ConfigError::InvalidRouteRewriteTemplate {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                }
            })?;
            if self.path_regex.is_none()
                || self.strip_prefix.is_some()
                || self.rewrite_prefix.is_some()
            {
                return Err(ConfigError::InvalidRouteRewriteTemplate {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                });
            }
        }
        if self
            .max_request_body_bytes
            .is_some_and(|bytes| bytes.as_u64() == 0)
        {
            return Err(ConfigError::InvalidRouteLimit {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                field: "max_request_body_bytes",
            });
        }
        self.access
            .validate("vhosts.routes.access")
            .map_err(|source| ConfigError::RouteSection {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                section: "access",
                source: Box::new(source),
            })?;
        self.rate_limit
            .validate("vhosts.routes.rate_limit")
            .map_err(|source| ConfigError::RouteSection {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                section: "rate_limit",
                source: Box::new(source),
            })?;
        self.concurrency
            .validate("vhosts.routes.concurrency")
            .map_err(|source| ConfigError::RouteSection {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                section: "concurrency",
                source: Box::new(source),
            })?;
        if self.grpc.enabled && !self.grpc.require_content_type {
            return Err(ConfigError::InvalidRouteGrpcPolicy {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                reason: "require_content_type must remain true for gRPC routes",
            });
        }

        let action_count = usize::from(self.redirect.is_some())
            + usize::from(self.proxy.is_some())
            + usize::from(self.web.is_some())
            + usize::from(self.php.is_some());
        if action_count != 1 {
            return Err(ConfigError::InvalidRouteAction {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
            });
        }

        if let Some(redirect) = &self.redirect {
            redirect.validate(vhost, &self.name)?;
        }
        if let Some(proxy) = &self.proxy {
            proxy
                .validate()
                .map_err(|source| ConfigError::RouteSection {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                    section: "proxy",
                    source: Box::new(source),
                })?;
            if self.grpc.enabled && proxy.upstream_http_version == UpstreamHttpVersion::Http1 {
                return Err(ConfigError::InvalidRouteGrpcPolicy {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                    reason: "gRPC routes require proxy.upstream_http_version = \"http2\" or \"http1-and-http2\"",
                });
            }
        }
        if self.grpc.enabled && self.proxy.is_none() {
            return Err(ConfigError::InvalidRouteGrpcPolicy {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                reason: "gRPC routes must use a proxy action",
            });
        }
        if let Some(web) = &self.web {
            web.validate().map_err(|source| ConfigError::RouteSection {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                section: "web",
                source: Box::new(source),
            })?;
            if !web.enabled() {
                return Err(ConfigError::InvalidRouteAction {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                });
            }
        }
        if let Some(php) = &self.php {
            php.validate("vhosts.routes.php")
                .map_err(|source| ConfigError::RouteSection {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                    section: "php",
                    source: Box::new(source),
                })?;
            if !php.enabled {
                return Err(ConfigError::InvalidRouteAction {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                });
            }
        }
        if let Some(cache) = &self.cache {
            cache
                .validate("vhosts.routes.cache")
                .map_err(|source| ConfigError::RouteSection {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                    section: "cache",
                    source: Box::new(source),
                })?;
            if self.grpc.enabled && cache.enabled {
                return Err(ConfigError::InvalidRouteGrpcPolicy {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                    reason: "gRPC routes cannot enable response caching because trailers and streaming status must pass through",
                });
            }
        }
        if let Some(compression) = &self.compression {
            compression
                .validate()
                .map_err(|source| ConfigError::RouteSection {
                    vhost: vhost.to_owned(),
                    route: self.name.clone(),
                    section: "compression",
                    source: Box::new(source),
                })?;
        }
        self.headers
            .validate()
            .map_err(|source| ConfigError::RouteSection {
                vhost: vhost.to_owned(),
                route: self.name.clone(),
                section: "headers",
                source: Box::new(source),
            })?;
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRedirectConfig {
    pub to: String,
    #[serde(default = "default_route_redirect_status")]
    pub status: u16,
}

impl RouteRedirectConfig {
    fn validate(&self, vhost: &str, route: &str) -> Result<(), ConfigError> {
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

pub fn validate_route_path(
    _field: &'static str,
    value: &str,
    _prefix: bool,
) -> Result<(), ConfigError> {
    if !value.starts_with('/')
        || value.contains('\0')
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value.chars().any(char::is_control)
        || value
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(ConfigError::InvalidRouteMatcher {
            vhost: String::new(),
            route: String::new(),
        });
    }
    Ok(())
}

pub fn validate_route_rewrite_prefix_path(value: &str) -> Result<(), ConfigError> {
    validate_route_path("vhosts.routes.rewrite_prefix", value, true)?;
    if value.contains('%') || value.chars().any(char::is_whitespace) {
        return Err(ConfigError::InvalidRouteMatcher {
            vhost: String::new(),
            route: String::new(),
        });
    }
    Ok(())
}

pub fn validate_route_rewrite_template_path(value: &str) -> Result<(), ConfigError> {
    if !value.starts_with('/')
        || value.contains('\0')
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value.contains('%')
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ConfigError::InvalidRouteMatcher {
            vhost: String::new(),
            route: String::new(),
        });
    }

    let mut rest = value;
    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return Err(ConfigError::InvalidRouteMatcher {
                vhost: String::new(),
                route: String::new(),
            });
        };
        let variable = &after_open[..close];
        if !variable
            .strip_prefix("route.regex.")
            .is_some_and(valid_route_regex_capture_variable)
        {
            return Err(ConfigError::InvalidRouteMatcher {
                vhost: String::new(),
                route: String::new(),
            });
        }
        rest = &after_open[close + 1..];
    }

    if rest.contains('}') {
        return Err(ConfigError::InvalidRouteMatcher {
            vhost: String::new(),
            route: String::new(),
        });
    }

    Ok(())
}

pub fn validate_route_regex(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > MAX_ROUTE_REGEX_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(ConfigError::InvalidRouteRegex {
            vhost: String::new(),
            route: String::new(),
        });
    }
    regex::RegexBuilder::new(value)
        .size_limit(MAX_ROUTE_REGEX_PROGRAM_BYTES)
        .build()
        .map_err(|_| ConfigError::InvalidRouteRegex {
            vhost: String::new(),
            route: String::new(),
        })?;
    Ok(())
}

pub fn validate_route_methods(
    vhost: &str,
    route: &str,
    methods: &[String],
) -> Result<(), ConfigError> {
    if methods.len() > MAX_ROUTE_METHODS {
        return Err(ConfigError::InvalidRouteMethods {
            vhost: vhost.to_owned(),
            route: route.to_owned(),
            reason: "at most 16 methods are allowed",
        });
    }

    let mut seen = HashSet::new();
    for method in methods {
        if method.is_empty()
            || method.len() > 32
            || !valid_http_token(method)
            || method.chars().any(char::is_lowercase)
        {
            return Err(ConfigError::InvalidRouteMethods {
                vhost: vhost.to_owned(),
                route: route.to_owned(),
                reason: "methods must be uppercase HTTP method tokens",
            });
        }
        if !seen.insert(method) {
            return Err(ConfigError::InvalidRouteMethods {
                vhost: vhost.to_owned(),
                route: route.to_owned(),
                reason: "contains duplicate methods",
            });
        }
    }
    Ok(())
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

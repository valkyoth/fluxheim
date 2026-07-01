use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{
    ByteSize, CacheConfig, CompressionConfig, ConcurrencyLimitConfig, ConfigError, MAX_VHOST_HOSTS,
    MAX_VHOST_NAME_BYTES, MAX_VHOST_ROUTES, PhpConfig, ProxyConfig, RateLimitConfig, RouteConfig,
    TlsConfig, VhostAcmeChallengeConfig, VhostHeaderPolicyConfig, VhostRedirectConfig,
    VhostTlsConfig, WebConfig, validate_config_list_len,
};
use crate::config_net::normalize_host_pattern;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostConfig {
    pub name: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub max_request_body_bytes: Option<ByteSize>,
    #[serde(default)]
    pub access: crate::config::AccessPolicyConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub concurrency: ConcurrencyLimitConfig,
    #[serde(default)]
    pub tls: VhostTlsConfig,
    #[serde(default)]
    pub acme_challenge: VhostAcmeChallengeConfig,
    #[serde(default)]
    pub redirect: VhostRedirectConfig,
    #[serde(default = "disabled_proxy_config")]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub compression: Option<CompressionConfig>,
    #[serde(default)]
    pub headers: VhostHeaderPolicyConfig,
    #[serde(default)]
    pub php: PhpConfig,
    #[serde(default)]
    pub web: WebConfig,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

impl VhostConfig {
    pub fn normalized_hosts(&self) -> Vec<String> {
        self.hosts
            .iter()
            .filter_map(|host| normalize_host_pattern(host))
            .collect()
    }

    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.tls.resolve_relative_paths(base_dir);
        self.proxy.resolve_relative_paths(base_dir);
        self.cache.resolve_relative_paths(base_dir);
        self.php.resolve_relative_paths(base_dir);
        self.web.resolve_relative_paths(base_dir);
        for route in &mut self.routes {
            route.resolve_relative_paths(base_dir);
        }
    }

    pub(crate) fn validate(&self, regex_enabled: bool) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::EmptyVhostName);
        }
        if self.name.len() > MAX_VHOST_NAME_BYTES {
            return Err(ConfigError::InvalidConfigNameLength {
                field: "vhosts.name",
                max: MAX_VHOST_NAME_BYTES,
            });
        }

        if self.hosts.is_empty() {
            return Err(ConfigError::EmptyVhostHosts {
                vhost: self.name.clone(),
            });
        }
        validate_config_list_len(
            format!("vhost {:?}.hosts", self.name),
            self.hosts.len(),
            MAX_VHOST_HOSTS,
        )?;
        validate_config_list_len(
            format!("vhost {:?}.routes", self.name),
            self.routes.len(),
            MAX_VHOST_ROUTES,
        )?;

        self.proxy
            .validate()
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "proxy",
                source: Box::new(source),
            })?;
        self.acme_challenge.validate(&self.name)?;
        self.redirect.validate(&self.name)?;
        self.access
            .validate("vhosts.access")
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "access",
                source: Box::new(source),
            })?;
        self.rate_limit
            .validate("vhosts.rate_limit")
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "rate_limit",
                source: Box::new(source),
            })?;
        self.concurrency
            .validate("vhosts.concurrency")
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "concurrency",
                source: Box::new(source),
            })?;
        self.cache
            .validate("vhosts.cache")
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "cache",
                source: Box::new(source),
            })?;
        if let Some(compression) = &self.compression {
            compression
                .validate()
                .map_err(|source| ConfigError::VhostSection {
                    vhost: self.name.clone(),
                    section: "compression",
                    source: Box::new(source),
                })?;
        }
        self.headers
            .validate()
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "headers",
                source: Box::new(source),
            })?;
        self.php
            .validate("vhosts.php")
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "php",
                source: Box::new(source),
            })?;
        self.web
            .validate()
            .map_err(|source| ConfigError::VhostSection {
                vhost: self.name.clone(),
                section: "web",
                source: Box::new(source),
            })?;
        self.validate_routes(regex_enabled)?;
        if matches!(self.max_request_body_bytes, Some(bytes) if bytes.as_u64() == 0) {
            return Err(ConfigError::InvalidVhostLimit {
                vhost: self.name.clone(),
                field: "max_request_body_bytes",
            });
        }

        for host in &self.hosts {
            if normalize_host_pattern(host).is_none() {
                return Err(ConfigError::InvalidVhostHost {
                    vhost: self.name.clone(),
                    host: host.clone(),
                });
            }
        }

        Ok(())
    }

    fn validate_routes(&self, regex_enabled: bool) -> Result<(), ConfigError> {
        let mut fallback_seen = false;
        for route in &self.routes {
            route.validate(&self.name, regex_enabled)?;
            if route.fallback {
                if fallback_seen {
                    return Err(ConfigError::DuplicateFallbackRoute {
                        vhost: self.name.clone(),
                    });
                }
                fallback_seen = true;
            }
        }
        if self.redirect.enabled && fallback_seen {
            return Err(ConfigError::VhostRedirectConflictsWithFallback {
                vhost: self.name.clone(),
            });
        }
        Ok(())
    }

    pub(crate) fn validate_tls(
        &self,
        global_tls: &TlsConfig,
        has_shared_certificate_source: bool,
    ) -> Result<(), ConfigError> {
        self.tls.validate(
            "vhosts.tls",
            &self.hosts,
            global_tls,
            has_shared_certificate_source,
        )
    }
}

fn disabled_proxy_config() -> ProxyConfig {
    ProxyConfig::disabled()
}

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{
    ConfigError, DownstreamProxyProtocol, UpstreamProxyProtocol, validate_config_list_len,
    validate_required_timeout_secs,
};
use crate::config_net::{
    valid_authority, valid_ip_matcher, valid_trusted_proxy, valid_upstream_alias,
};
pub use crate::config_stream_slots::{StreamConnectionSlot, acquire_stream_connection_slot};

pub const MAX_STREAM_ROUTES: usize = 128;
pub const MAX_STREAM_ROUTE_NAME_BYTES: usize = 128;
pub const MAX_STREAM_LISTENERS: usize = 64;
pub const MAX_STREAM_UPSTREAMS: usize = 64;
pub const MAX_STREAM_SOURCE_MATCHERS: usize = 256;
pub const MAX_STREAM_MAX_CONNECTIONS: usize = 1_000_000;
const MAX_STREAM_UPSTREAM_WEIGHT: usize = 1000;
const MAX_STREAM_UPSTREAM_TOTAL_WEIGHT: usize = u16::MAX as usize;

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub routes: Vec<StreamRouteConfig>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamConfigFragment {
    enabled: Option<bool>,
    routes: Option<Vec<StreamRouteConfig>>,
}

impl StreamConfig {
    pub fn merge(&mut self, fragment: StreamConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(routes) = fragment.routes {
            self.routes = routes;
        }
    }

    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        for route in &mut self.routes {
            route.resolve_relative_paths(base_dir);
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled {
            #[cfg(not(feature = "stream-proxy"))]
            return Err(ConfigError::StreamProxyNotCompiled);
            #[cfg(feature = "stream-proxy")]
            if self.routes.is_empty() {
                return Err(ConfigError::InvalidStreamProxyPolicy {
                    field: "stream.routes",
                    reason: "stream.enabled requires at least one stream route",
                });
            }
        } else if !self.routes.is_empty() {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes",
                reason: "stream routes require stream.enabled = true",
            });
        }

        validate_config_list_len("stream.routes", self.routes.len(), MAX_STREAM_ROUTES)?;
        let mut seen_names = HashSet::new();
        let mut seen_listeners = HashSet::new();
        for route in &self.routes {
            route.validate()?;
            if !seen_names.insert(route.name.to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateStreamRouteName {
                    name: route.name.clone(),
                });
            }
            for listen in &route.listen {
                if !seen_listeners.insert(listen.clone()) {
                    return Err(ConfigError::DuplicateStreamListener {
                        listen: listen.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

impl StreamConfigFragment {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(routes) = &mut self.routes {
            for route in routes {
                route.resolve_relative_paths(base_dir);
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamRouteConfig {
    pub name: String,
    #[serde(default)]
    pub listen: Vec<String>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub upstream_weights: Vec<usize>,
    #[serde(default)]
    pub upstream_aliases: Vec<String>,
    #[serde(default)]
    pub backup_upstreams: Vec<String>,
    #[serde(default)]
    pub drain_upstreams: Vec<String>,
    #[serde(default = "default_stream_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_stream_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub max_connection_secs: Option<u64>,
    #[serde(default)]
    pub max_connection_bytes: Option<u64>,
    #[serde(default = "default_stream_max_connections")]
    pub max_connections: usize,
    #[serde(default)]
    pub downstream_proxy_protocol: DownstreamProxyProtocol,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub allow_sources: Vec<String>,
    #[serde(default)]
    pub deny_sources: Vec<String>,
    #[serde(default)]
    pub upstream_proxy_protocol: UpstreamProxyProtocol,
    #[serde(default)]
    pub upstream_tls: bool,
    #[serde(default)]
    pub upstream_dns_allow_private_addresses: bool,
    #[serde(default)]
    pub upstream_sni: Option<String>,
    #[serde(default = "default_true")]
    pub upstream_verify_cert: bool,
    #[serde(default = "default_true")]
    pub upstream_verify_hostname: bool,
    #[serde(default)]
    pub upstream_alternative_cn: Option<String>,
    #[serde(default)]
    pub upstream_ca_path: Option<PathBuf>,
    #[serde(default)]
    pub upstream_client_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub upstream_client_key_path: Option<PathBuf>,
}

impl StreamRouteConfig {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        for path in [
            &mut self.upstream_ca_path,
            &mut self.upstream_client_cert_path,
            &mut self.upstream_client_key_path,
        ]
        .into_iter()
        .flatten()
        {
            if path.is_relative() {
                *path = base_dir.join(&path);
            }
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.name.is_empty() || self.name.len() > MAX_STREAM_ROUTE_NAME_BYTES {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.name",
                reason: "must be 1-128 bytes",
            });
        }
        if self.listen.is_empty() {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.listen",
                reason: "each stream route requires at least one listener",
            });
        }
        validate_config_list_len(
            "stream.routes.listen",
            self.listen.len(),
            MAX_STREAM_LISTENERS,
        )?;
        for listen in &self.listen {
            if listen.parse::<std::net::SocketAddr>().is_err() {
                return Err(ConfigError::InvalidStreamListenAddress {
                    address: listen.clone(),
                });
            }
        }

        if self.upstream.is_some() && !self.upstreams.is_empty() {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.upstream",
                reason: "upstream and upstreams are mutually exclusive",
            });
        }
        let upstream_count = usize::from(self.upstream.is_some()) + self.upstreams.len();
        if upstream_count == 0 {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.upstream",
                reason: "each stream route requires upstream or upstreams",
            });
        }
        validate_config_list_len(
            "stream.routes.upstreams",
            upstream_count,
            MAX_STREAM_UPSTREAMS,
        )?;
        let mut seen_upstreams = HashSet::new();
        for upstream in self.upstreams() {
            if !valid_authority(upstream) {
                return Err(ConfigError::InvalidStreamUpstream {
                    address: upstream.to_owned(),
                });
            }
            if !seen_upstreams.insert(upstream.to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateStreamUpstream {
                    upstream: upstream.to_owned(),
                });
            }
        }
        self.validate_upstream_selection_policy()?;

        validate_required_timeout_secs(
            "stream.routes.connect_timeout_secs",
            self.connect_timeout_secs,
        )?;
        validate_required_timeout_secs("stream.routes.idle_timeout_secs", self.idle_timeout_secs)?;
        validate_optional_timeout_secs(
            "stream.routes.max_connection_secs",
            self.max_connection_secs,
        )?;
        if self.max_connection_bytes == Some(0) {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.max_connection_bytes",
                reason: "must be greater than zero when set",
            });
        }
        if self.max_connections > MAX_STREAM_MAX_CONNECTIONS {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.max_connections",
                reason: "must be at most 1000000; use 0 for unlimited",
            });
        }
        for proxy in &self.trusted_proxies {
            if !valid_trusted_proxy(proxy) {
                return Err(ConfigError::InvalidStreamProxyPolicy {
                    field: "stream.routes.trusted_proxies",
                    reason: "trusted_proxies entries must be IP addresses or CIDR ranges",
                });
            }
        }
        self.validate_source_matchers("stream.routes.allow_sources", &self.allow_sources)?;
        self.validate_source_matchers("stream.routes.deny_sources", &self.deny_sources)?;
        if self.downstream_proxy_protocol != DownstreamProxyProtocol::Off
            && self.trusted_proxies.is_empty()
        {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.downstream_proxy_protocol",
                reason: "downstream_proxy_protocol requires stream route trusted_proxies so client identity cannot be spoofed by direct peers",
            });
        }
        self.validate_upstream_tls_policy()?;
        Ok(())
    }

    pub fn upstreams(&self) -> impl Iterator<Item = &str> {
        self.upstream
            .iter()
            .map(String::as_str)
            .chain(self.upstreams.iter().map(String::as_str))
    }

    fn validate_source_matchers(
        &self,
        field: &'static str,
        matchers: &[String],
    ) -> Result<(), ConfigError> {
        validate_config_list_len(field, matchers.len(), MAX_STREAM_SOURCE_MATCHERS)?;
        let mut seen = HashSet::new();
        for matcher in matchers {
            if !valid_ip_matcher(matcher) {
                return Err(ConfigError::InvalidStreamProxyPolicy {
                    field,
                    reason: "entries must be IP addresses or CIDR ranges",
                });
            }
            if !seen.insert(matcher.to_ascii_lowercase()) {
                return Err(ConfigError::InvalidStreamProxyPolicy {
                    field,
                    reason: "entries must be unique",
                });
            }
        }
        Ok(())
    }

    fn validate_upstream_selection_policy(&self) -> Result<(), ConfigError> {
        if !self.upstream_weights.is_empty() {
            if self.upstream.is_some() || self.upstream_weights.len() != self.upstreams.len() {
                return Err(ConfigError::InvalidStreamProxyPolicy {
                    field: "stream.routes.upstream_weights",
                    reason: "upstream_weights must match stream route upstreams and cannot be used with upstream",
                });
            }
            let mut total_weight = 0usize;
            for weight in &self.upstream_weights {
                if *weight == 0 || *weight > MAX_STREAM_UPSTREAM_WEIGHT {
                    return Err(ConfigError::InvalidStreamProxyPolicy {
                        field: "stream.routes.upstream_weights",
                        reason: "weights must be between 1 and 1000",
                    });
                }
                total_weight = total_weight.saturating_add(*weight);
            }
            if total_weight > MAX_STREAM_UPSTREAM_TOTAL_WEIGHT {
                return Err(ConfigError::InvalidStreamProxyPolicy {
                    field: "stream.routes.upstream_weights",
                    reason: "total upstream weight is too large",
                });
            }
        }
        if !self.upstream_aliases.is_empty() {
            if self.upstream.is_some() || self.upstream_aliases.len() != self.upstreams.len() {
                return Err(ConfigError::InvalidStreamProxyPolicy {
                    field: "stream.routes.upstream_aliases",
                    reason: "upstream_aliases must match stream route upstreams and cannot be used with upstream",
                });
            }
            let mut seen_aliases = HashSet::new();
            for alias in &self.upstream_aliases {
                if !valid_upstream_alias(alias) {
                    return Err(ConfigError::InvalidStreamProxyPolicy {
                        field: "stream.routes.upstream_aliases",
                        reason: "aliases must be 1-64 ASCII letters, digits, dots, dashes, or underscores",
                    });
                }
                if !seen_aliases.insert(alias.to_ascii_lowercase()) {
                    return Err(ConfigError::InvalidStreamProxyPolicy {
                        field: "stream.routes.upstream_aliases",
                        reason: "aliases must be unique case-insensitively",
                    });
                }
            }
        }
        if self.backup_upstreams.is_empty() && self.drain_upstreams.is_empty() {
            return Ok(());
        }
        if self.upstream.is_some() || self.upstreams.len() < 2 {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.upstreams",
                reason: "backup_upstreams and drain_upstreams require upstreams with at least two entries",
            });
        }
        let configured = self
            .upstreams
            .iter()
            .map(|upstream| upstream.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        let backup = validate_stream_upstream_subset(
            "stream.routes.backup_upstreams",
            &self.backup_upstreams,
            &configured,
        )?;
        let drain = validate_stream_upstream_subset(
            "stream.routes.drain_upstreams",
            &self.drain_upstreams,
            &configured,
        )?;
        if !backup.is_disjoint(&drain) {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.backup_upstreams",
                reason: "backup_upstreams and drain_upstreams must not overlap",
            });
        }
        let primary_count = configured.len().saturating_sub(backup.len() + drain.len());
        if primary_count == 0 {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.upstreams",
                reason: "at least one upstream must remain primary and not drained",
            });
        }
        Ok(())
    }
}

fn validate_stream_upstream_subset(
    field: &'static str,
    subset: &[String],
    configured: &HashSet<String>,
) -> Result<HashSet<String>, ConfigError> {
    let mut seen = HashSet::new();
    for upstream in subset {
        let normalized = upstream.to_ascii_lowercase();
        if !configured.contains(&normalized) {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field,
                reason: "entries must exactly match configured upstreams",
            });
        }
        if !seen.insert(normalized) {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field,
                reason: "entries must be unique",
            });
        }
    }
    Ok(seen)
}

impl Default for StreamRouteConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            listen: Vec::new(),
            upstream: None,
            upstreams: Vec::new(),
            upstream_weights: Vec::new(),
            upstream_aliases: Vec::new(),
            backup_upstreams: Vec::new(),
            drain_upstreams: Vec::new(),
            connect_timeout_secs: default_stream_connect_timeout_secs(),
            idle_timeout_secs: default_stream_idle_timeout_secs(),
            max_connection_secs: None,
            max_connection_bytes: None,
            max_connections: DEFAULT_STREAM_MAX_CONNECTIONS,
            downstream_proxy_protocol: DownstreamProxyProtocol::default(),
            trusted_proxies: Vec::new(),
            allow_sources: Vec::new(),
            deny_sources: Vec::new(),
            upstream_proxy_protocol: UpstreamProxyProtocol::default(),
            upstream_tls: false,
            upstream_dns_allow_private_addresses: false,
            upstream_sni: None,
            upstream_verify_cert: true,
            upstream_verify_hostname: true,
            upstream_alternative_cn: None,
            upstream_ca_path: None,
            upstream_client_cert_path: None,
            upstream_client_key_path: None,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_stream_connect_timeout_secs() -> u64 {
    5
}

pub const DEFAULT_STREAM_MAX_CONNECTIONS: usize = 1024;

fn default_stream_idle_timeout_secs() -> u64 {
    300
}

fn default_stream_max_connections() -> usize {
    DEFAULT_STREAM_MAX_CONNECTIONS
}

fn validate_optional_timeout_secs(
    field: &'static str,
    value: Option<u64>,
) -> Result<(), ConfigError> {
    if let Some(value) = value {
        validate_required_timeout_secs(field, value)?;
    }
    Ok(())
}

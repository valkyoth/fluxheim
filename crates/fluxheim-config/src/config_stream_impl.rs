use std::collections::HashSet;
use std::path::Path;

use crate::config::{
    ConfigError, DownstreamProxyProtocol, validate_config_list_len, validate_required_timeout_secs,
};
use crate::config_net::{
    valid_authority, valid_ip_matcher, valid_trusted_proxy, valid_upstream_alias,
};
use crate::config_stream_defaults::validate_stream_optional_timeout_secs;

use super::{
    MAX_STREAM_LISTENERS, MAX_STREAM_MAX_CONNECTIONS, MAX_STREAM_ROUTE_NAME_BYTES,
    MAX_STREAM_ROUTES, MAX_STREAM_SOURCE_MATCHERS, MAX_STREAM_UPSTREAM_TOTAL_WEIGHT,
    MAX_STREAM_UPSTREAM_WEIGHT, MAX_STREAM_UPSTREAMS, StreamConfig, StreamConfigFragment,
    StreamRouteConfig,
};

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
        validate_stream_optional_timeout_secs(
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

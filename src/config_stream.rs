use std::collections::HashSet;
#[cfg(feature = "stream-proxy")]
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};

use crate::config::{
    ConfigError, UpstreamProxyProtocol, validate_config_list_len, validate_required_timeout_secs,
};
use crate::config_net::valid_authority;

pub(crate) const MAX_STREAM_ROUTES: usize = 128;
pub(crate) const MAX_STREAM_ROUTE_NAME_BYTES: usize = 128;
pub(crate) const MAX_STREAM_LISTENERS: usize = 64;
pub(crate) const MAX_STREAM_UPSTREAMS: usize = 64;
pub(crate) const MAX_STREAM_MAX_CONNECTIONS: usize = 1_000_000;

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub routes: Vec<StreamRouteConfig>,
}

impl StreamConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
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
    #[serde(default = "default_stream_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_stream_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub max_connections: usize,
    #[serde(default)]
    pub upstream_proxy_protocol: UpstreamProxyProtocol,
}

impl StreamRouteConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
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

        validate_required_timeout_secs(
            "stream.routes.connect_timeout_secs",
            self.connect_timeout_secs,
        )?;
        validate_required_timeout_secs("stream.routes.idle_timeout_secs", self.idle_timeout_secs)?;
        if self.max_connections > MAX_STREAM_MAX_CONNECTIONS {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.max_connections",
                reason: "must be at most 1000000; use 0 for unlimited",
            });
        }
        Ok(())
    }

    pub(crate) fn upstreams(&self) -> impl Iterator<Item = &str> {
        self.upstream
            .iter()
            .map(String::as_str)
            .chain(self.upstreams.iter().map(String::as_str))
    }
}

impl Default for StreamRouteConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            listen: Vec::new(),
            upstream: None,
            upstreams: Vec::new(),
            connect_timeout_secs: default_stream_connect_timeout_secs(),
            idle_timeout_secs: default_stream_idle_timeout_secs(),
            max_connections: 0,
            upstream_proxy_protocol: UpstreamProxyProtocol::default(),
        }
    }
}

fn default_stream_connect_timeout_secs() -> u64 {
    5
}

fn default_stream_idle_timeout_secs() -> u64 {
    300
}

#[derive(Debug)]
#[cfg(feature = "stream-proxy")]
pub(crate) struct StreamConnectionSlot {
    current: std::sync::Arc<AtomicUsize>,
}

#[cfg(feature = "stream-proxy")]
impl Drop for StreamConnectionSlot {
    fn drop(&mut self) {
        self.current.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(feature = "stream-proxy")]
pub(crate) fn acquire_stream_connection_slot(
    current: &std::sync::Arc<AtomicUsize>,
    max_connections: usize,
) -> Option<StreamConnectionSlot> {
    if max_connections == 0 {
        let mut observed = current.load(Ordering::Acquire);
        loop {
            let next = observed.checked_add(1)?;
            match current.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(StreamConnectionSlot {
                        current: current.clone(),
                    });
                }
                Err(actual) => observed = actual,
            }
        }
    }

    let mut observed = current.load(Ordering::Acquire);
    loop {
        if observed >= max_connections {
            return None;
        }
        let next = observed.checked_add(1)?;
        match current.compare_exchange_weak(observed, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                return Some(StreamConnectionSlot {
                    current: current.clone(),
                });
            }
            Err(actual) => observed = actual,
        }
    }
}

#[cfg(all(test, feature = "stream-proxy"))]
mod tests {
    use super::{StreamConfig, acquire_stream_connection_slot};
    use crate::config::{Config, StreamRouteConfig};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn stream_config_accepts_valid_tcp_route() {
        let config: StreamConfig = toml::from_str(
            r#"
enabled = true

[[routes]]
name = "postgres"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"
"#,
        )
        .unwrap();

        assert!(config.validate().is_ok());
    }

    #[test]
    fn stream_config_rejects_duplicate_listeners() {
        let config: StreamConfig = toml::from_str(
            r#"
enabled = true

[[routes]]
name = "one"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:5432"

[[routes]]
name = "two"
listen = ["127.0.0.1:15432"]
upstream = "127.0.0.1:6432"
"#,
        )
        .unwrap();

        assert!(config.validate().is_err());
    }

    #[test]
    fn stream_enabled_allows_no_http_listeners() {
        let mut config = Config::default();
        config.server.listen = Vec::new();
        config.stream.enabled = true;
        config.stream.routes = vec![StreamRouteConfig {
            name: "postgres".to_owned(),
            listen: vec!["127.0.0.1:15432".to_owned()],
            upstream: Some("127.0.0.1:5432".to_owned()),
            ..StreamRouteConfig::default()
        }];

        assert!(config.validate().is_ok());
    }

    #[test]
    fn stream_connection_slots_respect_limit() {
        let current = Arc::new(AtomicUsize::new(0));
        let first = acquire_stream_connection_slot(&current, 1).unwrap();
        assert!(acquire_stream_connection_slot(&current, 1).is_none());
        drop(first);
        assert_eq!(current.load(Ordering::Acquire), 0);
        assert!(acquire_stream_connection_slot(&current, 1).is_some());
    }
}

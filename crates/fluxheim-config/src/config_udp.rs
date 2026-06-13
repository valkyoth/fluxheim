use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, validate_config_list_len, validate_required_timeout_secs};
use crate::config_net::{valid_authority, valid_upstream_alias};

pub const MAX_UDP_ROUTES: usize = 64;
pub const MAX_UDP_ROUTE_NAME_BYTES: usize = 128;
pub const MAX_UDP_LISTENERS: usize = 64;
pub const MAX_UDP_UPSTREAMS: usize = 64;
pub const MAX_UDP_MAX_SESSIONS: usize = 1_000_000;
pub const MAX_UDP_MAX_SESSIONS_PER_SOURCE: usize = 1_000_000;
pub const MAX_UDP_MAX_RESPONSES_PER_SOURCE_PER_SECOND: usize = 1_000_000;
pub const MAX_UDP_DATAGRAM_BYTES: usize = 65_507;
pub const MAX_UDP_PASSIVE_HEALTH_FAILURES: usize = 1000;
const MAX_UDP_UPSTREAM_WEIGHT: usize = 1000;
const MAX_UDP_UPSTREAM_TOTAL_WEIGHT: usize = u16::MAX as usize;

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UdpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub routes: Vec<UdpRouteConfig>,
}

impl UdpConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled {
            #[cfg(not(feature = "udp-proxy"))]
            return Err(ConfigError::UdpProxyNotCompiled);
            #[cfg(feature = "udp-proxy")]
            if self.routes.is_empty() {
                return Err(ConfigError::InvalidUdpProxyPolicy {
                    field: "udp.routes",
                    reason: "udp.enabled requires at least one UDP route",
                });
            }
        } else if !self.routes.is_empty() {
            return Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes",
                reason: "UDP routes require udp.enabled = true",
            });
        }

        validate_config_list_len("udp.routes", self.routes.len(), MAX_UDP_ROUTES)?;
        let mut seen_names = HashSet::new();
        let mut seen_listeners = HashSet::new();
        for route in &self.routes {
            route.validate()?;
            if !seen_names.insert(route.name.to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateUdpRouteName {
                    name: route.name.clone(),
                });
            }
            for listen in &route.listen {
                if !seen_listeners.insert(listen.clone()) {
                    return Err(ConfigError::DuplicateUdpListener {
                        listen: listen.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdpRouteMode {
    #[default]
    DnsLoadBalance,
    SyslogForward,
    QuicPassThrough,
    GameProxy,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UdpRouteConfig {
    pub name: String,
    #[serde(default)]
    pub mode: UdpRouteMode,
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
    #[serde(default = "default_udp_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_udp_response_timeout_secs")]
    pub response_timeout_secs: u64,
    #[serde(default = "default_udp_max_datagram_bytes")]
    pub max_datagram_bytes: usize,
    #[serde(default = "default_udp_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "default_udp_max_sessions_per_source")]
    pub max_sessions_per_source: usize,
    #[serde(default = "default_udp_max_responses_per_source_per_second")]
    pub max_responses_per_source_per_second: usize,
    #[serde(default = "default_true")]
    pub passive_health_enabled: bool,
    #[serde(default = "default_udp_passive_health_failures")]
    pub passive_health_failures: usize,
    #[serde(default = "default_udp_passive_health_ejection_secs")]
    pub passive_health_ejection_secs: u64,
}

impl UdpRouteConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if matches!(
            self.mode,
            UdpRouteMode::QuicPassThrough | UdpRouteMode::GameProxy
        ) {
            return Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.mode",
                reason: "quic-pass-through and game-proxy are reserved until UDP session affinity is implemented",
            });
        }
        if self.name.is_empty() || self.name.len() > MAX_UDP_ROUTE_NAME_BYTES {
            return Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.name",
                reason: "must be 1-128 bytes",
            });
        }
        if self.listen.is_empty() {
            return Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.listen",
                reason: "each UDP route requires at least one listener",
            });
        }
        validate_config_list_len("udp.routes.listen", self.listen.len(), MAX_UDP_LISTENERS)?;
        for listen in &self.listen {
            if listen.parse::<std::net::SocketAddr>().is_err() {
                return Err(ConfigError::InvalidUdpListenAddress {
                    address: listen.clone(),
                });
            }
        }

        if self.upstream.is_some() && !self.upstreams.is_empty() {
            return Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.upstream",
                reason: "upstream and upstreams are mutually exclusive",
            });
        }
        let upstream_count = usize::from(self.upstream.is_some()) + self.upstreams.len();
        if upstream_count == 0 {
            return Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.upstream",
                reason: "each UDP route requires upstream or upstreams",
            });
        }
        validate_config_list_len("udp.routes.upstreams", upstream_count, MAX_UDP_UPSTREAMS)?;
        let mut seen_upstreams = HashSet::new();
        for upstream in self.upstreams() {
            if !valid_authority(upstream) {
                return Err(ConfigError::InvalidUdpUpstream {
                    address: upstream.to_owned(),
                });
            }
            if !seen_upstreams.insert(upstream.to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateUdpUpstream {
                    upstream: upstream.to_owned(),
                });
            }
        }
        self.validate_upstream_selection_policy()?;

        validate_required_timeout_secs("udp.routes.idle_timeout_secs", self.idle_timeout_secs)?;
        validate_required_timeout_secs(
            "udp.routes.response_timeout_secs",
            self.response_timeout_secs,
        )?;
        if self.response_timeout_secs > self.idle_timeout_secs {
            return Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.response_timeout_secs",
                reason: "must be less than or equal to idle_timeout_secs",
            });
        }
        if self.max_datagram_bytes == 0 || self.max_datagram_bytes > MAX_UDP_DATAGRAM_BYTES {
            return Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.max_datagram_bytes",
                reason: "must be between 1 and 65507 bytes",
            });
        }
        if self.max_sessions > MAX_UDP_MAX_SESSIONS {
            return Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.max_sessions",
                reason: "must be at most 1000000; use 0 for unlimited",
            });
        }
        if self.max_sessions_per_source > MAX_UDP_MAX_SESSIONS_PER_SOURCE {
            return Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.max_sessions_per_source",
                reason: "must be at most 1000000; use 0 for unlimited",
            });
        }
        if self.max_responses_per_source_per_second > MAX_UDP_MAX_RESPONSES_PER_SOURCE_PER_SECOND {
            return Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.max_responses_per_source_per_second",
                reason: "must be at most 1000000; use 0 for unlimited",
            });
        }
        if self.passive_health_enabled {
            if self.passive_health_failures == 0
                || self.passive_health_failures > MAX_UDP_PASSIVE_HEALTH_FAILURES
            {
                return Err(ConfigError::InvalidUdpProxyPolicy {
                    field: "udp.routes.passive_health_failures",
                    reason: "must be between 1 and 1000 when passive health is enabled",
                });
            }
            validate_required_timeout_secs(
                "udp.routes.passive_health_ejection_secs",
                self.passive_health_ejection_secs,
            )?;
        }
        Ok(())
    }

    pub fn upstreams(&self) -> impl Iterator<Item = &str> {
        self.upstream
            .iter()
            .map(String::as_str)
            .chain(self.upstreams.iter().map(String::as_str))
    }

    fn validate_upstream_selection_policy(&self) -> Result<(), ConfigError> {
        if !self.upstream_weights.is_empty() {
            if self.upstream.is_some() || self.upstream_weights.len() != self.upstreams.len() {
                return Err(ConfigError::InvalidUdpProxyPolicy {
                    field: "udp.routes.upstream_weights",
                    reason: "must match upstreams length and cannot be used with single upstream",
                });
            }
            let total = self
                .upstream_weights
                .iter()
                .try_fold(0usize, |sum, weight| {
                    if *weight == 0 || *weight > MAX_UDP_UPSTREAM_WEIGHT {
                        return None;
                    }
                    sum.checked_add(*weight)
                })
                .filter(|total| *total <= MAX_UDP_UPSTREAM_TOTAL_WEIGHT);
            if total.is_none() {
                return Err(ConfigError::InvalidUdpProxyPolicy {
                    field: "udp.routes.upstream_weights",
                    reason: "weights must be 1-1000 and total weight must be at most 65535",
                });
            }
        }

        if !self.upstream_aliases.is_empty() {
            if self.upstream.is_some() || self.upstream_aliases.len() != self.upstreams.len() {
                return Err(ConfigError::InvalidUdpProxyPolicy {
                    field: "udp.routes.upstream_aliases",
                    reason: "must match upstreams length and cannot be used with single upstream",
                });
            }
            let mut aliases = HashSet::new();
            for alias in &self.upstream_aliases {
                if !valid_upstream_alias(alias) {
                    return Err(ConfigError::InvalidUdpProxyPolicy {
                        field: "udp.routes.upstream_aliases",
                        reason: "aliases must be 1-128 bytes and contain only ASCII letters, digits, '.', '_', ':' or '-'",
                    });
                }
                if !aliases.insert(alias.to_ascii_lowercase()) {
                    return Err(ConfigError::InvalidUdpProxyPolicy {
                        field: "udp.routes.upstream_aliases",
                        reason: "aliases must be unique per route",
                    });
                }
            }
        }

        Ok(())
    }
}

const fn default_udp_idle_timeout_secs() -> u64 {
    30
}

const fn default_udp_response_timeout_secs() -> u64 {
    3
}

const fn default_udp_max_datagram_bytes() -> usize {
    4096
}

const fn default_udp_max_sessions() -> usize {
    4096
}

const fn default_udp_max_sessions_per_source() -> usize {
    64
}

const fn default_udp_max_responses_per_source_per_second() -> usize {
    256
}

const fn default_udp_passive_health_failures() -> usize {
    3
}

const fn default_udp_passive_health_ejection_secs() -> u64 {
    10
}

const fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::{UdpConfig, UdpRouteConfig, UdpRouteMode};
    use crate::config::ConfigError;

    fn route() -> UdpRouteConfig {
        UdpRouteConfig {
            name: "dns-edge".to_owned(),
            mode: UdpRouteMode::DnsLoadBalance,
            listen: vec!["127.0.0.1:5353".to_owned()],
            upstream: None,
            upstreams: vec!["192.0.2.10:53".to_owned(), "192.0.2.11:53".to_owned()],
            upstream_weights: vec![1, 2],
            upstream_aliases: vec!["dns-a".to_owned(), "dns-b".to_owned()],
            idle_timeout_secs: 30,
            response_timeout_secs: 3,
            max_datagram_bytes: 1232,
            max_sessions: 4096,
            max_sessions_per_source: 64,
            max_responses_per_source_per_second: 256,
            passive_health_enabled: true,
            passive_health_failures: 3,
            passive_health_ejection_secs: 10,
        }
    }

    #[test]
    fn disabled_udp_config_accepts_no_routes() {
        UdpConfig::default().validate().unwrap();
    }

    #[test]
    fn disabled_udp_config_rejects_routes() {
        let config = UdpConfig {
            enabled: false,
            routes: vec![route()],
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidUdpProxyPolicy { field, .. }) if field == "udp.routes"
        ));
    }

    #[cfg(not(feature = "udp-proxy"))]
    #[test]
    fn enabled_udp_config_rejects_when_not_compiled() {
        let config = UdpConfig {
            enabled: true,
            routes: vec![route()],
        };
        assert_eq!(config.validate(), Err(ConfigError::UdpProxyNotCompiled));
    }

    #[test]
    fn udp_route_rejects_oversized_datagrams() {
        let mut route = route();
        route.max_datagram_bytes = super::MAX_UDP_DATAGRAM_BYTES + 1;
        assert!(matches!(
            route.validate(),
            Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.max_datagram_bytes",
                ..
            })
        ));
    }

    #[test]
    fn udp_route_rejects_oversized_source_limits() {
        let mut route = route();
        route.max_sessions_per_source = super::MAX_UDP_MAX_SESSIONS_PER_SOURCE + 1;
        assert!(matches!(
            route.validate(),
            Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.max_sessions_per_source",
                ..
            })
        ));

        let mut route = route();
        route.max_responses_per_source_per_second =
            super::MAX_UDP_MAX_RESPONSES_PER_SOURCE_PER_SECOND + 1;
        assert!(matches!(
            route.validate(),
            Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.max_responses_per_source_per_second",
                ..
            })
        ));
    }

    #[test]
    fn udp_route_rejects_invalid_passive_health_policy() {
        let mut route = route();
        route.passive_health_failures = 0;
        assert!(matches!(
            route.validate(),
            Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.passive_health_failures",
                ..
            })
        ));

        let mut route = route();
        route.passive_health_ejection_secs = 0;
        assert!(matches!(
            route.validate(),
            Err(ConfigError::InvalidConfig { field, .. })
                if field == "udp.routes.passive_health_ejection_secs"
        ));

        let mut route = route();
        route.passive_health_enabled = false;
        route.passive_health_failures = 0;
        route.passive_health_ejection_secs = 0;
        route.validate().unwrap();
    }

    #[test]
    fn udp_route_rejects_response_timeout_above_idle_timeout() {
        let mut route = route();
        route.idle_timeout_secs = 2;
        route.response_timeout_secs = 3;
        assert!(matches!(
            route.validate(),
            Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.response_timeout_secs",
                ..
            })
        ));
    }

    #[test]
    fn udp_route_rejects_duplicate_upstreams() {
        let mut route = route();
        route.upstreams = vec!["192.0.2.10:53".to_owned(), "192.0.2.10:53".to_owned()];
        route.upstream_weights.clear();
        route.upstream_aliases.clear();
        assert!(matches!(
            route.validate(),
            Err(ConfigError::DuplicateUdpUpstream { .. })
        ));
    }

    #[test]
    fn udp_route_rejects_reserved_session_modes() {
        let mut route = route();
        route.mode = UdpRouteMode::QuicPassThrough;
        assert!(matches!(
            route.validate(),
            Err(ConfigError::InvalidUdpProxyPolicy {
                field: "udp.routes.mode",
                ..
            })
        ));
    }

    #[cfg(feature = "udp-proxy")]
    #[test]
    fn udp_enabled_allows_empty_http_listeners() {
        let mut config = crate::config::Config::default();
        config.server.listen.clear();
        config.server.tls_listen.clear();
        config.udp = UdpConfig {
            enabled: true,
            routes: vec![route()],
        };

        config.validate().unwrap();
    }
}

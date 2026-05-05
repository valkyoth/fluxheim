use crate::config::Config;
#[cfg(feature = "load-balancer")]
use crate::config::{ProxyConfig, VhostConfig};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReloadImpact {
    Noop,
    Snapshot,
    ProcessUpgrade { reasons: Vec<ReloadReason> },
}

impl ReloadImpact {
    pub fn is_snapshot_safe(&self) -> bool {
        matches!(self, Self::Noop | Self::Snapshot)
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Noop => "noop",
            Self::Snapshot => "snapshot",
            Self::ProcessUpgrade { .. } => "process-upgrade",
        }
    }

    pub fn reasons(&self) -> &[ReloadReason] {
        match self {
            Self::ProcessUpgrade { reasons } => reasons,
            Self::Noop | Self::Snapshot => &[],
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReloadReason {
    ListenerChanged,
    LoggingRuntimeChanged,
    TlsModeChanged,
    TlsBackendChanged,
    AdminServiceChanged,
    MetricsServiceChanged,
    LoadBalancerServicesChanged,
}

impl std::fmt::Display for ReloadImpact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Noop => formatter.write_str("noop"),
            Self::Snapshot => formatter.write_str("snapshot"),
            Self::ProcessUpgrade { reasons } => {
                formatter.write_str("process-upgrade")?;
                if !reasons.is_empty() {
                    formatter.write_str(": ")?;
                    for (index, reason) in reasons.iter().enumerate() {
                        if index > 0 {
                            formatter.write_str(", ")?;
                        }
                        write!(formatter, "{reason}")?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl std::fmt::Display for ReloadReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ListenerChanged => "listener-changed",
            Self::LoggingRuntimeChanged => "logging-runtime-changed",
            Self::TlsModeChanged => "tls-mode-changed",
            Self::TlsBackendChanged => "tls-backend-changed",
            Self::AdminServiceChanged => "admin-service-changed",
            Self::MetricsServiceChanged => "metrics-service-changed",
            Self::LoadBalancerServicesChanged => "load-balancer-services-changed",
        })
    }
}

pub fn classify_reload(old: &Config, new: &Config) -> ReloadImpact {
    if old == new {
        return ReloadImpact::Noop;
    }

    let mut reasons = Vec::new();

    if old.server.listen != new.server.listen || old.server.tls_listen != new.server.tls_listen {
        reasons.push(ReloadReason::ListenerChanged);
    }

    if old.logging.level != new.logging.level || old.logging.format != new.logging.format {
        reasons.push(ReloadReason::LoggingRuntimeChanged);
    }

    if old.tls.enabled != new.tls.enabled {
        reasons.push(ReloadReason::TlsModeChanged);
    }

    if old.tls.backend != new.tls.backend {
        reasons.push(ReloadReason::TlsBackendChanged);
    }

    if old.admin != new.admin {
        reasons.push(ReloadReason::AdminServiceChanged);
    }

    if old.metrics != new.metrics {
        reasons.push(ReloadReason::MetricsServiceChanged);
    }

    #[cfg(feature = "load-balancer")]
    if load_balancer_service_signature(old) != load_balancer_service_signature(new) {
        reasons.push(ReloadReason::LoadBalancerServicesChanged);
    }

    if reasons.is_empty() {
        ReloadImpact::Snapshot
    } else {
        ReloadImpact::ProcessUpgrade { reasons }
    }
}

#[cfg(feature = "load-balancer")]
fn load_balancer_service_signature(config: &Config) -> Vec<(String, Vec<String>, bool)> {
    if config.vhosts.is_empty() {
        return proxy_load_balancer_signature("default", &config.proxy)
            .into_iter()
            .collect();
    }

    config
        .vhosts
        .iter()
        .filter_map(vhost_load_balancer_signature)
        .collect()
}

#[cfg(feature = "load-balancer")]
fn vhost_load_balancer_signature(vhost: &VhostConfig) -> Option<(String, Vec<String>, bool)> {
    proxy_load_balancer_signature(&vhost.name, &vhost.proxy)
}

#[cfg(feature = "load-balancer")]
fn proxy_load_balancer_signature(
    name: &str,
    proxy: &ProxyConfig,
) -> Option<(String, Vec<String>, bool)> {
    if proxy.upstreams.is_empty() {
        return None;
    }

    Some((
        name.to_owned(),
        proxy.upstreams.clone(),
        proxy.load_balance.health_check.enabled,
    ))
}

#[cfg(test)]
mod tests {
    use crate::config::{
        AdminConfig, Config, LoggingConfig, LoggingFormat, LoggingLevel, MetricsConfig,
        ProxyConfig, ServerConfig, TlsBackend, TlsConfig, VhostConfig, WebConfig,
    };

    use super::{ReloadImpact, ReloadReason, classify_reload};

    #[test]
    fn unchanged_config_is_noop() {
        let config = Config::default();

        assert_eq!(classify_reload(&config, &config), ReloadImpact::Noop);
        assert_eq!(classify_reload(&config, &config).kind(), "noop");
        assert!(classify_reload(&config, &config).is_snapshot_safe());
    }

    #[test]
    fn vhost_policy_change_is_snapshot_reload() {
        let old = Config::default();
        let new = Config {
            vhosts: vec![VhostConfig {
                name: "example".to_owned(),
                hosts: vec!["example.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };

        assert_eq!(classify_reload(&old, &new), ReloadImpact::Snapshot);
        assert_eq!(classify_reload(&old, &new).to_string(), "snapshot");
        assert!(classify_reload(&old, &new).is_snapshot_safe());
    }

    #[test]
    fn listener_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            server: ServerConfig {
                listen: vec!["127.0.0.1:18081".to_owned()],
                ..ServerConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::ListenerChanged]
            }
        );
        assert_eq!(
            classify_reload(&old, &new).to_string(),
            "process-upgrade: listener-changed"
        );
        assert!(!classify_reload(&old, &new).is_snapshot_safe());
        assert_eq!(
            classify_reload(&old, &new).reasons(),
            &[ReloadReason::ListenerChanged]
        );
    }

    #[test]
    fn logging_runtime_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            logging: LoggingConfig {
                level: LoggingLevel::Debug,
                ..LoggingConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::LoggingRuntimeChanged]
            }
        );
        assert_eq!(
            classify_reload(&old, &new).to_string(),
            "process-upgrade: logging-runtime-changed"
        );
    }

    #[test]
    fn logging_format_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            logging: LoggingConfig {
                format: LoggingFormat::Text,
                ..LoggingConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::LoggingRuntimeChanged]
            }
        );
    }

    #[test]
    fn tls_listener_address_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            server: ServerConfig {
                tls_listen: vec!["127.0.0.1:18443".to_owned()],
                ..ServerConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::ListenerChanged]
            }
        );
    }

    #[test]
    fn tls_listener_mode_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            tls: TlsConfig {
                enabled: true,
                ..TlsConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::TlsModeChanged]
            }
        );
    }

    #[test]
    fn tls_backend_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            tls: TlsConfig {
                backend: TlsBackend::Openssl,
                ..TlsConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::TlsBackendChanged]
            }
        );
    }

    #[test]
    fn admin_service_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            admin: AdminConfig {
                listen: "127.0.0.1:19090".to_owned(),
                ..AdminConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::AdminServiceChanged]
            }
        );
        assert_eq!(
            classify_reload(&old, &new).to_string(),
            "process-upgrade: admin-service-changed"
        );
    }

    #[test]
    fn metrics_service_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            metrics: MetricsConfig {
                enabled: true,
                ..MetricsConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::MetricsServiceChanged]
            }
        );
        assert_eq!(
            classify_reload(&old, &new).to_string(),
            "process-upgrade: metrics-service-changed"
        );
    }

    #[cfg(feature = "load-balancer")]
    #[test]
    fn load_balancer_service_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            proxy: ProxyConfig {
                upstreams: vec!["127.0.0.1:3001".to_owned()],
                ..ProxyConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::LoadBalancerServicesChanged]
            }
        );
    }
}

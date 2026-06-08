use crate::config::Config;
#[cfg(feature = "load-balancer")]
use crate::config::{ProxyConfig, VhostConfig};
#[cfg(feature = "load-balancer")]
use std::path::PathBuf;

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
    ProcessSettingsChanged,
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
            Self::ProcessSettingsChanged => "process-settings-changed",
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

    if old.server.process != new.server.process {
        reasons.push(ReloadReason::ProcessSettingsChanged);
    }

    if old.logging.level != new.logging.level
        || old.logging.format != new.logging.format
        || old.logging.target != new.logging.target
        || old.logging.file != new.logging.file
    {
        reasons.push(ReloadReason::LoggingRuntimeChanged);
    }

    if old.tls.enabled != new.tls.enabled {
        reasons.push(ReloadReason::TlsModeChanged);
    }

    if old.tls.backend != new.tls.backend {
        reasons.push(ReloadReason::TlsBackendChanged);
    }

    if old.tls.profile != new.tls.profile
        || old.tls.min_protocol != new.tls.min_protocol
        || old.tls.alpn != new.tls.alpn
        || old.tls.curve_preferences != new.tls.curve_preferences
        || old.tls.cipher_suites != new.tls.cipher_suites
        || old.tls.fips != new.tls.fips
    {
        reasons.push(ReloadReason::TlsModeChanged);
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
#[derive(Debug, Clone, Eq, PartialEq)]
struct LoadBalancerServiceSignature {
    vhost: String,
    route: Option<String>,
    source: LoadBalancerServiceSource,
    health_check_enabled: bool,
}

#[cfg(feature = "load-balancer")]
#[derive(Debug, Clone, Eq, PartialEq)]
enum LoadBalancerServiceSource {
    Static {
        upstreams: Vec<String>,
    },
    File {
        path: PathBuf,
        refresh_secs: u64,
    },
    Http {
        url: String,
        refresh_secs: u64,
        bearer_token_file: Option<PathBuf>,
    },
    Dns {
        upstreams: Vec<String>,
        refresh_secs: u64,
    },
}

#[cfg(feature = "load-balancer")]
fn load_balancer_service_signature(config: &Config) -> Vec<LoadBalancerServiceSignature> {
    if config.vhosts.is_empty() {
        return proxy_load_balancer_signature("default", None, &config.proxy)
            .into_iter()
            .collect();
    }

    config
        .vhosts
        .iter()
        .flat_map(vhost_load_balancer_signatures)
        .collect()
}

#[cfg(feature = "load-balancer")]
fn vhost_load_balancer_signatures(vhost: &VhostConfig) -> Vec<LoadBalancerServiceSignature> {
    let mut signatures = Vec::new();
    if let Some(signature) = proxy_load_balancer_signature(&vhost.name, None, &vhost.proxy) {
        signatures.push(signature);
    }
    signatures.extend(vhost.routes.iter().filter_map(|route| {
        route.proxy.as_ref().and_then(|proxy| {
            proxy_load_balancer_signature(&vhost.name, Some(route.name.as_str()), proxy)
        })
    }));
    signatures
}

#[cfg(feature = "load-balancer")]
fn proxy_load_balancer_signature(
    vhost: &str,
    route: Option<&str>,
    proxy: &ProxyConfig,
) -> Option<LoadBalancerServiceSignature> {
    let source = if let Some(path) = &proxy.upstreams_file {
        LoadBalancerServiceSource::File {
            path: path.clone(),
            refresh_secs: proxy.upstreams_file_refresh_secs,
        }
    } else if let Some(url) = &proxy.upstreams_http_url {
        LoadBalancerServiceSource::Http {
            url: url.clone(),
            refresh_secs: proxy.upstreams_http_refresh_secs,
            bearer_token_file: proxy.upstreams_http_bearer_token_file.clone(),
        }
    } else if let Some(refresh_secs) = proxy.upstream_dns_refresh_secs {
        LoadBalancerServiceSource::Dns {
            upstreams: proxy.upstreams.clone(),
            refresh_secs,
        }
    } else if proxy.upstreams.len() >= 2 {
        LoadBalancerServiceSource::Static {
            upstreams: proxy.upstreams.clone(),
        }
    } else {
        return None;
    };

    Some(LoadBalancerServiceSignature {
        vhost: vhost.to_owned(),
        route: route.map(str::to_owned),
        source,
        health_check_enabled: proxy.load_balance.health_check.enabled,
    })
}

#[cfg(test)]
mod tests {
    use crate::config::{
        AdminConfig, Config, HttpsRedirectConfig, LoggingConfig, LoggingFileConfig, LoggingFormat,
        LoggingLevel, LoggingTarget, MetricsConfig, ProxyConfig, ServerConfig, ServerProcessConfig,
        TlsBackend, TlsCipherSuite, TlsConfig, TlsCurvePreference, TlsFipsConfig, TlsPolicyProfile,
        VhostConfig, WebConfig,
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
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                compression: None,
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };

        assert_eq!(classify_reload(&old, &new), ReloadImpact::Snapshot);
        assert_eq!(classify_reload(&old, &new).to_string(), "snapshot");
        assert!(classify_reload(&old, &new).is_snapshot_safe());
    }

    #[test]
    fn https_redirect_policy_change_is_snapshot_reload() {
        let old = Config {
            server: ServerConfig {
                tls_listen: vec!["127.0.0.1:18443".to_owned()],
                ..ServerConfig::default()
            },
            tls: TlsConfig {
                enabled: true,
                certificates: vec![crate::config::StaticCertificateConfig {
                    cert_path: "fullchain.pem".into(),
                    key_path: "key.pem".into(),
                }],
                ..TlsConfig::default()
            },
            ..Config::default()
        };
        let new = Config {
            server: ServerConfig {
                https_redirect: HttpsRedirectConfig {
                    enabled: true,
                    status: 308,
                    target_port: Some(8443),
                },
                ..old.server.clone()
            },
            ..old.clone()
        };

        assert_eq!(classify_reload(&old, &new), ReloadImpact::Snapshot);
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
    fn process_settings_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            server: ServerConfig {
                process: ServerProcessConfig {
                    threads: 4,
                    ..ServerProcessConfig::default()
                },
                ..ServerConfig::default()
            },
            ..Config::default()
        };

        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::ProcessSettingsChanged]
            }
        );
        assert_eq!(
            classify_reload(&old, &new).to_string(),
            "process-upgrade: process-settings-changed"
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
    fn logging_target_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            logging: LoggingConfig {
                target: LoggingTarget::Stdout,
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
    fn logging_file_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            logging: LoggingConfig {
                file: LoggingFileConfig {
                    enabled: true,
                    path: Some("/var/log/fluxheim/fluxheim.log".into()),
                    append: true,
                },
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
    fn tls_policy_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            tls: TlsConfig {
                profile: TlsPolicyProfile::Modern,
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
    fn tls_fips_change_requires_process_upgrade() {
        let old = Config::default();
        let new = Config {
            tls: TlsConfig {
                fips: TlsFipsConfig {
                    required: true,
                    require_disk_cache_encryption: false,
                },
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
    fn tls_cipher_and_curve_changes_require_process_upgrade() {
        let old = Config::default();
        let new = Config {
            tls: TlsConfig {
                curve_preferences: vec![TlsCurvePreference::P256],
                cipher_suites: vec![TlsCipherSuite::Tls13Aes256GcmSha384],
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
                upstream: None,
                upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
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

    #[cfg(feature = "load-balancer")]
    #[test]
    fn load_balancer_dynamic_discovery_change_requires_process_upgrade() {
        let old = Config {
            proxy: ProxyConfig {
                upstream: None,
                upstreams_file: Some("/run/fluxheim/backends-a.txt".into()),
                upstreams_file_refresh_secs: 5,
                ..ProxyConfig::default()
            },
            ..Config::default()
        };
        let new = Config {
            proxy: ProxyConfig {
                upstream: None,
                upstreams_file: Some("/run/fluxheim/backends-b.txt".into()),
                upstreams_file_refresh_secs: 10,
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

    #[cfg(feature = "load-balancer")]
    #[test]
    fn load_balancer_http_discovery_change_requires_process_upgrade() {
        let old = Config {
            proxy: ProxyConfig {
                upstream: None,
                upstreams_http_url: Some("https://discovery.example.test/v1/upstreams".to_owned()),
                upstreams_http_refresh_secs: 5,
                upstreams_http_bearer_token_file: Some("/run/secrets/discovery-token-a".into()),
                ..ProxyConfig::default()
            },
            ..Config::default()
        };
        let new = Config {
            proxy: ProxyConfig {
                upstream: None,
                upstreams_http_url: Some("https://discovery.example.test/v2/upstreams".to_owned()),
                upstreams_http_refresh_secs: 15,
                upstreams_http_bearer_token_file: Some("/run/secrets/discovery-token-b".into()),
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

    #[cfg(feature = "load-balancer")]
    #[test]
    fn load_balancer_dns_refresh_change_requires_process_upgrade() {
        let old = Config {
            proxy: ProxyConfig {
                upstream: None,
                upstreams: vec!["app.service.local:8080".to_owned()],
                upstream_dns_refresh_secs: Some(5),
                ..ProxyConfig::default()
            },
            ..Config::default()
        };
        let new = Config {
            proxy: ProxyConfig {
                upstream: None,
                upstreams: vec!["app.service.local:8080".to_owned()],
                upstream_dns_refresh_secs: Some(30),
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

    #[cfg(feature = "load-balancer")]
    #[test]
    fn route_load_balancer_service_change_requires_process_upgrade() {
        let mut old = Config {
            vhosts: vec![VhostConfig {
                name: "example".to_owned(),
                hosts: vec!["example.test".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                compression: None,
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        };
        let mut new = old.clone();
        new.vhosts[0].routes.push(crate::config::RouteConfig {
            name: "api".to_owned(),
            path_prefix: Some("/api/".to_owned()),
            proxy: Some(ProxyConfig {
                upstream: None,
                upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
                ..ProxyConfig::default()
            }),
            path_exact: None,
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: crate::config::GrpcRouteConfig::default(),
            redirect: None,
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
        });

        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::LoadBalancerServicesChanged]
            }
        );
        old.vhosts[0].routes = new.vhosts[0].routes.clone();
        old.vhosts[0].routes[0].proxy.as_mut().unwrap().upstreams[1] = "127.0.0.1:3003".to_owned();
        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::LoadBalancerServicesChanged]
            }
        );
    }
}

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

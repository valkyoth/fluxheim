use crate::config::Config;
#[cfg(feature = "load-balancer")]
use crate::config::{ProxyConfig, VhostConfig};
#[cfg(feature = "load-balancer")]
use std::path::PathBuf;

#[path = "reload_service_signatures.rs"]
mod reload_service_signatures;
use reload_service_signatures::{managed_acme_services, managed_php_services};

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
    ListenerSecurityChanged,
    ProcessSettingsChanged,
    LoggingRuntimeChanged,
    TlsModeChanged,
    TlsBackendChanged,
    TlsClientAuthChanged,
    ComplianceModeChanged,
    AcmeServiceChanged,
    ManagedPhpServiceChanged,
    AdminServiceChanged,
    MetricsServiceChanged,
    TracingServiceChanged,
    CachePurgerServiceChanged,
    StreamServiceChanged,
    UdpServiceChanged,
    LoadBalancerServicesChanged,
    WasmRuntimeChanged,
    UnclassifiedProcessStateChanged,
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
            Self::ListenerSecurityChanged => "listener-security-changed",
            Self::ProcessSettingsChanged => "process-settings-changed",
            Self::LoggingRuntimeChanged => "logging-runtime-changed",
            Self::TlsModeChanged => "tls-mode-changed",
            Self::TlsBackendChanged => "tls-backend-changed",
            Self::TlsClientAuthChanged => "tls-client-auth-changed",
            Self::ComplianceModeChanged => "compliance-mode-changed",
            Self::AcmeServiceChanged => "acme-service-changed",
            Self::ManagedPhpServiceChanged => "managed-php-service-changed",
            Self::AdminServiceChanged => "admin-service-changed",
            Self::MetricsServiceChanged => "metrics-service-changed",
            Self::TracingServiceChanged => "tracing-service-changed",
            Self::CachePurgerServiceChanged => "cache-purger-service-changed",
            Self::StreamServiceChanged => "stream-service-changed",
            Self::UdpServiceChanged => "udp-service-changed",
            Self::LoadBalancerServicesChanged => "load-balancer-services-changed",
            Self::WasmRuntimeChanged => "wasm-runtime-changed",
            Self::UnclassifiedProcessStateChanged => "unclassified-process-state-changed",
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

    if old.server.trusted_proxies != new.server.trusted_proxies
        || old.server.proxy_protocol != new.server.proxy_protocol
        || old.server.limits != new.server.limits
    {
        reasons.push(ReloadReason::ListenerSecurityChanged);
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

    if old.tls.client_auth != new.tls.client_auth {
        reasons.push(ReloadReason::TlsClientAuthChanged);
    }

    if old.tls.iso19790 != new.tls.iso19790 {
        reasons.push(ReloadReason::ComplianceModeChanged);
    }

    if old.tls.acme != new.tls.acme || managed_acme_services(old) != managed_acme_services(new) {
        reasons.push(ReloadReason::AcmeServiceChanged);
    }

    if managed_php_services(old) != managed_php_services(new) {
        reasons.push(ReloadReason::ManagedPhpServiceChanged);
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

    if old.tracing != new.tracing {
        reasons.push(ReloadReason::TracingServiceChanged);
    }

    if old.cache_purger != new.cache_purger {
        reasons.push(ReloadReason::CachePurgerServiceChanged);
    }

    if old.stream != new.stream {
        reasons.push(ReloadReason::StreamServiceChanged);
    }

    if old.udp != new.udp {
        reasons.push(ReloadReason::UdpServiceChanged);
    }

    if old.wasm != new.wasm {
        reasons.push(ReloadReason::WasmRuntimeChanged);
    }

    #[cfg(feature = "load-balancer")]
    if load_balancer_service_signature(old) != load_balancer_service_signature(new) {
        reasons.push(ReloadReason::LoadBalancerServicesChanged);
    }

    if reasons.is_empty() && !only_snapshot_safe_fields_changed(old, new) {
        reasons.push(ReloadReason::UnclassifiedProcessStateChanged);
    }

    if reasons.is_empty() {
        ReloadImpact::Snapshot
    } else {
        ReloadImpact::ProcessUpgrade { reasons }
    }
}

fn only_snapshot_safe_fields_changed(old: &Config, new: &Config) -> bool {
    // This exhaustive top-level destructure makes future Config fields fail compilation until
    // their reload ownership is classified explicitly. Nested startup-owned fields are audited
    // by the service-signature module.
    let Config {
        server: _,
        admin: _,
        metrics: _,
        tracing: _,
        logging: _,
        headers: _,
        tls: _,
        proxy: _,
        compression: _,
        cache: _,
        cache_purger: _,
        web: _,
        geoip: _,
        stream: _,
        udp: _,
        wasm: _,
        vhosts: _,
    } = new;

    let mut candidate = old.clone();
    copy_snapshot_safe_server_fields(&mut candidate.server, &new.server);
    copy_snapshot_safe_logging_fields(&mut candidate.logging, &new.logging);
    copy_snapshot_safe_tls_fields(&mut candidate.tls, &new.tls);
    candidate.headers = new.headers.clone();
    candidate.proxy = new.proxy.clone();
    candidate.compression = new.compression.clone();
    candidate.cache = new.cache.clone();
    candidate.web = new.web.clone();
    candidate.geoip = new.geoip.clone();
    candidate.vhosts = new.vhosts.clone();
    candidate == *new
}

fn copy_snapshot_safe_server_fields(
    candidate: &mut crate::config::ServerConfig,
    new: &crate::config::ServerConfig,
) {
    let crate::config::ServerConfig {
        listen: _,
        tls_listen: _,
        default_vhost,
        trusted_proxies: _,
        proxy_protocol: _,
        regex_enabled,
        limits: _,
        process: _,
        https_redirect,
        host_routing,
    } = new;
    candidate.default_vhost = default_vhost.clone();
    candidate.regex_enabled = *regex_enabled;
    candidate.https_redirect = *https_redirect;
    candidate.host_routing = *host_routing;
}

fn copy_snapshot_safe_logging_fields(
    candidate: &mut crate::config::LoggingConfig,
    new: &crate::config::LoggingConfig,
) {
    let crate::config::LoggingConfig {
        level: _,
        format: _,
        target: _,
        file: _,
        access,
    } = new;
    candidate.access = access.clone();
}

fn copy_snapshot_safe_tls_fields(
    candidate: &mut crate::config::TlsConfig,
    new: &crate::config::TlsConfig,
) {
    let crate::config::TlsConfig {
        enabled: _,
        backend: _,
        profile: _,
        min_protocol: _,
        alpn: _,
        curve_preferences: _,
        cipher_suites: _,
        client_auth: _,
        certificates,
        fips: _,
        iso19790: _,
        acme: _,
    } = new;
    candidate.certificates = certificates.clone();
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

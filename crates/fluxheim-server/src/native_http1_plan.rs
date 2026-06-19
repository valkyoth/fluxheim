use fluxheim_config::{AccessPolicyConfig, Config, ProxyConfig, RouteConfig, VhostConfig};

use crate::{DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1ProxyConfigError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1ProxyCandidate {
    scope: String,
    result: Result<(), NativeHttp1ProxyConfigError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttp1ProxyCutoverStatus {
    NoProxy,
    NativeReady,
    Mixed,
    CompatibilityRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHttp1ProxyCutoverSummary {
    status: NativeHttp1ProxyCutoverStatus,
    total: usize,
    eligible: usize,
    unsupported: usize,
}

impl NativeHttp1ProxyCutoverSummary {
    pub(crate) fn from_candidates(candidates: &[NativeHttp1ProxyCandidate]) -> Self {
        let total = candidates.len();
        let eligible = candidates
            .iter()
            .filter(|candidate| candidate.is_eligible())
            .count();
        let unsupported = total.saturating_sub(eligible);
        let status = match (total, eligible) {
            (0, _) => NativeHttp1ProxyCutoverStatus::NoProxy,
            (_, eligible) if eligible == total => NativeHttp1ProxyCutoverStatus::NativeReady,
            (_, 0) => NativeHttp1ProxyCutoverStatus::CompatibilityRequired,
            _ => NativeHttp1ProxyCutoverStatus::Mixed,
        };
        Self {
            status,
            total,
            eligible,
            unsupported,
        }
    }

    pub const fn status(&self) -> NativeHttp1ProxyCutoverStatus {
        self.status
    }

    pub const fn total(&self) -> usize {
        self.total
    }

    pub const fn eligible(&self) -> usize {
        self.eligible
    }

    pub const fn unsupported(&self) -> usize {
        self.unsupported
    }
}

impl NativeHttp1ProxyCandidate {
    fn eligible(scope: String) -> Self {
        Self {
            scope,
            result: Ok(()),
        }
    }

    fn unsupported(scope: String, error: NativeHttp1ProxyConfigError) -> Self {
        Self {
            scope,
            result: Err(error),
        }
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub const fn is_eligible(&self) -> bool {
        self.result.is_ok()
    }

    pub const fn unsupported_reason(&self) -> Option<NativeHttp1ProxyConfigError> {
        match self.result {
            Ok(()) => None,
            Err(error) => Some(error),
        }
    }
}

pub(crate) fn native_http1_proxy_candidates_from_config(
    config: &Config,
    policy: DownstreamHttp1Policy,
    pool_max_idle: usize,
) -> Vec<NativeHttp1ProxyCandidate> {
    let mut candidates = Vec::new();

    if config.vhosts.is_empty() {
        push_proxy_candidate(
            "proxy".to_owned(),
            &config.proxy,
            root_policy_supported(config),
            policy,
            pool_max_idle,
            &mut candidates,
        );
        return candidates;
    }

    for vhost in &config.vhosts {
        push_proxy_candidate(
            format!("vhost {:?} proxy", vhost.name),
            &vhost.proxy,
            vhost_policy_supported(vhost),
            policy,
            pool_max_idle,
            &mut candidates,
        );
        for route in &vhost.routes {
            if let Some(proxy) = &route.proxy {
                push_proxy_candidate(
                    format!("vhost {:?} route {:?} proxy", vhost.name, route.name),
                    proxy,
                    vhost_policy_supported(vhost) && route_policy_supported(route),
                    policy,
                    pool_max_idle,
                    &mut candidates,
                );
            }
        }
    }

    candidates
}

fn push_proxy_candidate(
    scope: String,
    proxy: &ProxyConfig,
    policy_supported: bool,
    policy: DownstreamHttp1Policy,
    pool_max_idle: usize,
    candidates: &mut Vec<NativeHttp1ProxyCandidate>,
) {
    if !proxy.has_configured_upstream() {
        return;
    }

    if !policy_supported {
        candidates.push(NativeHttp1ProxyCandidate::unsupported(
            scope,
            NativeHttp1ProxyConfigError::HttpPolicy,
        ));
        return;
    }

    match NativeHttp1Proxy::from_proxy_config_with_pool_size(proxy, policy, pool_max_idle) {
        Ok(Some(_)) => candidates.push(NativeHttp1ProxyCandidate::eligible(scope)),
        Ok(None) => {}
        Err(error) => candidates.push(NativeHttp1ProxyCandidate::unsupported(scope, error)),
    }
}

fn root_policy_supported(config: &Config) -> bool {
    config.headers == fluxheim_config::HeaderPolicyConfig::default()
        && !config.compression.enabled
        && !cache_enabled(&config.cache)
        && !config.web.enabled()
}

fn vhost_policy_supported(vhost: &VhostConfig) -> bool {
    !access_policy_active(&vhost.access)
        && !vhost.rate_limit.enabled
        && !vhost.concurrency.enabled
        && !vhost.redirect.enabled
        && !vhost.acme_challenge.enabled
        && vhost.headers == fluxheim_config::VhostHeaderPolicyConfig::default()
        && !cache_enabled(&vhost.cache)
        && vhost
            .compression
            .as_ref()
            .is_none_or(|compression| !compression.enabled)
        && !vhost.php.enabled
        && !vhost.web.enabled()
}

fn route_policy_supported(route: &RouteConfig) -> bool {
    !access_policy_active(&route.access)
        && !route.rate_limit.enabled
        && !route.concurrency.enabled
        && !route.grpc.enabled
        && route.redirect.is_none()
        && route.strip_prefix.is_none()
        && route.rewrite_prefix.is_none()
        && route.rewrite_template.is_none()
        && route.headers == fluxheim_config::VhostHeaderPolicyConfig::default()
        && route
            .cache
            .as_ref()
            .is_none_or(|cache| !cache_enabled(cache))
        && route
            .compression
            .as_ref()
            .is_none_or(|compression| !compression.enabled)
        && route.web.as_ref().is_none_or(|web| !web.enabled())
        && route.php.as_ref().is_none_or(|php| !php.enabled)
}

fn access_policy_active(access: &AccessPolicyConfig) -> bool {
    access.enabled
        && (!access.allow.is_empty()
            || !access.deny.is_empty()
            || access.require_client_cert
            || !access.allow_client_cert_sha256.is_empty()
            || !access.deny_client_cert_sha256.is_empty()
            || !access.allow_countries.is_empty()
            || !access.deny_countries.is_empty()
            || !access.allow_asns.is_empty()
            || !access.deny_asns.is_empty())
}

fn cache_enabled(cache: &fluxheim_config::CacheConfig) -> bool {
    cache.enabled || cache.local_static
}

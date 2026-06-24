use fluxheim_config::{AccessPolicyConfig, Config, ProxyConfig, RouteConfig, VhostConfig};

use crate::{
    DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1ProxyConfigError, NativeHttp1StaticWeb,
};

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
            _ if eligible == total => NativeHttp1ProxyCutoverStatus::NativeReady,
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
        push_root_http_candidate(
            "proxy".to_owned(),
            config,
            root_policy_support(config),
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
            vhost_policy_support(vhost),
            policy,
            pool_max_idle,
            &mut candidates,
        );
        for route in vhost
            .acme_challenge
            .route_config()
            .into_iter()
            .chain(vhost.routes.iter().cloned())
            .chain(vhost.redirect.route_config())
        {
            if route.redirect.is_some() || route.web.as_ref().is_some_and(|web| web.enabled()) {
                continue;
            }
            if let Some(proxy) = &route.proxy {
                push_proxy_candidate(
                    format!("vhost {:?} route {:?} proxy", vhost.name, route.name),
                    proxy,
                    vhost_policy_support(vhost).and_then(|()| route_policy_support(&route)),
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
    policy_support: Result<(), NativeHttp1ProxyConfigError>,
    policy: DownstreamHttp1Policy,
    pool_max_idle: usize,
    candidates: &mut Vec<NativeHttp1ProxyCandidate>,
) {
    if !proxy.has_configured_upstream() {
        return;
    }

    if let Err(error) = policy_support {
        candidates.push(NativeHttp1ProxyCandidate::unsupported(scope, error));
        return;
    }

    match NativeHttp1Proxy::from_proxy_config_with_pool_size(proxy, policy, pool_max_idle) {
        Ok(Some(_)) => candidates.push(NativeHttp1ProxyCandidate::eligible(scope)),
        Ok(None) => {}
        Err(error) => candidates.push(NativeHttp1ProxyCandidate::unsupported(scope, error)),
    }
}

fn push_root_http_candidate(
    scope: String,
    config: &Config,
    policy_support: Result<(), NativeHttp1ProxyConfigError>,
    policy: DownstreamHttp1Policy,
    pool_max_idle: usize,
    candidates: &mut Vec<NativeHttp1ProxyCandidate>,
) {
    if !config.proxy.has_configured_upstream() && !config.web.enabled() {
        return;
    }

    if let Err(error) = policy_support {
        candidates.push(NativeHttp1ProxyCandidate::unsupported(scope, error));
        return;
    }

    match NativeHttp1Proxy::from_root_config(config, policy, pool_max_idle) {
        Ok(Some(_)) | Ok(None) if config.web.enabled() => {
            candidates.push(NativeHttp1ProxyCandidate::eligible(scope));
        }
        Ok(Some(_)) => candidates.push(NativeHttp1ProxyCandidate::eligible(scope)),
        Ok(None) => {}
        Err(error) => candidates.push(NativeHttp1ProxyCandidate::unsupported(scope, error)),
    }
}

fn root_policy_support(config: &Config) -> Result<(), NativeHttp1ProxyConfigError> {
    if !header_policy_supported(&config.headers) || !compression_supported(&config.compression) {
        return Err(NativeHttp1ProxyConfigError::HttpPolicy);
    }
    if cache_enabled(&config.cache)
        && (!config.web.enabled() || !NativeHttp1StaticWeb::cache_supported(&config.cache))
    {
        return Err(NativeHttp1ProxyConfigError::CachePolicy);
    }
    Ok(())
}

fn vhost_policy_support(vhost: &VhostConfig) -> Result<(), NativeHttp1ProxyConfigError> {
    if !access_policy_native_supported(&vhost.access)
        || !vhost_header_overlay_supported(&vhost.headers)
        || !vhost.compression.as_ref().is_none_or(compression_supported)
    {
        return Err(NativeHttp1ProxyConfigError::HttpPolicy);
    }
    if vhost_cache_policy_blocked(vhost) {
        return Err(NativeHttp1ProxyConfigError::CachePolicy);
    }
    if vhost.php.enabled {
        return Err(NativeHttp1ProxyConfigError::PhpFpm);
    }
    if let Some(route) = vhost.acme_challenge.route_config() {
        route_policy_support(&route)?;
    }
    if let Some(route) = vhost.redirect.route_config() {
        route_policy_support(&route)?;
    }
    Ok(())
}

fn route_policy_support(route: &RouteConfig) -> Result<(), NativeHttp1ProxyConfigError> {
    if !access_policy_native_supported(&route.access)
        || !route_request_header_policy_supported(&route.headers.request)
        || !route_response_header_policy_supported(&route.headers.response)
        || !route.compression.as_ref().is_none_or(compression_supported)
    {
        return Err(NativeHttp1ProxyConfigError::HttpPolicy);
    }
    if route_cache_policy_blocked(route) {
        return Err(NativeHttp1ProxyConfigError::CachePolicy);
    }
    if route.php.as_ref().is_some_and(|php| php.enabled) {
        return Err(NativeHttp1ProxyConfigError::PhpFpm);
    }
    Ok(())
}

fn header_policy_supported(headers: &fluxheim_config::HeaderPolicyConfig) -> bool {
    request_header_policy_supported(&headers.request)
        && root_response_header_policy_supported(&headers.response)
}

fn root_response_header_policy_supported(
    _response: &fluxheim_config::ResponseHeaderPolicyConfig,
) -> bool {
    // All current root response policy fields are implemented by
    // NativeRouteResponseHeaderPolicy::from_policy(). Keep this helper explicit
    // so future root response-policy fields get a fail-closed review point
    // before native cutover marks them supported.
    true
}

fn request_header_policy_supported(request: &fluxheim_config::RequestHeaderPolicyConfig) -> bool {
    let defaults = fluxheim_config::RequestHeaderPolicyConfig::default();
    request.enabled == defaults.enabled
}

fn vhost_header_overlay_supported(headers: &fluxheim_config::VhostHeaderPolicyConfig) -> bool {
    route_request_header_policy_supported(&headers.request)
}

fn route_request_header_policy_supported(
    request: &fluxheim_config::RequestHeaderPolicyOverlayConfig,
) -> bool {
    request.enabled != Some(false)
}

fn route_response_header_policy_supported(
    _response: &fluxheim_config::ResponseHeaderPolicyOverlayConfig,
) -> bool {
    // All current response overlay fields are implemented by
    // NativeRouteResponseHeaderPolicy. Keep this helper explicit so future
    // response-policy fields get a fail-closed review point before native
    // cutover marks them supported.
    true
}

fn access_policy_native_supported(_access: &AccessPolicyConfig) -> bool {
    true
}

fn cache_enabled(cache: &fluxheim_config::CacheConfig) -> bool {
    cache.enabled || cache.local_static
}

fn vhost_cache_policy_blocked(vhost: &VhostConfig) -> bool {
    if !cache_enabled(&vhost.cache) {
        return false;
    }
    !vhost.web.enabled() || !NativeHttp1StaticWeb::cache_supported(&vhost.cache)
}

fn route_cache_policy_blocked(route: &RouteConfig) -> bool {
    route.cache.as_ref().is_some_and(|cache| {
        if !cache_enabled(cache) {
            return false;
        }
        let has_static_web = route.web.as_ref().is_some_and(|web| web.enabled());
        !has_static_web || !NativeHttp1StaticWeb::cache_supported(cache)
    })
}

fn compression_supported(compression: &fluxheim_config::CompressionConfig) -> bool {
    !compression.enabled || native_route_compression_compiled()
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
const fn native_route_compression_compiled() -> bool {
    true
}

#[cfg(not(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
)))]
const fn native_route_compression_compiled() -> bool {
    false
}

use std::cmp::Reverse;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fluxheim_config::config_net::{normalize_host, normalize_host_pattern};
use fluxheim_config::{Config, HeaderPolicyConfig, VhostConfig};

use crate::{
    DownstreamHttp1Policy, NativeHttp1Handler, NativeHttp1Proxy, NativeHttp1Request,
    NativeHttp1Response, NativeHttp1RouteProxy, NativeHttp1RouteProxyConfigError,
    ProxyProtocolTrustedSource,
};

#[derive(Clone, Debug)]
pub struct NativeHttp1HostRouter {
    exact_hosts: HashMap<String, Arc<NativeHttp1RouteProxy>>,
    wildcard_hosts: Vec<NativeHttp1WildcardHost>,
    default_proxy: Arc<NativeHttp1RouteProxy>,
}

#[derive(Clone, Debug)]
struct NativeHttp1WildcardHost {
    suffix: String,
    proxy: Arc<NativeHttp1RouteProxy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeHttp1HostRouterConfigError {
    InvalidHostPattern { vhost: String, host: String },
    MissingDefaultVhost { name: String },
    MissingVhost,
    RouteProxy(NativeHttp1RouteProxyConfigError),
    TrustedProxy { source: String, reason: String },
}

impl std::fmt::Display for NativeHttp1HostRouterConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHostPattern { vhost, host } => {
                write!(
                    formatter,
                    "vhost {vhost:?} has invalid host pattern {host:?}"
                )
            }
            Self::MissingDefaultVhost { name } => {
                write!(
                    formatter,
                    "server.default_vhost references unknown vhost {name:?}"
                )
            }
            Self::MissingVhost => write!(formatter, "native HTTP/1 host router requires a vhost"),
            Self::RouteProxy(error) => write!(formatter, "native HTTP/1 route proxy: {error}"),
            Self::TrustedProxy { source, reason } => {
                write!(
                    formatter,
                    "invalid server.trusted_proxies source {source:?}: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for NativeHttp1HostRouterConfigError {}

impl From<NativeHttp1RouteProxyConfigError> for NativeHttp1HostRouterConfigError {
    fn from(error: NativeHttp1RouteProxyConfigError) -> Self {
        Self::RouteProxy(error)
    }
}

impl NativeHttp1HostRouter {
    pub fn from_config(
        config: &Config,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Self, NativeHttp1HostRouterConfigError> {
        if config.vhosts.is_empty() {
            return Self::from_root_config(config, policy, pool_max_idle);
        }
        let trusted_sources = trusted_sources_from_config(config)?;
        let mut proxies = Vec::with_capacity(config.vhosts.len());
        let mut exact_hosts = HashMap::new();
        let mut wildcard_hosts = Vec::new();

        for vhost in &config.vhosts {
            let proxy = Arc::new(route_proxy_from_config(
                config,
                vhost,
                &config.headers,
                policy,
                pool_max_idle,
                &trusted_sources,
            )?);
            for host in &vhost.hosts {
                let Some(normalized) = normalize_host_pattern(host) else {
                    return Err(NativeHttp1HostRouterConfigError::InvalidHostPattern {
                        vhost: vhost.name.clone(),
                        host: host.clone(),
                    });
                };
                if let Some(suffix) = normalized.strip_prefix("*.") {
                    wildcard_hosts.push(NativeHttp1WildcardHost {
                        suffix: suffix.to_owned(),
                        proxy: proxy.clone(),
                    });
                } else {
                    exact_hosts.insert(normalized, proxy.clone());
                }
            }
            proxies.push((vhost.name.as_str(), proxy));
        }

        wildcard_hosts.sort_by_key(|wildcard| Reverse(wildcard.suffix.len()));
        let default_proxy = default_proxy(config, &proxies)?;

        Ok(Self {
            exact_hosts,
            wildcard_hosts,
            default_proxy,
        })
    }

    fn from_root_config(
        config: &Config,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Self, NativeHttp1HostRouterConfigError> {
        let proxy = NativeHttp1Proxy::from_root_config(config, policy, pool_max_idle)
            .map_err(NativeHttp1RouteProxyConfigError::Proxy)?
            .ok_or(NativeHttp1HostRouterConfigError::MissingVhost)?;
        let default_proxy = Arc::new(NativeHttp1RouteProxy::new(Vec::new(), Some(proxy)));
        Ok(Self {
            exact_hosts: HashMap::new(),
            wildcard_hosts: Vec::new(),
            default_proxy,
        })
    }

    pub fn select(&self, host: Option<&str>) -> &NativeHttp1RouteProxy {
        let Some(host) = host.and_then(normalize_host) else {
            return &self.default_proxy;
        };
        if let Some(proxy) = self.exact_hosts.get(&host) {
            return proxy;
        }
        self.wildcard_hosts
            .iter()
            .find(|wildcard| wildcard_matches(&host, &wildcard.suffix))
            .map(|wildcard| wildcard.proxy.as_ref())
            .unwrap_or(&self.default_proxy)
    }

    fn select_request(&self, request: &NativeHttp1Request) -> &NativeHttp1RouteProxy {
        self.select(request_host(request))
    }
}

impl NativeHttp1Handler for NativeHttp1HostRouter {
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        let proxy = self.select_request(&request).clone();
        Box::pin(async move { proxy.handle(request).await })
    }

    fn prepare_request_context(&self, request: &mut NativeHttp1Request) {
        self.select_request(request)
            .prepare_request_context(request);
    }

    fn request_body_timeout(&self, request: &NativeHttp1Request) -> Option<Duration> {
        self.select_request(request).request_body_timeout(request)
    }
}

fn route_proxy_from_config(
    config: &Config,
    vhost: &VhostConfig,
    base_headers: &HeaderPolicyConfig,
    policy: DownstreamHttp1Policy,
    pool_max_idle: usize,
    trusted_sources: &[ProxyProtocolTrustedSource],
) -> Result<NativeHttp1RouteProxy, NativeHttp1RouteProxyConfigError> {
    #[cfg(feature = "acme")]
    {
        NativeHttp1RouteProxy::from_config_with_trusted_sources(
            config,
            vhost,
            base_headers,
            Some(&config.compression),
            policy,
            pool_max_idle,
            trusted_sources,
        )
    }
    #[cfg(not(feature = "acme"))]
    {
        NativeHttp1RouteProxy::from_vhost_config_with_trusted_sources(
            vhost,
            base_headers,
            Some(&config.compression),
            policy,
            pool_max_idle,
            trusted_sources,
        )
    }
}

fn default_proxy(
    config: &Config,
    proxies: &[(&str, Arc<NativeHttp1RouteProxy>)],
) -> Result<Arc<NativeHttp1RouteProxy>, NativeHttp1HostRouterConfigError> {
    let Some(default_name) = config.server.default_vhost.as_deref() else {
        return proxies
            .first()
            .map(|(_, proxy)| proxy.clone())
            .ok_or(NativeHttp1HostRouterConfigError::MissingVhost);
    };
    proxies
        .iter()
        .find(|(name, _)| *name == default_name)
        .map(|(_, proxy)| proxy.clone())
        .ok_or_else(|| NativeHttp1HostRouterConfigError::MissingDefaultVhost {
            name: default_name.to_owned(),
        })
}

fn request_host(request: &NativeHttp1Request) -> Option<&str> {
    request.headers.iter().find_map(|(name, value)| {
        name.eq_ignore_ascii_case("host")
            .then_some(value.trim())
            .filter(|value| !value.is_empty())
    })
}

fn wildcard_matches(host: &str, suffix: &str) -> bool {
    host.len() > suffix.len() + 1
        && host.ends_with(suffix)
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
}

fn trusted_sources_from_config(
    config: &Config,
) -> Result<Vec<ProxyProtocolTrustedSource>, NativeHttp1HostRouterConfigError> {
    config
        .server
        .trusted_proxies
        .iter()
        .map(
            |source| match fluxheim_protocol::parse_proxy_protocol_trusted_source(source) {
                Ok(fluxheim_protocol::ProxyProtocolTrustedSource::Ip(address)) => {
                    Ok(ProxyProtocolTrustedSource::Ip(address))
                }
                Ok(fluxheim_protocol::ProxyProtocolTrustedSource::Cidr { network, prefix }) => {
                    Ok(ProxyProtocolTrustedSource::Cidr { network, prefix })
                }
                Err(error) => Err(NativeHttp1HostRouterConfigError::TrustedProxy {
                    source: source.clone(),
                    reason: error.to_string(),
                }),
            },
        )
        .collect()
}

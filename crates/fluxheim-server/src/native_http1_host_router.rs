use std::cmp::Reverse;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fluxheim_config::config_net::{normalize_host, normalize_host_pattern};
use fluxheim_config::{Config, VhostConfig};

use crate::native_http1_route_proxy::NativeRouteProxyBuildContext;
#[cfg(feature = "load-balancer")]
use crate::native_http1_route_proxy_upstream::NativeLoadBalancerCollectors;
#[cfg(feature = "wasm")]
use crate::native_http1_route_wasm::NativeWasmHookRegistry;
use crate::{
    DownstreamHttp1Policy, NativeHttp1ConnectionStream, NativeHttp1Error, NativeHttp1Handler,
    NativeHttp1Request, NativeHttp1Response, NativeHttp1RouteProxy,
    NativeHttp1RouteProxyConfigError, ProxyProtocolTrustedSource,
};

#[cfg(feature = "load-balancer")]
type NativeLoadBalancerServices = Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>;
#[cfg(not(feature = "load-balancer"))]
type NativeLoadBalancerServices = Vec<()>;
#[cfg(feature = "load-balancer")]
pub type NativeLoadBalancerAdminPools = Vec<crate::NativeLoadBalancerAdminPool>;
#[cfg(not(feature = "load-balancer"))]
pub type NativeLoadBalancerAdminPools = Vec<()>;

#[derive(Clone, Debug)]
pub struct NativeHttp1HostRouter {
    exact_hosts: HashMap<String, Arc<NativeHttp1RouteProxy>>,
    wildcard_hosts: Vec<NativeHttp1WildcardHost>,
    default_proxy: Arc<NativeHttp1RouteProxy>,
    strict: bool,
}

#[derive(Clone, Debug)]
struct NativeHttp1WildcardHost {
    suffix: String,
    proxy: Arc<NativeHttp1RouteProxy>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHostRouteError {
    MissingOrInvalid,
    Unknown,
}

impl NativeHostRouteError {
    fn response(self) -> NativeHttp1Response {
        match self {
            Self::MissingOrInvalid => {
                NativeHttp1Response::new(400, "Bad Request", b"missing or invalid host identity\n")
            }
            Self::Unknown => {
                NativeHttp1Response::new(421, "Misdirected Request", b"unknown host identity\n")
            }
        }
        .close_connection()
    }
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
        let (router, _, _) = Self::from_config_with_load_balancer_services(
            config,
            policy,
            pool_max_idle,
            #[cfg(feature = "load-balancer")]
            false,
        )?;
        Ok(router)
    }

    #[cfg(feature = "load-balancer")]
    pub fn from_config_with_native_load_balancer_services(
        config: &Config,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<
        (
            Self,
            NativeLoadBalancerServices,
            NativeLoadBalancerAdminPools,
        ),
        NativeHttp1HostRouterConfigError,
    > {
        Self::from_config_with_load_balancer_services(
            config,
            policy,
            pool_max_idle,
            #[cfg(feature = "load-balancer")]
            true,
        )
    }

    fn from_config_with_load_balancer_services(
        config: &Config,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
        #[cfg(feature = "load-balancer")] collect_load_balancer_services: bool,
    ) -> Result<
        (
            Self,
            NativeLoadBalancerServices,
            NativeLoadBalancerAdminPools,
        ),
        NativeHttp1HostRouterConfigError,
    > {
        #[cfg(not(feature = "load-balancer"))]
        let _ = config;
        #[cfg_attr(not(feature = "load-balancer"), allow(unused_mut))]
        let mut load_balancer_services = Vec::new();
        #[cfg_attr(not(feature = "load-balancer"), allow(unused_mut))]
        let mut load_balancer_admin_pools = Vec::new();
        if config.vhosts.is_empty() {
            return Self::from_root_config(
                config,
                policy,
                pool_max_idle,
                #[cfg(feature = "load-balancer")]
                collect_load_balancer_services.then_some(&mut load_balancer_services),
                #[cfg(feature = "load-balancer")]
                Some(&mut load_balancer_admin_pools),
            )
            .map(|router| (router, load_balancer_services, load_balancer_admin_pools));
        }
        let trusted_sources = trusted_sources_from_config(config)?;
        #[cfg(feature = "wasm")]
        let wasm_registry = NativeWasmHookRegistry::from_config(config).map_err(|_| {
            NativeHttp1HostRouterConfigError::RouteProxy(NativeHttp1RouteProxyConfigError::Wasm)
        })?;
        let mut proxies = Vec::with_capacity(config.vhosts.len());
        let mut exact_hosts = HashMap::new();
        let mut wildcard_hosts = Vec::new();

        for vhost in &config.vhosts {
            let context = NativeRouteProxyBuildContext::new(
                &config.headers,
                Some(&config.compression),
                policy,
                pool_max_idle,
                &trusted_sources,
            );
            #[cfg(feature = "wasm")]
            let context = context.with_wasm_registry(wasm_registry.as_ref());
            let proxy = Arc::new(route_proxy_from_config(
                config,
                vhost,
                context,
                #[cfg(feature = "load-balancer")]
                NativeLoadBalancerCollectors::new(
                    collect_load_balancer_services.then_some(&mut load_balancer_services),
                    Some(&mut load_balancer_admin_pools),
                ),
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

        Ok((
            Self {
                exact_hosts,
                wildcard_hosts,
                default_proxy,
                strict: config.server.host_routing.strict,
            },
            load_balancer_services,
            load_balancer_admin_pools,
        ))
    }

    fn from_root_config(
        config: &Config,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
        #[cfg(feature = "load-balancer")] load_balancer_services: Option<
            &mut Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>,
        >,
        #[cfg(feature = "load-balancer")] load_balancer_admin_pools: Option<
            &mut Vec<crate::NativeLoadBalancerAdminPool>,
        >,
    ) -> Result<Self, NativeHttp1HostRouterConfigError> {
        let default_proxy =
            match NativeHttp1RouteProxy::from_root_config_with_load_balancer_services(
                config,
                policy,
                pool_max_idle,
                #[cfg(feature = "load-balancer")]
                load_balancer_services,
                #[cfg(feature = "load-balancer")]
                load_balancer_admin_pools,
            ) {
                Ok(proxy) => Arc::new(proxy),
                Err(NativeHttp1RouteProxyConfigError::MissingRouteAction) => {
                    return Err(NativeHttp1HostRouterConfigError::MissingVhost);
                }
                Err(error) => return Err(NativeHttp1HostRouterConfigError::from(error)),
            };
        Ok(Self {
            exact_hosts: HashMap::new(),
            wildcard_hosts: Vec::new(),
            default_proxy,
            strict: false,
        })
    }

    pub fn select(
        &self,
        host: Option<&str>,
    ) -> Result<&NativeHttp1RouteProxy, NativeHostRouteError> {
        let Some(host) = host.and_then(normalize_host) else {
            return if self.strict {
                Err(NativeHostRouteError::MissingOrInvalid)
            } else {
                Ok(&self.default_proxy)
            };
        };
        if let Some(proxy) = self.exact_hosts.get(&host) {
            return Ok(proxy);
        }
        if let Some(proxy) = self
            .wildcard_hosts
            .iter()
            .find(|wildcard| wildcard_matches(&host, &wildcard.suffix))
            .map(|wildcard| wildcard.proxy.as_ref())
        {
            return Ok(proxy);
        }
        if self.strict {
            Err(NativeHostRouteError::Unknown)
        } else {
            Ok(&self.default_proxy)
        }
    }

    fn select_request(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<&NativeHttp1RouteProxy, NativeHostRouteError> {
        self.select(request_host(request))
    }
}

impl NativeHttp1Handler for NativeHttp1HostRouter {
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        let selected = self.select_request(&request).cloned();
        Box::pin(async move {
            match selected {
                Ok(proxy) => proxy.handle(request).await,
                Err(error) => error.response(),
            }
        })
    }

    fn prepare_request_context(&self, request: &mut NativeHttp1Request) {
        if let Ok(proxy) = self.select_request(request) {
            proxy.prepare_request_context(request);
        }
    }

    fn request_body_timeout(&self, request: &NativeHttp1Request) -> Option<Duration> {
        self.select_request(request)
            .ok()
            .and_then(|proxy| proxy.request_body_timeout(request))
    }

    fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        self.select_request(request)
            .is_ok_and(|proxy| proxy.handles_connection_takeover(request))
    }

    fn handle_connection_takeover<'a>(
        &'a self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Pin<Box<dyn Future<Output = Result<(), NativeHttp1Error>> + Send + 'a>> {
        let selected = self.select_request(&request).cloned();
        Box::pin(async move {
            match selected {
                Ok(proxy) => {
                    proxy
                        .handle_connection_takeover(request, prebuffered, stream)
                        .await
                }
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "strict host routing rejected connection takeover",
                )
                .into()),
            }
        })
    }
}

fn route_proxy_from_config(
    config: &Config,
    vhost: &VhostConfig,
    context: NativeRouteProxyBuildContext<'_>,
    #[cfg(feature = "load-balancer")] collectors: NativeLoadBalancerCollectors<'_>,
) -> Result<NativeHttp1RouteProxy, NativeHttp1RouteProxyConfigError> {
    let route_proxy = {
        #[cfg(feature = "acme")]
        {
            NativeHttp1RouteProxy::from_config_with_build_context(
                config,
                vhost,
                context,
                #[cfg(feature = "load-balancer")]
                collectors,
            )
        }
        #[cfg(not(feature = "acme"))]
        {
            NativeHttp1RouteProxy::from_vhost_config_with_trusted_sources_and_load_balancer_services(
                vhost,
                context,
                #[cfg(feature = "load-balancer")]
                collectors,
            )
        }
    }?;
    let route_proxy = route_proxy.with_https_redirect(config.server.https_redirect);
    #[cfg(feature = "otel-tracing")]
    let route_proxy = route_proxy.with_trace_config(&config.tracing);
    Ok(route_proxy)
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

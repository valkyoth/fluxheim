use std::fmt::{Debug, Formatter};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use pingora::http::RequestHeader;
use pingora::lb::Backend;
use pingora::lb::Backends;
use pingora::lb::discovery::Static;
use pingora::lb::health_check::TcpHealthCheck;
use pingora::lb::prelude::LoadBalancer;
use pingora::lb::selection::{BackendIter, BackendSelection, Consistent, FNVHash, RoundRobin};
use pingora::services::ServiceWithDependents;
use pingora::services::background::{BackgroundService, GenBackgroundService};

use crate::config::{LoadBalanceSelection, ProxyConfig};

pub type UpstreamLoadBalancerService = Box<dyn ServiceWithDependents>;

#[derive(Clone)]
pub struct UpstreamLoadBalancer {
    inner: UpstreamLoadBalancerInner,
    key_source: LoadBalanceKeySource,
    max_iterations: usize,
}

impl Debug for UpstreamLoadBalancer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpstreamLoadBalancer")
            .field("max_iterations", &self.max_iterations)
            .finish_non_exhaustive()
    }
}

impl UpstreamLoadBalancer {
    pub fn from_proxy_config(config: &ProxyConfig) -> io::Result<Option<Self>> {
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => {
                let Some(inner) = configured_load_balancer::<RoundRobin>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::RoundRobin(Arc::new(inner)),
                    config,
                )))
            }
            LoadBalanceSelection::SourceHash
            | LoadBalanceSelection::UriHash
            | LoadBalanceSelection::HeaderHash => {
                let Some(inner) = configured_load_balancer::<FNVHash>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::FnvHash(Arc::new(inner)),
                    config,
                )))
            }
            LoadBalanceSelection::ConsistentSourceHash
            | LoadBalanceSelection::ConsistentUriHash
            | LoadBalanceSelection::ConsistentHeaderHash => {
                let Some(inner) = configured_load_balancer::<Consistent>(config)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::ConsistentHash(Arc::new(inner)),
                    config,
                )))
            }
        }
    }

    pub fn background_service_from_proxy_config(
        name: &str,
        config: &ProxyConfig,
    ) -> io::Result<Option<(Self, UpstreamLoadBalancerService)>> {
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => background_service_for::<RoundRobin>(
                name,
                config,
                UpstreamLoadBalancerInner::RoundRobin,
            ),
            LoadBalanceSelection::SourceHash
            | LoadBalanceSelection::UriHash
            | LoadBalanceSelection::HeaderHash => {
                background_service_for::<FNVHash>(name, config, UpstreamLoadBalancerInner::FnvHash)
            }
            LoadBalanceSelection::ConsistentSourceHash
            | LoadBalanceSelection::ConsistentUriHash
            | LoadBalanceSelection::ConsistentHeaderHash => background_service_for::<Consistent>(
                name,
                config,
                UpstreamLoadBalancerInner::ConsistentHash,
            ),
        }
    }

    pub fn select(&self, request: &RequestHeader, client_ip: Option<IpAddr>) -> Option<Backend> {
        let key = self.key_source.request_key(request, client_ip);
        self.inner.select(key.as_deref(), self.max_iterations)
    }

    fn from_inner(inner: UpstreamLoadBalancerInner, config: &ProxyConfig) -> Self {
        Self {
            inner,
            key_source: LoadBalanceKeySource::from_config(config),
            max_iterations: config.load_balance.max_iterations,
        }
    }

    #[cfg(test)]
    fn backend_count(&self) -> usize {
        self.inner.backend_count()
    }

    #[cfg(test)]
    fn backend_weights(&self) -> Vec<usize> {
        self.inner.backend_weights()
    }

    #[cfg(test)]
    fn health_check_frequency(&self) -> Option<Duration> {
        self.inner.health_check_frequency()
    }

    #[cfg(test)]
    fn parallel_health_check(&self) -> bool {
        self.inner.parallel_health_check()
    }
}

#[derive(Clone)]
enum UpstreamLoadBalancerInner {
    RoundRobin(Arc<LoadBalancer<RoundRobin>>),
    FnvHash(Arc<LoadBalancer<FNVHash>>),
    ConsistentHash(Arc<LoadBalancer<Consistent>>),
}

impl UpstreamLoadBalancerInner {
    fn select(&self, key: Option<&[u8]>, max_iterations: usize) -> Option<Backend> {
        match self {
            Self::RoundRobin(inner) => inner.select(b"", max_iterations),
            Self::FnvHash(inner) => inner.select(key.unwrap_or_default(), max_iterations),
            Self::ConsistentHash(inner) => inner.select(key.unwrap_or_default(), max_iterations),
        }
    }

    #[cfg(test)]
    fn backend_count(&self) -> usize {
        match self {
            Self::RoundRobin(inner) => inner.backends().get_backend().len(),
            Self::FnvHash(inner) => inner.backends().get_backend().len(),
            Self::ConsistentHash(inner) => inner.backends().get_backend().len(),
        }
    }

    #[cfg(test)]
    fn backend_weights(&self) -> Vec<usize> {
        match self {
            Self::RoundRobin(inner) => backend_weights(inner),
            Self::FnvHash(inner) => backend_weights(inner),
            Self::ConsistentHash(inner) => backend_weights(inner),
        }
    }

    #[cfg(test)]
    fn health_check_frequency(&self) -> Option<Duration> {
        match self {
            Self::RoundRobin(inner) => inner.health_check_frequency,
            Self::FnvHash(inner) => inner.health_check_frequency,
            Self::ConsistentHash(inner) => inner.health_check_frequency,
        }
    }

    #[cfg(test)]
    fn parallel_health_check(&self) -> bool {
        match self {
            Self::RoundRobin(inner) => inner.parallel_health_check,
            Self::FnvHash(inner) => inner.parallel_health_check,
            Self::ConsistentHash(inner) => inner.parallel_health_check,
        }
    }
}

#[derive(Clone, Debug)]
enum LoadBalanceKeySource {
    None,
    SourceIp,
    Uri,
    Header(String),
}

impl LoadBalanceKeySource {
    fn from_config(config: &ProxyConfig) -> Self {
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => Self::None,
            LoadBalanceSelection::SourceHash | LoadBalanceSelection::ConsistentSourceHash => {
                Self::SourceIp
            }
            LoadBalanceSelection::UriHash | LoadBalanceSelection::ConsistentUriHash => Self::Uri,
            LoadBalanceSelection::HeaderHash | LoadBalanceSelection::ConsistentHeaderHash => config
                .load_balance
                .hash_header
                .clone()
                .map(Self::Header)
                .unwrap_or(Self::None),
        }
    }

    fn request_key(&self, request: &RequestHeader, client_ip: Option<IpAddr>) -> Option<Vec<u8>> {
        match self {
            Self::None => None,
            Self::SourceIp => client_ip.map(|ip| ip.to_string().into_bytes()),
            Self::Uri => Some(request.uri.to_string().into_bytes()),
            Self::Header(name) => {
                let mut key = Vec::new();
                for value in request.headers.get_all(name.as_str()) {
                    let bytes = value.as_bytes();
                    key.extend_from_slice(&bytes.len().to_le_bytes());
                    key.extend_from_slice(bytes);
                }
                (!key.is_empty()).then_some(key)
            }
        }
    }
}

fn configured_load_balancer<S>(config: &ProxyConfig) -> io::Result<Option<LoadBalancer<S>>>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    if config.upstreams.len() < 2 {
        return Ok(None);
    }

    let backends = configured_backends(config)?;
    let mut load_balancer = LoadBalancer::from_backends(Backends::new(Static::new(backends)));
    load_balancer
        .update()
        .now_or_never()
        .ok_or_else(|| io::Error::other("static load balancer update blocked unexpectedly"))?
        .map_err(|error| io::Error::other(error.to_string()))?;
    if config.load_balance.health_check.enabled {
        let mut health_check = if config.upstream_tls {
            TcpHealthCheck::new_tls(&config.upstream_sni())
        } else {
            TcpHealthCheck::new()
        };
        health_check.consecutive_success = config.load_balance.health_check.consecutive_success;
        health_check.consecutive_failure = config.load_balance.health_check.consecutive_failure;
        load_balancer.set_health_check(health_check);
        load_balancer.health_check_frequency = Some(Duration::from_secs(
            config.load_balance.health_check.interval_secs,
        ));
        load_balancer.parallel_health_check = config.load_balance.health_check.parallel;
    }

    Ok(Some(load_balancer))
}

fn background_service_for<S>(
    name: &str,
    config: &ProxyConfig,
    wrap: fn(Arc<LoadBalancer<S>>) -> UpstreamLoadBalancerInner,
) -> io::Result<Option<(UpstreamLoadBalancer, UpstreamLoadBalancerService)>>
where
    S: BackendSelection + Send + Sync + 'static,
    S::Iter: BackendIter,
    LoadBalancer<S>: BackgroundService,
{
    let Some(inner) = configured_load_balancer::<S>(config)? else {
        return Ok(None);
    };

    let service = GenBackgroundService::new(format!("LB {name}"), Arc::new(inner));
    let load_balancer = UpstreamLoadBalancer::from_inner(wrap(service.task()), config);
    Ok(Some((load_balancer, Box::new(service))))
}

fn configured_backends(config: &ProxyConfig) -> io::Result<std::collections::BTreeSet<Backend>> {
    let mut backends = std::collections::BTreeSet::new();
    for (index, upstream) in config.upstreams.iter().enumerate() {
        let weight = config.upstream_weights.get(index).copied().unwrap_or(1);
        let backend = Backend::new_with_weight(upstream, weight)
            .map_err(|error| io::Error::other(error.to_string()))?;
        backends.insert(backend);
    }
    Ok(backends)
}

#[cfg(test)]
fn backend_weights<S>(inner: &LoadBalancer<S>) -> Vec<usize>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    inner
        .backends()
        .get_backend()
        .iter()
        .map(|backend| backend.weight)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use pingora::http::RequestHeader;

    use crate::config::{
        LoadBalanceConfig, LoadBalanceHealthCheckConfig, LoadBalanceSelection, ProxyConfig,
    };

    use super::UpstreamLoadBalancer;

    fn install_test_crypto_provider() {
        #[cfg(feature = "tls-rustls-backend")]
        let _ = crate::tls::install_rustls_crypto_provider();
    }

    fn request() -> RequestHeader {
        RequestHeader::build("GET", b"/app?id=42", None).unwrap()
    }

    #[test]
    fn builds_round_robin_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(balancer.backend_count(), 2);
        assert!(balancer.select(&request(), None).is_some());
    }

    #[test]
    fn builds_weighted_round_robin_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            upstream_weights: vec![1, 4],
            load_balance: LoadBalanceConfig {
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(balancer.backend_count(), 2);
        assert_eq!(balancer.backend_weights(), [1, 4]);
        assert!(balancer.select(&request(), None).is_some());
    }

    #[test]
    fn builds_hash_selection_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::SourceHash,
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let client_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let first = balancer.select(&request(), Some(client_ip)).unwrap();
        let second = balancer.select(&request(), Some(client_ip)).unwrap();
        assert_eq!(first.addr, second.addr);
    }

    #[test]
    fn builds_consistent_header_hash_selection_from_proxy_upstreams() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                selection: LoadBalanceSelection::ConsistentHeaderHash,
                hash_header: Some("x-session".to_owned()),
                max_iterations: 8,
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        let mut request = request();
        request.insert_header("x-session", "abc").unwrap();
        let first = balancer.select(&request, None).unwrap();
        let second = balancer.select(&request, None).unwrap();
        assert_eq!(first.addr, second.addr);
    }

    #[test]
    fn configures_pingora_tcp_health_check() {
        install_test_crypto_provider();
        let balancer = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
            load_balance: LoadBalanceConfig {
                health_check: LoadBalanceHealthCheckConfig {
                    enabled: true,
                    interval_secs: 3,
                    consecutive_success: 2,
                    consecutive_failure: 4,
                    parallel: true,
                },
                ..LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(
            balancer.health_check_frequency(),
            Some(Duration::from_secs(3))
        );
        assert!(balancer.parallel_health_check());
    }

    #[test]
    fn builds_background_service_and_shared_selector() {
        install_test_crypto_provider();
        let (balancer, _service) = UpstreamLoadBalancer::background_service_from_proxy_config(
            "test",
            &ProxyConfig {
                upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
                ..ProxyConfig::default()
            },
        )
        .unwrap()
        .unwrap();

        assert_eq!(balancer.backend_count(), 2);
        assert!(balancer.select(&request(), None).is_some());
    }

    #[test]
    fn stays_disabled_without_load_balanced_upstreams() {
        let without_upstreams =
            UpstreamLoadBalancer::from_proxy_config(&ProxyConfig::default()).unwrap();
        let single_upstream = UpstreamLoadBalancer::from_proxy_config(&ProxyConfig {
            upstreams: vec!["missing-container.test:3000".to_owned()],
            ..ProxyConfig::default()
        })
        .unwrap();

        assert!(without_upstreams.is_none());
        assert!(single_upstream.is_none());
    }
}

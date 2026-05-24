use std::fmt::{Debug, Formatter};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use pingora::lb::Backend;
use pingora::lb::Backends;
use pingora::lb::discovery::Static;
use pingora::lb::health_check::TcpHealthCheck;
use pingora::lb::prelude::{LoadBalancer, RoundRobin};
use pingora::services::background::GenBackgroundService;

use crate::config::ProxyConfig;

pub type UpstreamLoadBalancerService = GenBackgroundService<LoadBalancer<RoundRobin>>;

#[derive(Clone)]
pub struct UpstreamLoadBalancer {
    inner: Arc<LoadBalancer<RoundRobin>>,
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
        let Some(inner) = configured_load_balancer(config)? else {
            return Ok(None);
        };

        Ok(Some(Self::from_arc(
            Arc::new(inner),
            config.load_balance.max_iterations,
        )))
    }

    pub fn background_service_from_proxy_config(
        name: &str,
        config: &ProxyConfig,
    ) -> io::Result<Option<(Self, UpstreamLoadBalancerService)>> {
        let Some(inner) = configured_load_balancer(config)? else {
            return Ok(None);
        };

        let service = GenBackgroundService::new(format!("LB {name}"), Arc::new(inner));
        let load_balancer = Self::from_arc(service.task(), config.load_balance.max_iterations);
        Ok(Some((load_balancer, service)))
    }

    pub fn select(&self) -> Option<Backend> {
        self.inner.select(b"", self.max_iterations)
    }

    fn from_arc(inner: Arc<LoadBalancer<RoundRobin>>, max_iterations: usize) -> Self {
        Self {
            inner,
            max_iterations,
        }
    }

    #[cfg(test)]
    fn backend_count(&self) -> usize {
        self.inner.backends().get_backend().len()
    }

    #[cfg(test)]
    fn backend_weights(&self) -> Vec<usize> {
        self.inner
            .backends()
            .get_backend()
            .iter()
            .map(|backend| backend.weight)
            .collect()
    }

    #[cfg(test)]
    fn health_check_frequency(&self) -> Option<Duration> {
        self.inner.health_check_frequency
    }

    #[cfg(test)]
    fn parallel_health_check(&self) -> bool {
        self.inner.parallel_health_check
    }
}

fn configured_load_balancer(config: &ProxyConfig) -> io::Result<Option<LoadBalancer<RoundRobin>>> {
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
mod tests {
    use std::time::Duration;

    use crate::config::{LoadBalanceConfig, LoadBalanceHealthCheckConfig, ProxyConfig};

    use super::UpstreamLoadBalancer;

    fn install_test_crypto_provider() {
        #[cfg(feature = "tls-rustls-backend")]
        let _ = crate::tls::install_rustls_crypto_provider();
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
        assert!(balancer.select().is_some());
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
        assert!(balancer.select().is_some());
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
        assert!(balancer.select().is_some());
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

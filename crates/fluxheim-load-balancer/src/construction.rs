use std::io;
use std::sync::Arc;

use fluxheim_config::{LoadBalanceSelection, ProxyConfig};

use crate::UpstreamLoadBalancer;
use crate::api::LoadBalancerMetricLabels;
use crate::discovery::{
    background_maglev_service_for, background_service_for, configured_load_balancer,
    configured_maglev_table, configured_nginx_ketama_table,
};
use crate::inner::UpstreamLoadBalancerInner;
use crate::policy::BackendSelectionPolicy;
use crate::service::UpstreamLoadBalancerService;
use crate::state::BackendLatencyState;

impl UpstreamLoadBalancer {
    pub fn from_proxy_config(config: &ProxyConfig) -> io::Result<Option<Self>> {
        #[cfg(test)]
        crate::install_test_crypto_provider();

        let backend_policy = BackendSelectionPolicy::from_config(config);
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::RoundRobin(Arc::new(inner)),
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::LeastConnections => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::LeastConnections(Arc::new(inner)),
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::LeastSessions => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::LeastSessions(Arc::new(inner)),
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::LeastTime => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::LeastTime {
                        inner: Arc::new(inner),
                        latency: Arc::new(BackendLatencyState::default()),
                    },
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::PowerOfTwo => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::PowerOfTwo(Arc::new(inner)),
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::SourceHash
            | LoadBalanceSelection::UriHash
            | LoadBalanceSelection::HeaderHash
            | LoadBalanceSelection::CookieHash => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::FnvHash(Arc::new(inner)),
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::ConsistentSourceHash
            | LoadBalanceSelection::ConsistentUriHash
            | LoadBalanceSelection::ConsistentHeaderHash
            | LoadBalanceSelection::ConsistentCookieHash => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::ConsistentHash(Arc::new(inner)),
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::NginxConsistentSourceHash
            | LoadBalanceSelection::NginxConsistentUriHash
            | LoadBalanceSelection::NginxConsistentHeaderHash
            | LoadBalanceSelection::NginxConsistentCookieHash => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                let table = Arc::new(configured_nginx_ketama_table(config)?);
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::NginxConsistentHash {
                        inner: Arc::new(inner),
                        table,
                    },
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::BoundedLoadConsistentSourceHash
            | LoadBalanceSelection::BoundedLoadConsistentUriHash
            | LoadBalanceSelection::BoundedLoadConsistentHeaderHash
            | LoadBalanceSelection::BoundedLoadConsistentCookieHash => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::BoundedLoadConsistentHash {
                        inner: Arc::new(inner),
                        factor_per_mille: config.load_balance.bounded_load_factor_per_mille,
                    },
                    config,
                    backend_policy,
                )))
            }
            LoadBalanceSelection::MaglevSourceHash
            | LoadBalanceSelection::MaglevUriHash
            | LoadBalanceSelection::MaglevHeaderHash
            | LoadBalanceSelection::MaglevCookieHash => {
                let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
                    return Ok(None);
                };
                let table = Arc::new(configured_maglev_table(config)?);
                Ok(Some(Self::from_inner(
                    UpstreamLoadBalancerInner::MaglevHash {
                        inner: Arc::new(inner),
                        table,
                    },
                    config,
                    backend_policy,
                )))
            }
        }
    }

    pub fn background_service_from_proxy_config(
        name: &str,
        vhost: &str,
        route: Option<&str>,
        config: &ProxyConfig,
    ) -> io::Result<Option<(Self, UpstreamLoadBalancerService)>> {
        #[cfg(test)]
        crate::install_test_crypto_provider();

        let metric_labels = LoadBalancerMetricLabels::new(vhost, route);
        match config.load_balance.selection {
            LoadBalanceSelection::RoundRobin => background_service_for(
                name,
                metric_labels,
                config,
                UpstreamLoadBalancerInner::RoundRobin,
            ),
            LoadBalanceSelection::LeastConnections => {
                background_service_for(name, metric_labels, config, |inner| {
                    UpstreamLoadBalancerInner::LeastConnections(inner)
                })
            }
            LoadBalanceSelection::LeastSessions => {
                background_service_for(name, metric_labels, config, |inner| {
                    UpstreamLoadBalancerInner::LeastSessions(inner)
                })
            }
            LoadBalanceSelection::LeastTime => {
                background_service_for(name, metric_labels, config, |inner| {
                    UpstreamLoadBalancerInner::LeastTime {
                        inner,
                        latency: Arc::new(BackendLatencyState::default()),
                    }
                })
            }
            LoadBalanceSelection::PowerOfTwo => {
                background_service_for(name, metric_labels, config, |inner| {
                    UpstreamLoadBalancerInner::PowerOfTwo(inner)
                })
            }
            LoadBalanceSelection::SourceHash
            | LoadBalanceSelection::UriHash
            | LoadBalanceSelection::HeaderHash
            | LoadBalanceSelection::CookieHash => background_service_for(
                name,
                metric_labels,
                config,
                UpstreamLoadBalancerInner::FnvHash,
            ),
            LoadBalanceSelection::ConsistentSourceHash
            | LoadBalanceSelection::ConsistentUriHash
            | LoadBalanceSelection::ConsistentHeaderHash
            | LoadBalanceSelection::ConsistentCookieHash => background_service_for(
                name,
                metric_labels,
                config,
                UpstreamLoadBalancerInner::ConsistentHash,
            ),
            LoadBalanceSelection::NginxConsistentSourceHash
            | LoadBalanceSelection::NginxConsistentUriHash
            | LoadBalanceSelection::NginxConsistentHeaderHash
            | LoadBalanceSelection::NginxConsistentCookieHash => {
                let table = Arc::new(configured_nginx_ketama_table(config)?);
                background_service_for(name, metric_labels, config, move |inner| {
                    UpstreamLoadBalancerInner::NginxConsistentHash {
                        inner,
                        table: Arc::clone(&table),
                    }
                })
            }
            LoadBalanceSelection::BoundedLoadConsistentSourceHash
            | LoadBalanceSelection::BoundedLoadConsistentUriHash
            | LoadBalanceSelection::BoundedLoadConsistentHeaderHash
            | LoadBalanceSelection::BoundedLoadConsistentCookieHash => {
                let factor_per_mille = config.load_balance.bounded_load_factor_per_mille;
                background_service_for(name, metric_labels, config, move |inner| {
                    UpstreamLoadBalancerInner::BoundedLoadConsistentHash {
                        inner,
                        factor_per_mille,
                    }
                })
            }
            LoadBalanceSelection::MaglevSourceHash
            | LoadBalanceSelection::MaglevUriHash
            | LoadBalanceSelection::MaglevHeaderHash
            | LoadBalanceSelection::MaglevCookieHash => {
                background_maglev_service_for(name, metric_labels, config)
            }
        }
    }
}

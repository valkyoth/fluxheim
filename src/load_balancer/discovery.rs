use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::FutureExt;
use pingora::lb::Backend;
use pingora::lb::Backends;
use pingora::lb::discovery::{ServiceDiscovery, Static};
use pingora::lb::prelude::LoadBalancer;
use pingora::lb::selection::{BackendIter, BackendSelection, RoundRobin};
use pingora::services::background::{BackgroundService, GenBackgroundService};
use pingora::{Error, ErrorType};

use crate::config::ProxyConfig;
use crate::flux_error::{FluxError, FluxResult};

use super::backend::{FluxBackend, FluxBackendSet};
use super::health::configured_health_check;
use super::selection::MaglevTable;
use super::{UpstreamLoadBalancer, UpstreamLoadBalancerInner, UpstreamLoadBalancerService};

pub(super) fn configured_load_balancer<S>(
    config: &ProxyConfig,
) -> io::Result<Option<LoadBalancer<S>>>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    if config.upstreams.len() < 2
        && config.upstreams_file.is_none()
        && config.upstream_dns_refresh_secs.is_none()
    {
        return Ok(None);
    }

    let mut load_balancer = LoadBalancer::from_backends(configured_backend_discovery(config)?);
    if config.upstreams_file.is_some() {
        load_balancer.update_frequency = Some(Duration::from_secs(
            config.upstreams_file_refresh_secs.clamp(1, 300),
        ));
    } else if let Some(refresh_secs) = config.upstream_dns_refresh_secs {
        load_balancer.update_frequency = Some(Duration::from_secs(refresh_secs.clamp(1, 300)));
    }
    load_balancer
        .update()
        .now_or_never()
        .ok_or_else(|| io::Error::other("static load balancer update blocked unexpectedly"))?
        .map_err(|error| io::Error::other(error.to_string()))?;
    apply_disabled_backend_enablement(&load_balancer, config);
    if config.load_balance.health_check.enabled {
        let health_check = configured_health_check(config)?;
        load_balancer.set_health_check(health_check);
        load_balancer.health_check_frequency = Some(Duration::from_secs(
            config.load_balance.health_check.interval_secs,
        ));
        load_balancer.parallel_health_check = config.load_balance.health_check.parallel;
    }

    Ok(Some(load_balancer))
}

fn apply_disabled_backend_enablement<S>(load_balancer: &LoadBalancer<S>, config: &ProxyConfig)
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    for upstream in &config.disabled_upstreams {
        if let Ok(backend) =
            FluxBackend::new(upstream).and_then(|backend| backend.to_pingora_backend())
        {
            load_balancer.backends().set_enable(&backend, false);
        }
    }
}

struct FileUpstreamDiscovery {
    path: PathBuf,
}

#[async_trait]
trait FluxBackendDiscovery {
    async fn discover_flux_backends(&self) -> Result<FluxBackendSet, DiscoveryError>;
}

#[async_trait]
impl FluxBackendDiscovery for FileUpstreamDiscovery {
    async fn discover_flux_backends(&self) -> Result<FluxBackendSet, DiscoveryError> {
        let upstreams = read_proxy_upstreams_file_for_discovery(self.path.clone()).await?;
        let mut backends = FluxBackendSet::default();
        for upstream in upstreams {
            let backend = FluxBackend::new(&upstream)
                .map_err(|error| DiscoveryError::new(ErrorType::InvalidHTTPHeader, error))?;
            backends.insert(backend);
        }
        Ok(backends)
    }
}

#[async_trait]
impl ServiceDiscovery for FileUpstreamDiscovery {
    async fn discover(
        &self,
    ) -> pingora::Result<(
        std::collections::BTreeSet<Backend>,
        std::collections::HashMap<u64, bool>,
    )> {
        adapt_flux_discovery_to_pingora(self.discover_flux_backends().await)
    }
}

async fn read_proxy_upstreams_file_for_discovery(
    path: PathBuf,
) -> Result<Vec<String>, DiscoveryError> {
    let result = if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::spawn_blocking(move || crate::config::read_proxy_upstreams_file(&path))
            .await
            .map_err(|error| {
                DiscoveryError::new(
                    ErrorType::InternalError,
                    FluxError::io(
                        "proxy upstreams file discovery task failed",
                        io::Error::other(error.to_string()),
                    ),
                )
            })?
    } else {
        // Pingora performs the initial load-balancer update synchronously during
        // construction. There is no Tokio reactor yet in that path, so this
        // bootstrap read must stay immediately ready for now_or_never().
        crate::config::read_proxy_upstreams_file(&path)
    };

    result.map_err(|error| {
        DiscoveryError::new(
            ErrorType::ReadError,
            FluxError::io("failed to read proxy upstreams file", error),
        )
    })
}

struct DnsUpstreamDiscovery {
    upstreams: Arc<[String]>,
}

#[async_trait]
impl FluxBackendDiscovery for DnsUpstreamDiscovery {
    async fn discover_flux_backends(&self) -> Result<FluxBackendSet, DiscoveryError> {
        let mut backends = FluxBackendSet::default();
        for upstream in self.upstreams.iter() {
            let resolved = resolve_proxy_upstream_for_discovery(upstream).await?;
            for address in resolved {
                let backend = FluxBackend::new(&address.to_string())
                    .map_err(|error| DiscoveryError::new(ErrorType::InternalError, error))?;
                backends.insert(backend);
            }
        }
        if backends.is_empty() {
            return Err(DiscoveryError::new(
                ErrorType::ConnectError,
                FluxError::InvalidInput("DNS discovery resolved no proxy upstreams"),
            ));
        }
        Ok(backends)
    }
}

#[async_trait]
impl ServiceDiscovery for DnsUpstreamDiscovery {
    async fn discover(
        &self,
    ) -> pingora::Result<(
        std::collections::BTreeSet<Backend>,
        std::collections::HashMap<u64, bool>,
    )> {
        adapt_flux_discovery_to_pingora(self.discover_flux_backends().await)
    }
}

fn adapt_flux_discovery_to_pingora(
    discovered: Result<FluxBackendSet, DiscoveryError>,
) -> pingora::Result<(
    std::collections::BTreeSet<Backend>,
    std::collections::HashMap<u64, bool>,
)> {
    discovered
        .and_then(|backends| {
            backends
                .into_pingora_parts()
                .map_err(|error| DiscoveryError::new(ErrorType::InternalError, error))
        })
        .map_err(DiscoveryError::into_pingora)
}

async fn resolve_proxy_upstream_for_discovery(
    upstream: &str,
) -> Result<Vec<SocketAddr>, DiscoveryError> {
    let result = if tokio::runtime::Handle::try_current().is_ok() {
        tokio::net::lookup_host(upstream)
            .await
            .map(|resolved| resolved.collect())
    } else {
        // See read_proxy_upstreams_file_for_discovery(): construction-time
        // update is polled synchronously before a reactor is available. Later
        // refreshes run under Tokio and use lookup_host().
        upstream
            .to_socket_addrs()
            .map(|resolved| resolved.collect::<Vec<_>>())
    };

    result.map_err(|error| {
        DiscoveryError::new(
            ErrorType::ConnectError,
            FluxError::io("failed to resolve proxy upstream", error),
        )
    })
}

struct DiscoveryError {
    kind: ErrorType,
    error: FluxError,
}

impl DiscoveryError {
    fn new(kind: ErrorType, error: FluxError) -> Self {
        Self { kind, error }
    }

    fn into_pingora(self) -> Box<Error> {
        Error::because(self.kind, "load-balancer discovery failed", self.error)
    }
}

pub(super) fn background_service_for<S, F>(
    name: &str,
    config: &ProxyConfig,
    wrap: F,
) -> io::Result<Option<(UpstreamLoadBalancer, UpstreamLoadBalancerService)>>
where
    S: BackendSelection + Send + Sync + 'static,
    S::Iter: BackendIter,
    LoadBalancer<S>: BackgroundService,
    F: FnOnce(Arc<LoadBalancer<S>>) -> UpstreamLoadBalancerInner,
{
    let Some(inner) = configured_load_balancer::<S>(config)? else {
        return Ok(None);
    };

    let service = GenBackgroundService::new(format!("LB {name}"), Arc::new(inner));
    let load_balancer = UpstreamLoadBalancer::from_inner(wrap(service.task()), config);
    Ok(Some((load_balancer, Box::new(service))))
}

pub(super) fn background_maglev_service_for(
    name: &str,
    config: &ProxyConfig,
) -> io::Result<Option<(UpstreamLoadBalancer, UpstreamLoadBalancerService)>> {
    let Some(inner) = configured_load_balancer::<RoundRobin>(config)? else {
        return Ok(None);
    };
    let table = Arc::new(configured_maglev_table(config)?);
    let service = GenBackgroundService::new(format!("LB {name}"), Arc::new(inner));
    let load_balancer = UpstreamLoadBalancer::from_inner(
        UpstreamLoadBalancerInner::MaglevHash {
            inner: service.task(),
            table,
        },
        config,
    );
    Ok(Some((load_balancer, Box::new(service))))
}

fn configured_backends(config: &ProxyConfig) -> FluxResult<FluxBackendSet> {
    let mut backends = FluxBackendSet::default();
    for (index, upstream) in config.upstreams.iter().enumerate() {
        let weight = config.upstream_weights.get(index).copied().unwrap_or(1);
        let backend = FluxBackend::new_with_weight(upstream, weight)?;
        backends.insert(backend);
    }
    Ok(backends)
}

pub(super) fn configured_maglev_table(config: &ProxyConfig) -> io::Result<MaglevTable> {
    let backends = configured_backends(config).map_err(FluxError::into_io)?;
    MaglevTable::from_backend_identities(backends.iter()).map_err(FluxError::into_io)
}

fn configured_backend_discovery(config: &ProxyConfig) -> io::Result<Backends> {
    if let Some(path) = &config.upstreams_file {
        return Ok(Backends::new(Box::new(FileUpstreamDiscovery {
            path: path.clone(),
        })));
    }
    if config.upstream_dns_refresh_secs.is_some() {
        return Ok(Backends::new(Box::new(DnsUpstreamDiscovery {
            upstreams: config.upstreams.clone().into(),
        })));
    }

    Ok(Backends::new(Static::new(
        configured_backends(config)
            .and_then(FluxBackendSet::into_pingora_backends)
            .map_err(FluxError::into_io)?,
    )))
}

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::FutureExt;
#[cfg(unix)]
use pingora::server::ListenFds;
use pingora::server::ShutdownWatch;
use pingora::services::{ServiceReadyNotifier, ServiceWithDependents};

use crate::config::ProxyConfig;
use crate::flux_error::{FluxError, FluxResult};

use super::backend::{FluxBackend, FluxBackendDiscovery, FluxBackendSet, FluxLoadBalancerRuntime};
use super::health::configured_health_check;
use super::policy::BackendSelectionPolicy;
use super::selection::MaglevTable;
use super::{UpstreamLoadBalancer, UpstreamLoadBalancerInner, UpstreamLoadBalancerService};

pub(super) fn configured_load_balancer(
    config: &ProxyConfig,
    backend_policy: &BackendSelectionPolicy,
) -> io::Result<Option<FluxLoadBalancerRuntime>> {
    if config.upstreams.len() < 2
        && config.upstreams_file.is_none()
        && config.upstream_dns_refresh_secs.is_none()
    {
        return Ok(None);
    }

    let mut load_balancer = FluxLoadBalancerRuntime::new(configured_backend_discovery(config)?);
    if config.upstreams_file.is_some() {
        load_balancer.set_update_frequency(Some(Duration::from_secs(
            config.upstreams_file_refresh_secs.clamp(1, 300),
        )));
    } else if let Some(refresh_secs) = config.upstream_dns_refresh_secs {
        load_balancer.set_update_frequency(Some(Duration::from_secs(refresh_secs.clamp(1, 300))));
    }
    load_balancer
        .update()
        .now_or_never()
        .ok_or_else(|| io::Error::other("static load balancer update blocked unexpectedly"))?
        .map_err(FluxError::into_io)?;
    apply_disabled_backend_enablement(&load_balancer, config);
    if config.load_balance.health_check.enabled {
        let health_check = configured_health_check(config, backend_policy.health_weights())?;
        load_balancer.set_health_check(health_check);
        load_balancer.set_health_check_frequency(Some(Duration::from_secs(
            config.load_balance.health_check.interval_secs,
        )));
        load_balancer.set_parallel_health_check(config.load_balance.health_check.parallel);
    }

    Ok(Some(load_balancer))
}

fn apply_disabled_backend_enablement(
    load_balancer: &FluxLoadBalancerRuntime,
    config: &ProxyConfig,
) {
    for upstream in &config.disabled_upstreams {
        if let Ok(backend) =
            FluxBackend::new(upstream).and_then(|backend| backend.to_pingora_backend())
        {
            load_balancer.set_enable(&backend, false);
        }
    }
}

struct FileUpstreamDiscovery {
    path: PathBuf,
}

struct StaticUpstreamDiscovery {
    backends: FluxBackendSet,
}

#[async_trait]
impl FluxBackendDiscovery for StaticUpstreamDiscovery {
    async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet> {
        Ok(self.backends.clone())
    }
}

#[async_trait]
impl FluxBackendDiscovery for FileUpstreamDiscovery {
    async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet> {
        let upstreams = read_proxy_upstreams_file_for_discovery(self.path.clone()).await?;
        let mut backends = FluxBackendSet::default();
        for upstream in upstreams {
            let backend = FluxBackend::new(&upstream)?;
            backends.insert(backend);
        }
        Ok(backends)
    }
}

async fn read_proxy_upstreams_file_for_discovery(path: PathBuf) -> FluxResult<Vec<String>> {
    let result = if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::spawn_blocking(move || crate::config::read_proxy_upstreams_file(&path))
            .await
            .map_err(|error| {
                FluxError::io(
                    "proxy upstreams file discovery task failed",
                    io::Error::other(error.to_string()),
                )
            })?
    } else {
        // Pingora performs the initial load-balancer update synchronously during
        // construction. There is no Tokio reactor yet in that path, so this
        // bootstrap read must stay immediately ready for now_or_never().
        crate::config::read_proxy_upstreams_file(&path)
    };

    result.map_err(|error| FluxError::io("failed to read proxy upstreams file", error))
}

struct DnsUpstreamDiscovery {
    upstreams: Arc<[String]>,
}

#[async_trait]
impl FluxBackendDiscovery for DnsUpstreamDiscovery {
    async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet> {
        let mut backends = FluxBackendSet::default();
        for upstream in self.upstreams.iter() {
            let resolved = resolve_proxy_upstream_for_discovery(upstream).await?;
            for address in resolved {
                let backend = FluxBackend::new(&address.to_string())?;
                backends.insert(backend);
            }
        }
        if backends.is_empty() {
            return Err(FluxError::InvalidInput(
                "DNS discovery resolved no proxy upstreams",
            ));
        }
        Ok(backends)
    }
}

async fn resolve_proxy_upstream_for_discovery(upstream: &str) -> FluxResult<Vec<SocketAddr>> {
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

    result.map_err(|error| FluxError::io("failed to resolve proxy upstream", error))
}

pub(super) fn background_service_for<F>(
    name: &str,
    config: &ProxyConfig,
    wrap: F,
) -> io::Result<Option<(UpstreamLoadBalancer, UpstreamLoadBalancerService)>>
where
    F: FnOnce(Arc<FluxLoadBalancerRuntime>) -> UpstreamLoadBalancerInner,
{
    let backend_policy = BackendSelectionPolicy::from_config(config);
    let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
        return Ok(None);
    };

    let service = FluxLoadBalancerBackgroundService::new(format!("LB {name}"), inner);
    let load_balancer =
        UpstreamLoadBalancer::from_inner(wrap(service.task()), config, backend_policy);
    Ok(Some((load_balancer, Box::new(service))))
}

pub(super) fn background_maglev_service_for(
    name: &str,
    config: &ProxyConfig,
) -> io::Result<Option<(UpstreamLoadBalancer, UpstreamLoadBalancerService)>> {
    let backend_policy = BackendSelectionPolicy::from_config(config);
    let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
        return Ok(None);
    };
    let table = Arc::new(configured_maglev_table(config)?);
    let service = FluxLoadBalancerBackgroundService::new(format!("LB {name}"), inner);
    let load_balancer = UpstreamLoadBalancer::from_inner(
        UpstreamLoadBalancerInner::MaglevHash {
            inner: service.task(),
            table,
        },
        config,
        backend_policy,
    );
    Ok(Some((load_balancer, Box::new(service))))
}

struct FluxLoadBalancerBackgroundService {
    name: String,
    task: Arc<FluxLoadBalancerRuntime>,
}

impl FluxLoadBalancerBackgroundService {
    fn new(name: String, task: FluxLoadBalancerRuntime) -> Self {
        Self {
            name,
            task: Arc::new(task),
        }
    }

    fn task(&self) -> Arc<FluxLoadBalancerRuntime> {
        self.task.clone()
    }
}

#[async_trait]
impl ServiceWithDependents for FluxLoadBalancerBackgroundService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<ListenFds>,
        shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
        ready: ServiceReadyNotifier,
    ) {
        self.task.run(shutdown, Some(ready)).await;
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
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

fn configured_backend_discovery(config: &ProxyConfig) -> io::Result<Box<dyn FluxBackendDiscovery>> {
    if let Some(path) = &config.upstreams_file {
        return Ok(Box::new(FileUpstreamDiscovery { path: path.clone() }));
    }
    if config.upstream_dns_refresh_secs.is_some() {
        return Ok(Box::new(DnsUpstreamDiscovery {
            upstreams: config.upstreams.clone().into(),
        }));
    }

    Ok(Box::new(StaticUpstreamDiscovery {
        backends: configured_backends(config).map_err(FluxError::into_io)?,
    }))
}

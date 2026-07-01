use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::FutureExt;

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::ProxyConfig;

use super::backend::{FluxBackend, FluxBackendDiscovery, FluxBackendSet, FluxLoadBalancerRuntime};
use super::discovery_dns::DnsUpstreamDiscovery;
use super::discovery_http::fetch_proxy_upstreams_http_for_discovery;
use super::health::configured_health_check;
use super::policy::BackendSelectionPolicy;
use super::selection_ketama::NginxKetamaTable;
use super::selection_maglev::MaglevTable;
use super::{
    LoadBalancerMetricLabels, UpstreamLoadBalancer, UpstreamLoadBalancerInner,
    UpstreamLoadBalancerService,
};

pub(super) fn configured_load_balancer(
    config: &ProxyConfig,
    backend_policy: &BackendSelectionPolicy,
) -> io::Result<Option<FluxLoadBalancerRuntime>> {
    #[cfg(test)]
    crate::install_test_crypto_provider();

    if config.upstreams.len() < 2
        && config.upstreams_file.is_none()
        && config.upstreams_http_url.is_none()
        && config.upstream_dns_refresh_secs.is_none()
    {
        return Ok(None);
    }

    let mut load_balancer = FluxLoadBalancerRuntime::new(configured_backend_discovery(config)?);
    if config.upstreams_file.is_some() {
        load_balancer.set_update_frequency(Some(Duration::from_secs(
            config.upstreams_file_refresh_secs.clamp(1, 300),
        )));
    } else if config.upstreams_http_url.is_some() {
        load_balancer.set_update_frequency(Some(Duration::from_secs(
            config.upstreams_http_refresh_secs.clamp(1, 300),
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
        if let Ok(backend) = FluxBackend::new(upstream) {
            load_balancer.set_enable(&backend, false);
        }
    }
}

struct FileUpstreamDiscovery {
    path: PathBuf,
}

struct HttpUpstreamDiscovery {
    url: String,
    bearer_token_file: Option<PathBuf>,
    allow_private_backends: bool,
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

#[async_trait]
impl FluxBackendDiscovery for HttpUpstreamDiscovery {
    async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet> {
        let upstreams = fetch_proxy_upstreams_http_for_discovery(
            self.url.clone(),
            self.bearer_token_file.clone(),
            self.allow_private_backends,
        )
        .await?;
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
        tokio::task::spawn_blocking(move || fluxheim_config::read_proxy_upstreams_file(&path))
            .await
            .map_err(|error| {
                FluxError::io(
                    "proxy upstreams file discovery task failed",
                    io::Error::other(error.to_string()),
                )
            })?
    } else {
        // Some bootstrap callers perform the initial load-balancer update
        // synchronously before a Tokio reactor is available, so this read must
        // stay immediately ready for now_or_never().
        fluxheim_config::read_proxy_upstreams_file(&path)
    };

    result.map_err(|error| FluxError::io("failed to read proxy upstreams file", error))
}

pub(super) fn background_service_for<F>(
    name: &str,
    metric_labels: LoadBalancerMetricLabels,
    config: &ProxyConfig,
    wrap: F,
) -> io::Result<Option<(UpstreamLoadBalancer, UpstreamLoadBalancerService)>>
where
    F: FnOnce(Arc<FluxLoadBalancerRuntime>) -> UpstreamLoadBalancerInner,
{
    let backend_policy = BackendSelectionPolicy::from_config(config);
    let Some(mut inner) = configured_load_balancer(config, &backend_policy)? else {
        return Ok(None);
    };
    inner.set_metric_labels(metric_labels);

    let inner_service = crate::background::background_service_with_kind(
        format!("LB {name}"),
        crate::background::BackgroundTaskKind::LoadBalancerRefresh,
        inner,
    );
    let load_balancer =
        UpstreamLoadBalancer::from_inner(wrap(inner_service.task()), config, backend_policy);
    let service = UpstreamLoadBalancerService::new(inner_service, load_balancer.clone());
    Ok(Some((load_balancer, service)))
}

pub(super) fn background_maglev_service_for(
    name: &str,
    metric_labels: LoadBalancerMetricLabels,
    config: &ProxyConfig,
) -> io::Result<Option<(UpstreamLoadBalancer, UpstreamLoadBalancerService)>> {
    let backend_policy = BackendSelectionPolicy::from_config(config);
    let Some(mut inner) = configured_load_balancer(config, &backend_policy)? else {
        return Ok(None);
    };
    inner.set_metric_labels(metric_labels);
    let table = Arc::new(configured_maglev_table(config)?);
    let inner_service = crate::background::background_service_with_kind(
        format!("LB {name}"),
        crate::background::BackgroundTaskKind::LoadBalancerRefresh,
        inner,
    );
    let load_balancer = UpstreamLoadBalancer::from_inner(
        UpstreamLoadBalancerInner::MaglevHash {
            inner: inner_service.task(),
            table,
        },
        config,
        backend_policy,
    );
    let service = UpstreamLoadBalancerService::new(inner_service, load_balancer.clone());
    Ok(Some((load_balancer, service)))
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

pub(super) fn configured_nginx_ketama_table(config: &ProxyConfig) -> io::Result<NginxKetamaTable> {
    if config.upstreams_file.is_some()
        || config.upstreams_http_url.is_some()
        || config.upstream_dns_refresh_secs.is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nginx-compatible Ketama selections require static proxy.upstreams; dynamic discovery would make the compatibility ring stale",
        ));
    }
    let backends = configured_backends(config).map_err(FluxError::into_io)?;
    NginxKetamaTable::from_backend_identities(backends.iter()).map_err(FluxError::into_io)
}

fn configured_backend_discovery(config: &ProxyConfig) -> io::Result<Box<dyn FluxBackendDiscovery>> {
    if let Some(path) = &config.upstreams_file {
        return Ok(Box::new(FileUpstreamDiscovery { path: path.clone() }));
    }
    if let Some(url) = &config.upstreams_http_url {
        return Ok(Box::new(HttpUpstreamDiscovery {
            url: url.clone(),
            bearer_token_file: config.upstreams_http_bearer_token_file.clone(),
            allow_private_backends: config.upstreams_http_allow_private_backends,
        }));
    }
    if config.upstream_dns_refresh_secs.is_some() {
        return Ok(Box::new(DnsUpstreamDiscovery {
            upstreams: config.upstreams.clone().into(),
            allow_private_backends: config.upstream_dns_allow_private_backends,
        }));
    }

    Ok(Box::new(StaticUpstreamDiscovery {
        backends: configured_backends(config).map_err(FluxError::into_io)?,
    }))
}

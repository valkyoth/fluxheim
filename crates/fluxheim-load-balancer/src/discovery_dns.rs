use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use async_trait::async_trait;
use fluxheim_common::{FluxError, FluxResult};

use super::backend::{FluxBackend, FluxBackendDiscovery, FluxBackendSet};
use super::discovery_http::restricted_discovery_ip;

pub(super) struct DnsUpstreamDiscovery {
    pub(super) upstreams: Arc<[String]>,
    pub(super) allow_private_backends: bool,
}

#[async_trait]
impl FluxBackendDiscovery for DnsUpstreamDiscovery {
    async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet> {
        let mut backends = FluxBackendSet::default();
        for upstream in self.upstreams.iter() {
            let resolved = resolve_proxy_upstream_for_discovery(upstream).await?;
            for address in resolved {
                if !self.allow_private_backends && restricted_discovery_ip(address.ip()) {
                    return Err(FluxError::InvalidInput(
                        "DNS discovery resolved a private, loopback, link-local, multicast, reserved, or documentation IP address without proxy.upstream_dns_allow_private_backends",
                    ));
                }
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
        // Construction-time update is polled synchronously before a reactor is
        // available. Later refreshes run under Tokio and use lookup_host().
        upstream
            .to_socket_addrs()
            .map(|resolved| resolved.collect::<Vec<_>>())
    };

    result.map_err(|error| FluxError::io("failed to resolve proxy upstream", error))
}

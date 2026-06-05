use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use pingora::connectors::TransportConnector;
use pingora::upstreams::peer::HttpPeer;

use crate::config::StreamRouteConfig;
use crate::config_net::upstream_host;
use crate::flux_error::{FluxError, FluxResult};
use crate::stream_proxy::FluxStream;
use crate::upstream_tls::RuntimeUpstreamTls;

#[derive(Clone)]
pub(crate) struct StreamUpstreamTlsConnector {
    sni: Option<Arc<str>>,
    verify_cert: bool,
    verify_hostname: bool,
    alternative_cn: Option<Arc<str>>,
    material: RuntimeUpstreamTls,
    connector: Arc<TransportConnector>,
}

impl StreamUpstreamTlsConnector {
    pub(crate) fn from_route(route: &StreamRouteConfig) -> FluxResult<Option<Self>> {
        if !route.upstream_tls {
            return Ok(None);
        }

        let material = RuntimeUpstreamTls::from_paths(
            route.upstream_ca_path.as_deref(),
            route.upstream_client_cert_path.as_deref(),
            route.upstream_client_key_path.as_deref(),
        )
        .map_err(|error| {
            FluxError::io(
                "load stream upstream TLS material",
                io::Error::new(error.kind(), format!("route {}: {error}", route.name)),
            )
        })?;

        Ok(Some(Self {
            sni: route.upstream_sni.as_deref().map(Arc::from),
            verify_cert: route.upstream_verify_cert,
            verify_hostname: route.upstream_verify_hostname,
            alternative_cn: route.upstream_alternative_cn.as_deref().map(Arc::from),
            material,
            connector: Arc::new(TransportConnector::new(None)),
        }))
    }

    pub(crate) async fn connect(
        &self,
        upstream_authority: &str,
        socket_addr: std::net::SocketAddr,
        connect_timeout: Duration,
    ) -> FluxResult<FluxStream> {
        let sni = stream_upstream_tls_sni(self.sni.as_deref(), upstream_authority);
        let mut peer = HttpPeer::new(socket_addr, true, sni);
        peer.options.connection_timeout = Some(connect_timeout);
        peer.options.total_connection_timeout = Some(connect_timeout);
        peer.options.verify_cert = self.verify_cert;
        peer.options.verify_hostname = self.verify_hostname;
        peer.options.alternative_cn = self.alternative_cn.as_deref().map(str::to_owned);
        peer.options.ca = self.material.ca.clone();
        peer.client_cert_key = self.material.client_cert_key.clone();

        self.connector
            .get_stream(&peer)
            .await
            .map(|(stream, _reused)| Box::new(stream) as FluxStream)
            .map_err(|error| {
                FluxError::invalid_input(format!("stream upstream TLS connect failed: {error}"))
            })
    }
}

fn stream_upstream_tls_sni(configured: Option<&str>, upstream_authority: &str) -> String {
    configured
        .map(str::to_owned)
        .or_else(|| {
            let host = upstream_host(upstream_authority)?;
            host.parse::<IpAddr>().is_err().then_some(host)
        })
        .unwrap_or_default()
}

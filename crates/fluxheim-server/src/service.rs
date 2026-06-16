use fluxheim_config::{Config, ProxyConfig};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceKind {
    AdminControlPlane,
    AdminOpsSocket,
    LoadBalancerHealthChecks,
    MetricsHttp,
    ProxyHttp,
    StreamProxy,
    UdpProxy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceSpec {
    name: &'static str,
    kind: ServiceKind,
}

impl ServiceSpec {
    pub const fn new(name: &'static str, kind: ServiceKind) -> Self {
        Self { name, kind }
    }

    pub const fn name(self) -> &'static str {
        self.name
    }

    pub const fn kind(self) -> ServiceKind {
        self.kind
    }
}

pub(crate) fn service_specs_from_config(config: &Config) -> Vec<ServiceSpec> {
    let mut services = Vec::new();

    if !config.server.listen.is_empty() || !config.server.tls_listen.is_empty() {
        services.push(ServiceSpec::new(
            "Fluxheim HTTP Proxy",
            ServiceKind::ProxyHttp,
        ));
    }
    if any_load_balancer_pool_configured(config) {
        services.push(ServiceSpec::new(
            "Fluxheim Load Balancer Health Checks",
            ServiceKind::LoadBalancerHealthChecks,
        ));
    }
    if config.admin.enabled {
        services.push(ServiceSpec::new(
            "Fluxheim Admin Control Plane",
            ServiceKind::AdminControlPlane,
        ));
        if config.admin.ops_socket.enabled {
            services.push(ServiceSpec::new(
                "Fluxheim Local Ops Socket",
                ServiceKind::AdminOpsSocket,
            ));
        }
    }
    if config.metrics.enabled {
        services.push(ServiceSpec::new(
            "Fluxheim Metrics HTTP",
            ServiceKind::MetricsHttp,
        ));
    }
    if config.stream.enabled {
        services.push(ServiceSpec::new(
            "Fluxheim Stream Proxy",
            ServiceKind::StreamProxy,
        ));
    }
    if config.udp.enabled {
        services.push(ServiceSpec::new(
            "Fluxheim UDP Proxy",
            ServiceKind::UdpProxy,
        ));
    }

    services
}

fn any_load_balancer_pool_configured(config: &Config) -> bool {
    if config.vhosts.is_empty() {
        return load_balancer_pool_configured(&config.proxy);
    }

    config.vhosts.iter().any(|vhost| {
        load_balancer_pool_configured(&vhost.proxy)
            || vhost.routes.iter().any(|route| {
                route
                    .proxy
                    .as_ref()
                    .is_some_and(load_balancer_pool_configured)
            })
    })
}

fn load_balancer_pool_configured(proxy: &ProxyConfig) -> bool {
    proxy.upstreams.len() >= 2
        || proxy.upstreams_file.is_some()
        || proxy.upstreams_http_url.is_some()
        || proxy.upstream_dns_refresh_secs.is_some()
}

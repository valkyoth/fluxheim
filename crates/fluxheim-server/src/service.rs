use std::path::{Path, PathBuf};

use fluxheim_config::{Config, ProxyConfig};

use crate::ListenerProtocol;

const PROXY_HTTP_LISTENERS: &[ListenerProtocol] =
    &[ListenerProtocol::Http, ListenerProtocol::Https];
const ADMIN_CONTROL_PLANE_LISTENERS: &[ListenerProtocol] = &[ListenerProtocol::AdminHttp];
const METRICS_HTTP_LISTENERS: &[ListenerProtocol] = &[ListenerProtocol::MetricsHttp];
const STREAM_PROXY_LISTENERS: &[ListenerProtocol] = &[ListenerProtocol::StreamTcp];
const UDP_PROXY_LISTENERS: &[ListenerProtocol] = &[ListenerProtocol::Udp];

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
    listener_protocols: &'static [ListenerProtocol],
}

impl ServiceSpec {
    pub const fn new(
        name: &'static str,
        kind: ServiceKind,
        listener_protocols: &'static [ListenerProtocol],
    ) -> Self {
        Self {
            name,
            kind,
            listener_protocols,
        }
    }

    pub const fn name(self) -> &'static str {
        self.name
    }

    pub const fn kind(self) -> ServiceKind {
        self.kind
    }

    pub const fn listener_protocols(self) -> &'static [ListenerProtocol] {
        self.listener_protocols
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminOpsSocketPlan {
    path: PathBuf,
    mode_bits: u32,
}

impl AdminOpsSocketPlan {
    pub(crate) fn new(path: PathBuf, mode_bits: u32) -> Self {
        Self { path, mode_bits }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn mode_bits(&self) -> u32 {
        self.mode_bits
    }
}

pub(crate) fn service_specs_from_config(config: &Config) -> Vec<ServiceSpec> {
    let mut services = Vec::new();

    if !config.server.listen.is_empty() || !config.server.tls_listen.is_empty() {
        services.push(ServiceSpec::new(
            "Fluxheim HTTP Proxy",
            ServiceKind::ProxyHttp,
            PROXY_HTTP_LISTENERS,
        ));
    }
    if any_load_balancer_pool_configured(config) {
        services.push(ServiceSpec::new(
            "Fluxheim Load Balancer Health Checks",
            ServiceKind::LoadBalancerHealthChecks,
            &[],
        ));
    }
    if config.admin.enabled {
        services.push(ServiceSpec::new(
            "Fluxheim Admin Control Plane",
            ServiceKind::AdminControlPlane,
            ADMIN_CONTROL_PLANE_LISTENERS,
        ));
        if config.admin.ops_socket.enabled {
            services.push(ServiceSpec::new(
                "Fluxheim Local Ops Socket",
                ServiceKind::AdminOpsSocket,
                &[],
            ));
        }
    }
    if config.metrics.enabled {
        services.push(ServiceSpec::new(
            "Fluxheim Metrics HTTP",
            ServiceKind::MetricsHttp,
            METRICS_HTTP_LISTENERS,
        ));
    }
    if config.stream.enabled {
        services.push(ServiceSpec::new(
            "Fluxheim Stream Proxy",
            ServiceKind::StreamProxy,
            STREAM_PROXY_LISTENERS,
        ));
    }
    if config.udp.enabled {
        services.push(ServiceSpec::new(
            "Fluxheim UDP Proxy",
            ServiceKind::UdpProxy,
            UDP_PROXY_LISTENERS,
        ));
    }

    services
}

pub(crate) fn admin_ops_socket_plan_from_config(config: &Config) -> Option<AdminOpsSocketPlan> {
    if !config.admin.enabled || !config.admin.ops_socket.enabled {
        return None;
    }
    Some(AdminOpsSocketPlan::new(
        config.admin.ops_socket.path.clone(),
        admin_ops_socket_mode_bits(&config.admin.ops_socket.mode),
    ))
}

fn admin_ops_socket_mode_bits(mode: &str) -> u32 {
    let raw = mode.trim_start_matches("0o");
    u32::from_str_radix(raw, 8).unwrap_or(0o600)
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

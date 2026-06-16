use std::net::SocketAddr;

use fluxheim_config::{Config, DownstreamProxyProtocol};

use crate::ServerPlanError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerProtocol {
    AdminHttp,
    Http,
    Https,
    MetricsHttp,
    StreamTcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerSpec {
    addr: SocketAddr,
    protocol: ListenerProtocol,
    proxy_protocol: bool,
}

impl ListenerSpec {
    pub const fn new(addr: SocketAddr, protocol: ListenerProtocol) -> Self {
        Self {
            addr,
            protocol,
            proxy_protocol: false,
        }
    }

    pub const fn with_proxy_protocol(mut self, enabled: bool) -> Self {
        self.proxy_protocol = enabled;
        self
    }

    pub const fn addr(self) -> SocketAddr {
        self.addr
    }

    pub const fn protocol(self) -> ListenerProtocol {
        self.protocol
    }

    /// Reports only the server-level HTTP/HTTPS downstream PROXY protocol
    /// policy. Stream and UDP routes manage their own per-route PROXY protocol
    /// settings independently.
    pub const fn proxy_protocol_enabled(self) -> bool {
        self.proxy_protocol
    }

    pub fn is_loopback(self) -> bool {
        self.addr.ip().is_loopback()
    }
}

pub(crate) fn listener_specs_from_config(
    config: &Config,
) -> Result<Vec<ListenerSpec>, ServerPlanError> {
    let mut listeners = Vec::new();
    let proxy_protocol = config.server.proxy_protocol != DownstreamProxyProtocol::Off;

    for listen in &config.server.listen {
        listeners.push(
            ListenerSpec::new(parse_listener(listen)?, ListenerProtocol::Http)
                .with_proxy_protocol(proxy_protocol),
        );
    }
    for listen in &config.server.tls_listen {
        listeners.push(
            ListenerSpec::new(parse_listener(listen)?, ListenerProtocol::Https)
                .with_proxy_protocol(proxy_protocol),
        );
    }
    if config.admin.enabled {
        listeners.push(ListenerSpec::new(
            parse_listener(&config.admin.listen)?,
            ListenerProtocol::AdminHttp,
        ));
    }
    if config.metrics.enabled {
        listeners.push(ListenerSpec::new(
            parse_listener(&config.metrics.listen)?,
            ListenerProtocol::MetricsHttp,
        ));
    }
    if config.stream.enabled {
        for route in &config.stream.routes {
            for listen in &route.listen {
                listeners.push(ListenerSpec::new(
                    parse_listener(listen)?,
                    ListenerProtocol::StreamTcp,
                ));
            }
        }
    }
    if config.udp.enabled {
        for route in &config.udp.routes {
            for listen in &route.listen {
                listeners.push(ListenerSpec::new(
                    parse_listener(listen)?,
                    ListenerProtocol::Udp,
                ));
            }
        }
    }

    Ok(listeners)
}

fn parse_listener(value: &str) -> Result<SocketAddr, ServerPlanError> {
    value
        .parse::<SocketAddr>()
        .map_err(|_| ServerPlanError::InvalidListenerAddress {
            address: value.to_owned(),
        })
}

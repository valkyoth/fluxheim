use std::net::SocketAddr;

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

    pub const fn proxy_protocol_enabled(self) -> bool {
        self.proxy_protocol
    }

    pub fn is_loopback(self) -> bool {
        self.addr.ip().is_loopback()
    }
}

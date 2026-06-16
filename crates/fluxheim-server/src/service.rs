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

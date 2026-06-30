use std::net::SocketAddr;
use std::sync::Arc;

use super::Backend;
use super::persistence::ManagedAffinityCookie;
use super::state::{LoadBalancedConnectionPermit, LoadBalancedUpstreamReporter};

pub struct SelectedUpstream {
    pub backend: Backend,
    pub alias: Option<Arc<str>>,
    pub permit: Option<LoadBalancedConnectionPermit>,
    pub reporter: Option<LoadBalancedUpstreamReporter>,
    pub persistence_outcome: Option<LoadBalancerPersistenceOutcome>,
    pub managed_affinity_cookie: Option<ManagedAffinityCookie>,
}

impl SelectedUpstream {
    pub(crate) fn new(backend: Backend) -> Self {
        Self {
            backend,
            alias: None,
            permit: None,
            reporter: None,
            persistence_outcome: None,
            managed_affinity_cookie: None,
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.backend.addr
    }

    pub fn authority(&self) -> String {
        self.backend.addr.to_string()
    }

    pub fn alias(&self) -> Option<&str> {
        self.alias.as_deref()
    }

    pub fn persistence_outcome(&self) -> Option<LoadBalancerPersistenceOutcome> {
        self.persistence_outcome
    }

    pub fn managed_affinity_cookie(&self) -> Option<&ManagedAffinityCookie> {
        self.managed_affinity_cookie.as_ref()
    }

    pub fn reporter(&self) -> Option<&LoadBalancedUpstreamReporter> {
        self.reporter.as_ref()
    }

    pub fn has_connection_permit(&self) -> bool {
        self.permit.is_some()
    }
}

pub struct LoadBalancerSelectionResult {
    pub selected: Option<SelectedUpstream>,
    pub queue_outcome: Option<LoadBalancerQueueOutcome>,
    pub queue_wait: Option<std::time::Duration>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadBalancerPersistenceOutcome {
    Hit,
    Miss,
    Fallback,
}

impl LoadBalancerPersistenceOutcome {
    pub fn event(self) -> &'static str {
        match self {
            Self::Hit => "persistence_hit",
            Self::Miss => "persistence_miss",
            Self::Fallback => "persistence_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadBalancerQueueOutcome {
    Waited,
    Full,
    Timeout,
}

impl LoadBalancerQueueOutcome {
    pub fn event(self) -> &'static str {
        match self {
            Self::Waited => "queue_waited",
            Self::Full => "queue_full",
            Self::Timeout => "queue_timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadBalancedUpstreamOutcome {
    pub failed: bool,
    pub ejected: bool,
}

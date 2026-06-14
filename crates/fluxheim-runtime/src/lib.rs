#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::future::Future;

pub mod policy;

pub use policy::{
    PolicyEpoch, PolicyProof, RuntimeDecision, RuntimeDecisionKind, RuntimeDecisionReason,
    RuntimeFact, RuntimeFactKind, RuntimeFactVisibility,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownReason {
    Signal,
    Supervisor,
    Fatal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownState {
    requested: bool,
    reason: Option<ShutdownReason>,
}

impl ShutdownState {
    pub const fn running() -> Self {
        Self {
            requested: false,
            reason: None,
        }
    }

    pub const fn requested(reason: ShutdownReason) -> Self {
        Self {
            requested: true,
            reason: Some(reason),
        }
    }

    pub const fn is_requested(self) -> bool {
        self.requested
    }

    pub const fn reason(self) -> Option<ShutdownReason> {
        self.reason
    }
}

pub trait ShutdownView {
    fn shutdown_state(&self) -> ShutdownState;

    fn is_shutdown_requested(&self) -> bool {
        self.shutdown_state().is_requested()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackgroundTaskKind {
    AcmeRenewal,
    CacheMetrics,
    CacheStalePurge,
    LoadBalancerRefresh,
    MetricsExport,
    RuntimeWatchdog,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackgroundTaskSpec {
    name: &'static str,
    kind: BackgroundTaskKind,
    critical: bool,
}

impl BackgroundTaskSpec {
    pub const fn new(name: &'static str, kind: BackgroundTaskKind) -> Self {
        Self {
            name,
            kind,
            critical: false,
        }
    }

    pub const fn critical(mut self, critical: bool) -> Self {
        self.critical = critical;
        self
    }

    pub const fn name(self) -> &'static str {
        self.name
    }

    pub const fn kind(self) -> BackgroundTaskKind {
        self.kind
    }

    pub const fn is_critical(self) -> bool {
        self.critical
    }
}

pub trait BackgroundTaskSpawner {
    type JoinHandle;

    fn spawn_background<F>(&self, spec: BackgroundTaskSpec, task: F) -> Self::JoinHandle
    where
        F: Future<Output = ()> + Send + 'static;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct StaticShutdown(ShutdownState);

    impl ShutdownView for StaticShutdown {
        fn shutdown_state(&self) -> ShutdownState {
            self.0
        }
    }

    #[test]
    fn shutdown_state_reports_running_and_requested() {
        assert!(!ShutdownState::running().is_requested());
        let requested = ShutdownState::requested(ShutdownReason::Signal);
        assert!(requested.is_requested());
        assert_eq!(requested.reason(), Some(ShutdownReason::Signal));
    }

    #[test]
    fn shutdown_view_default_uses_state() {
        let view = StaticShutdown(ShutdownState::requested(ShutdownReason::Supervisor));
        assert!(view.is_shutdown_requested());
    }

    #[test]
    fn background_task_spec_preserves_kind_name_and_criticality() {
        let spec = BackgroundTaskSpec::new(
            "load-balancer-refresh",
            BackgroundTaskKind::LoadBalancerRefresh,
        )
        .critical(true);

        assert_eq!(spec.name(), "load-balancer-refresh");
        assert_eq!(spec.kind(), BackgroundTaskKind::LoadBalancerRefresh);
        assert!(spec.is_critical());
    }
}

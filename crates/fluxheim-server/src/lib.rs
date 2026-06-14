#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::net::SocketAddr;

use fluxheim_runtime::{BackgroundTaskSpec, ShutdownView};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerPlan {
    listeners: Vec<ListenerSpec>,
    background_tasks: Vec<BackgroundTaskSpec>,
}

impl ServerPlan {
    pub fn new(listeners: Vec<ListenerSpec>, background_tasks: Vec<BackgroundTaskSpec>) -> Self {
        Self {
            listeners,
            background_tasks,
        }
    }

    pub fn listeners(&self) -> &[ListenerSpec] {
        &self.listeners
    }

    pub fn background_tasks(&self) -> &[BackgroundTaskSpec] {
        &self.background_tasks
    }

    pub fn has_public_listener(&self) -> bool {
        self.listeners
            .iter()
            .any(|listener| !listener.is_loopback())
    }
}

pub trait ServerRunner {
    type Error;

    fn run(&self, plan: ServerPlan, shutdown: &dyn ShutdownView) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxheim_runtime::{BackgroundTaskKind, ShutdownReason, ShutdownState};

    struct StaticShutdown(ShutdownState);

    impl ShutdownView for StaticShutdown {
        fn shutdown_state(&self) -> ShutdownState {
            self.0
        }
    }

    struct RecordingRunner;

    impl ServerRunner for RecordingRunner {
        type Error = &'static str;

        fn run(&self, _plan: ServerPlan, shutdown: &dyn ShutdownView) -> Result<(), Self::Error> {
            if shutdown.is_shutdown_requested() {
                return Err("shutdown requested");
            }
            Ok(())
        }
    }

    #[test]
    fn listener_spec_reports_loopback_and_proxy_protocol() {
        let spec = ListenerSpec::new("127.0.0.1:8080".parse().unwrap(), ListenerProtocol::Http)
            .with_proxy_protocol(true);

        assert!(spec.is_loopback());
        assert!(spec.proxy_protocol_enabled());
    }

    #[test]
    fn server_plan_reports_public_listeners() {
        let public = ListenerSpec::new("0.0.0.0:443".parse().unwrap(), ListenerProtocol::Https);
        let local = ListenerSpec::new(
            "127.0.0.1:9090".parse().unwrap(),
            ListenerProtocol::MetricsHttp,
        );

        assert!(ServerPlan::new(vec![local, public], Vec::new()).has_public_listener());
        assert!(!ServerPlan::new(vec![local], Vec::new()).has_public_listener());
    }

    #[test]
    fn server_runner_boundary_accepts_shutdown_view() {
        let plan = ServerPlan::new(
            Vec::new(),
            vec![BackgroundTaskSpec::new(
                "metrics-export",
                BackgroundTaskKind::MetricsExport,
            )],
        );
        let runner = RecordingRunner;

        assert!(
            runner
                .run(plan.clone(), &StaticShutdown(ShutdownState::running()))
                .is_ok()
        );
        assert_eq!(
            runner.run(
                plan,
                &StaticShutdown(ShutdownState::requested(ShutdownReason::Signal))
            ),
            Err("shutdown requested")
        );
    }
}

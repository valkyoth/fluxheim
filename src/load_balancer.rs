pub use fluxheim_load_balancer::*;

#[cfg(feature = "proxy")]
pub(crate) struct PingoraLoadBalancerService {
    inner: fluxheim_load_balancer::UpstreamLoadBalancerService,
}

#[cfg(feature = "proxy")]
impl PingoraLoadBalancerService {
    pub(crate) fn new(inner: fluxheim_load_balancer::UpstreamLoadBalancerService) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "proxy")]
#[async_trait::async_trait]
impl pingora::services::ServiceWithDependents for PingoraLoadBalancerService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<pingora::server::ListenFds>,
        shutdown: pingora::server::ShutdownWatch,
        _listeners_per_fd: usize,
        ready: pingora::services::ServiceReadyNotifier,
    ) {
        self.inner
            .start(
                fluxheim_load_balancer::FluxShutdown::new(shutdown),
                fluxheim_load_balancer::FluxBackgroundReady::new(move || {
                    ready.notify_ready();
                }),
            )
            .await;
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn threads(&self) -> Option<usize> {
        self.inner.threads()
    }
}

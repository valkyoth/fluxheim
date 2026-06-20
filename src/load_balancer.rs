pub use fluxheim_load_balancer::*;

#[cfg(feature = "proxy")]
pub(crate) struct PingoraRequestView<'a> {
    request: &'a pingora::http::RequestHeader,
}

#[cfg(feature = "proxy")]
impl<'a> PingoraRequestView<'a> {
    pub(crate) fn new(request: &'a pingora::http::RequestHeader) -> Self {
        Self { request }
    }
}

#[cfg(feature = "proxy")]
impl fluxheim_load_balancer::LoadBalancerRequestView for PingoraRequestView<'_> {
    fn uri_key(&self) -> Vec<u8> {
        self.request.uri.to_string().into_bytes()
    }

    fn header_values<'a>(&'a self, name: &str) -> Box<dyn Iterator<Item = &'a [u8]> + 'a> {
        Box::new(
            self.request
                .headers
                .get_all(name)
                .into_iter()
                .map(|value| value.as_bytes()),
        )
    }

    fn cookie_headers<'a>(&'a self) -> Box<dyn Iterator<Item = &'a str> + 'a> {
        Box::new(
            self.request
                .headers
                .get_all("cookie")
                .into_iter()
                .filter_map(|value| value.to_str().ok()),
        )
    }
}

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

    #[allow(deprecated)]
    fn threads(&self) -> Option<usize> {
        self.inner.threads()
    }
}

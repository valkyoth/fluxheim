pub use fluxheim_load_balancer::*;

#[cfg(all(feature = "proxy", feature = "pingora-compat"))]
pub(crate) struct PingoraRequestView<'a> {
    request: &'a pingora::http::RequestHeader,
}

#[cfg(all(feature = "proxy", feature = "pingora-compat"))]
impl<'a> PingoraRequestView<'a> {
    pub(crate) fn new(request: &'a pingora::http::RequestHeader) -> Self {
        Self { request }
    }
}

#[cfg(all(feature = "proxy", feature = "pingora-compat"))]
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

#[cfg(all(feature = "proxy", feature = "pingora-compat"))]
pub(crate) struct PingoraLoadBalancerService {
    inner: fluxheim_runtime::FluxBackgroundService<
        fluxheim_load_balancer::UpstreamLoadBalancerService,
    >,
}

#[cfg(all(feature = "proxy", feature = "pingora-compat"))]
impl PingoraLoadBalancerService {
    pub(crate) fn new(inner: fluxheim_load_balancer::UpstreamLoadBalancerService) -> Self {
        Self {
            inner: inner.into_native_service(),
        }
    }
}

#[cfg(all(feature = "proxy", feature = "pingora-compat"))]
#[async_trait::async_trait]
impl pingora::services::ServiceWithDependents for PingoraLoadBalancerService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<pingora::server::ListenFds>,
        shutdown: pingora::server::ShutdownWatch,
        _listeners_per_fd: usize,
        ready: pingora::services::ServiceReadyNotifier,
    ) {
        let task = self.inner.task();
        fluxheim_runtime::FluxBackgroundTask::start(
            task.as_ref(),
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

#[cfg(all(test, feature = "proxy", feature = "pingora-compat"))]
mod tests {
    use fluxheim_config::ProxyConfig;

    use super::PingoraLoadBalancerService;

    #[test]
    fn pingora_load_balancer_adapter_uses_native_task_metadata() {
        let (_balancer, service) =
            fluxheim_load_balancer::UpstreamLoadBalancer::background_service_from_proxy_config(
                "lb-test",
                "lb-test",
                None,
                &ProxyConfig {
                    upstreams: vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3001".to_owned()],
                    ..ProxyConfig::default()
                },
            )
            .unwrap()
            .unwrap();

        let service = PingoraLoadBalancerService::new(service);

        assert_eq!(
            service.inner.kind(),
            Some(fluxheim_runtime::BackgroundTaskKind::LoadBalancerRefresh)
        );
        assert_eq!(service.inner.name(), "LB lb-test");
    }
}

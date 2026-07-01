use super::UpstreamLoadBalancer;
use super::backend;
use super::background;

pub struct UpstreamLoadBalancerService {
    inner: background::FluxBackgroundService<backend::FluxLoadBalancerRuntime>,
    load_balancer: UpstreamLoadBalancer,
}

impl UpstreamLoadBalancerService {
    pub(crate) fn new(
        inner: background::FluxBackgroundService<backend::FluxLoadBalancerRuntime>,
        load_balancer: UpstreamLoadBalancer,
    ) -> Self {
        Self {
            inner,
            load_balancer,
        }
    }

    pub async fn start(
        &self,
        shutdown: background::FluxShutdown,
        ready: background::FluxBackgroundReady,
    ) {
        self.inner.task().run(shutdown, ready).await;
    }

    pub fn into_native_service(self) -> fluxheim_runtime::FluxBackgroundService<Self> {
        let name = self.name().to_owned();
        fluxheim_runtime::FluxBackgroundService::with_kind(
            name,
            fluxheim_runtime::BackgroundTaskKind::LoadBalancerRefresh,
            self,
        )
    }

    pub fn name(&self) -> &str {
        self.inner.name()
    }

    pub fn load_balancer(&self) -> UpstreamLoadBalancer {
        self.load_balancer.clone()
    }

    #[allow(deprecated)]
    pub fn threads(&self) -> Option<usize> {
        self.inner.threads()
    }
}

#[async_trait::async_trait]
impl fluxheim_runtime::FluxBackgroundTask for UpstreamLoadBalancerService {
    async fn start(
        &self,
        shutdown: background::FluxShutdown,
        ready: background::FluxBackgroundReady,
    ) {
        self.inner.task().run(shutdown, ready).await;
    }
}

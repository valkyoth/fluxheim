use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use arc_swap::ArcSwap;
use fluxheim_config::Config;

use crate::{
    DownstreamHttp1Policy, NativeHttp1ConnectionStream, NativeHttp1Error, NativeHttp1Handler,
    NativeHttp1HostRouter, NativeHttp1HostRouterConfigError, NativeHttp1Request,
    NativeHttp1Response, NativeRequestBodyBudget,
};

struct NativeHttp1ReloadableRouterState {
    active: ArcSwap<NativeHttp1HostRouter>,
    policy: DownstreamHttp1Policy,
    pool_max_idle: usize,
    background_load_balancer_services: bool,
    request_body_budget: NativeRequestBodyBudget,
}

#[derive(Clone)]
pub struct NativeHttp1ReloadableRouter {
    state: Arc<NativeHttp1ReloadableRouterState>,
}

#[derive(Clone)]
pub struct NativeHttp1RouterReloadHandle {
    state: Arc<NativeHttp1ReloadableRouterState>,
}

#[derive(Debug)]
pub enum NativeHttp1RouterReloadError {
    BackgroundLoadBalancerServices,
    Build(NativeHttp1HostRouterConfigError),
}

impl std::fmt::Display for NativeHttp1RouterReloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackgroundLoadBalancerServices => formatter.write_str(
                "live router reload is unavailable while background load-balancer services are active",
            ),
            Self::Build(error) => write!(formatter, "candidate router: {error}"),
        }
    }
}

impl std::error::Error for NativeHttp1RouterReloadError {}

impl NativeHttp1ReloadableRouter {
    pub fn new(
        router: NativeHttp1HostRouter,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
        background_load_balancer_services: bool,
        request_body_budget: NativeRequestBodyBudget,
    ) -> (Self, NativeHttp1RouterReloadHandle) {
        let state = Arc::new(NativeHttp1ReloadableRouterState {
            active: ArcSwap::from_pointee(router),
            policy,
            pool_max_idle,
            background_load_balancer_services,
            request_body_budget,
        });
        (
            Self {
                state: state.clone(),
            },
            NativeHttp1RouterReloadHandle { state },
        )
    }

    fn active(&self) -> Arc<NativeHttp1HostRouter> {
        self.state.active.load_full()
    }
}

impl NativeHttp1RouterReloadHandle {
    pub fn reload_from_config(&self, config: &Config) -> Result<(), NativeHttp1RouterReloadError> {
        if self.state.background_load_balancer_services {
            return Err(NativeHttp1RouterReloadError::BackgroundLoadBalancerServices);
        }
        let replacement =
            NativeHttp1HostRouter::from_config(config, self.state.policy, self.state.pool_max_idle)
                .map_err(NativeHttp1RouterReloadError::Build)?;
        self.state.active.store(Arc::new(replacement));
        Ok(())
    }
}

impl NativeHttp1Handler for NativeHttp1ReloadableRouter {
    fn pin_request_handler(&self) -> Option<Arc<dyn NativeHttp1Handler>> {
        Some(self.active())
    }

    fn request_body_budget(&self) -> Option<NativeRequestBodyBudget> {
        Some(self.state.request_body_budget.clone())
    }

    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        let active = self.active();
        Box::pin(async move { active.handle(request).await })
    }

    fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        self.active().handles_connection_takeover(request)
    }

    fn handle_connection_takeover<'a>(
        &'a self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Pin<Box<dyn Future<Output = Result<(), NativeHttp1Error>> + Send + 'a>> {
        let active = self.active();
        Box::pin(async move {
            active
                .handle_connection_takeover(request, prebuffered, stream)
                .await
        })
    }

    fn prepare_request_context(&self, request: &mut NativeHttp1Request) {
        self.active().prepare_request_context(request);
    }

    fn request_body_timeout(&self, request: &NativeHttp1Request) -> Option<std::time::Duration> {
        self.active().request_body_timeout(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redirect_config(target: &str) -> Config {
        let process_root = tempfile::tempdir_in("target").unwrap();
        let process_root_path = std::fs::canonicalize(process_root.path()).unwrap();
        Config::load_snapshot_bytes(
            format!(
                r#"
[server]
default_vhost = "reload.test"

[server.process]
pid_file = "{}"
upgrade_sock = "{}"
certificate_reload_sock = "{}"

[proxy]
upstreams = ["127.0.0.1:9"]
upstream_tls = false

[[vhosts]]
name = "reload.test"
hosts = ["reload.test"]

[vhosts.redirect]
enabled = true
to = "{target}"
status = 308
"#,
                process_root_path.join("fluxheim.pid").display(),
                process_root_path.join("fluxheim-upgrade.sock").display(),
                process_root_path
                    .join("fluxheim-certificate-reload.sock")
                    .display(),
            )
            .as_bytes(),
        )
        .unwrap()
    }

    fn request() -> NativeHttp1Request {
        NativeHttp1Request {
            method: "GET".to_owned(),
            peer_addr: None,
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: false,
            tls_identity: None,
            geo_context: None,
            target: "/asset".to_owned(),
            version: fluxheim_protocol::Http1Version::Http11,
            headers: vec![("host".to_owned(), "reload.test".to_owned())],
            body: Default::default(),
            trailers: Vec::new(),
        }
    }

    fn location(response: &NativeHttp1Response) -> Option<&str> {
        response.headers().iter().find_map(|(name, value)| {
            name.eq_ignore_ascii_case("location")
                .then_some(value.as_str())
        })
    }

    #[tokio::test]
    async fn reload_swaps_complete_router_after_candidate_build() {
        let baseline = redirect_config("https://baseline.test{uri}");
        let candidate = redirect_config("https://candidate.test{uri}");
        let router =
            NativeHttp1HostRouter::from_config(&baseline, DownstreamHttp1Policy::default(), 0)
                .unwrap();
        let (router, reloader) = NativeHttp1ReloadableRouter::new(
            router,
            DownstreamHttp1Policy::default(),
            0,
            false,
            NativeRequestBodyBudget::new(256 * 1024 * 1024),
        );

        assert_eq!(
            location(&router.handle(request()).await),
            Some("https://baseline.test/asset")
        );
        reloader.reload_from_config(&candidate).unwrap();
        assert_eq!(
            location(&router.handle(request()).await),
            Some("https://candidate.test/asset")
        );
    }

    #[tokio::test]
    async fn pinned_request_keeps_one_router_generation_across_reload() {
        let baseline = redirect_config("https://baseline.test{uri}");
        let candidate = redirect_config("https://candidate.test{uri}");
        let router =
            NativeHttp1HostRouter::from_config(&baseline, DownstreamHttp1Policy::default(), 0)
                .unwrap();
        let (router, reloader) = NativeHttp1ReloadableRouter::new(
            router,
            DownstreamHttp1Policy::default(),
            0,
            false,
            NativeRequestBodyBudget::new(256 * 1024 * 1024),
        );
        let pinned = router.pin_request_handler().unwrap();

        reloader.reload_from_config(&candidate).unwrap();

        assert_eq!(
            location(&pinned.handle(request()).await),
            Some("https://baseline.test/asset")
        );
        assert_eq!(
            location(&router.handle(request()).await),
            Some("https://candidate.test/asset")
        );
    }

    #[tokio::test]
    async fn failed_candidate_build_preserves_active_router() {
        let baseline = redirect_config("https://baseline.test{uri}");
        let invalid = Config {
            proxy: fluxheim_config::ProxyConfig::disabled(),
            ..Config::default()
        };
        let router =
            NativeHttp1HostRouter::from_config(&baseline, DownstreamHttp1Policy::default(), 0)
                .unwrap();
        let (router, reloader) = NativeHttp1ReloadableRouter::new(
            router,
            DownstreamHttp1Policy::default(),
            0,
            false,
            NativeRequestBodyBudget::new(256 * 1024 * 1024),
        );

        assert!(matches!(
            reloader.reload_from_config(&invalid),
            Err(NativeHttp1RouterReloadError::Build(_))
        ));
        assert_eq!(
            location(&router.handle(request()).await),
            Some("https://baseline.test/asset")
        );
    }

    #[test]
    fn background_load_balancer_router_reload_fails_closed() {
        let baseline = redirect_config("https://baseline.test{uri}");
        let router =
            NativeHttp1HostRouter::from_config(&baseline, DownstreamHttp1Policy::default(), 0)
                .unwrap();
        let (_, reloader) = NativeHttp1ReloadableRouter::new(
            router,
            DownstreamHttp1Policy::default(),
            0,
            true,
            NativeRequestBodyBudget::new(256 * 1024 * 1024),
        );

        assert!(matches!(
            reloader.reload_from_config(&baseline),
            Err(NativeHttp1RouterReloadError::BackgroundLoadBalancerServices)
        ));
    }
}

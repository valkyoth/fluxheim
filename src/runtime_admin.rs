use std::error::Error;
use std::future::Future;
use std::sync::Arc;

use tokio::task::JoinSet;

pub(super) struct PreparedAdminRuntime {
    policy: fluxheim_server::DownstreamHttp1Policy,
    tcp: Vec<(tokio::net::TcpListener, Arc<crate::admin::AdminApp>)>,
    #[cfg(unix)]
    ops: Option<(tokio::net::UnixListener, Arc<crate::admin::AdminOpsApp>)>,
    watchdog: Option<crate::background::FluxBackgroundService<crate::admin::AdminApp>>,
}

impl PreparedAdminRuntime {
    pub(super) async fn prepare(
        config: &crate::config::Config,
        server_plan: &fluxheim_server::ServerPlan,
        router_reloader: Option<fluxheim_server::NativeHttp1RouterReloadHandle>,
        #[cfg(feature = "load-balancer")] load_balancer_admin_pools: Vec<
            fluxheim_server::NativeLoadBalancerAdminPool,
        >,
    ) -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        let Some(service) = server_plan.service(fluxheim_server::ServiceKind::AdminControlPlane)
        else {
            return Ok(None);
        };
        let Some(admin) = crate::admin::native_admin_services_from_config(
            config,
            server_plan,
            router_reloader,
            #[cfg(feature = "load-balancer")]
            load_balancer_admin_pools,
        )?
        else {
            return Ok(None);
        };

        let app = Arc::new(admin.control_plane);
        let mut tcp = Vec::new();
        for listener in
            server_plan.service_listeners(fluxheim_server::ServiceKind::AdminControlPlane)
        {
            let listener = tokio::net::TcpListener::bind(listener.addr()).await?;
            log::info!("{} prepared on {}", service.name(), listener.local_addr()?);
            tcp.push((listener, app.clone()));
        }

        #[cfg(unix)]
        let ops = match admin.ops_socket {
            Some(app) => {
                let Some(plan) = server_plan.admin_ops_socket() else {
                    return Err("admin ops socket service missing from native launch plan".into());
                };
                let listener = fluxheim_server::replace_private_unix_listener(plan.path())?;
                listener.set_nonblocking(true)?;
                let listener = tokio::net::UnixListener::from_std(listener)?;
                log::info!(
                    "Fluxheim Local Ops Socket prepared on {}",
                    plan.path().display()
                );
                Some((listener, Arc::new(app)))
            }
            None => None,
        };

        Ok(Some(Self {
            policy: *server_plan.downstream_http1(),
            tcp,
            #[cfg(unix)]
            ops,
            watchdog: admin.watchdog,
        }))
    }

    pub(super) fn take_watchdog(
        &mut self,
    ) -> Option<crate::background::FluxBackgroundService<crate::admin::AdminApp>> {
        self.watchdog.take()
    }

    pub(super) fn start(
        self,
        supervisor: &fluxheim_runtime::NativeBackgroundSupervisor,
    ) -> NativeAdminListenerTasks {
        let mut tasks = NativeAdminListenerTasks::new();
        for (listener, app) in self.tcp {
            let policy = self.policy;
            let shutdown = supervisor.shutdown_view();
            tasks.spawn(async move {
                fluxheim_server::serve_native_http1_listener(
                    listener,
                    policy,
                    app,
                    shutdown_wait(shutdown),
                )
                .await
            });
        }
        #[cfg(unix)]
        if let Some((listener, app)) = self.ops {
            let policy = self.policy;
            let shutdown = supervisor.shutdown_view();
            tasks.spawn(async move {
                fluxheim_server::serve_native_http1_unix_listener(
                    listener,
                    policy,
                    app,
                    shutdown_wait(shutdown),
                )
                .await
            });
        }
        tasks
    }
}

pub(super) struct NativeAdminListenerTasks {
    tasks: JoinSet<Result<(), fluxheim_server::NativeHttp1Error>>,
}

impl NativeAdminListenerTasks {
    pub(super) fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
        }
    }

    pub(super) fn spawn(
        &mut self,
        task: impl Future<Output = Result<(), fluxheim_server::NativeHttp1Error>> + Send + 'static,
    ) {
        self.tasks.spawn(task);
    }

    pub(super) async fn join(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        while let Some(result) = self.tasks.join_next().await {
            match result {
                Ok(result) => result?,
                Err(error) if error.is_cancelled() => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub(super) fn abort_all(&mut self) {
        self.tasks.abort_all();
    }
}

async fn shutdown_wait(mut shutdown: fluxheim_runtime::FluxShutdown) {
    let _ = shutdown.wait_for_shutdown().await;
}

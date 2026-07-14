use std::error::Error;
#[cfg(feature = "proxy")]
use std::sync::Arc;

use crate::config::Config;

#[cfg(feature = "proxy")]
#[path = "runtime_background.rs"]
mod runtime_background;
#[cfg(all(feature = "proxy", feature = "acme-client"))]
use runtime_background::AcmeRenewalBackgroundService;
#[cfg(all(feature = "proxy", feature = "cache"))]
use runtime_background::CacheStalePurgerBackgroundService;
#[cfg(feature = "proxy")]
use runtime_background::DownstreamCertificateReloader;
#[cfg(all(feature = "proxy", feature = "metrics-otlp"))]
use runtime_background::MetricsOtlpBackgroundService;
#[cfg(all(feature = "proxy", feature = "acme-client", unix))]
use runtime_background::certificate_reload_control_service;
#[cfg(all(feature = "proxy", feature = "cache", feature = "metrics"))]
use runtime_background::{CacheRuntimeMetricsBackgroundService, record_cache_runtime_metrics};

#[cfg(feature = "proxy")]
#[path = "runtime_cutover.rs"]
mod runtime_cutover;
#[cfg(all(test, feature = "proxy"))]
use runtime_cutover::native_runtime_manifest_preview;
#[cfg(feature = "proxy")]
use runtime_cutover::{
    log_native_http1_proxy_cutover_summary, log_native_runtime_cutover_summary,
    log_native_runtime_manifest_preview, validate_native_http1_router_factory,
};

#[cfg(feature = "proxy")]
#[path = "runtime_logging.rs"]
mod runtime_logging;
#[cfg(feature = "proxy")]
#[path = "runtime_readiness.rs"]
mod runtime_readiness;
#[cfg(feature = "proxy")]
use runtime_logging::init_logging;
#[cfg(feature = "proxy")]
#[path = "runtime_shutdown.rs"]
mod runtime_shutdown;
#[cfg(feature = "proxy")]
#[path = "runtime_socket_activation.rs"]
mod runtime_socket_activation;
#[cfg(feature = "proxy")]
use runtime_shutdown::{
    native_runtime_shutdown_grace, native_runtime_shutdown_timeout,
    wait_native_runtime_shutdown_signal,
};
#[cfg(feature = "proxy")]
pub fn run(config: Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    init_logging(&config)?;
    #[cfg(all(feature = "tls-rustls-backend", not(feature = "tls-openssl")))]
    crate::tls::install_rustls_crypto_provider()?;
    #[cfg(any(
        feature = "tls",
        feature = "tls-rustls-backend",
        feature = "tls-openssl"
    ))]
    crate::tls::validate_fips_runtime_config(&config)?;

    #[cfg(feature = "load-balancer")]
    fluxheim_load_balancer::set_admin_hmac_sha256(|context, key, message| {
        crate::internal_crypto::admin_hmac_sha256_or_abort(
            crate::internal_crypto::admin_mac_provider(),
            context,
            key,
            message,
        )
    });
    #[cfg(all(feature = "load-balancer", feature = "metrics"))]
    fluxheim_load_balancer::set_load_balancer_event_recorder(
        crate::metrics::record_load_balancer_event,
    );
    #[cfg(all(
        feature = "tls-rustls-backend",
        feature = "metrics",
        not(feature = "tls-openssl")
    ))]
    fluxheim_tls::set_pending_managed_certificate_recorder(record_pending_managed_certificate);

    let server_plan = fluxheim_server::ServerPlan::from_config(&config)?;
    if matches!(
        server_plan.native_runtime_target_adapter(),
        fluxheim_server::RuntimeAdapterKind::NativeRuntime
    ) {
        return run_native_runtime(config, server_plan);
    }
    let blockers = server_plan
        .native_runtime_cutover_summary()
        .blockers()
        .iter()
        .map(|blocker| blocker.key())
        .collect::<Vec<_>>()
        .join(",");
    Err(format!("native runtime launch blocked; blockers={blockers}").into())
}

#[cfg(feature = "proxy")]
const NATIVE_RUNTIME_MAX_BLOCKING_THREADS: usize = 384;

#[cfg(feature = "proxy")]
fn run_native_runtime(
    config: Config,
    server_plan: fluxheim_server::ServerPlan,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    log_native_runtime_cutover_summary(&server_plan);
    log_native_runtime_manifest_preview(&server_plan);
    log_native_http1_proxy_cutover_summary(&server_plan);
    validate_native_http1_router_factory(&config, &server_plan)?;

    let threads = server_plan.process().threads().max(1);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .max_blocking_threads(NATIVE_RUNTIME_MAX_BLOCKING_THREADS)
        .enable_all()
        .build()?;
    runtime.block_on(run_native_runtime_async(config, server_plan))
}

#[cfg(feature = "proxy")]
async fn run_native_runtime_async(
    config: Config,
    server_plan: fluxheim_server::ServerPlan,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let launch_plan = server_plan.native_runtime_launch_plan()?;

    #[cfg(feature = "metrics")]
    {
        crate::metrics::init()?;
        crate::metrics::install_native_cache_metrics_recorder();
        crate::metrics::record_config(&config);
    }

    #[cfg_attr(not(feature = "load-balancer"), allow(unused_mut))]
    let mut native_proxy_runtime = if server_plan
        .service(fluxheim_server::ServiceKind::ProxyHttp)
        .is_some()
    {
        Some(runtime_socket_activation::bind_native_proxy_runtime(&config, &server_plan).await?)
    } else {
        None
    };
    #[cfg(all(feature = "tls-rustls-backend", not(feature = "tls-openssl")))]
    let native_certificate_reloader = native_proxy_runtime
        .as_ref()
        .and_then(fluxheim_server::NativeHttp1ProxyRuntime::rustls_certificate_resolver)
        .map(DownstreamCertificateReloader::Rustls);
    #[cfg(all(feature = "tls-openssl", not(feature = "tls-rustls-backend")))]
    let native_certificate_reloader = native_proxy_runtime
        .as_ref()
        .and_then(fluxheim_server::NativeHttp1ProxyRuntime::openssl_certificate_store)
        .map(DownstreamCertificateReloader::Openssl);
    #[cfg(not(any(
        all(feature = "tls-rustls-backend", not(feature = "tls-openssl")),
        all(feature = "tls-openssl", not(feature = "tls-rustls-backend"))
    )))]
    let native_certificate_reloader: Option<DownstreamCertificateReloader> = None;
    reject_unsupported_native_background_tasks(
        &launch_plan,
        native_certificate_reloader.is_some(),
    )?;
    #[cfg(feature = "load-balancer")]
    let native_load_balancer_admin_pools = native_proxy_runtime
        .as_ref()
        .map(fluxheim_server::NativeHttp1ProxyRuntime::load_balancer_admin_pools)
        .unwrap_or_default();
    #[cfg(feature = "load-balancer")]
    let native_load_balancer_services = native_proxy_runtime
        .as_mut()
        .map(fluxheim_server::NativeHttp1ProxyRuntime::take_load_balancer_services)
        .unwrap_or_default();
    let supervisor = fluxheim_runtime::NativeBackgroundSupervisor::new();
    let mut background_readiness = runtime_readiness::BackgroundReadiness::new();
    let mut background_handles = Vec::new();

    #[cfg(feature = "stream-proxy")]
    if let Some(stream_service_spec) =
        server_plan.service(fluxheim_server::ServiceKind::StreamProxy)
    {
        for service in crate::stream_proxy::stream_background_services_from_config(&config)? {
            log::info!("{} enabled", stream_service_spec.name());
            background_handles.push(background_readiness.spawn(&supervisor, service.into_native()));
        }
    }

    #[cfg(feature = "udp-proxy")]
    if let Some(udp_service_spec) = server_plan.service(fluxheim_server::ServiceKind::UdpProxy) {
        for service in crate::udp_proxy::udp_background_services_from_config(&config)? {
            log::info!("{} enabled", udp_service_spec.name());
            background_handles.push(background_readiness.spawn(&supervisor, service.into_native()));
        }
    }

    #[cfg(feature = "metrics")]
    if let Some(metrics_service_spec) =
        server_plan.service(fluxheim_server::ServiceKind::MetricsHttp)
    {
        if let Some(metrics_service) =
            crate::metrics::metrics_background_service_from_config(&config.metrics)?
        {
            log::info!("{} enabled", metrics_service_spec.name());
            background_handles
                .push(background_readiness.spawn(&supervisor, metrics_service.into_native()));
        }

        #[cfg(feature = "cache")]
        if let Some(task) =
            server_plan.background_task(fluxheim_runtime::BackgroundTaskKind::CacheMetrics)
        {
            record_cache_runtime_metrics();
            background_handles.push(
                background_readiness.spawn(
                    &supervisor,
                    crate::background::background_service_for_spec(
                        task,
                        CacheRuntimeMetricsBackgroundService,
                    )
                    .into_native(),
                ),
            );
        }

        #[cfg(feature = "metrics-otlp")]
        if let Some(task) =
            server_plan.background_task(fluxheim_runtime::BackgroundTaskKind::MetricsExport)
        {
            if let Some(exporter) =
                crate::metrics_otlp::MetricsOtlpExporter::from_config(&config.metrics.otlp)?
            {
                background_handles.push(
                    background_readiness.spawn(
                        &supervisor,
                        crate::background::background_service_for_spec(
                            task,
                            MetricsOtlpBackgroundService { exporter },
                        )
                        .into_native(),
                    ),
                );
            }
            log::info!(
                "OTLP metrics export enabled to {}",
                config.metrics.otlp.endpoint
            );
        }
    }

    #[cfg(feature = "cache")]
    if let Some(task) =
        server_plan.background_task(fluxheim_runtime::BackgroundTaskKind::CacheStalePurge)
    {
        log::info!(
            "cache stale disk purger enabled; interval={}s limit={} batches={}",
            config.cache_purger.interval_secs,
            config.cache_purger.limit,
            config.cache_purger.batches
        );
        background_handles.push(
            background_readiness.spawn(
                &supervisor,
                crate::background::background_service_for_spec(
                    task,
                    CacheStalePurgerBackgroundService {
                        config: config.cache_purger.clone(),
                    },
                )
                .into_native(),
            ),
        );
    }

    #[cfg(feature = "load-balancer")]
    if let Some(load_balancer_service_spec) =
        server_plan.service(fluxheim_server::ServiceKind::LoadBalancerHealthChecks)
    {
        for service in native_load_balancer_services {
            log::info!("{} enabled", load_balancer_service_spec.name());
            background_handles
                .push(background_readiness.spawn(&supervisor, service.into_native_service()));
        }
    }

    #[cfg(all(feature = "acme-client", unix))]
    if let Some(task) =
        server_plan.background_task(fluxheim_runtime::BackgroundTaskKind::CertificateReload)
        && let Some(service) = certificate_reload_control_service(
            task,
            server_plan.certificate_reload_control(),
            native_certificate_reloader.clone(),
        )?
    {
        background_handles.push(background_readiness.spawn(&supervisor, service.into_native()));
    }

    #[cfg(feature = "acme-client")]
    if let Some(task) =
        server_plan.background_task(fluxheim_runtime::BackgroundTaskKind::AcmeRenewal)
    {
        log::info!(
            "ACME renewal service enabled; interval={}s",
            config.tls.acme.renewal.check_interval_secs
        );
        background_handles.push(
            background_readiness.spawn(
                &supervisor,
                crate::background::background_service_for_spec(
                    task,
                    AcmeRenewalBackgroundService {
                        config: config.clone(),
                        certificate_reloader: native_certificate_reloader.clone(),
                    },
                )
                .into_native(),
            ),
        );
    }

    let mut listener_handles: Vec<
        tokio::task::JoinHandle<Result<(), fluxheim_server::NativeHttp1Error>>,
    > = Vec::new();
    let proxy_runtime = native_proxy_runtime.map(|runtime| runtime.start(&supervisor));

    if let Some(admin_service_spec) =
        server_plan.service(fluxheim_server::ServiceKind::AdminControlPlane)
        && let Some(admin_services) = crate::admin::native_admin_services_from_config(
            &config,
            &server_plan,
            #[cfg(feature = "load-balancer")]
            native_load_balancer_admin_pools,
        )?
    {
        let app = Arc::new(admin_services.control_plane);
        for listener in
            server_plan.service_listeners(fluxheim_server::ServiceKind::AdminControlPlane)
        {
            let tcp = tokio::net::TcpListener::bind(listener.addr()).await?;
            let local_addr = tcp.local_addr()?;
            log::info!("{} enabled on {}", admin_service_spec.name(), local_addr);
            let policy = *server_plan.downstream_http1();
            let app = app.clone();
            let shutdown = supervisor.shutdown_view();
            listener_handles.push(tokio::spawn(async move {
                fluxheim_server::serve_native_http1_listener(
                    tcp,
                    policy,
                    app,
                    native_shutdown_wait(shutdown),
                )
                .await
            }));
        }

        #[cfg(unix)]
        if let Some(ops_socket) = admin_services.ops_socket {
            let Some(ops_socket_plan) = server_plan.admin_ops_socket() else {
                return Err("admin ops socket service missing from native launch plan".into());
            };
            let listener = fluxheim_server::replace_private_unix_listener(ops_socket_plan.path())?;
            listener.set_nonblocking(true)?;
            let listener = tokio::net::UnixListener::from_std(listener)?;
            log::info!(
                "Fluxheim Local Ops Socket enabled on {}",
                ops_socket_plan.path().display()
            );
            let policy = *server_plan.downstream_http1();
            let app = Arc::new(ops_socket);
            let shutdown = supervisor.shutdown_view();
            listener_handles.push(tokio::spawn(async move {
                fluxheim_server::serve_native_http1_unix_listener(
                    listener,
                    policy,
                    app,
                    native_shutdown_wait(shutdown),
                )
                .await
            }));
        }

        if let Some(watchdog) = admin_services.watchdog {
            log::info!("admin self-healing watchdog enabled");
            background_handles
                .push(background_readiness.spawn(&supervisor, watchdog.into_native()));
        }
    }

    background_readiness.wait(&supervisor).await?;
    let (critical_handles, background_handles): (Vec<_>, Vec<_>) = background_handles
        .into_iter()
        .partition(fluxheim_runtime::NativeBackgroundJoinHandle::is_critical);
    let watchdog = supervisor.spawn_critical_watchdog(critical_handles);
    runtime_readiness::notify_ready()?;
    log::info!("native runtime started");
    wait_native_runtime_shutdown_signal().await;
    runtime_readiness::notify_stopping();

    if let Some(grace) = native_runtime_shutdown_grace(launch_plan.process()) {
        log::info!(
            "native runtime shutdown signal received; grace period={}s",
            grace.as_secs()
        );
        tokio::time::sleep(grace).await;
    }

    let _ = supervisor.shutdown();
    let drain_timeout = native_runtime_shutdown_timeout(launch_plan.process());
    log::info!(
        "native runtime draining established work; timeout={}s",
        drain_timeout.as_secs()
    );
    let drain = async move {
        if let Some(proxy_runtime) = proxy_runtime {
            for result in proxy_runtime.join().await {
                result?;
            }
        }
        for handle in listener_handles {
            match handle.await {
                Ok(result) => result?,
                Err(error) if error.is_cancelled() => {}
                Err(error) => return Err(Box::<dyn Error + Send + Sync>::from(error)),
            }
        }
        for handle in background_handles {
            handle.join().await?;
        }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };
    match tokio::time::timeout(drain_timeout, drain).await {
        Ok(result) => result?,
        Err(_) => {
            log::warn!(
                target: "fluxheim::native_runtime",
                "native runtime graceful drain timed out after {}s; remaining work will be terminated",
                drain_timeout.as_secs()
            );
        }
    }
    watchdog.abort();
    let _ = watchdog.join().await;
    Ok(())
}

#[cfg(feature = "proxy")]
fn reject_unsupported_native_background_tasks(
    launch_plan: &fluxheim_server::NativeRuntimeLaunchPlan,
    certificate_reloader_available: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    for task in launch_plan.background_tasks() {
        match task.kind() {
            fluxheim_runtime::BackgroundTaskKind::LoadBalancerRefresh => {}
            fluxheim_runtime::BackgroundTaskKind::AcmeRenewal
            | fluxheim_runtime::BackgroundTaskKind::CertificateReload
                if !certificate_reloader_available =>
            {
                return Err(format!(
                    "native runtime does not yet support {} background task",
                    task.name()
                )
                .into());
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(feature = "proxy")]
async fn native_shutdown_wait(mut shutdown: fluxheim_runtime::FluxShutdown) {
    let _ = shutdown.wait_for_shutdown().await;
}

#[cfg(all(
    feature = "proxy",
    feature = "metrics",
    any(
        all(feature = "tls-rustls-backend", not(feature = "tls-openssl")),
        feature = "tls-openssl"
    )
))]
fn record_pending_managed_certificate() {
    crate::metrics::record_acme_event("pending");
}

#[cfg(all(test, feature = "proxy", feature = "acme-client"))]
fn acme_background_service_enabled(config: &Config) -> bool {
    runtime_background::acme_background_service_enabled(config)
}

#[cfg(not(feature = "proxy"))]
pub fn run(_config: Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("no runnable Fluxheim module is enabled; enable the `proxy` feature".into())
}

#[cfg(all(test, feature = "proxy"))]
#[path = "runtime_tests.rs"]
mod tests;

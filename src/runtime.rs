use std::error::Error;
#[cfg(feature = "proxy")]
use std::fs::File;
#[cfg(all(feature = "proxy", feature = "acme-client", unix))]
use std::io::Read;
#[cfg(feature = "proxy")]
use std::io::Write;
#[cfg(feature = "proxy")]
use std::path::Path;
#[cfg(feature = "proxy")]
use std::sync::Arc;

#[cfg(all(feature = "proxy", feature = "cache"))]
use crate::config::CachePurgerConfig;
use crate::config::Config;
#[cfg(feature = "proxy")]
use crate::config::{LoggingFormat, LoggingTarget};

#[cfg(all(feature = "proxy", feature = "cache", feature = "metrics"))]
const CACHE_RUNTIME_METRICS_INTERVAL_SECS: u64 = 5;
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
        Some(
            fluxheim_server::NativeHttp1ProxyRuntime::bind_from_config(&config, &server_plan)
                .await?,
        )
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
    let mut background_handles = Vec::new();

    #[cfg(feature = "stream-proxy")]
    if let Some(stream_service_spec) =
        server_plan.service(fluxheim_server::ServiceKind::StreamProxy)
    {
        for service in crate::stream_proxy::stream_background_services_from_config(&config)? {
            log::info!("{} enabled", stream_service_spec.name());
            background_handles.push(supervisor.spawn_service(service.into_native()));
        }
    }

    #[cfg(feature = "udp-proxy")]
    if let Some(udp_service_spec) = server_plan.service(fluxheim_server::ServiceKind::UdpProxy) {
        for service in crate::udp_proxy::udp_background_services_from_config(&config)? {
            log::info!("{} enabled", udp_service_spec.name());
            background_handles.push(supervisor.spawn_service(service.into_native()));
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
            background_handles.push(supervisor.spawn_service(metrics_service.into_native()));
        }

        #[cfg(feature = "cache")]
        if let Some(task) =
            server_plan.background_task(fluxheim_runtime::BackgroundTaskKind::CacheMetrics)
        {
            record_cache_runtime_metrics();
            background_handles.push(
                supervisor.spawn_service(
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
                    supervisor.spawn_service(
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
            supervisor.spawn_service(
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
            background_handles.push(supervisor.spawn_service(service.into_native_service()));
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
        background_handles.push(supervisor.spawn_service(service.into_native()));
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
            supervisor.spawn_service(
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
            background_handles.push(supervisor.spawn_service(watchdog.into_native()));
        }
    }

    let (critical_handles, background_handles): (Vec<_>, Vec<_>) = background_handles
        .into_iter()
        .partition(fluxheim_runtime::NativeBackgroundJoinHandle::is_critical);
    let watchdog = supervisor.spawn_critical_watchdog(critical_handles);
    log::info!("native runtime started");
    wait_native_runtime_shutdown_signal().await;
    let _ = supervisor.shutdown();

    if let Some(proxy_runtime) = proxy_runtime {
        for result in proxy_runtime.join().await {
            result?;
        }
    }
    for handle in listener_handles {
        match handle.await {
            Ok(result) => result?,
            Err(error) if error.is_cancelled() => {}
            Err(error) => return Err(Box::new(error)),
        }
    }
    for handle in background_handles {
        handle.join().await?;
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

#[cfg(feature = "proxy")]
async fn wait_native_runtime_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate()).ok();
        let mut quit = signal(SignalKind::quit()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                if let Some(signal) = &mut terminate {
                    let _ = signal.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
            _ = async {
                if let Some(signal) = &mut quit {
                    let _ = signal.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
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

#[cfg(feature = "proxy")]
fn log_native_runtime_cutover_summary(server_plan: &fluxheim_server::ServerPlan) {
    let summary = server_plan.native_runtime_cutover_summary();
    if summary.is_ready() {
        log::info!("native runtime cutover preview: no blockers detected");
        return;
    }

    let blockers = summary
        .blockers()
        .iter()
        .map(|blocker| blocker.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    log::info!(
        "native runtime cutover preview: compatibility adapter retained; blockers={blockers}"
    );
}

#[cfg(feature = "proxy")]
fn log_native_runtime_manifest_preview(server_plan: &fluxheim_server::ServerPlan) {
    if let Some(summary) = native_runtime_manifest_preview(server_plan) {
        log::info!("native runtime manifest preview: {summary}");
    }
}

#[cfg(feature = "proxy")]
fn native_runtime_manifest_preview(server_plan: &fluxheim_server::ServerPlan) -> Option<String> {
    let manifest = server_plan.native_runtime_manifest().ok()?;
    let service_count = manifest.services().len();
    let listener_count: usize = manifest
        .services()
        .iter()
        .map(|service| service.listeners().len())
        .sum();
    let background_task_count = manifest.background_tasks().len();
    let services = manifest
        .services()
        .iter()
        .map(|service| {
            let listeners = service
                .listeners()
                .iter()
                .map(|listener| format!("{:?}@{}", listener.protocol(), listener.addr()))
                .collect::<Vec<_>>()
                .join(",");
            format!("{:?}=[{}]", service.kind(), listeners)
        })
        .collect::<Vec<_>>()
        .join("; ");
    Some(format!(
        "services={service_count} listeners={listener_count} background_tasks={background_task_count} graph={services}"
    ))
}

#[cfg(feature = "proxy")]
fn log_native_http1_proxy_cutover_summary(server_plan: &fluxheim_server::ServerPlan) {
    let summary = server_plan.native_http1_proxy_cutover_summary();
    match summary.status() {
        fluxheim_server::NativeHttp1ProxyCutoverStatus::NoProxy => {}
        fluxheim_server::NativeHttp1ProxyCutoverStatus::NativeReady => {
            log::info!(
                "native HTTP/1 proxy cutover ready for {} configured proxy path(s)",
                summary.total()
            );
        }
        fluxheim_server::NativeHttp1ProxyCutoverStatus::Mixed => {
            log::info!(
                "native HTTP/1 proxy cutover mixed: {} eligible, {} compatibility-only",
                summary.eligible(),
                summary.unsupported()
            );
        }
        fluxheim_server::NativeHttp1ProxyCutoverStatus::CompatibilityRequired => {
            log::info!(
                "native HTTP/1 proxy cutover not ready: {} configured proxy path(s) require compatibility adapter",
                summary.unsupported()
            );
        }
    }

    for candidate in server_plan.native_http1_proxy_candidates() {
        if let Some(reason) = candidate.unsupported_reason() {
            log::info!(
                "native HTTP/1 proxy compatibility path retained for {}: {}",
                candidate.scope(),
                reason
            );
        }
    }
}

#[cfg(feature = "proxy")]
fn validate_native_http1_router_factory(
    config: &Config,
    server_plan: &fluxheim_server::ServerPlan,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !server_plan.has_service(fluxheim_server::ServiceKind::ProxyHttp) {
        return Ok(());
    }
    match server_plan.native_http1_proxy_cutover_summary().status() {
        fluxheim_server::NativeHttp1ProxyCutoverStatus::NoProxy
        | fluxheim_server::NativeHttp1ProxyCutoverStatus::NativeReady => {}
        fluxheim_server::NativeHttp1ProxyCutoverStatus::Mixed
        | fluxheim_server::NativeHttp1ProxyCutoverStatus::CompatibilityRequired => {
            return Ok(());
        }
    }

    let _router = fluxheim_server::NativeHttp1HostRouter::from_config(
        config,
        *server_plan.downstream_http1(),
        server_plan.process().upstream_keepalive_pool_size(),
    )?;
    log::debug!("native HTTP/1 host-router factory validated for proxy service");
    Ok(())
}

#[cfg(all(feature = "proxy", feature = "acme-client", unix))]
fn certificate_reload_control_service(
    task: fluxheim_runtime::BackgroundTaskSpec,
    control_plan: Option<&fluxheim_server::CertificateReloadControlPlan>,
    reloader: Option<DownstreamCertificateReloader>,
) -> Result<
    Option<crate::background::FluxBackgroundService<CertificateReloadControlBackgroundService>>,
    Box<dyn Error + Send + Sync>,
> {
    let Some(control_plan) = control_plan else {
        return Ok(None);
    };

    let listener = fluxheim_server::replace_private_unix_listener(control_plan.socket_path())?;
    log::info!(
        "certificate reload control socket enabled at {}",
        control_plan.socket_path().display()
    );

    Ok(Some(crate::background::background_service_for_spec(
        task,
        CertificateReloadControlBackgroundService {
            listener,
            reloader,
            semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(
                control_plan.max_concurrent_requests(),
            )),
            read_timeout: control_plan.read_timeout(),
        },
    )))
}

#[cfg(all(feature = "proxy", feature = "acme-client", unix))]
fn handle_certificate_reload_control_request(
    stream: &mut std::os::unix::net::UnixStream,
    reloader: Option<&DownstreamCertificateReloader>,
    read_timeout: std::time::Duration,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    stream.set_read_timeout(Some(read_timeout))?;
    let mut buffer = [0_u8; 1024];
    let bytes = stream.read(&mut buffer)?;
    let command = std::str::from_utf8(&buffer[..bytes])?.trim();
    if command != "reload-certificates" {
        stream.write_all(b"error: unsupported command\n")?;
        return Ok(());
    }

    let Some(reloader) = reloader else {
        stream.write_all(b"error: certificate reload handle unavailable\n")?;
        return Ok(());
    };

    match reloader.reload() {
        Ok(()) => {
            stream.write_all(b"ok\n")?;
            log::info!("downstream TLS certificates reloaded by local control socket");
        }
        Err(error) => {
            let response = format!("error: {error}\n");
            stream.write_all(response.as_bytes())?;
        }
    }
    Ok(())
}

#[cfg(all(feature = "proxy", feature = "acme-client", unix))]
struct CertificateReloadControlBackgroundService {
    listener: std::os::unix::net::UnixListener,
    reloader: Option<DownstreamCertificateReloader>,
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    read_timeout: std::time::Duration,
}

#[cfg(all(feature = "proxy", feature = "acme-client", unix))]
#[async_trait::async_trait]
impl crate::background::FluxBackgroundTask for CertificateReloadControlBackgroundService {
    async fn start(
        &self,
        mut shutdown: crate::background::FluxShutdown,
        mut ready: crate::background::FluxBackgroundReady,
    ) {
        ready.notify_ready();
        let retry_delay = std::time::Duration::from_millis(100);

        loop {
            if shutdown.is_shutdown() {
                break;
            }

            match self.listener.accept() {
                Ok((mut stream, _addr)) => {
                    let Ok(permit) = self.semaphore.clone().try_acquire_owned() else {
                        log::debug!("certificate reload control request dropped: concurrency cap");
                        continue;
                    };
                    let reloader = self.reloader.clone();
                    let read_timeout = self.read_timeout;
                    tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        if let Err(error) = stream.set_nonblocking(false) {
                            log::warn!("certificate reload control request setup failed: {error}");
                            return;
                        }
                        if let Err(error) = handle_certificate_reload_control_request(
                            &mut stream,
                            reloader.as_ref(),
                            read_timeout,
                        ) {
                            log::warn!("certificate reload control request failed: {error}");
                        }
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if shutdown.sleep_or_shutdown(retry_delay).await {
                        break;
                    }
                }
                Err(error) => {
                    log::warn!("certificate reload control socket accept failed: {error}");
                    if shutdown.sleep_or_shutdown(retry_delay).await {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(all(feature = "proxy", feature = "cache", feature = "metrics"))]
struct CacheRuntimeMetricsBackgroundService;

#[cfg(all(feature = "proxy", feature = "cache", feature = "metrics"))]
#[async_trait::async_trait]
impl crate::background::FluxBackgroundTask for CacheRuntimeMetricsBackgroundService {
    async fn start(
        &self,
        mut shutdown: crate::background::FluxShutdown,
        mut ready: crate::background::FluxBackgroundReady,
    ) {
        ready.notify_ready();
        let interval = std::time::Duration::from_secs(CACHE_RUNTIME_METRICS_INTERVAL_SECS);

        loop {
            if shutdown.is_shutdown() {
                break;
            }

            record_cache_runtime_metrics();
            if shutdown.sleep_or_shutdown(interval).await {
                break;
            }
        }
    }
}

#[cfg(all(feature = "proxy", feature = "cache", feature = "metrics"))]
fn record_cache_runtime_metrics() {
    let native_totals = fluxheim_server::native_cache_runtime_totals();
    if native_totals.memory_tiers > 0 || native_totals.disk_tiers > 0 {
        crate::metrics::record_native_cache_runtime_totals(&native_totals);
    }
}

#[cfg(all(test, feature = "proxy", feature = "acme-client"))]
fn acme_background_service_enabled(config: &Config) -> bool {
    config.tls.acme.automation == crate::config::AcmeAutomationMode::Background
        && !crate::acme::renewal_targets(config).is_empty()
}

#[cfg(all(feature = "proxy", feature = "cache"))]
struct CacheStalePurgerBackgroundService {
    config: CachePurgerConfig,
}

#[cfg(all(feature = "proxy", feature = "cache"))]
#[async_trait::async_trait]
impl crate::background::FluxBackgroundTask for CacheStalePurgerBackgroundService {
    async fn start(
        &self,
        mut shutdown: crate::background::FluxShutdown,
        mut ready: crate::background::FluxBackgroundReady,
    ) {
        ready.notify_ready();
        let interval = std::time::Duration::from_secs(self.config.interval_secs);

        loop {
            if shutdown.is_shutdown() {
                break;
            }

            run_cache_stale_purge_tick(&self.config);
            if shutdown.sleep_or_shutdown(interval).await {
                break;
            }
        }
    }
}

#[cfg(all(feature = "proxy", feature = "cache"))]
fn run_cache_stale_purge_tick(config: &CachePurgerConfig) {
    #[cfg(feature = "metrics")]
    let started_at = std::time::Instant::now();

    match native_stale_disk_cache_purge_once(config.limit, config.batches) {
        Ok(result) if result.targets == 0 => {
            #[cfg(feature = "metrics")]
            record_cache_stale_purge_metrics("skipped", &result, started_at.elapsed());
            log::debug!("cache stale disk purge skipped; no disk cache targets");
        }
        Ok(result) if result.purged == 0 => {
            #[cfg(feature = "metrics")]
            record_cache_stale_purge_metrics(
                if result.truncated {
                    "truncated"
                } else {
                    "clean"
                },
                &result,
                started_at.elapsed(),
            );
            log::debug!(
                "cache stale disk purge complete; targets={} scanned={} stale={} purged=0 truncated={}",
                result.targets,
                result.scanned,
                result.stale,
                result.truncated
            );
        }
        Ok(result) => {
            #[cfg(feature = "metrics")]
            record_cache_stale_purge_metrics(
                if result.truncated {
                    "truncated"
                } else {
                    "purged"
                },
                &result,
                started_at.elapsed(),
            );
            log::info!(
                "cache stale disk purge complete; targets={} scanned={} stale={} purged={} truncated={}",
                result.targets,
                result.scanned,
                result.stale,
                result.purged,
                result.truncated
            );
        }
        Err(error) => {
            #[cfg(feature = "metrics")]
            {
                crate::metrics::record_cache_purger_run("error");
                crate::metrics::record_cache_purger_duration("error", started_at.elapsed());
            }
            log::error!("cache stale disk purge failed: {error}");
        }
    }
}

#[cfg(all(feature = "proxy", feature = "cache"))]
fn native_stale_disk_cache_purge_once(
    limit: usize,
    batches: usize,
) -> std::io::Result<fluxheim_cache::CacheBackgroundPurgeResult> {
    fluxheim_server::purge_native_disk_cache_stale_all(limit, batches)
}

#[cfg(all(feature = "proxy", feature = "cache", feature = "metrics"))]
fn record_cache_stale_purge_metrics(
    outcome: &str,
    result: &crate::cache_api::CacheBackgroundPurgeResult,
    duration: std::time::Duration,
) {
    crate::metrics::record_cache_purger_run(outcome);
    crate::metrics::record_cache_purger_entries(
        "scanned",
        fluxheim_observability::metrics_usize_to_u64_saturating(result.scanned),
    );
    crate::metrics::record_cache_purger_entries(
        "stale",
        fluxheim_observability::metrics_usize_to_u64_saturating(result.stale),
    );
    crate::metrics::record_cache_purger_entries(
        "purged",
        fluxheim_observability::metrics_usize_to_u64_saturating(result.purged),
    );
    crate::metrics::record_cache_purger_duration(outcome, duration);
}

#[cfg(all(feature = "proxy", feature = "acme-client"))]
struct AcmeRenewalBackgroundService {
    config: Config,
    certificate_reloader: Option<DownstreamCertificateReloader>,
}

#[cfg(all(feature = "proxy", feature = "metrics-otlp"))]
struct MetricsOtlpBackgroundService {
    exporter: crate::metrics_otlp::MetricsOtlpExporter,
}

#[cfg(all(feature = "proxy", feature = "metrics-otlp"))]
#[async_trait::async_trait]
impl crate::background::FluxBackgroundTask for MetricsOtlpBackgroundService {
    async fn start(
        &self,
        mut shutdown: crate::background::FluxShutdown,
        mut ready: crate::background::FluxBackgroundReady,
    ) {
        ready.notify_ready();
        let interval = self.exporter.interval();

        loop {
            if shutdown.sleep_or_shutdown(interval).await {
                break;
            }
            self.exporter.export_once();
        }
    }
}

#[cfg(all(feature = "proxy", feature = "acme-client"))]
#[async_trait::async_trait]
impl crate::background::FluxBackgroundTask for AcmeRenewalBackgroundService {
    async fn start(
        &self,
        mut shutdown: crate::background::FluxShutdown,
        mut ready: crate::background::FluxBackgroundReady,
    ) {
        ready.notify_ready();
        let interval =
            std::time::Duration::from_secs(self.config.tls.acme.renewal.check_interval_secs);

        loop {
            if shutdown.is_shutdown() {
                break;
            }

            run_acme_renewal_tick(&self.config, self.certificate_reloader.as_ref()).await;
            if shutdown.sleep_or_shutdown(interval).await {
                break;
            }
        }
    }
}

#[cfg(all(feature = "proxy", feature = "acme-client"))]
async fn run_acme_renewal_tick(config: &Config, reloader: Option<&DownstreamCertificateReloader>) {
    match crate::acme::renew_due_instant_acme_targets(config, std::time::SystemTime::now()).await {
        Ok(run) if run.attempted == 0 => {
            log::debug!("ACME renewal check complete; no due certificates");
        }
        Ok(run) => {
            log::info!(
                "ACME renewal check complete; attempted={} renewed={} failed={}",
                run.attempted,
                run.renewed.len(),
                run.failed.len()
            );
            let renewed_count = run.renewed.len();
            for outcome in run.renewed {
                #[cfg(feature = "metrics")]
                crate::metrics::record_acme_event("renewed");
                log::info!(
                    "ACME renewed vhost={} issuer={} cert={} key={} challenges={}",
                    outcome.vhost_name,
                    outcome.issuer,
                    outcome.certificate.cert_path.display(),
                    outcome.certificate.key_path.display(),
                    outcome.published_challenges
                );
            }
            for failure in run.failed {
                #[cfg(feature = "metrics")]
                crate::metrics::record_acme_event("failed");
                log::error!(
                    "ACME renewal failed vhost={} issuer={} domains={} error={}",
                    failure.vhost_name,
                    failure.issuer,
                    failure.domains.join(","),
                    failure.error
                );
            }
            if renewed_count == 0 {
                log::debug!("ACME renewal check completed without renewed certificates");
            } else if let Some(reloader) = reloader {
                if let Err(error) = reloader.reload() {
                    #[cfg(feature = "metrics")]
                    crate::metrics::record_acme_event("reload_failed");
                    log::error!(
                        "failed to reload downstream TLS certificates after ACME renewal: {error}"
                    );
                } else {
                    #[cfg(feature = "metrics")]
                    crate::metrics::record_acme_event("reload_success");
                    log::info!("downstream TLS certificates reloaded after ACME renewal");
                }
            } else {
                #[cfg(feature = "metrics")]
                crate::metrics::record_acme_event("reload_unavailable");
                log::warn!(
                    "ACME renewed certificates but no downstream TLS reload handle is available; restart or reload Fluxheim to use them"
                );
            }
        }
        Err(error) => {
            #[cfg(feature = "metrics")]
            crate::metrics::record_acme_event("tick_error");
            log::error!("ACME renewal check failed: {error}");
        }
    }
}

#[cfg(not(feature = "proxy"))]
pub fn run(_config: Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("no runnable Fluxheim module is enabled; enable the `proxy` feature".into())
}

#[cfg(feature = "proxy")]
fn init_logging(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let env = env_logger::Env::default().default_filter_or(config.logging.level.as_filter());
    let format = config.logging.format;
    let mut builder = env_logger::Builder::from_env(env);
    builder.format(move |buf, record| match format {
        LoggingFormat::Json => write_json_log_record(buf, record),
        LoggingFormat::Text => write_text_log_record(buf, record),
    });

    if config.logging.file.enabled {
        let path = config.logging.file.path.as_deref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "logging.file.enabled requires logging.file.path",
            )
        })?;
        let file = open_log_file(path, config.logging.file.append)?;
        builder.target(env_logger::Target::Pipe(Box::new(file)));
    } else {
        builder.target(match config.logging.target {
            LoggingTarget::Stdout => env_logger::Target::Stdout,
            LoggingTarget::Stderr => env_logger::Target::Stderr,
        });
    }

    let _ = builder.try_init();
    Ok(())
}

#[cfg(feature = "proxy")]
fn open_log_file(path: &Path, append: bool) -> std::io::Result<File> {
    reject_log_path_symlink_prefix(path)?;

    let mut flags =
        rustix::fs::OFlags::CREATE | rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC;
    if append {
        flags |= rustix::fs::OFlags::APPEND;
    } else {
        flags |= rustix::fs::OFlags::TRUNC;
    }

    #[cfg(unix)]
    {
        flags |= rustix::fs::OFlags::NOFOLLOW;
    }

    let fd = rustix::fs::open(
        path,
        flags,
        rustix::fs::Mode::RUSR
            | rustix::fs::Mode::WUSR
            | rustix::fs::Mode::RGRP
            | rustix::fs::Mode::WGRP
            | rustix::fs::Mode::ROTH
            | rustix::fs::Mode::WOTH,
    )
    .map_err(rustix_to_io_error)?;
    let file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("log path is not a regular file: {}", path.display()),
        ));
    }

    Ok(file)
}

#[cfg(feature = "proxy")]
fn reject_log_path_symlink_prefix(path: &Path) -> std::io::Result<()> {
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("log path contains symlink component: {}", current.display()),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(feature = "proxy")]
fn rustix_to_io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(feature = "proxy")]
fn write_text_log_record(
    buf: &mut env_logger::fmt::Formatter,
    record: &log::Record<'_>,
) -> std::io::Result<()> {
    writeln!(
        buf,
        "{} {} {}: {}",
        buf.timestamp_millis(),
        record.level(),
        record.target(),
        record.args()
    )
}

#[cfg(feature = "proxy")]
fn write_json_log_record(
    buf: &mut env_logger::fmt::Formatter,
    record: &log::Record<'_>,
) -> std::io::Result<()> {
    if record.target() == "fluxheim::access" {
        return writeln!(buf, "{}", record.args());
    }

    writeln!(
        buf,
        "{}",
        log_record_json(
            &buf.timestamp_millis().to_string(),
            record.level().as_str(),
            record.target(),
            &record.args().to_string(),
        )
    )
}

#[cfg(feature = "proxy")]
fn log_record_json(timestamp: &str, level: &str, target: &str, message: &str) -> String {
    format!(
        "{{\"timestamp\":\"{}\",\"level\":\"{}\",\"target\":\"{}\",\"message\":\"{}\"}}",
        fluxheim_observability::json_escape(timestamp),
        fluxheim_observability::json_escape(level),
        fluxheim_observability::json_escape(target),
        fluxheim_observability::json_escape(message),
    )
}

#[cfg(all(test, feature = "proxy"))]
mod tests {
    use super::{log_record_json, open_log_file};
    use crate::test_support::unique_temp_path;

    #[test]
    fn json_log_record_escapes_fields() {
        let record = log_record_json(
            "2026-05-05T12:00:00Z",
            "INFO",
            "fluxheim::test",
            "line\n\"x\"",
        );

        assert_eq!(
            record,
            "{\"timestamp\":\"2026-05-05T12:00:00Z\",\"level\":\"INFO\",\"target\":\"fluxheim::test\",\"message\":\"line\\n\\\"x\\\"\"}"
        );
    }

    #[test]
    fn json_escape_escapes_control_characters() {
        assert_eq!(
            fluxheim_observability::json_escape("a\u{0001}b"),
            "a\\u0001b"
        );
    }

    #[test]
    fn native_runtime_manifest_preview_reports_ready_service_graph() {
        let mut config = crate::config::Config::default();
        config.server.listen = vec!["127.0.0.1:18080".to_owned()];
        config.admin.enabled = true;
        config.admin.listen = "127.0.0.1:19090".to_owned();
        config.metrics.enabled = true;
        config.metrics.listen = "127.0.0.1:19091".to_owned();
        config.stream.enabled = true;
        config.stream.routes = vec![crate::config::StreamRouteConfig {
            name: "tcp".to_owned(),
            listen: vec!["127.0.0.1:15432".to_owned()],
            upstream: Some("127.0.0.1:5432".to_owned()),
            ..crate::config::StreamRouteConfig::default()
        }];
        config.udp.enabled = true;
        config.udp.routes = vec![crate::config::UdpRouteConfig {
            name: "dns".to_owned(),
            mode: crate::config::UdpRouteMode::DnsLoadBalance,
            listen: vec!["127.0.0.1:15353".to_owned()],
            upstream: Some("127.0.0.1:5353".to_owned()),
            upstreams: Vec::new(),
            upstream_weights: Vec::new(),
            upstream_aliases: Vec::new(),
            idle_timeout_secs: 30,
            response_timeout_secs: 3,
            max_datagram_bytes: 1232,
            max_sessions: 4096,
            max_sessions_per_source: 64,
            max_responses_per_source_per_second: 256,
            passive_health_enabled: true,
            passive_health_failures: 3,
            passive_health_ejection_secs: 10,
        }];
        let plan = fluxheim_server::ServerPlan::from_config(&config).unwrap();

        let preview = super::native_runtime_manifest_preview(&plan).expect("ready manifest");

        assert!(preview.contains("services=5"));
        assert!(preview.contains("listeners=5"));
        assert!(preview.contains("ProxyHttp=[Http@127.0.0.1:18080]"));
        assert!(preview.contains("AdminControlPlane=[AdminHttp@127.0.0.1:19090]"));
        assert!(preview.contains("MetricsHttp=[MetricsHttp@127.0.0.1:19091]"));
        assert!(preview.contains("StreamProxy=[StreamTcp@127.0.0.1:15432]"));
        assert!(preview.contains("UdpProxy=[Udp@127.0.0.1:15353]"));
    }

    #[test]
    fn native_runtime_manifest_preview_stays_empty_when_blocked() {
        let mut config = crate::config::Config::default();
        config.server.listen = vec!["127.0.0.1:18080".to_owned()];
        config.cache.enabled = true;
        let plan = fluxheim_server::ServerPlan::from_config(&config).unwrap();

        assert!(super::native_runtime_manifest_preview(&plan).is_none());
    }

    #[test]
    fn native_http1_router_factory_validates_when_cutover_ready() {
        let mut config = crate::config::Config::default();
        config.server.listen = vec!["127.0.0.1:18080".to_owned()];
        config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
        let plan = fluxheim_server::ServerPlan::from_config(&config).unwrap();

        assert_eq!(
            plan.native_http1_proxy_cutover_summary().status(),
            fluxheim_server::NativeHttp1ProxyCutoverStatus::NativeReady
        );
        super::validate_native_http1_router_factory(&config, &plan).unwrap();
    }

    #[test]
    fn native_runtime_target_adapter_selects_native_for_ready_plan() {
        let mut config = crate::config::Config::default();
        config.server.listen = vec!["127.0.0.1:18080".to_owned()];
        config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
        let plan = fluxheim_server::ServerPlan::from_config(&config).unwrap();

        assert_eq!(
            plan.native_runtime_target_adapter(),
            fluxheim_server::RuntimeAdapterKind::NativeRuntime
        );
    }

    #[test]
    fn native_runtime_rejects_unsupported_certificate_background_tasks() {
        let plan = fluxheim_server::ServerPlan::with_process(
            fluxheim_server::ProcessSpec::default(),
            Vec::new(),
            Vec::new(),
            vec![fluxheim_runtime::BackgroundTaskSpec::new(
                "ACME renewal",
                fluxheim_runtime::BackgroundTaskKind::AcmeRenewal,
            )],
        );
        let launch_plan = plan.native_runtime_launch_plan().unwrap();

        let error = super::reject_unsupported_native_background_tasks(&launch_plan, false)
            .unwrap_err()
            .to_string();

        assert!(error.contains("native runtime does not yet support ACME renewal"));
        super::reject_unsupported_native_background_tasks(&launch_plan, true).unwrap();
    }

    #[cfg(feature = "acme-client")]
    #[test]
    fn acme_background_service_honors_automation_mode() {
        let mut config = crate::config::Config {
            tls: crate::config::TlsConfig {
                enabled: true,
                acme: crate::config::AcmeConfig {
                    enabled: true,
                    storage: Some(std::path::PathBuf::from("/var/lib/fluxheim/acme")),
                    ..crate::config::AcmeConfig::default()
                },
                ..crate::config::TlsConfig::default()
            },
            vhosts: vec![crate::config::VhostConfig {
                name: "example".to_owned(),
                hosts: vec!["example.test".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                tls: crate::config::VhostTlsConfig {
                    enabled: true,
                    acme: crate::config::VhostAcmeConfig {
                        enabled: true,
                        issuer: None,
                        domains: Vec::new(),
                    },
                    ..crate::config::VhostTlsConfig::default()
                },
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                proxy: crate::config::ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                compression: None,
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: crate::config::WebConfig::default(),
                routes: Vec::new(),
            }],
            ..crate::config::Config::default()
        };

        assert!(super::acme_background_service_enabled(&config));

        config.tls.acme.automation = crate::config::AcmeAutomationMode::External;

        assert!(!super::acme_background_service_enabled(&config));
    }

    #[cfg(all(feature = "acme-client", unix))]
    #[test]
    fn certificate_reload_control_service_skips_when_acme_disabled() {
        let config = crate::config::Config::default();
        let server_plan = fluxheim_server::ServerPlan::from_config(&config).unwrap();
        let task = fluxheim_runtime::BackgroundTaskSpec::new(
            "cert-reload",
            fluxheim_runtime::BackgroundTaskKind::CertificateReload,
        );

        assert!(
            super::certificate_reload_control_service(
                task,
                server_plan.certificate_reload_control(),
                None
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn opens_regular_log_file_for_append() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = unique_temp_path("runtime-log-append").with_extension("log");
        let _ = std::fs::remove_file(&path);

        let file = open_log_file(&path, true)?;

        assert!(file.metadata()?.is_file());
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_symlink_log_file() {
        let target = unique_temp_path("runtime-log-target").with_extension("log");
        let link = unique_temp_path("runtime-log-link").with_extension("log");
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(&link);
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(open_log_file(&link, true).is_err());

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_symlink_log_file_parent() {
        let real_dir = unique_temp_path("runtime-log-real-parent");
        let link_dir = unique_temp_path("runtime-log-link-parent");
        let _ = std::fs::remove_dir_all(&real_dir);
        let _ = std::fs::remove_file(&link_dir);
        std::fs::create_dir(&real_dir).unwrap();
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();
        let log_path = link_dir.join("fluxheim.log");

        assert!(open_log_file(&log_path, true).is_err());

        let _ = std::fs::remove_file(&link_dir);
        let _ = std::fs::remove_dir_all(&real_dir);
    }

    #[cfg(all(
        feature = "tls-rustls-backend",
        feature = "acme",
        not(feature = "tls-openssl")
    ))]
    #[test]
    fn rustls_alpn_protocols_include_acme_tls_alpn_when_enabled() {
        let tls = crate::config::TlsConfig {
            acme: crate::config::AcmeConfig {
                enabled: true,
                challenge: crate::config::AcmeChallenge::TlsAlpn01,
                storage: Some(std::path::PathBuf::from("/var/lib/fluxheim/acme")),
                ..crate::config::AcmeConfig::default()
            },
            ..crate::config::TlsConfig::default()
        };

        let protocols =
            fluxheim_tls::rustls_alpn_protocols(&tls, Some(crate::acme::acme_tls_alpn_protocol()));

        assert_eq!(
            protocols.first().map(Vec::as_slice),
            Some(crate::acme::acme_tls_alpn_protocol())
        );
        assert!(protocols.iter().any(|protocol| protocol == b"h2"));
        assert!(protocols.iter().any(|protocol| protocol == b"http/1.1"));
    }
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls-backend",
    not(feature = "tls-openssl")
))]
type RustlsSniCertificateResolver = fluxheim_tls::RustlsDownstreamCertificateResolver;

#[cfg(feature = "proxy")]
#[cfg_attr(not(feature = "acme-client"), allow(dead_code))]
#[derive(Clone)]
enum DownstreamCertificateReloader {
    #[cfg(all(feature = "tls-rustls-backend", not(feature = "tls-openssl")))]
    Rustls(std::sync::Arc<RustlsSniCertificateResolver>),
    #[cfg(feature = "tls-openssl")]
    Openssl(std::sync::Arc<fluxheim_tls::OpenSslDownstreamCertificateStore>),
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(feature = "acme-client"), allow(dead_code))]
impl DownstreamCertificateReloader {
    #[cfg_attr(not(feature = "acme-client"), allow(dead_code))]
    fn reload(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        match self {
            #[cfg(all(feature = "tls-rustls-backend", not(feature = "tls-openssl")))]
            Self::Rustls(resolver) => Ok(resolver.reload()?),
            #[cfg(feature = "tls-openssl")]
            Self::Openssl(store) => Ok(store.reload()?),
            #[cfg(not(any(
                all(feature = "tls-rustls-backend", not(feature = "tls-openssl")),
                feature = "tls-openssl"
            )))]
            _ => Ok(()),
        }
    }
}

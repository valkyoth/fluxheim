use std::error::Error;
#[cfg(feature = "proxy")]
use std::fs::File;
#[cfg(all(feature = "proxy", feature = "acme-client", unix))]
use std::io::Read;
#[cfg(feature = "proxy")]
use std::io::Write;
#[cfg(feature = "proxy")]
use std::path::Path;

#[cfg(all(
    feature = "acme",
    feature = "proxy",
    feature = "tls-rustls-backend",
    not(feature = "tls-openssl")
))]
use crate::config::AcmeChallenge;
#[cfg(all(feature = "proxy", feature = "cache"))]
use crate::config::CachePurgerConfig;
use crate::config::Config;
#[cfg(feature = "proxy")]
use crate::config::{LoggingFormat, LoggingTarget};

#[cfg(all(feature = "proxy", feature = "cache", feature = "metrics"))]
const CACHE_RUNTIME_METRICS_INTERVAL_SECS: u64 = 5;
#[cfg(all(
    feature = "proxy",
    any(
        all(feature = "tls-rustls-backend", not(feature = "tls-openssl")),
        feature = "tls-openssl"
    )
))]
#[cfg(all(feature = "proxy", feature = "tls-openssl"))]
use crate::config::TlsAlpnPolicy;
#[cfg(all(
    feature = "proxy",
    any(
        all(feature = "tls-rustls-backend", not(feature = "tls-openssl")),
        feature = "tls-openssl"
    )
))]
use crate::config::{TlsCipherSuite, TlsClientAuthMode, TlsCurvePreference};
#[cfg(all(
    feature = "proxy",
    any(
        all(feature = "tls-rustls-backend", not(feature = "tls-openssl")),
        feature = "tls-openssl"
    )
))]
use crate::config::{TlsConfig, TlsProtocolVersion};
#[cfg(all(feature = "proxy", feature = "tls-openssl"))]
use pingora::tls::{
    ssl::{SslVerifyMode, SslVersion},
    x509::X509Name,
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
    match server_plan.runtime_adapter() {
        fluxheim_server::RuntimeAdapterKind::PingoraCompatibility => {}
    }
    log_native_runtime_cutover_summary(&server_plan);
    log_native_runtime_manifest_preview(&server_plan);
    log_native_http1_proxy_cutover_summary(&server_plan);
    let pingora_conf = pingora_server_conf(&server_plan);
    let mut server = pingora::server::Server::new_with_opt_and_conf(None, pingora_conf);
    server.bootstrap();

    #[cfg(feature = "load-balancer")]
    let (proxy, load_balancer_services) =
        crate::proxy::FluxProxy::from_config_with_background_services(&config)?;

    #[cfg(not(feature = "load-balancer"))]
    let proxy = crate::proxy::FluxProxy::from_config(&config)?;

    let admin_proxy = proxy.clone();
    #[cfg(all(feature = "cache", feature = "metrics"))]
    let metrics_proxy = proxy.clone();
    let mut proxy_service = pingora::proxy::http_proxy_service(&server.configuration, proxy);
    harden_proxy_service_http2_options(&mut proxy_service, server_plan.downstream_http2())?;

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
        server.add_service(crate::background::background_service_for_spec(
            task,
            CacheStalePurgerBackgroundService {
                config: config.cache_purger.clone(),
                proxy: admin_proxy.clone(),
            },
        ));
    }

    for listener in server_plan.service_listeners_for_protocol(
        fluxheim_server::ServiceKind::ProxyHttp,
        fluxheim_server::ListenerProtocol::Http,
    ) {
        let listen = listener.addr().to_string();
        log::info!("proxy listener enabled on {listen}");
        proxy_service.add_tcp(&listen);
    }
    let certificate_reloader = add_tls_listeners(&mut proxy_service, &config, &server_plan)?;
    apply_downstream_proxy_protocol(&mut proxy_service, &server_plan)?;
    #[cfg(not(feature = "acme-client"))]
    let _ = &certificate_reloader;
    #[cfg(all(feature = "acme-client", unix))]
    if let Some(task) =
        server_plan.background_task(fluxheim_runtime::BackgroundTaskKind::CertificateReload)
        && let Some(service) = certificate_reload_control_service(
            task,
            server_plan.certificate_reload_control(),
            certificate_reloader.clone(),
        )?
    {
        server.add_service(service);
    }

    #[cfg(feature = "load-balancer")]
    if let Some(load_balancer_service_spec) =
        server_plan.service(fluxheim_server::ServiceKind::LoadBalancerHealthChecks)
    {
        for service in load_balancer_services {
            log::info!("{} enabled", load_balancer_service_spec.name());
            server.add_service(crate::load_balancer::PingoraLoadBalancerService::new(
                service,
            ));
        }
    }

    #[cfg(feature = "stream-proxy")]
    if let Some(stream_service_spec) =
        server_plan.service(fluxheim_server::ServiceKind::StreamProxy)
    {
        for stream_service in crate::stream_proxy::stream_services_from_config(&config)? {
            log::info!("{} enabled", stream_service_spec.name());
            server.add_service(stream_service);
        }
    }

    #[cfg(feature = "udp-proxy")]
    if let Some(udp_service_spec) = server_plan.service(fluxheim_server::ServiceKind::UdpProxy) {
        for udp_service in crate::udp_proxy::udp_services_from_config(&config)? {
            log::info!("{} enabled", udp_service_spec.name());
            server.add_service(udp_service);
        }
    }

    if let Some(admin_service) =
        server_plan.service(fluxheim_server::ServiceKind::AdminControlPlane)
        && let Some(admin_services) =
            crate::admin::admin_services_from_config(&config, admin_proxy, &server_plan)?
    {
        let admin_listener = server_plan
            .first_service_listener_addr(fluxheim_server::ServiceKind::AdminControlPlane)
            .unwrap_or_else(|| "unknown".to_owned());
        log::info!("{} enabled on {}", admin_service.name(), admin_listener);
        if let Some(watchdog) = admin_services.watchdog {
            log::info!("admin self-healing watchdog enabled");
            server.add_service(watchdog);
        }
        #[cfg(unix)]
        if let Some(ops_service) = server_plan.service(fluxheim_server::ServiceKind::AdminOpsSocket)
            && let Some(ops_socket) = admin_services.ops_socket
        {
            log::info!(
                "{} enabled on {}",
                ops_service.name(),
                config.admin.ops_socket.path.display()
            );
            server.add_service(ops_socket);
        }
        server.add_service(admin_services.control_plane);
    }

    #[cfg(feature = "metrics")]
    if let Some(metrics_service_spec) =
        server_plan.service(fluxheim_server::ServiceKind::MetricsHttp)
    {
        crate::metrics::init()?;
        crate::metrics::record_config(&config);
        #[cfg(feature = "cache")]
        if let Some(task) =
            server_plan.background_task(fluxheim_runtime::BackgroundTaskKind::CacheMetrics)
        {
            record_cache_runtime_metrics(&metrics_proxy);
            server.add_service(crate::background::background_service_for_spec(
                task,
                CacheRuntimeMetricsBackgroundService {
                    proxy: metrics_proxy.clone(),
                },
            ));
        }
        let mut metrics_service = pingora::services::listening::Service::prometheus_http_service();
        for listener in server_plan.service_listeners(fluxheim_server::ServiceKind::MetricsHttp) {
            let listen = listener.addr().to_string();
            log::info!(
                "{} listener enabled on {listen}",
                metrics_service_spec.name()
            );
            metrics_service.add_tcp(&listen);
        }
        server.add_service(metrics_service);

        #[cfg(feature = "metrics-otlp")]
        if let Some(task) =
            server_plan.background_task(fluxheim_runtime::BackgroundTaskKind::MetricsExport)
        {
            if let Some(exporter) =
                crate::metrics_otlp::MetricsOtlpExporter::from_config(&config.metrics.otlp)?
            {
                server.add_service(crate::background::background_service_for_spec(
                    task,
                    MetricsOtlpBackgroundService { exporter },
                ));
            }
            log::info!(
                "OTLP metrics export enabled to {}",
                config.metrics.otlp.endpoint
            );
        }
    }

    #[cfg(feature = "acme-client")]
    if let Some(task) =
        server_plan.background_task(fluxheim_runtime::BackgroundTaskKind::AcmeRenewal)
    {
        log::info!(
            "ACME renewal service enabled; interval={}s",
            config.tls.acme.renewal.check_interval_secs
        );
        server.add_service(crate::background::background_service_for_spec(
            task,
            AcmeRenewalBackgroundService {
                config: config.clone(),
                certificate_reloader: certificate_reloader.clone(),
            },
        ));
    }

    server.add_service(proxy_service);
    server.run_forever();
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
fn hardened_downstream_h2_options(
    policy: &fluxheim_server::DownstreamHttp2Policy,
) -> pingora::protocols::http::v2::server::H2Options {
    let mut options = pingora::protocols::http::v2::server::H2Options::new();
    options.max_header_list_size(policy.max_header_list_size());
    options.max_concurrent_streams(policy.max_concurrent_streams());
    options.initial_window_size(policy.initial_window_size());
    options.max_frame_size(policy.max_frame_size());
    options.max_send_buffer_size(policy.max_send_buffer_size());
    options.max_pending_accept_reset_streams(policy.max_pending_accept_reset_streams());
    options
}

#[cfg(feature = "proxy")]
fn harden_proxy_service_http2_options<SV>(
    service: &mut pingora::services::listening::Service<pingora::proxy::HttpProxy<SV>>,
    policy: &fluxheim_server::DownstreamHttp2Policy,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    SV: pingora::proxy::ProxyHttp,
{
    let Some(app) = service.app_logic_mut() else {
        return Err(std::io::Error::other("proxy service app missing before registration").into());
    };
    app.h2_options = Some(hardened_downstream_h2_options(policy));
    Ok(())
}

#[cfg(feature = "proxy")]
fn apply_downstream_proxy_protocol<S>(
    service: &mut pingora::services::listening::Service<S>,
    server_plan: &fluxheim_server::ServerPlan,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    match server_plan.proxy_protocol() {
        fluxheim_server::ProxyProtocolPolicy::Off => {}
        fluxheim_server::ProxyProtocolPolicy::V1 { trusted_sources } => {
            let trusted_sources = pingora_proxy_protocol_trusted_sources(trusted_sources);
            log::info!(
                "downstream PROXY protocol v1 receive enabled for {} trusted source(s)",
                trusted_sources.len()
            );
            service.set_proxy_protocol_v1(pingora::listeners::ProxyProtocolConfig::v1(
                trusted_sources,
            ));
        }
        fluxheim_server::ProxyProtocolPolicy::V2 { trusted_sources } => {
            let trusted_sources = pingora_proxy_protocol_trusted_sources(trusted_sources);
            log::info!(
                "downstream PROXY protocol v2 receive enabled for {} trusted source(s)",
                trusted_sources.len()
            );
            service.set_proxy_protocol_v2(pingora::listeners::ProxyProtocolConfig::v2(
                trusted_sources,
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "proxy")]
fn pingora_proxy_protocol_trusted_sources(
    sources: &[fluxheim_server::ProxyProtocolTrustedSource],
) -> Vec<pingora::listeners::ProxyProtocolTrustedSource> {
    sources
        .iter()
        .map(|source| match source {
            fluxheim_server::ProxyProtocolTrustedSource::Ip(address) => {
                pingora::listeners::ProxyProtocolTrustedSource::Ip(*address)
            }
            fluxheim_server::ProxyProtocolTrustedSource::Cidr { network, prefix } => {
                pingora::listeners::ProxyProtocolTrustedSource::Cidr {
                    network: *network,
                    prefix: *prefix,
                }
            }
        })
        .collect()
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
struct CacheRuntimeMetricsBackgroundService {
    proxy: crate::proxy::FluxProxy,
}

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

            record_cache_runtime_metrics(&self.proxy);
            if shutdown.sleep_or_shutdown(interval).await {
                break;
            }
        }
    }
}

#[cfg(all(feature = "proxy", feature = "cache", feature = "metrics"))]
fn record_cache_runtime_metrics(proxy: &crate::proxy::FluxProxy) {
    match proxy.cache_runtime_stats() {
        Ok(stats) => crate::metrics::record_cache_runtime_totals(&stats.totals),
        Err(error) => log::debug!("cache runtime metrics unavailable: {error}"),
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
    proxy: crate::proxy::FluxProxy,
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

            run_cache_stale_purge_tick(&self.config, &self.proxy);
            if shutdown.sleep_or_shutdown(interval).await {
                break;
            }
        }
    }
}

#[cfg(all(feature = "proxy", feature = "cache"))]
fn run_cache_stale_purge_tick(config: &CachePurgerConfig, proxy: &crate::proxy::FluxProxy) {
    #[cfg(feature = "metrics")]
    let started_at = std::time::Instant::now();

    match proxy.purge_stale_disk_cache_once(config.limit, config.batches) {
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

#[cfg(all(feature = "proxy", feature = "cache", feature = "metrics"))]
fn record_cache_stale_purge_metrics(
    outcome: &str,
    result: &crate::proxy::CacheBackgroundPurgeResult,
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

#[cfg(feature = "proxy")]
fn pingora_server_conf(
    plan: &fluxheim_server::ServerPlan,
) -> pingora::server::configuration::ServerConf {
    let process = plan.process();
    pingora::server::configuration::ServerConf {
        daemon: process.daemon(),
        error_log: process
            .error_log()
            .map(|path| path.to_string_lossy().into_owned()),
        pid_file: process.pid_file().to_string_lossy().into_owned(),
        upgrade_sock: process.upgrade_sock().to_string_lossy().into_owned(),
        threads: process.threads(),
        listener_tasks_per_fd: process.listener_tasks_per_fd(),
        work_stealing: process.work_stealing(),
        upstream_keepalive_pool_size: process.upstream_keepalive_pool_size(),
        max_retries: process.max_retries(),
        grace_period_seconds: process.grace_period_seconds(),
        graceful_shutdown_timeout_seconds: process.graceful_shutdown_timeout_seconds(),
        ..pingora::server::configuration::ServerConf::default()
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
    use super::{
        harden_proxy_service_http2_options, log_record_json, open_log_file, pingora_server_conf,
    };
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
    fn hardened_downstream_h2_options_builds_with_flow_control_caps() {
        let policy = fluxheim_server::DownstreamHttp2Policy::default();
        let _options = super::hardened_downstream_h2_options(&policy);

        assert_eq!(policy.max_concurrent_streams(), 32);
        assert_eq!(policy.max_send_buffer_size(), 256 * 1024);
        assert_eq!(policy.max_pending_accept_reset_streams(), 8);
    }

    #[test]
    fn maps_server_process_config_to_pingora_conf() {
        let config = crate::config::Config {
            server: crate::config::ServerConfig {
                process: crate::config::ServerProcessConfig {
                    daemon: true,
                    error_log: Some(std::path::PathBuf::from("/run/fluxheim/error.log")),
                    pid_file: std::path::PathBuf::from("/run/fluxheim/fluxheim.pid"),
                    upgrade_sock: std::path::PathBuf::from("/run/fluxheim/fluxheim-upgrade.sock"),
                    certificate_reload_sock: std::path::PathBuf::from(
                        "/run/fluxheim/fluxheim-cert-reload.sock",
                    ),
                    threads: 4,
                    listener_tasks_per_fd: 2,
                    work_stealing: false,
                    upstream_keepalive_pool_size: 512,
                    max_retries: 8,
                    grace_period_seconds: Some(10),
                    graceful_shutdown_timeout_seconds: Some(30),
                },
                ..crate::config::ServerConfig::default()
            },
            ..crate::config::Config::default()
        };

        let plan = fluxheim_server::ServerPlan::from_config(&config).expect("valid server plan");
        let pingora = pingora_server_conf(&plan);

        assert!(pingora.daemon);
        assert_eq!(
            pingora.error_log.as_deref(),
            Some("/run/fluxheim/error.log")
        );
        assert_eq!(pingora.pid_file, "/run/fluxheim/fluxheim.pid");
        assert_eq!(pingora.upgrade_sock, "/run/fluxheim/fluxheim-upgrade.sock");
        assert_eq!(
            plan.process().certificate_reload_sock(),
            std::path::Path::new("/run/fluxheim/fluxheim-cert-reload.sock")
        );
        assert_eq!(pingora.threads, 4);
        assert_eq!(pingora.listener_tasks_per_fd, 2);
        assert!(!pingora.work_stealing);
        assert_eq!(pingora.upstream_keepalive_pool_size, 512);
        assert_eq!(pingora.max_retries, 8);
        assert_eq!(pingora.grace_period_seconds, Some(10));
        assert_eq!(pingora.graceful_shutdown_timeout_seconds, Some(30));
    }

    #[test]
    fn proxy_service_installs_hardened_http2_options() {
        #[cfg(feature = "tls-rustls-backend")]
        let _ = crate::tls::install_rustls_crypto_provider();

        let config = crate::config::Config::default();
        let proxy = crate::proxy::FluxProxy::from_config(&config).unwrap();
        let plan = fluxheim_server::ServerPlan::from_config(&config).unwrap();
        let pingora_conf = std::sync::Arc::new(pingora_server_conf(&plan));
        let mut service = pingora::proxy::http_proxy_service(&pingora_conf, proxy);

        assert!(
            service
                .app_logic()
                .and_then(|app| app.h2_options.as_ref())
                .is_none()
        );

        harden_proxy_service_http2_options(&mut service, plan.downstream_http2()).unwrap();

        assert!(
            service
                .app_logic()
                .and_then(|app| app.h2_options.as_ref())
                .is_some()
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

        let protocols = super::rustls_alpn_protocols(&tls);

        assert_eq!(
            protocols.first().map(Vec::as_slice),
            Some(crate::acme::acme_tls_alpn_protocol())
        );
        assert!(protocols.iter().any(|protocol| protocol == b"h2"));
        assert!(protocols.iter().any(|protocol| protocol == b"http/1.1"));
    }

    #[cfg(all(feature = "tls-rustls-backend", not(feature = "tls-openssl")))]
    #[test]
    fn rustls_sni_resolver_can_reload_certificate_files()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let certificate = crate::config::StaticCertificateConfig {
            cert_path: std::path::PathBuf::from("tests/fixtures/tls/localhost-cert.pem"),
            key_path: std::path::PathBuf::from("tests/fixtures/tls/localhost-key.pem"),
        };
        let config = crate::config::Config {
            tls: crate::config::TlsConfig {
                enabled: true,
                certificates: vec![certificate],
                ..crate::config::TlsConfig::default()
            },
            ..crate::config::Config::default()
        };
        let selector = fluxheim_tls::DownstreamCertificateSelector::from_config(&config)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "expected downstream certificate selector",
                )
            })?;
        let resolver = super::rustls_sni_certificate_resolver(&selector, &config.tls)?;

        resolver.reload()?;

        assert_eq!(resolver.certificate_slot_count(), 1);
        assert_eq!(resolver.loaded_certificate_count(), 1);
        Ok(())
    }

    #[cfg(all(
        feature = "tls-rustls-backend",
        feature = "acme",
        not(feature = "tls-openssl")
    ))]
    #[test]
    fn rustls_sni_resolver_allows_pending_managed_acme_certificates() {
        let acme_storage = unique_temp_path("runtime-pending-acme-certificates");
        std::fs::create_dir_all(&acme_storage).unwrap();
        let default_certificate = crate::config::StaticCertificateConfig {
            cert_path: std::path::PathBuf::from("tests/fixtures/tls/localhost-cert.pem"),
            key_path: std::path::PathBuf::from("tests/fixtures/tls/localhost-key.pem"),
        };
        let config = crate::config::Config {
            server: crate::config::ServerConfig {
                default_vhost: Some("default".to_owned()),
                tls_listen: vec!["127.0.0.1:8443".to_owned()],
                ..crate::config::ServerConfig::default()
            },
            tls: crate::config::TlsConfig {
                enabled: true,
                certificates: vec![default_certificate],
                acme: crate::config::AcmeConfig {
                    enabled: true,
                    storage: Some(acme_storage.clone()),
                    ..crate::config::AcmeConfig::default()
                },
                ..crate::config::TlsConfig::default()
            },
            vhosts: vec![crate::config::VhostConfig {
                name: "new-site".to_owned(),
                hosts: vec!["new-site.example.test".to_owned()],
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
        let plan = crate::tls::downstream_tls_listener_plan(&config)
            .unwrap()
            .unwrap();
        let resolver =
            super::rustls_sni_certificate_resolver(plan.selector(), &config.tls).unwrap();

        assert_eq!(resolver.certificate_slot_count(), 2);
        assert_eq!(resolver.loaded_certificate_count(), 1);

        std::fs::remove_dir_all(acme_storage).unwrap();
    }
}

#[cfg(all(
    feature = "proxy",
    any(feature = "tls-rustls-backend", feature = "tls-openssl")
))]
fn add_tls_listeners<S>(
    service: &mut pingora::services::listening::Service<S>,
    config: &Config,
    server_plan: &fluxheim_server::ServerPlan,
) -> Result<Option<DownstreamCertificateReloader>, Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    let Some(plan) = crate::tls::downstream_tls_listener_plan(config)? else {
        return Ok(None);
    };
    let tls_listens = server_plan.service_listener_addrs_for_protocol(
        fluxheim_server::ServiceKind::ProxyHttp,
        fluxheim_server::ListenerProtocol::Https,
    );

    let reloader = add_downstream_tls_listeners(
        service,
        &tls_listens,
        plan.selector(),
        plan.requires_certificate_resolver(),
        &config.tls,
    )?;
    Ok(reloader)
}

#[cfg(all(feature = "proxy", feature = "tls-openssl"))]
fn tls_alpn_policy(policy: TlsAlpnPolicy) -> pingora::protocols::ALPN {
    match policy {
        TlsAlpnPolicy::Http1 => pingora::protocols::ALPN::H1,
        TlsAlpnPolicy::Http2 => pingora::protocols::ALPN::H2,
        TlsAlpnPolicy::Http1AndHttp2 => pingora::protocols::ALPN::H2H1,
    }
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls-backend",
    not(feature = "tls-openssl")
))]
fn apply_tls_policy(
    settings: &mut pingora::listeners::tls::TlsSettings,
    tls: &TlsConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let fips_required = tls.compliance_mode().required();
    settings.set_crypto_provider(crate::tls::rustls_crypto_provider());
    settings.set_alpn_protocols(rustls_alpn_protocols(tls));
    settings.set_cipher_suites(
        tls.effective_cipher_suites()
            .into_iter()
            .map(|cipher| rustls_cipher_suite(cipher, fips_required))
            .collect::<Result<Vec<_>, _>>()?,
    );
    settings.set_kx_groups(
        tls.effective_curve_preferences()
            .into_iter()
            .map(|curve| rustls_kx_group(curve, fips_required))
            .collect::<Result<Vec<_>, _>>()?,
    );
    match tls.effective_min_protocol() {
        TlsProtocolVersion::Tls12 => settings.set_min_protocol_tls12(),
        TlsProtocolVersion::Tls13 => settings.set_min_protocol_tls13(),
    }
    if let Some(verifier) = rustls_client_cert_verifier(tls)? {
        settings.set_client_cert_verifier(verifier);
    }
    settings.set_require_fips(fips_required);
    Ok(())
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls-backend",
    not(feature = "tls-openssl")
))]
fn rustls_client_cert_verifier(
    tls: &TlsConfig,
) -> Result<
    Option<std::sync::Arc<dyn rustls::server::danger::ClientCertVerifier>>,
    Box<dyn Error + Send + Sync>,
> {
    if tls.client_auth.mode == TlsClientAuthMode::Off {
        return Ok(None);
    }
    let ca_path = tls
        .client_auth
        .ca_path
        .as_deref()
        .ok_or("tls.client_auth.ca_path is required when client auth is enabled")?;
    use rustls::pki_types::{CertificateDer, pem::PemObject};

    let reader = std::io::BufReader::new(std::fs::File::open(ca_path).map_err(|error| {
        format!(
            "failed to open TLS client auth CA bundle {}: {error}",
            ca_path.display()
        )
    })?);
    let mut roots = rustls::RootCertStore::empty();
    let mut loaded = 0usize;
    for certificate in CertificateDer::pem_reader_iter(reader) {
        let certificate = certificate.map_err(|error| {
            format!(
                "failed to parse TLS client auth CA bundle {}: {error}",
                ca_path.display()
            )
        })?;
        roots.add(certificate).map_err(|error| {
            format!(
                "failed to add certificate from TLS client auth CA bundle {}: {error}",
                ca_path.display()
            )
        })?;
        loaded += 1;
    }
    if loaded == 0 {
        return Err(format!(
            "TLS client auth CA bundle {} does not contain any certificates",
            ca_path.display()
        )
        .into());
    }

    let builder = rustls::server::WebPkiClientVerifier::builder_with_provider(
        std::sync::Arc::new(roots),
        std::sync::Arc::new(crate::tls::rustls_crypto_provider()),
    );
    let builder = match tls.client_auth.mode {
        TlsClientAuthMode::Off => return Ok(None),
        TlsClientAuthMode::Required => builder,
        TlsClientAuthMode::Optional => builder.allow_unauthenticated(),
    };
    Ok(Some(builder.build().map_err(|error| {
        format!(
            "failed to build TLS client certificate verifier from {}: {error}",
            ca_path.display()
        )
    })?))
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls-backend",
    not(feature = "tls-openssl")
))]
fn rustls_alpn_protocols(tls: &TlsConfig) -> Vec<Vec<u8>> {
    #[cfg(feature = "acme")]
    {
        let acme_protocol = (tls.acme.enabled && tls.acme.challenge == AcmeChallenge::TlsAlpn01)
            .then_some(crate::acme::acme_tls_alpn_protocol());
        fluxheim_tls::rustls_alpn_protocols(tls, acme_protocol)
    }
    #[cfg(not(feature = "acme"))]
    {
        fluxheim_tls::rustls_alpn_protocols(tls, None)
    }
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls-backend",
    not(feature = "tls-openssl")
))]
fn rustls_cipher_suite(
    cipher: TlsCipherSuite,
    fips_required: bool,
) -> Result<rustls::SupportedCipherSuite, Box<dyn Error + Send + Sync>> {
    fluxheim_tls::rustls_cipher_suite(cipher, fips_required).map_err(Into::into)
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls-backend",
    not(feature = "tls-openssl")
))]
fn rustls_kx_group(
    curve: TlsCurvePreference,
    fips_required: bool,
) -> Result<&'static dyn rustls::crypto::SupportedKxGroup, Box<dyn Error + Send + Sync>> {
    fluxheim_tls::rustls_kx_group(curve, fips_required).map_err(Into::into)
}

#[cfg(all(feature = "proxy", feature = "tls-openssl"))]
fn apply_tls_policy(
    settings: &mut pingora::listeners::tls::TlsSettings,
    tls: &TlsConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    settings.set_alpn(tls_alpn_policy(tls.effective_alpn()));
    settings.set_groups_list(&openssl_curve_list(&tls.effective_curve_preferences()))?;
    let (tls12_ciphers, tls13_ciphers) = openssl_cipher_lists(&tls.effective_cipher_suites());
    if !tls12_ciphers.is_empty() {
        settings.set_cipher_list(&tls12_ciphers)?;
    }
    if !tls13_ciphers.is_empty() {
        settings.set_ciphersuites(&tls13_ciphers)?;
    }
    let min_version = match tls.effective_min_protocol() {
        TlsProtocolVersion::Tls12 => SslVersion::TLS1_2,
        TlsProtocolVersion::Tls13 => SslVersion::TLS1_3,
    };
    settings.set_min_proto_version(Some(min_version))?;
    apply_openssl_client_auth(settings, tls)?;
    Ok(())
}

#[cfg(all(feature = "proxy", feature = "tls-openssl"))]
fn apply_openssl_client_auth(
    settings: &mut pingora::listeners::tls::TlsSettings,
    tls: &TlsConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if tls.client_auth.mode == TlsClientAuthMode::Off {
        return Ok(());
    }
    let ca_path = tls
        .client_auth
        .ca_path
        .as_deref()
        .ok_or("tls.client_auth.ca_path is required when client auth is enabled")?;
    let ca_path = ca_path
        .to_str()
        .ok_or("tls.client_auth.ca_path must be valid UTF-8 for the TLS backend")?;
    let verify = match tls.client_auth.mode {
        TlsClientAuthMode::Off => SslVerifyMode::NONE,
        TlsClientAuthMode::Optional => SslVerifyMode::PEER,
        TlsClientAuthMode::Required => SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
    };
    settings.set_verify(verify);
    settings.set_ca_file(ca_path)?;
    settings.set_client_ca_list(X509Name::load_client_ca_file(ca_path)?);
    Ok(())
}

#[cfg(all(feature = "proxy", feature = "tls-openssl"))]
fn openssl_curve_list(curves: &[TlsCurvePreference]) -> String {
    fluxheim_tls::openssl_curve_list(curves)
}

#[cfg(all(feature = "proxy", feature = "tls-openssl"))]
fn openssl_cipher_lists(ciphers: &[TlsCipherSuite]) -> (String, String) {
    fluxheim_tls::openssl_cipher_lists(ciphers)
}

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

#[cfg(all(feature = "proxy", feature = "tls-openssl"))]
fn add_downstream_tls_listeners<S>(
    service: &mut pingora::services::listening::Service<S>,
    listens: &[String],
    selector: &fluxheim_tls::DownstreamCertificateSelector,
    requires_certificate_resolver: bool,
    tls: &TlsConfig,
) -> Result<Option<DownstreamCertificateReloader>, Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    if requires_certificate_resolver {
        let store = std::sync::Arc::new(fluxheim_tls::OpenSslDownstreamCertificateStore::new(
            selector,
            openssl_pending_managed_certificate_recorder(),
        )?);
        for listen in listens {
            log::info!("proxy TLS listener enabled on {listen}");
            let mut settings = pingora::listeners::tls::TlsSettings::with_callbacks(Box::new(
                SharedSniCertificateCallback {
                    inner: store.clone(),
                },
            ))?;
            apply_tls_policy(&mut settings, tls)?;
            service.add_tls_with_settings(listen, None, settings);
        }
        return Ok(Some(DownstreamCertificateReloader::Openssl(store)));
    }

    let certificate = selector.certificate_for_sni(None);
    let (cert_path, key_path) = downstream_certificate_paths(certificate)?;
    for listen in listens {
        log::info!("proxy TLS listener enabled on {listen}");
        let mut settings = pingora::listeners::tls::TlsSettings::intermediate(cert_path, key_path)?;
        apply_tls_policy(&mut settings, tls)?;
        service.add_tls_with_settings(listen, None, settings);
    }
    Ok(None)
}

#[cfg(all(feature = "proxy", feature = "tls-openssl"))]
fn openssl_pending_managed_certificate_recorder() -> Option<fn()> {
    #[cfg(feature = "metrics")]
    {
        Some(record_pending_managed_certificate)
    }
    #[cfg(not(feature = "metrics"))]
    {
        None
    }
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls-backend",
    not(feature = "tls-openssl")
))]
fn add_downstream_tls_listeners<S>(
    service: &mut pingora::services::listening::Service<S>,
    listens: &[String],
    selector: &fluxheim_tls::DownstreamCertificateSelector,
    requires_certificate_resolver: bool,
    tls: &TlsConfig,
) -> Result<Option<DownstreamCertificateReloader>, Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    if requires_certificate_resolver {
        let resolver = std::sync::Arc::new(rustls_sni_certificate_resolver(selector, tls)?);
        for listen in listens {
            log::info!("proxy TLS listener enabled on {listen}");
            let mut settings =
                pingora::listeners::tls::TlsSettings::with_cert_resolver(resolver.clone())?;
            apply_tls_policy(&mut settings, tls)?;
            service.add_tls_with_settings(listen, None, settings);
        }
        return Ok(Some(DownstreamCertificateReloader::Rustls(resolver)));
    }

    let certificate = selector.certificate_for_sni(None);
    let (cert_path, key_path) = downstream_certificate_paths(certificate)?;
    for listen in listens {
        log::info!("proxy TLS listener enabled on {listen}");
        let mut settings = pingora::listeners::tls::TlsSettings::intermediate(cert_path, key_path)?;
        apply_tls_policy(&mut settings, tls)?;
        service.add_tls_with_settings(listen, None, settings);
    }
    Ok(None)
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls-backend",
    not(feature = "tls-openssl")
))]
type RustlsSniCertificateResolver = fluxheim_tls::RustlsDownstreamCertificateResolver;

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls-backend",
    not(feature = "tls-openssl")
))]
fn rustls_sni_certificate_resolver(
    selector: &fluxheim_tls::DownstreamCertificateSelector,
    _tls: &TlsConfig,
) -> Result<RustlsSniCertificateResolver, Box<dyn Error + Send + Sync>> {
    #[cfg(feature = "acme")]
    if rustls_acme_tls_alpn_enabled(_tls)
        && let Some(storage) = _tls.acme.storage.as_deref()
    {
        return fluxheim_tls::RustlsDownstreamCertificateResolver::with_tls_alpn_challenge(
            selector,
            crate::acme::acme_tls_alpn_protocol().to_vec(),
            std::sync::Arc::new(AcmeTlsAlpnCertificateLoader {
                store: crate::acme::AcmeTlsAlpn01ChallengeStore::new(storage),
            }),
        )
        .map_err(Into::into);
    }

    fluxheim_tls::RustlsDownstreamCertificateResolver::new(selector).map_err(Into::into)
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls-backend",
    feature = "acme",
    not(feature = "tls-openssl")
))]
fn rustls_acme_tls_alpn_enabled(tls: &TlsConfig) -> bool {
    tls.acme.enabled && tls.acme.challenge == AcmeChallenge::TlsAlpn01
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls-backend",
    feature = "acme",
    not(feature = "tls-openssl")
))]
#[derive(Debug)]
struct AcmeTlsAlpnCertificateLoader {
    store: crate::acme::AcmeTlsAlpn01ChallengeStore,
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls-backend",
    feature = "acme",
    not(feature = "tls-openssl")
))]
impl fluxheim_tls::RustlsTlsAlpnCertificateLoader for AcmeTlsAlpnCertificateLoader {
    fn load_tls_alpn_certificate(
        &self,
        sni: Option<&str>,
    ) -> Result<Option<rustls::sign::CertifiedKey>, fluxheim_tls::RustlsDownstreamCertificateError>
    {
        let Some(sni) = sni else {
            return Ok(None);
        };
        let Some(paths) = self.store.certificate_paths_for_sni(sni) else {
            return Ok(None);
        };
        fluxheim_tls::load_rustls_certified_key_from_paths(&paths.cert_path, &paths.key_path)
            .map(Some)
    }
}

#[cfg(all(feature = "proxy", feature = "tls-openssl"))]
struct SharedSniCertificateCallback {
    inner: std::sync::Arc<fluxheim_tls::OpenSslDownstreamCertificateStore>,
}

#[cfg(all(feature = "proxy", feature = "tls-openssl"))]
#[async_trait::async_trait]
impl pingora::listeners::TlsAccept for SharedSniCertificateCallback {
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        let sni = ssl
            .servername(pingora::tls::ssl::NameType::HOST_NAME)
            .map(str::to_owned);
        if let Err(error) = self.inner.apply_certificate_for_sni(sni.as_deref(), ssl) {
            log::error!("failed to set downstream SNI certificate: {error}");
        }
    }
}

#[cfg(all(
    feature = "proxy",
    any(feature = "tls-rustls-backend", feature = "tls-openssl")
))]
fn downstream_certificate_paths(
    certificate: &crate::config::StaticCertificateConfig,
) -> Result<(&str, &str), Box<dyn Error + Send + Sync>> {
    let cert_path = certificate
        .cert_path
        .to_str()
        .ok_or("TLS certificate path must be valid UTF-8 for Pingora")?;
    let key_path = certificate
        .key_path
        .to_str()
        .ok_or("TLS private key path must be valid UTF-8 for Pingora")?;

    Ok((cert_path, key_path))
}

#[cfg(all(
    feature = "proxy",
    not(any(feature = "tls-rustls-backend", feature = "tls-openssl"))
))]
fn add_tls_listeners<S>(
    _service: &mut pingora::services::listening::Service<S>,
    _config: &Config,
    server_plan: &fluxheim_server::ServerPlan,
) -> Result<Option<DownstreamCertificateReloader>, Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    if server_plan
        .service_listener_addrs_for_protocol(
            fluxheim_server::ServiceKind::ProxyHttp,
            fluxheim_server::ListenerProtocol::Https,
        )
        .is_empty()
    {
        Ok(None)
    } else {
        Err("server.tls_listen requires a TLS feature".into())
    }
}

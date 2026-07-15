use std::error::Error;

#[cfg(all(feature = "cache", feature = "metrics"))]
const CACHE_RUNTIME_METRICS_INTERVAL_SECS: u64 = 5;

#[cfg(feature = "tls-openssl")]
const OPENSSL_CERTIFICATE_GENERATION_DRAIN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(10);

#[cfg(all(feature = "tls-rustls-backend", not(feature = "tls-openssl")))]
type RustlsSniCertificateResolver = fluxheim_tls::RustlsDownstreamCertificateResolver;

#[cfg_attr(not(feature = "acme-client"), allow(dead_code))]
#[derive(Clone)]
pub(super) enum DownstreamCertificateReloader {
    #[cfg(all(feature = "tls-rustls-backend", not(feature = "tls-openssl")))]
    Rustls(std::sync::Arc<RustlsSniCertificateResolver>),
    #[cfg(feature = "tls-openssl")]
    Openssl(std::sync::Arc<fluxheim_tls::OpenSslDownstreamCertificateStore>),
}

#[cfg_attr(not(feature = "acme-client"), allow(dead_code))]
impl DownstreamCertificateReloader {
    #[cfg_attr(not(feature = "acme-client"), allow(dead_code))]
    fn reload(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        match self {
            #[cfg(all(feature = "tls-rustls-backend", not(feature = "tls-openssl")))]
            Self::Rustls(resolver) => Ok(resolver.reload()?),
            #[cfg(feature = "tls-openssl")]
            Self::Openssl(store) => Ok(store
                .reload_after_generation_drain(OPENSSL_CERTIFICATE_GENERATION_DRAIN_TIMEOUT)?),
            #[cfg(not(any(
                all(feature = "tls-rustls-backend", not(feature = "tls-openssl")),
                feature = "tls-openssl"
            )))]
            _ => Ok(()),
        }
    }
}

#[cfg(feature = "acme-client")]
async fn reload_downstream_certificates(
    reloader: &DownstreamCertificateReloader,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let reloader = reloader.clone();
    tokio::task::spawn_blocking(move || reloader.reload()).await?
}

#[cfg(all(feature = "acme-client", unix))]
pub(super) fn certificate_reload_control_service(
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

#[cfg(all(feature = "acme-client", unix))]
fn handle_certificate_reload_control_request(
    stream: &mut std::os::unix::net::UnixStream,
    reloader: Option<&DownstreamCertificateReloader>,
    read_timeout: std::time::Duration,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    use std::io::{Read as _, Write as _};

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

#[cfg(all(feature = "acme-client", unix))]
pub(super) struct CertificateReloadControlBackgroundService {
    listener: std::os::unix::net::UnixListener,
    reloader: Option<DownstreamCertificateReloader>,
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    read_timeout: std::time::Duration,
}

#[cfg(all(feature = "acme-client", unix))]
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

#[cfg(all(feature = "cache", feature = "metrics"))]
pub(super) struct CacheRuntimeMetricsBackgroundService;

#[cfg(all(feature = "cache", feature = "metrics"))]
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

#[cfg(all(feature = "cache", feature = "metrics"))]
pub(super) fn record_cache_runtime_metrics() {
    let native_totals = fluxheim_server::native_cache_runtime_totals();
    if native_totals.memory_tiers > 0 || native_totals.disk_tiers > 0 {
        crate::metrics::record_native_cache_runtime_totals(&native_totals);
    }
}

#[cfg(all(test, feature = "acme-client"))]
pub(super) fn acme_background_service_enabled(config: &crate::config::Config) -> bool {
    config.tls.acme.automation == crate::config::AcmeAutomationMode::Background
        && !fluxheim_acme::renewal_targets(config).is_empty()
}

#[cfg(feature = "cache")]
pub(super) struct CacheStalePurgerBackgroundService {
    pub(super) config: crate::config::CachePurgerConfig,
}

#[cfg(feature = "cache")]
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

#[cfg(feature = "cache")]
fn run_cache_stale_purge_tick(config: &crate::config::CachePurgerConfig) {
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

#[cfg(feature = "cache")]
fn native_stale_disk_cache_purge_once(
    limit: usize,
    batches: usize,
) -> std::io::Result<fluxheim_cache::CacheBackgroundPurgeResult> {
    fluxheim_server::purge_native_disk_cache_stale_all(limit, batches)
}

#[cfg(all(feature = "cache", feature = "metrics"))]
fn record_cache_stale_purge_metrics(
    outcome: &str,
    result: &fluxheim_cache::CacheBackgroundPurgeResult,
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

#[cfg(feature = "acme-client")]
pub(super) struct AcmeRenewalBackgroundService {
    pub(super) config: crate::config::Config,
    pub(super) certificate_reloader: Option<DownstreamCertificateReloader>,
}

#[cfg(feature = "metrics-otlp")]
pub(super) struct MetricsOtlpBackgroundService {
    pub(super) exporter: crate::metrics_otlp::MetricsOtlpExporter,
}

#[cfg(feature = "metrics-otlp")]
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

#[cfg(feature = "acme-client")]
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

#[cfg(feature = "acme-client")]
async fn run_acme_renewal_tick(
    config: &crate::config::Config,
    reloader: Option<&DownstreamCertificateReloader>,
) {
    match fluxheim_acme::renew_due_instant_acme_targets(config, std::time::SystemTime::now()).await
    {
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
                if let Err(error) = reload_downstream_certificates(reloader).await {
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

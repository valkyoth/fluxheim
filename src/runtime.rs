use std::error::Error;
#[cfg(feature = "proxy")]
use std::fs::{File, OpenOptions};
#[cfg(feature = "proxy")]
use std::io::Write;
#[cfg(all(feature = "proxy", target_os = "linux"))]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(feature = "proxy")]
use std::path::Path;

#[cfg(all(feature = "proxy", feature = "acme-client"))]
use crate::config::AcmeAutomationMode;
#[cfg(all(
    feature = "acme",
    feature = "proxy",
    feature = "tls-rustls",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
use crate::config::AcmeChallenge;
#[cfg(all(feature = "proxy", feature = "cache"))]
use crate::config::CachePurgerConfig;
use crate::config::Config;
#[cfg(feature = "proxy")]
use crate::config::{LoggingFormat, LoggingTarget};
#[cfg(all(
    feature = "proxy",
    any(
        all(
            feature = "tls-rustls",
            not(any(feature = "tls-openssl", feature = "tls-boringssl"))
        ),
        feature = "tls-openssl",
        feature = "tls-boringssl",
        all(
            feature = "tls-s2n",
            not(any(
                feature = "tls-rustls",
                feature = "tls-openssl",
                feature = "tls-boringssl"
            ))
        )
    )
))]
use crate::config::{TlsAlpnPolicy, TlsConfig, TlsProtocolVersion};
#[cfg(all(
    feature = "proxy",
    any(
        all(
            feature = "tls-rustls",
            not(any(feature = "tls-openssl", feature = "tls-boringssl"))
        ),
        feature = "tls-openssl",
        feature = "tls-boringssl"
    )
))]
use crate::config::{TlsCipherSuite, TlsCurvePreference};
#[cfg(all(
    feature = "proxy",
    any(feature = "tls-openssl", feature = "tls-boringssl")
))]
use pingora::tls::{
    pkey::{PKey, Private},
    ssl::SslVersion,
    x509::X509,
};

#[cfg(feature = "proxy")]
pub fn run(config: Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    init_logging(&config)?;
    #[cfg(all(
        feature = "tls-rustls",
        not(any(feature = "tls-openssl", feature = "tls-boringssl"))
    ))]
    crate::tls::install_rustls_crypto_provider();

    let pingora_conf = pingora_server_conf(&config);
    let mut server = pingora::server::Server::new_with_opt_and_conf(None, pingora_conf);
    server.bootstrap();

    #[cfg(feature = "load-balancer")]
    let (proxy, load_balancer_services) =
        crate::proxy::FluxProxy::from_config_with_background_services(&config)?;

    #[cfg(not(feature = "load-balancer"))]
    let proxy = crate::proxy::FluxProxy::from_config(&config)?;

    let admin_proxy = proxy.clone();
    let mut proxy_service = pingora::proxy::http_proxy_service(&server.configuration, proxy);

    #[cfg(feature = "cache")]
    if config.cache_purger.enabled {
        log::info!(
            "cache stale disk purger enabled; interval={}s limit={} batches={}",
            config.cache_purger.interval_secs,
            config.cache_purger.limit,
            config.cache_purger.batches
        );
        server.add_service(pingora::services::background::background_service(
            "Cache stale disk purger",
            CacheStalePurgerBackgroundService {
                config: config.cache_purger.clone(),
                proxy: admin_proxy.clone(),
            },
        ));
    }

    for listen in &config.server.listen {
        log::info!("proxy listener enabled on {listen}");
        proxy_service.add_tcp(listen);
    }
    let certificate_reloader = add_tls_listeners(&mut proxy_service, &config)?;
    #[cfg(not(feature = "acme-client"))]
    let _ = &certificate_reloader;

    #[cfg(feature = "load-balancer")]
    for service in load_balancer_services {
        log::info!("load-balancer health-check service enabled");
        server.add_service(service);
    }

    if let Some(admin_services) = crate::admin::admin_services_from_config(&config, admin_proxy)? {
        log::info!("admin control plane enabled on {}", config.admin.listen);
        if let Some(watchdog) = admin_services.watchdog {
            log::info!("admin self-healing watchdog enabled");
            server.add_service(watchdog);
        }
        server.add_service(admin_services.control_plane);
    }

    #[cfg(feature = "metrics")]
    if config.metrics.enabled {
        crate::metrics::init()?;
        crate::metrics::record_config(&config);
        let mut metrics_service = pingora::services::listening::Service::prometheus_http_service();
        log::info!("metrics listener enabled on {}", config.metrics.listen);
        metrics_service.add_tcp(&config.metrics.listen);
        server.add_service(metrics_service);

        #[cfg(feature = "metrics-otlp")]
        if config.metrics.otlp.enabled {
            crate::metrics_otlp::spawn_from_config(&config.metrics.otlp)?;
            log::info!(
                "OTLP metrics export enabled to {}",
                config.metrics.otlp.endpoint
            );
        }
    }

    #[cfg(feature = "acme-client")]
    if acme_background_service_enabled(&config) {
        log::info!(
            "ACME renewal service enabled; interval={}s",
            config.tls.acme.renewal.check_interval_secs
        );
        server.add_service(pingora::services::background::background_service(
            "ACME renewal",
            AcmeRenewalBackgroundService {
                config: config.clone(),
                certificate_reloader: certificate_reloader.clone(),
            },
        ));
    }

    server.add_service(proxy_service);
    server.run_forever();
}

#[cfg(all(feature = "proxy", feature = "acme-client"))]
fn acme_background_service_enabled(config: &Config) -> bool {
    config.tls.acme.automation == AcmeAutomationMode::Background
        && !crate::acme::renewal_targets(config).is_empty()
}

#[cfg(all(feature = "proxy", feature = "cache"))]
struct CacheStalePurgerBackgroundService {
    config: CachePurgerConfig,
    proxy: crate::proxy::FluxProxy,
}

#[cfg(all(feature = "proxy", feature = "cache"))]
#[async_trait::async_trait]
impl pingora::services::background::BackgroundService for CacheStalePurgerBackgroundService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let interval = std::time::Duration::from_secs(self.config.interval_secs);

        loop {
            if *shutdown.borrow() {
                break;
            }

            run_cache_stale_purge_tick(&self.config, &self.proxy);

            match tokio::time::timeout(interval, shutdown.changed()).await {
                Ok(Ok(())) => continue,
                Ok(Err(_closed)) => break,
                Err(_elapsed) => continue,
            }
        }
    }
}

#[cfg(all(feature = "proxy", feature = "cache"))]
fn run_cache_stale_purge_tick(config: &CachePurgerConfig, proxy: &crate::proxy::FluxProxy) {
    match proxy.purge_stale_disk_cache_once(config.limit, config.batches) {
        Ok(result) if result.targets == 0 => {
            #[cfg(feature = "metrics")]
            record_cache_stale_purge_metrics("skipped", &result);
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
            crate::metrics::record_cache_purger_run("error");
            log::error!("cache stale disk purge failed: {error}");
        }
    }
}

#[cfg(all(feature = "proxy", feature = "cache", feature = "metrics"))]
fn record_cache_stale_purge_metrics(
    outcome: &str,
    result: &crate::proxy::CacheBackgroundPurgeResult,
) {
    crate::metrics::record_cache_purger_run(outcome);
    crate::metrics::record_cache_purger_entries("scanned", usize_to_u64_saturating(result.scanned));
    crate::metrics::record_cache_purger_entries("stale", usize_to_u64_saturating(result.stale));
    crate::metrics::record_cache_purger_entries("purged", usize_to_u64_saturating(result.purged));
}

#[cfg(all(feature = "proxy", feature = "cache", feature = "metrics"))]
fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(all(feature = "proxy", feature = "acme-client"))]
struct AcmeRenewalBackgroundService {
    config: Config,
    certificate_reloader: Option<DownstreamCertificateReloader>,
}

#[cfg(all(feature = "proxy", feature = "acme-client"))]
#[async_trait::async_trait]
impl pingora::services::background::BackgroundService for AcmeRenewalBackgroundService {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let interval =
            std::time::Duration::from_secs(self.config.tls.acme.renewal.check_interval_secs);

        loop {
            if *shutdown.borrow() {
                break;
            }

            run_acme_renewal_tick(&self.config, self.certificate_reloader.as_ref()).await;

            match tokio::time::timeout(interval, shutdown.changed()).await {
                Ok(Ok(())) => continue,
                Ok(Err(_closed)) => break,
                Err(_elapsed) => continue,
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
                    log::error!(
                        "failed to reload downstream TLS certificates after ACME renewal: {error}"
                    );
                } else {
                    log::info!("downstream TLS certificates reloaded after ACME renewal");
                }
            } else {
                log::warn!(
                    "ACME renewed certificates but no downstream TLS reload handle is available; restart or reload Fluxheim to use them"
                );
            }
        }
        Err(error) => {
            log::error!("ACME renewal check failed: {error}");
        }
    }
}

#[cfg(feature = "proxy")]
fn pingora_server_conf(config: &Config) -> pingora::server::configuration::ServerConf {
    let process = &config.server.process;
    pingora::server::configuration::ServerConf {
        daemon: process.daemon,
        error_log: process
            .error_log
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        pid_file: process.pid_file.to_string_lossy().into_owned(),
        upgrade_sock: process.upgrade_sock.to_string_lossy().into_owned(),
        threads: process.threads,
        listener_tasks_per_fd: process.listener_tasks_per_fd,
        work_stealing: process.work_stealing,
        upstream_keepalive_pool_size: process.upstream_keepalive_pool_size,
        max_retries: process.max_retries,
        grace_period_seconds: process.grace_period_seconds,
        graceful_shutdown_timeout_seconds: process.graceful_shutdown_timeout_seconds,
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
    let mut options = OpenOptions::new();
    options.create(true).write(true);
    if append {
        options.append(true);
    } else {
        options.truncate(true);
    }

    #[cfg(target_os = "linux")]
    options.custom_flags(O_NOFOLLOW);

    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("log path is not a regular file: {}", path.display()),
        ));
    }

    Ok(file)
}

#[cfg(all(feature = "proxy", target_os = "linux"))]
const O_NOFOLLOW: i32 = 0o400000;

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
        json_escape(timestamp),
        json_escape(level),
        json_escape(target),
        json_escape(message),
    )
}

#[cfg(feature = "proxy")]
fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(all(test, feature = "proxy"))]
mod tests {
    use super::{json_escape, log_record_json, open_log_file, pingora_server_conf};
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
        assert_eq!(json_escape("a\u{0001}b"), "a\\u0001b");
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

        let pingora = pingora_server_conf(&config);

        assert!(pingora.daemon);
        assert_eq!(
            pingora.error_log.as_deref(),
            Some("/run/fluxheim/error.log")
        );
        assert_eq!(pingora.pid_file, "/run/fluxheim/fluxheim.pid");
        assert_eq!(pingora.upgrade_sock, "/run/fluxheim/fluxheim-upgrade.sock");
        assert_eq!(pingora.threads, 4);
        assert_eq!(pingora.listener_tasks_per_fd, 2);
        assert!(!pingora.work_stealing);
        assert_eq!(pingora.upstream_keepalive_pool_size, 512);
        assert_eq!(pingora.max_retries, 8);
        assert_eq!(pingora.grace_period_seconds, Some(10));
        assert_eq!(pingora.graceful_shutdown_timeout_seconds, Some(30));
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
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                web: crate::config::WebConfig::default(),
                routes: Vec::new(),
            }],
            ..crate::config::Config::default()
        };

        assert!(super::acme_background_service_enabled(&config));

        config.tls.acme.automation = crate::config::AcmeAutomationMode::External;

        assert!(!super::acme_background_service_enabled(&config));
    }

    #[test]
    fn opens_regular_log_file_for_append() {
        let path = unique_temp_path("runtime-log-append").with_extension("log");
        let _ = std::fs::remove_file(&path);

        let file = open_log_file(&path, true).unwrap();

        assert!(file.metadata().unwrap().is_file());
        let _ = std::fs::remove_file(&path);
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

    #[cfg(all(
        feature = "tls-rustls",
        feature = "acme",
        not(any(feature = "tls-openssl", feature = "tls-boringssl"))
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

    #[cfg(all(
        feature = "tls-rustls",
        not(any(feature = "tls-openssl", feature = "tls-boringssl"))
    ))]
    #[test]
    fn rustls_sni_resolver_can_reload_certificate_files() {
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
        let selector = crate::tls::DownstreamCertificateSelector::from_config(&config).unwrap();
        let resolver = super::RustlsSniCertificateResolver::new(&selector, &config.tls).unwrap();

        resolver.reload().unwrap();

        assert_eq!(resolver.certificates.load().len(), 1);
    }
}

#[cfg(all(
    feature = "proxy",
    any(
        feature = "tls-rustls",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    )
))]
fn add_tls_listeners<S>(
    service: &mut pingora::services::listening::Service<S>,
    config: &Config,
) -> Result<Option<DownstreamCertificateReloader>, Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    if config.server.tls_listen.is_empty() {
        return Ok(None);
    }
    if !config.tls.enabled {
        return Err("server.tls_listen requires tls.enabled = true".into());
    }

    let Some(selector) = crate::tls::DownstreamCertificateSelector::from_config(config) else {
        return Err(
            "server.tls_listen requires a global certificate or a static/ACME certificate source on server.default_vhost"
                .into(),
        );
    };

    let reloader =
        add_downstream_tls_listeners(service, &config.server.tls_listen, &selector, &config.tls)?;
    Ok(reloader)
}

#[cfg(all(
    feature = "proxy",
    any(feature = "tls-openssl", feature = "tls-boringssl")
))]
fn tls_alpn_policy(policy: TlsAlpnPolicy) -> pingora::protocols::ALPN {
    match policy {
        TlsAlpnPolicy::Http1 => pingora::protocols::ALPN::H1,
        TlsAlpnPolicy::Http2 => pingora::protocols::ALPN::H2,
        TlsAlpnPolicy::Http1AndHttp2 => pingora::protocols::ALPN::H2H1,
    }
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
fn apply_tls_policy(
    settings: &mut pingora::listeners::tls::TlsSettings,
    tls: &TlsConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    settings.set_alpn_protocols(rustls_alpn_protocols(tls));
    settings.set_cipher_suites(
        tls.effective_cipher_suites()
            .into_iter()
            .map(rustls_cipher_suite)
            .collect(),
    );
    settings.set_kx_groups(
        tls.effective_curve_preferences()
            .into_iter()
            .map(rustls_kx_group)
            .collect::<Result<Vec<_>, _>>()?,
    );
    match tls.effective_min_protocol() {
        TlsProtocolVersion::Tls12 => settings.set_min_protocol_tls12(),
        TlsProtocolVersion::Tls13 => settings.set_min_protocol_tls13(),
    }
    Ok(())
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
fn rustls_alpn_protocols(tls: &TlsConfig) -> Vec<Vec<u8>> {
    let protocols = match tls.effective_alpn() {
        TlsAlpnPolicy::Http1 => vec![b"http/1.1".to_vec()],
        TlsAlpnPolicy::Http2 => vec![b"h2".to_vec()],
        TlsAlpnPolicy::Http1AndHttp2 => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    };
    #[cfg(feature = "acme")]
    {
        let mut protocols = protocols;
        if tls.acme.enabled && tls.acme.challenge == AcmeChallenge::TlsAlpn01 {
            protocols.insert(0, crate::acme::acme_tls_alpn_protocol().to_vec());
        }
        protocols
    }
    #[cfg(not(feature = "acme"))]
    {
        protocols
    }
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
fn rustls_cipher_suite(cipher: TlsCipherSuite) -> rustls::SupportedCipherSuite {
    match cipher {
        TlsCipherSuite::Tls13Aes256GcmSha384 => {
            rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384
        }
        TlsCipherSuite::Tls13Chacha20Poly1305Sha256 => {
            rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
        }
        TlsCipherSuite::Tls13Aes128GcmSha256 => {
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        }
        TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256 => {
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        }
        TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256 => {
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        }
        TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384 => {
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        }
        TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384 => {
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        }
        TlsCipherSuite::TlsEcdheEcdsaWithChacha20Poly1305Sha256 => {
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        }
        TlsCipherSuite::TlsEcdheRsaWithChacha20Poly1305Sha256 => {
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        }
    }
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
fn rustls_kx_group(
    curve: TlsCurvePreference,
) -> Result<&'static dyn rustls::crypto::SupportedKxGroup, Box<dyn Error + Send + Sync>> {
    match curve {
        TlsCurvePreference::X25519 => Ok(rustls::crypto::ring::kx_group::X25519),
        TlsCurvePreference::P256 => Ok(rustls::crypto::ring::kx_group::SECP256R1),
        TlsCurvePreference::P384 => Ok(rustls::crypto::ring::kx_group::SECP384R1),
        TlsCurvePreference::X25519MlKem768 => {
            Err("X25519MLKEM768 is not available with the default rustls/ring backend".into())
        }
    }
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
    Ok(())
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-boringssl",
    not(feature = "tls-openssl")
))]
fn apply_tls_policy(
    settings: &mut pingora::listeners::tls::TlsSettings,
    tls: &TlsConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    settings.set_alpn(tls_alpn_policy(tls.effective_alpn()));
    settings.set_curves_list(&openssl_curve_list(&tls.effective_curve_preferences()))?;
    let (tls12_ciphers, _tls13_ciphers) = openssl_cipher_lists(&tls.effective_cipher_suites());
    if !tls12_ciphers.is_empty() {
        settings.set_cipher_list(&tls12_ciphers)?;
    }
    let min_version = match tls.effective_min_protocol() {
        TlsProtocolVersion::Tls12 => SslVersion::TLS1_2,
        TlsProtocolVersion::Tls13 => SslVersion::TLS1_3,
    };
    settings.set_min_proto_version(Some(min_version))?;
    Ok(())
}

#[cfg(all(
    feature = "proxy",
    any(feature = "tls-openssl", feature = "tls-boringssl")
))]
fn openssl_curve_list(curves: &[TlsCurvePreference]) -> String {
    curves
        .iter()
        .map(|curve| match curve {
            TlsCurvePreference::X25519 => "X25519",
            TlsCurvePreference::P256 => "P-256",
            TlsCurvePreference::P384 => "P-384",
            TlsCurvePreference::X25519MlKem768 => "X25519MLKEM768",
        })
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(all(
    feature = "proxy",
    any(feature = "tls-openssl", feature = "tls-boringssl")
))]
fn openssl_cipher_lists(ciphers: &[TlsCipherSuite]) -> (String, String) {
    let mut tls12 = Vec::new();
    let mut tls13 = Vec::new();
    for cipher in ciphers {
        match cipher {
            TlsCipherSuite::Tls13Aes256GcmSha384 => tls13.push("TLS_AES_256_GCM_SHA384"),
            TlsCipherSuite::Tls13Chacha20Poly1305Sha256 => {
                tls13.push("TLS_CHACHA20_POLY1305_SHA256");
            }
            TlsCipherSuite::Tls13Aes128GcmSha256 => tls13.push("TLS_AES_128_GCM_SHA256"),
            TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256 => {
                tls12.push("ECDHE-ECDSA-AES128-GCM-SHA256");
            }
            TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256 => {
                tls12.push("ECDHE-RSA-AES128-GCM-SHA256");
            }
            TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384 => {
                tls12.push("ECDHE-ECDSA-AES256-GCM-SHA384");
            }
            TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384 => {
                tls12.push("ECDHE-RSA-AES256-GCM-SHA384");
            }
            TlsCipherSuite::TlsEcdheEcdsaWithChacha20Poly1305Sha256 => {
                tls12.push("ECDHE-ECDSA-CHACHA20-POLY1305");
            }
            TlsCipherSuite::TlsEcdheRsaWithChacha20Poly1305Sha256 => {
                tls12.push("ECDHE-RSA-CHACHA20-POLY1305");
            }
        }
    }
    (tls12.join(":"), tls13.join(":"))
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-s2n",
    not(any(
        feature = "tls-rustls",
        feature = "tls-openssl",
        feature = "tls-boringssl"
    ))
))]
fn apply_tls_policy(
    settings: &mut pingora::listeners::tls::TlsSettings,
    tls: &TlsConfig,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug_assert_eq!(tls.effective_alpn(), TlsAlpnPolicy::Http1AndHttp2);
    debug_assert_eq!(tls.effective_min_protocol(), TlsProtocolVersion::Tls12);
    settings.enable_h2();
    Ok(())
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(feature = "acme-client"), allow(dead_code))]
#[derive(Clone)]
enum DownstreamCertificateReloader {
    #[cfg(all(
        feature = "tls-rustls",
        not(any(feature = "tls-openssl", feature = "tls-boringssl"))
    ))]
    Rustls(std::sync::Arc<RustlsSniCertificateResolver>),
    #[cfg(any(feature = "tls-openssl", feature = "tls-boringssl"))]
    Openssl(std::sync::Arc<SniCertificateCallback>),
}

#[cfg(feature = "proxy")]
#[cfg_attr(not(feature = "acme-client"), allow(dead_code))]
impl DownstreamCertificateReloader {
    #[cfg_attr(not(feature = "acme-client"), allow(dead_code))]
    fn reload(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        match self {
            #[cfg(all(
                feature = "tls-rustls",
                not(any(feature = "tls-openssl", feature = "tls-boringssl"))
            ))]
            Self::Rustls(resolver) => resolver.reload(),
            #[cfg(any(feature = "tls-openssl", feature = "tls-boringssl"))]
            Self::Openssl(callback) => callback.reload(),
            #[cfg(not(any(
                all(
                    feature = "tls-rustls",
                    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
                ),
                feature = "tls-openssl",
                feature = "tls-boringssl"
            )))]
            _ => Ok(()),
        }
    }
}

#[cfg(all(
    feature = "proxy",
    any(feature = "tls-openssl", feature = "tls-boringssl")
))]
fn add_downstream_tls_listeners<S>(
    service: &mut pingora::services::listening::Service<S>,
    listens: &[String],
    selector: &crate::tls::DownstreamCertificateSelector,
    tls: &TlsConfig,
) -> Result<Option<DownstreamCertificateReloader>, Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    if selector.has_sni_certificates() {
        let callback = std::sync::Arc::new(SniCertificateCallback::new(selector)?);
        for listen in listens {
            log::info!("proxy TLS listener enabled on {listen}");
            let mut settings = pingora::listeners::tls::TlsSettings::with_callbacks(Box::new(
                SharedSniCertificateCallback {
                    inner: callback.clone(),
                },
            ))?;
            apply_tls_policy(&mut settings, tls)?;
            service.add_tls_with_settings(listen, None, settings);
        }
        return Ok(Some(DownstreamCertificateReloader::Openssl(callback)));
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
    feature = "tls-rustls",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
fn add_downstream_tls_listeners<S>(
    service: &mut pingora::services::listening::Service<S>,
    listens: &[String],
    selector: &crate::tls::DownstreamCertificateSelector,
    tls: &TlsConfig,
) -> Result<Option<DownstreamCertificateReloader>, Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    if selector.has_sni_certificates() || rustls_acme_tls_alpn_enabled(tls) {
        let resolver = std::sync::Arc::new(RustlsSniCertificateResolver::new(selector, tls)?);
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
    feature = "tls-s2n",
    not(any(
        feature = "tls-rustls",
        feature = "tls-openssl",
        feature = "tls-boringssl"
    ))
))]
fn add_downstream_tls_listeners<S>(
    service: &mut pingora::services::listening::Service<S>,
    listens: &[String],
    selector: &crate::tls::DownstreamCertificateSelector,
    tls: &TlsConfig,
) -> Result<Option<DownstreamCertificateReloader>, Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    if selector.has_sni_certificates() {
        return Err(
            "vhost TLS certificates require a TLS backend with SNI certificate selection support"
                .into(),
        );
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
    feature = "tls-rustls",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
struct RustlsSniCertificateResolver {
    selector: crate::tls::DownstreamCertificateSelector,
    certificates: arc_swap::ArcSwap<Vec<std::sync::Arc<rustls::sign::CertifiedKey>>>,
    #[cfg(feature = "acme")]
    tls_alpn_01_store: Option<crate::acme::AcmeTlsAlpn01ChallengeStore>,
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
impl std::fmt::Debug for RustlsSniCertificateResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RustlsSniCertificateResolver")
            .field("certificate_count", &self.certificates.load().len())
            .finish_non_exhaustive()
    }
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
impl RustlsSniCertificateResolver {
    fn new(
        selector: &crate::tls::DownstreamCertificateSelector,
        tls: &TlsConfig,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        #[cfg(not(feature = "acme"))]
        let _ = tls;
        let mut certificates = Vec::with_capacity(selector.certificates().len());
        for certificate in selector.certificates() {
            certificates.push(std::sync::Arc::new(load_rustls_certified_key(certificate)?));
        }
        #[cfg(feature = "acme")]
        let tls_alpn_01_store = if rustls_acme_tls_alpn_enabled(tls) {
            tls.acme
                .storage
                .as_deref()
                .map(crate::acme::AcmeTlsAlpn01ChallengeStore::new)
        } else {
            None
        };

        Ok(Self {
            selector: selector.clone(),
            certificates: arc_swap::ArcSwap::from_pointee(certificates),
            #[cfg(feature = "acme")]
            tls_alpn_01_store,
        })
    }

    #[cfg_attr(not(feature = "acme-client"), allow(dead_code))]
    fn reload(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut certificates = Vec::with_capacity(self.selector.certificates().len());
        for certificate in self.selector.certificates() {
            certificates.push(std::sync::Arc::new(load_rustls_certified_key(certificate)?));
        }
        self.certificates.store(std::sync::Arc::new(certificates));
        Ok(())
    }
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
impl rustls::server::ResolvesServerCert for RustlsSniCertificateResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        #[cfg(feature = "acme")]
        if rustls_client_hello_requests_acme_tls_alpn(&client_hello) {
            return self.load_acme_tls_alpn_challenge(client_hello.server_name());
        }

        let index = self
            .selector
            .certificate_index_for_sni(client_hello.server_name());
        self.certificates.load().get(index).cloned()
    }
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
fn rustls_acme_tls_alpn_enabled(tls: &TlsConfig) -> bool {
    #[cfg(feature = "acme")]
    {
        tls.acme.enabled && tls.acme.challenge == AcmeChallenge::TlsAlpn01
    }
    #[cfg(not(feature = "acme"))]
    {
        let _ = tls;
        false
    }
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls",
    feature = "acme",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
fn rustls_client_hello_requests_acme_tls_alpn(
    client_hello: &rustls::server::ClientHello<'_>,
) -> bool {
    client_hello.alpn().is_some_and(|mut protocols| {
        protocols.any(|protocol| protocol == crate::acme::acme_tls_alpn_protocol())
    })
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls",
    feature = "acme",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
impl RustlsSniCertificateResolver {
    fn load_acme_tls_alpn_challenge(
        &self,
        sni: Option<&str>,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        let store = self.tls_alpn_01_store.as_ref()?;
        let paths = store.certificate_paths_for_sni(sni?)?;
        match load_rustls_certified_key_from_paths(&paths.cert_path, &paths.key_path) {
            Ok(certificate) => Some(std::sync::Arc::new(certificate)),
            Err(error) => {
                log::warn!("failed to load ACME TLS-ALPN-01 challenge certificate: {error}");
                None
            }
        }
    }
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
fn load_rustls_certified_key(
    certificate: &crate::config::StaticCertificateConfig,
) -> Result<rustls::sign::CertifiedKey, Box<dyn Error + Send + Sync>> {
    let (cert_path, key_path) = downstream_certificate_paths(certificate)?;
    load_rustls_certified_key_from_paths(Path::new(cert_path), Path::new(key_path))
}

#[cfg(all(
    feature = "proxy",
    feature = "tls-rustls",
    not(any(feature = "tls-openssl", feature = "tls-boringssl"))
))]
fn load_rustls_certified_key_from_paths(
    cert_path: &Path,
    key_path: &Path,
) -> Result<rustls::sign::CertifiedKey, Box<dyn Error + Send + Sync>> {
    let cert_path = cert_path
        .to_str()
        .ok_or("TLS certificate path must be valid UTF-8")?;
    let key_path = key_path
        .to_str()
        .ok_or("TLS private-key path must be valid UTF-8")?;
    let Some((certs, key)) = pingora::tls::load_certs_and_key_files(cert_path, key_path)? else {
        return Err("TLS certificate chain and private key must be readable PEM files".into());
    };

    let provider = rustls::crypto::ring::default_provider();
    let certified_key = rustls::sign::CertifiedKey::from_der(certs, key, &provider)?;
    Ok(certified_key)
}

#[cfg(all(
    feature = "proxy",
    any(feature = "tls-openssl", feature = "tls-boringssl")
))]
struct SniCertificateCallback {
    selector: crate::tls::DownstreamCertificateSelector,
    certificates: arc_swap::ArcSwap<Vec<CallbackCertificate>>,
}

#[cfg(all(
    feature = "proxy",
    any(feature = "tls-openssl", feature = "tls-boringssl")
))]
impl SniCertificateCallback {
    fn new(
        selector: &crate::tls::DownstreamCertificateSelector,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut certificates = Vec::with_capacity(selector.certificates().len());
        for certificate in selector.certificates() {
            let (cert_path, key_path) = downstream_certificate_paths(certificate)?;
            certificates.push(CallbackCertificate::load(cert_path, key_path)?);
        }

        Ok(Self {
            selector: selector.clone(),
            certificates: arc_swap::ArcSwap::from_pointee(certificates),
        })
    }

    fn reload(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut certificates = Vec::with_capacity(self.selector.certificates().len());
        for certificate in self.selector.certificates() {
            let (cert_path, key_path) = downstream_certificate_paths(certificate)?;
            certificates.push(CallbackCertificate::load(cert_path, key_path)?);
        }
        self.certificates.store(std::sync::Arc::new(certificates));
        Ok(())
    }
}

#[cfg(all(
    feature = "proxy",
    any(feature = "tls-openssl", feature = "tls-boringssl")
))]
struct SharedSniCertificateCallback {
    inner: std::sync::Arc<SniCertificateCallback>,
}

#[cfg(all(
    feature = "proxy",
    any(feature = "tls-openssl", feature = "tls-boringssl")
))]
#[async_trait::async_trait]
impl pingora::listeners::TlsAccept for SniCertificateCallback {
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        let sni = ssl.servername(pingora::tls::ssl::NameType::HOST_NAME);
        let index = self.selector.certificate_index_for_sni(sni);
        let certificates = self.certificates.load();
        let Some(certificate) = certificates.get(index) else {
            log::error!("downstream SNI certificate index {index} was not loaded");
            return;
        };
        if let Err(error) = certificate.apply_to_ssl(ssl) {
            log::error!("failed to set downstream SNI certificate: {error}");
        }
    }
}

#[cfg(all(
    feature = "proxy",
    any(feature = "tls-openssl", feature = "tls-boringssl")
))]
#[async_trait::async_trait]
impl pingora::listeners::TlsAccept for SharedSniCertificateCallback {
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        self.inner.certificate_callback(ssl).await;
    }
}

#[cfg(all(
    feature = "proxy",
    any(feature = "tls-openssl", feature = "tls-boringssl")
))]
struct CallbackCertificate {
    chain: Vec<X509>,
    private_key: PKey<Private>,
}

#[cfg(all(
    feature = "proxy",
    any(feature = "tls-openssl", feature = "tls-boringssl")
))]
impl CallbackCertificate {
    fn load(cert_path: &str, key_path: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let cert_bytes = std::fs::read(cert_path)?;
        let chain = X509::stack_from_pem(&cert_bytes)?;
        if chain.is_empty() {
            return Err("TLS certificate chain must contain at least one certificate".into());
        }

        let key_bytes = std::fs::read(key_path)?;
        let private_key = PKey::private_key_from_pem(&key_bytes)?;

        Ok(Self { chain, private_key })
    }

    #[cfg(all(feature = "tls-openssl", not(feature = "tls-boringssl")))]
    fn apply_to_ssl(
        &self,
        ssl: &mut pingora::tls::ssl::SslRef,
    ) -> Result<(), pingora::tls::error::ErrorStack> {
        let Some((leaf, chain)) = self.chain.split_first() else {
            log::error!("TLS callback certificate chain unexpectedly empty");
            return Ok(());
        };
        ssl.set_certificate(leaf)?;
        ssl.set_private_key(&self.private_key)?;
        for certificate in chain {
            ssl.add_chain_cert(certificate.clone())?;
        }
        Ok(())
    }

    #[cfg(feature = "tls-boringssl")]
    fn apply_to_ssl(
        &self,
        ssl: &mut pingora::tls::ssl::SslRef,
    ) -> Result<(), pingora::tls::error::ErrorStack> {
        let Some((leaf, chain)) = self.chain.split_first() else {
            log::error!("TLS callback certificate chain unexpectedly empty");
            return Ok(());
        };
        ssl.set_certificate(leaf)?;
        ssl.set_private_key(&self.private_key)?;
        for certificate in chain {
            ssl.add_chain_cert(certificate)?;
        }
        Ok(())
    }
}

#[cfg(all(
    feature = "proxy",
    any(
        feature = "tls-rustls",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    )
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
    not(any(
        feature = "tls-rustls",
        feature = "tls-openssl",
        feature = "tls-boringssl",
        feature = "tls-s2n"
    ))
))]
fn add_tls_listeners<S>(
    _service: &mut pingora::services::listening::Service<S>,
    config: &Config,
) -> Result<Option<DownstreamCertificateReloader>, Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    if config.server.tls_listen.is_empty() {
        Ok(None)
    } else {
        Err("server.tls_listen requires a TLS feature".into())
    }
}

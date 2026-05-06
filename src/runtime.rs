use std::error::Error;
#[cfg(feature = "proxy")]
use std::fs::{File, OpenOptions};
#[cfg(feature = "proxy")]
use std::io::Write;
#[cfg(all(feature = "proxy", target_os = "linux"))]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(feature = "proxy")]
use std::path::Path;

use crate::config::Config;
#[cfg(feature = "proxy")]
use crate::config::{LoggingFormat, LoggingTarget};

#[cfg(feature = "proxy")]
pub fn run(config: Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    init_logging(&config)?;

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

    for listen in &config.server.listen {
        log::info!("proxy listener enabled on {listen}");
        proxy_service.add_tcp(listen);
    }
    add_tls_listeners(&mut proxy_service, &config)?;

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
        let mut metrics_service = pingora::services::listening::Service::prometheus_http_service();
        log::info!("metrics listener enabled on {}", config.metrics.listen);
        metrics_service.add_tcp(&config.metrics.listen);
        server.add_service(metrics_service);
    }

    server.add_service(proxy_service);
    server.run_forever();
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
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    if config.server.tls_listen.is_empty() {
        return Ok(());
    }
    if !config.tls.enabled {
        return Err("server.tls_listen requires tls.enabled = true".into());
    }

    let Some(certificate) = crate::tls::default_downstream_certificate(config) else {
        return Err("server.tls_listen requires at least one [[tls.certificates]] entry".into());
    };
    let cert_path = certificate
        .cert_path
        .to_str()
        .ok_or("TLS certificate path must be valid UTF-8 for Pingora")?;
    let key_path = certificate
        .key_path
        .to_str()
        .ok_or("TLS private key path must be valid UTF-8 for Pingora")?;

    for listen in &config.server.tls_listen {
        log::info!("proxy TLS listener enabled on {listen}");
        service.add_tls(listen, cert_path, key_path)?;
    }

    Ok(())
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
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    S: Send + Sync + 'static,
{
    if config.server.tls_listen.is_empty() {
        Ok(())
    } else {
        Err("server.tls_listen requires a TLS feature".into())
    }
}

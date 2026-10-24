use std::io::Write;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

#[path = "runtime_crash_log.rs"]
mod crash;
#[path = "runtime_log_dispatch.rs"]
mod dispatch;
#[path = "runtime_log_file.rs"]
mod file;
#[path = "runtime_log_record.rs"]
mod record;
pub(crate) use dispatch::Status as LoggingStatus;
#[cfg(test)]
pub(super) fn open_log_file(
    path: &std::path::Path,
    append: bool,
) -> std::io::Result<std::fs::File> {
    file::open(path, append)
}
static LEGACY: OnceLock<Arc<dispatch::Logger>> = OnceLock::new();
static FILE_STATUS: OnceLock<Arc<file::Counters>> = OnceLock::new();

pub(crate) fn status() -> Option<LoggingStatus> {
    LEGACY.get().map(|logger| {
        let mut status = logger.status();
        status.file_sink = FILE_STATUS.get().map(|counters| counters.status());
        status
    })
}

pub(super) struct ShutdownGuard;
impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        let start = Instant::now();
        fluxheim_observability::operational::shutdown(Duration::ZERO);
        if let Some(logger) = LEGACY.get() {
            logger.shutdown(Duration::from_millis(500));
        }
        fluxheim_observability::operational::shutdown(
            Duration::from_millis(500).saturating_sub(start.elapsed()),
        );
    }
}

pub(super) fn init_logging(
    config: &crate::config::Config,
) -> Result<ShutdownGuard, Box<dyn std::error::Error + Send + Sync>> {
    if LEGACY.get().is_some() {
        return Err(std::io::Error::other("runtime logging already initialized").into());
    }
    #[cfg(feature = "privacy-mode")]
    if config.logging.crash_file.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "privacy mode disallows crash-file logging",
        )
        .into());
    }
    let format = config.logging.format;
    let crash_file = config
        .logging
        .crash_file
        .as_deref()
        .map(crash::open)
        .transpose()?;

    let writers: [Box<dyn Write + Send>; 4] = if config.logging.file.enabled {
        let path = config.logging.file.path.as_deref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "logging.file.enabled requires logging.file.path",
            )
        })?;
        let file = file::Sink::new(path, config.logging.file.append, crash_file.as_ref())?;
        FILE_STATUS
            .set(file.counters()?)
            .map_err(|_| std::io::Error::other("file logging already initialized"))?;
        [
            Box::new(file.clone()) as Box<dyn Write + Send>,
            Box::new(file.clone()),
            Box::new(file.clone()),
            Box::new(file),
        ]
    } else {
        std::array::from_fn(|_| match config.logging.target {
            crate::config::LoggingTarget::Stdout => {
                Box::new(std::io::stdout()) as Box<dyn Write + Send>
            }
            crate::config::LoggingTarget::Stderr => {
                Box::new(std::io::stderr()) as Box<dyn Write + Send>
            }
        })
    };
    fluxheim_common::fatal::start_watchdog()?;
    if let Some(file) = crash_file {
        fluxheim_common::fatal::install(file)?;
    }
    let [ordinary, security, audit, legacy_writer] = writers;
    let legacy = Arc::new(dispatch::Logger::new(
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or(config.logging.level.as_filter()),
        )
        .build(),
        format,
        legacy_writer,
    )?);
    LEGACY
        .set(legacy.clone())
        .map_err(|_| std::io::Error::other("runtime logging already initialized"))?;
    let guard = ShutdownGuard;

    // The separate matcher preserves env_logger target/level/regex semantics,
    // but only inspects a fixed message and never reaches its output target.
    let matcher = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(config.logging.level.as_filter()),
    )
    .build();
    let filter = std::sync::Arc::new(move |data: fluxheim_observability::event::EventData| {
        matcher.matches(
            &log::Record::builder()
                .target(data.target())
                .level(data.level())
                .args(format_args!("{}", data.message()))
                .build(),
        )
    });
    let format = match format {
        crate::config::LoggingFormat::Json => fluxheim_observability::event::EventFormat::Json,
        crate::config::LoggingFormat::Text => fluxheim_observability::event::EventFormat::Text,
    };
    fluxheim_observability::operational::install(
        fluxheim_observability::operational::Dispatcher::new(
            format,
            filter,
            [ordinary, security, audit],
        )?,
    )
    .map_err(std::io::Error::other)?;
    let max_level = legacy.max_level();
    log::set_boxed_logger(Box::new(legacy))
        .map_err(|_| std::io::Error::other("another process logger is already installed"))?;
    log::set_max_level(max_level);
    Ok(guard)
}

#[cfg(test)]
pub(super) fn log_record_json(timestamp: &str, level: &str, target: &str, message: &str) -> String {
    format!(
        "{{\"timestamp\":\"{}\",\"level\":\"{}\",\"target\":\"{}\",\"message\":\"{}\"}}",
        fluxheim_observability::json_escape(timestamp),
        fluxheim_observability::json_escape(level),
        fluxheim_observability::json_escape(target),
        fluxheim_observability::json_escape(message),
    )
}

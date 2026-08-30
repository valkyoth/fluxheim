use std::fs::File;
use std::io::Write;
use std::path::Path;

pub(super) fn init_logging(
    config: &crate::config::Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let env = env_logger::Env::default().default_filter_or(config.logging.level.as_filter());
    let format = config.logging.format;
    let mut builder = env_logger::Builder::from_env(env);
    builder.format(move |buf, record| match format {
        crate::config::LoggingFormat::Json => write_json_log_record(buf, record),
        crate::config::LoggingFormat::Text => write_text_log_record(buf, record),
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
            crate::config::LoggingTarget::Stdout => env_logger::Target::Stdout,
            crate::config::LoggingTarget::Stderr => env_logger::Target::Stderr,
        });
    }

    let _ = builder.try_init();
    Ok(())
}

pub(super) fn open_log_file(path: &Path, append: bool) -> std::io::Result<File> {
    reject_log_path_symlink_prefix(path)?;

    #[cfg(windows)]
    {
        return open_log_file_windows(path, append);
    }

    #[cfg(unix)]
    {
        let mut flags =
            rustix::fs::OFlags::CREATE | rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC;
        if append {
            flags |= rustix::fs::OFlags::APPEND;
        } else {
            flags |= rustix::fs::OFlags::TRUNC;
        }

        flags |= rustix::fs::OFlags::NOFOLLOW;

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
}

#[cfg(windows)]
fn open_log_file_windows(path: &Path, append: bool) -> std::io::Result<File> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    };

    if fluxheim_config::fs_trust::existing_parent_has_insecure_write_permissions(path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "log path has an untrusted owner or writable parent component",
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .security_qos_flags(SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("log path is not a regular file: {}", path.display()),
        ));
    }
    let path_handle = same_file::Handle::from_path(path)?;
    let opened_handle = same_file::Handle::from_file(file.try_clone()?)?;
    if path_handle != opened_handle {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "log path changed during secure open",
        ));
    }
    Ok(file)
}

fn reject_log_path_symlink_prefix(path: &Path) -> std::io::Result<()> {
    if fluxheim_config::config_path::path_existing_prefix_contains_symlink(path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("log path contains symlink component: {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn rustix_to_io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

pub(super) fn write_text_log_record(
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

pub(super) fn write_json_log_record(
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

pub(super) fn log_record_json(timestamp: &str, level: &str, target: &str, message: &str) -> String {
    format!(
        "{{\"timestamp\":\"{}\",\"level\":\"{}\",\"target\":\"{}\",\"message\":\"{}\"}}",
        fluxheim_observability::json_escape(timestamp),
        fluxheim_observability::json_escape(level),
        fluxheim_observability::json_escape(target),
        fluxheim_observability::json_escape(message),
    )
}

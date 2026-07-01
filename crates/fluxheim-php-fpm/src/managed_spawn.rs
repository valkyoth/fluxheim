use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::managed_config::managed_php_fpm_path_env_from;
use crate::request_body::{
    create_php_request_body_spool_dir_sync, ensure_php_request_body_spool_dir,
};

pub fn ensure_managed_php_fpm_binary_spawn_safe(scope: &str, binary: &Path) -> io::Result<()> {
    if binary.as_os_str().is_empty() || !binary.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{scope}: managed php-fpm binary {} must be an absolute path",
                binary.display()
            ),
        ));
    }
    if binary
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{scope}: managed php-fpm binary {} contains parent traversal",
                binary.display()
            ),
        ));
    }
    if existing_php_fpm_path_prefix_contains_symlink(binary)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{scope}: managed php-fpm binary {} must not be or be below a symlink",
                binary.display()
            ),
        ));
    }
    if existing_php_fpm_parent_has_insecure_write_permissions(binary)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{scope}: managed php-fpm binary {} is below a group/world-writable parent",
                binary.display()
            ),
        ));
    }
    let metadata = std::fs::symlink_metadata(binary).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "{scope}: failed to inspect managed php-fpm binary {} before spawn: {error}",
                binary.display()
            ),
        )
    })?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{scope}: managed php-fpm binary {} must point directly to a regular file",
                binary.display()
            ),
        ));
    }
    Ok(())
}

fn existing_php_fpm_path_prefix_contains_symlink(path: &Path) -> io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn existing_php_fpm_parent_has_insecure_write_permissions(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    let mut current = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    loop {
        match std::fs::metadata(&current) {
            Ok(metadata) => return Ok(metadata.permissions().mode() & 0o022 != 0),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !current.pop() {
                    return Ok(false);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn managed_php_fpm_path_env() -> String {
    managed_php_fpm_path_env_from(std::env::var("PATH").ok())
}

pub(super) fn write_managed_php_fpm_config_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Write;

    let file = rustix::fs::openat(
        rustix::fs::CWD,
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(io::Error::from)?;
    let mut file = std::fs::File::from(file);
    file.write_all(contents)?;
    file.sync_all()
}

pub(super) fn ensure_managed_php_fpm_directory(
    scope: &str,
    field: &str,
    path: Option<&Path>,
) -> io::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    create_php_request_body_spool_dir_sync(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "{scope}: failed to create managed php-fpm {field} {}: {error}",
                path.display()
            ),
        )
    })?;
    ensure_php_request_body_spool_dir(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "{scope}: managed php-fpm {field} {} is unsafe: {error}",
                path.display()
            ),
        )
    })
}

pub(super) fn wait_for_managed_php_fpm_socket(
    child: &mut std::process::Child,
    socket: &Path,
    connect_timeout_secs: Option<u64>,
    shutdown: Option<&AtomicBool>,
) -> io::Result<()> {
    let deadline =
        Instant::now() + Duration::from_secs(connect_timeout_secs.unwrap_or(5).clamp(1, 60));
    loop {
        if shutdown.is_some_and(|shutdown| shutdown.load(Ordering::Acquire)) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "managed php-fpm shutdown requested",
            ));
        }
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!(
                "php-fpm exited before creating socket with status {status}"
            )));
        }
        let error = match std::os::unix::net::UnixStream::connect(socket) {
            Ok(_) => return Ok(()),
            Err(error) => error,
        };
        if Instant::now() >= deadline {
            return Err(error);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

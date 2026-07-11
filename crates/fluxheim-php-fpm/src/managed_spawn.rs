use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::managed_config::managed_php_fpm_path_env_from;
use crate::request_body::{
    create_php_request_body_spool_dir_sync, ensure_php_request_body_spool_dir,
};

pub(super) struct ManagedPhpFpmExecutable {
    file: std::fs::File,
}

pub fn ensure_managed_php_fpm_binary_spawn_safe(scope: &str, binary: &Path) -> io::Result<()> {
    open_managed_php_fpm_executable(scope, binary).map(|_| ())
}

pub(super) fn open_managed_php_fpm_executable(
    scope: &str,
    binary: &Path,
) -> io::Result<ManagedPhpFpmExecutable> {
    use rustix::fs::{Mode, OFlags};

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
    let file = rustix::fs::openat(
        rustix::fs::CWD,
        binary,
        OFlags::RDONLY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        io::Error::new(
            io::Error::from(error).kind(),
            format!(
                "{scope}: failed to open managed php-fpm binary {} safely: {error}",
                binary.display()
            ),
        )
    })?;
    let stat = rustix::fs::fstat(&file).map_err(io::Error::from)?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file()
        || (stat.st_uid != 0 && stat.st_uid != effective_uid)
        || stat.st_mode & 0o022 != 0
        || stat.st_mode & 0o111 == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{scope}: managed php-fpm binary {} has an untrusted owner or mode",
                binary.display()
            ),
        ));
    }
    let parent = binary.parent().unwrap_or_else(|| Path::new("/"));
    if fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(parent)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{scope}: managed php-fpm binary {} is below an untrusted or group/world-writable ancestor",
                binary.display()
            ),
        ));
    }
    Ok(ManagedPhpFpmExecutable {
        file: std::fs::File::from(file),
    })
}

impl ManagedPhpFpmExecutable {
    pub(super) fn command(&self) -> std::process::Command {
        use std::os::fd::AsRawFd as _;

        #[cfg(target_os = "linux")]
        let path = format!("/proc/self/fd/{}", self.file.as_raw_fd());
        #[cfg(not(target_os = "linux"))]
        let path = format!("/dev/fd/{}", self.file.as_raw_fd());
        std::process::Command::new(path)
    }
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

pub(super) fn managed_php_fpm_path_env() -> String {
    managed_php_fpm_path_env_from(None)
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::ManagedPhpFpmExecutable;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn retained_executable_descriptor_survives_path_replacement() {
        use rustix::fs::{Mode, OFlags};

        let root = tempfile::TempDir::new().expect("temp dir");
        let binary = root.path().join("php-fpm");
        let moved = root.path().join("php-fpm.original");
        std::fs::copy("/usr/bin/true", &binary).expect("copy original executable");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
            .expect("set executable mode");
        let file = rustix::fs::openat(
            rustix::fs::CWD,
            &binary,
            OFlags::RDONLY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("open executable descriptor");
        let executable = ManagedPhpFpmExecutable {
            file: std::fs::File::from(file),
        };
        std::fs::rename(&binary, &moved).expect("move original executable");
        std::fs::copy("/usr/bin/false", &binary).expect("copy replacement executable");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
            .expect("set replacement mode");

        let retained_metadata = executable.file.metadata().expect("retained metadata");
        let replacement_metadata = std::fs::metadata(&binary).expect("replacement metadata");
        let command = executable.command();
        let command_path = command.get_program().to_string_lossy();

        assert_ne!(retained_metadata.ino(), replacement_metadata.ino());
        assert!(command_path.starts_with("/proc/self/fd/"));
    }
}

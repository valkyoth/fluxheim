use std::env;

use std::error::Error;

use std::fs;

use std::io::Read;

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::config::AdminConfig;

use super::{MAX_ADMIN_TOKEN_BYTES, MAX_ADMIN_TOKEN_FILE_BYTES};

pub(in crate::admin) fn load_admin_token(
    config: &AdminConfig,
) -> Result<Zeroizing<String>, Box<dyn Error + Send + Sync>> {
    let raw = match (&config.token_env, &config.token_file) {
        (Some(env_name), None) => Zeroizing::new(
            env::var(env_name)
                .map_err(|error| format!("failed to read admin token env {env_name:?}: {error}"))?,
        ),
        (None, Some(path)) => read_secret_file(path)?,
        _ => return Err("admin token source is invalid".into()),
    };
    let token = Zeroizing::new(raw.trim().to_owned());
    if token.is_empty() {
        Err("admin token cannot be empty".into())
    } else if token.len() > MAX_ADMIN_TOKEN_BYTES {
        Err(format!("admin token cannot exceed {MAX_ADMIN_TOKEN_BYTES} bytes").into())
    } else {
        Ok(token)
    }
}

pub(in crate::admin) fn read_secret_file(
    path: &Path,
) -> Result<Zeroizing<String>, Box<dyn Error + Send + Sync>> {
    if secret_parent_path_contains_symlink(path).map_err(|error| {
        format!(
            "failed to inspect admin token parent path {}: {error}",
            path.display()
        )
    })? {
        return Err(format!(
            "admin token file {} must not be below a symlinked directory",
            path.display()
        )
        .into());
    }

    #[cfg(unix)]
    if fluxheim_config::fs_trust::existing_parent_has_insecure_write_permissions(path).map_err(
        |error| {
            format!(
                "failed to inspect admin token parent path {}: {error}",
                path.display()
            )
        },
    )? {
        return Err(format!(
            "admin token file {} must not be below a group- or world-writable directory",
            path.display()
        )
        .into());
    }

    let file = open_regular_secret_file(path)?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "failed to inspect admin token file {}: {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!("admin token file {} must be a regular file", path.display()).into());
    }
    if metadata.len() > MAX_ADMIN_TOKEN_FILE_BYTES {
        return Err(format!(
            "admin token file {} is too large; limit is {MAX_ADMIN_TOKEN_FILE_BYTES} bytes",
            path.display()
        )
        .into());
    }

    read_bounded_secret_file(file, path, MAX_ADMIN_TOKEN_FILE_BYTES)
}

pub(in crate::admin) fn read_bounded_secret_file(
    file: fs::File,
    path: &Path,
    max_bytes: u64,
) -> Result<Zeroizing<String>, Box<dyn Error + Send + Sync>> {
    let mut token = Zeroizing::new(String::new());
    let mut limited = file.take(max_bytes.saturating_add(1));
    limited.read_to_string(&mut token).map_err(|error| {
        format!(
            "failed to read admin token file {}: {error}",
            path.display()
        )
    })?;
    if token.len() as u64 > max_bytes {
        return Err(format!(
            "admin token file {} changed while reading and exceeded {max_bytes} bytes",
            path.display(),
        )
        .into());
    }
    Ok(token)
}

fn secret_parent_path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let Some(parent) = path.parent() else {
        return Ok(false);
    };
    if parent.as_os_str().is_empty() {
        return Ok(false);
    }

    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

#[cfg(unix)]
fn open_regular_secret_file(path: &Path) -> Result<fs::File, Box<dyn Error + Send + Sync>> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(rustix_to_io_error)
    .map_err(|error| {
        format!(
            "failed to open admin token file {} without following symlinks: {error}",
            path.display()
        )
    })?;
    Ok(fd.into())
}

#[cfg(unix)]
fn rustix_to_io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(not(unix))]
fn open_regular_secret_file(path: &Path) -> Result<fs::File, Box<dyn Error + Send + Sync>> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect admin token file {}: {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!("admin token file {} must be a regular file", path.display()).into());
    }

    fs::File::open(path).map_err(|error| {
        format!(
            "failed to open admin token file {}: {error}",
            path.display()
        )
        .into()
    })
}

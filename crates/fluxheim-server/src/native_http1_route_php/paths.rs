use std::io;
use std::path::{Path, PathBuf};

pub(super) fn native_php_root(
    scope: &str,
    config: &fluxheim_config::PhpConfig,
) -> io::Result<PathBuf> {
    let configured_root = config.root.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{scope}: enabled PHP requires php.root"),
        )
    })?;
    let root_metadata = std::fs::symlink_metadata(configured_root).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{scope}: php root {}: {error}", configured_root.display()),
        )
    })?;
    if root_metadata.file_type().is_symlink() && !config.resolve_root_symlink {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{scope}: php root is not a real directory: {}",
                configured_root.display()
            ),
        ));
    }
    if !root_metadata.file_type().is_symlink() && !root_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{scope}: php root is not a real directory: {}",
                configured_root.display()
            ),
        ));
    }
    let root = configured_root.canonicalize().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{scope}: php root {}: {error}", configured_root.display()),
        )
    })?;
    let resolved_metadata = std::fs::metadata(&root).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{scope}: php root {}: {error}", root.display()),
        )
    })?;
    if !resolved_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{scope}: php root does not resolve to a directory: {}",
                configured_root.display()
            ),
        ));
    }
    Ok(root)
}

pub(super) fn native_php_fpm_root(
    scope: &str,
    config: &fluxheim_config::PhpConfig,
    root: &Path,
) -> io::Result<PathBuf> {
    let Some(configured_fpm_root) = &config.fpm_root else {
        return Ok(root.to_path_buf());
    };
    match configured_fpm_root.canonicalize() {
        Ok(resolved) => Ok(resolved),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(configured_fpm_root.clone()),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!(
                "{scope}: php fpm_root {}: {error}",
                configured_fpm_root.display()
            ),
        )),
    }
}

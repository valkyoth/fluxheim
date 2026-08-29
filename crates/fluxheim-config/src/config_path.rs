use std::path::Component;
use std::path::{Path, PathBuf};

use crate::config::ConfigError;

pub fn validate_path(field: impl Into<String>, path: Option<&Path>) -> Result<(), ConfigError> {
    let field = field.into();
    let Some(path) = path else {
        return Ok(());
    };

    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ConfigError::UnsafePath {
            field,
            path: path.to_path_buf(),
        });
    }

    match path_existing_prefix_contains_symlink(path) {
        Ok(true) => {
            return Err(ConfigError::UnsafePath {
                field,
                path: path.to_path_buf(),
            });
        }
        Ok(false) => {}
        Err(error) => {
            return Err(path_inspection_failed(field, path, error));
        }
    }

    Ok(())
}

pub fn validate_non_world_writable_parent(
    field: impl Into<String>,
    path: Option<&Path>,
) -> Result<(), ConfigError> {
    let field = field.into();
    let Some(path) = path else {
        return Ok(());
    };

    #[cfg(any(unix, windows))]
    match crate::fs_trust::existing_parent_has_insecure_write_permissions(path) {
        Ok(true) => {
            return Err(ConfigError::UnsafePath {
                field,
                path: path.to_path_buf(),
            });
        }
        Ok(false) => {}
        Err(error) => {
            return Err(path_inspection_failed(field, path, error));
        }
    }

    #[cfg(not(any(unix, windows)))]
    let _ = (field, path);

    Ok(())
}

pub fn validate_private_state_directory(
    field: impl Into<String>,
    path: Option<&Path>,
) -> Result<(), ConfigError> {
    let field = field.into();
    let Some(path) = path else {
        return Ok(());
    };
    if path_is_filesystem_root(path) {
        return Err(ConfigError::UnsafePath {
            field,
            path: path.to_path_buf(),
        });
    }

    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(path_inspection_failed(field, path, error)),
    };
    if metadata_is_link_like(&metadata) || !metadata.is_dir() {
        return Err(ConfigError::UnsafePath {
            field,
            path: path.to_path_buf(),
        });
    }
    #[cfg(windows)]
    match crate::fs_trust::existing_path_or_parent_has_insecure_write_permissions(path) {
        Ok(true) => {
            return Err(ConfigError::UnsafePath {
                field,
                path: path.to_path_buf(),
            });
        }
        Ok(false) => {}
        Err(error) => return Err(path_inspection_failed(field, path, error)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::UnsafePath {
                field,
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

fn path_is_filesystem_root(path: &Path) -> bool {
    let mut components = path.components();
    match components.next() {
        Some(Component::RootDir) => components.next().is_none(),
        Some(Component::Prefix(_)) => {
            matches!(components.next(), Some(Component::RootDir)) && components.next().is_none()
        }
        _ => false,
    }
}

pub fn validate_optional_process_path(
    field: &'static str,
    path: Option<&Path>,
) -> Result<(), ConfigError> {
    if let Some(path) = path {
        validate_required_process_path(field, path)?;
    }
    Ok(())
}

pub fn validate_required_process_path(field: &'static str, path: &Path) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::EmptyProcessPath { field });
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ConfigError::UnsafePath {
            field: field.to_owned(),
            path: path.to_path_buf(),
        });
    }
    match path_existing_prefix_contains_symlink(path) {
        Ok(true) => {
            return Err(ConfigError::UnsafePath {
                field: field.to_owned(),
                path: path.to_path_buf(),
            });
        }
        Ok(false) => {}
        Err(error) => {
            return Err(path_inspection_failed(field, path, error));
        }
    }
    #[cfg(any(unix, windows))]
    match crate::fs_trust::existing_parent_has_insecure_write_permissions(path) {
        Ok(true) => {
            return Err(ConfigError::UnsafePath {
                field: field.to_owned(),
                path: path.to_path_buf(),
            });
        }
        Ok(false) => {}
        Err(error) => {
            return Err(path_inspection_failed(field, path, error));
        }
    }
    Ok(())
}

pub fn path_inspection_failed(
    field: impl Into<String>,
    path: &Path,
    error: std::io::Error,
) -> ConfigError {
    let reason = match error.kind() {
        std::io::ErrorKind::PermissionDenied => {
            format!("permission denied while checking path ownership and symlinks: {error}")
        }
        _ => format!("failed to check path ownership and symlinks: {error}"),
    };
    ConfigError::PathInspectionFailed {
        field: field.into(),
        path: path.to_path_buf(),
        reason,
    }
}

pub fn path_existing_prefix_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let mut current = PathBuf::new();

    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata_is_link_like(&metadata) => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

#[cfg(not(windows))]
fn metadata_is_link_like(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn metadata_is_link_like(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
}

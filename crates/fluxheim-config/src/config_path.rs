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

    #[cfg(unix)]
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

    #[cfg(not(unix))]
    let _ = (field, path);

    Ok(())
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
    #[cfg(unix)]
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
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

use std::fs;
use std::path::{Path, PathBuf};

use crate::config::{ConfigError, ProxyErrorPageConfig};
#[cfg(not(unix))]
use crate::config_path::validate_non_world_writable_parent;
use crate::config_path::{
    path_existing_prefix_contains_symlink, path_inspection_failed, validate_path,
};
use crate::config_route::validate_route_path;

pub const MAX_PHP_ERROR_PAGES: usize = 64;

pub(crate) fn validate_php_request_body_spool_dir(
    field: String,
    path: &Path,
) -> Result<(), ConfigError> {
    validate_path(field.clone(), Some(path))?;
    #[cfg(unix)]
    match crate::fs_trust::existing_path_or_parent_has_insecure_write_permissions(path) {
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
    validate_non_world_writable_parent(field.clone(), Some(path))?;

    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.request_body_spool_dir",
                reason: "must be a directory when it already exists",
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(path_inspection_failed(field, path, error));
        }
    }

    Ok(())
}

pub(crate) fn validate_php_error_pages(
    error_pages: &[ProxyErrorPageConfig],
) -> Result<(), ConfigError> {
    if error_pages.len() > MAX_PHP_ERROR_PAGES {
        return Err(ConfigError::InvalidPhpConfig {
            field: "php.error_pages",
            reason: "at most 64 error pages are allowed",
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for error_page in error_pages {
        if !(400..=599).contains(&error_page.status) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.error_pages.status",
                reason: "statuses must be HTTP error statuses from 400 through 599",
            });
        }
        validate_route_path("php.error_pages.path", &error_page.path, false).map_err(|_| {
            ConfigError::InvalidPhpConfig {
                field: "php.error_pages.path",
                reason: "must be an absolute internal request path",
            }
        })?;
        error_page.web.validate()?;
        if !error_page.web.enabled() {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.error_pages.web.root",
                reason: "is required for each PHP error page",
            });
        }
        if !seen.insert(error_page.status) {
            return Err(ConfigError::InvalidPhpConfig {
                field: "php.error_pages.status",
                reason: "duplicate statuses are not allowed",
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_php_root_path(
    field: String,
    path: &Path,
    allow_final_symlink: bool,
) -> Result<(), ConfigError> {
    if !allow_final_symlink {
        return validate_path(field, Some(path));
    }

    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ConfigError::UnsafePath {
            field,
            path: path.to_path_buf(),
        });
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        match path_existing_prefix_contains_symlink(parent) {
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
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let resolved = path
                .canonicalize()
                .map_err(|error| path_inspection_failed(field.clone(), path, error))?;
            validate_path(format!("{field}.resolved"), Some(&resolved))?;
        }
        Ok(_) => validate_path(field, Some(path))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(path_inspection_failed(field, path, error));
        }
    }

    Ok(())
}

pub(crate) fn php_root_resolved_path(
    field: String,
    path: &Path,
) -> Result<Option<PathBuf>, ConfigError> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(None);
    };
    if !metadata.file_type().is_symlink() {
        return Ok(None);
    }
    path.canonicalize()
        .map(Some)
        .map_err(|error| path_inspection_failed(field, path, error))
}

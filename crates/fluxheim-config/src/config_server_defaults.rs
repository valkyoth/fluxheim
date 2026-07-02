use std::path::PathBuf;

use crate::config::{ByteSize, ConfigError};

pub(crate) fn default_https_redirect_status() -> u16 {
    308
}

pub(crate) fn default_listen() -> Vec<String> {
    vec!["127.0.0.1:8080".to_owned()]
}

pub(crate) fn default_max_request_header_bytes() -> ByteSize {
    ByteSize::from_bytes(64 * 1024)
}

pub(crate) fn default_max_uri_bytes() -> ByteSize {
    ByteSize::from_bytes(8 * 1024)
}

pub(crate) fn default_max_request_headers() -> usize {
    100
}

pub(crate) fn default_max_request_body_bytes() -> ByteSize {
    ByteSize::from_bytes(16 * 1024 * 1024)
}

pub(crate) fn default_process_pid_file() -> PathBuf {
    default_process_runtime_path("fluxheim.pid")
}

pub(crate) fn default_process_upgrade_sock() -> PathBuf {
    default_process_runtime_path("fluxheim-upgrade.sock")
}

pub(crate) fn default_process_certificate_reload_sock() -> PathBuf {
    default_process_runtime_path("fluxheim-cert-reload.sock")
}

#[cfg(not(any(test, feature = "test-support")))]
fn default_process_runtime_path(name: &str) -> PathBuf {
    PathBuf::from("/run/fluxheim").join(name)
}

#[cfg(any(test, feature = "test-support"))]
fn default_process_runtime_path(name: &str) -> PathBuf {
    let root = PathBuf::from("target/fluxheim-test-tmp");
    let _ = std::fs::create_dir_all(&root);
    let root = root.canonicalize().unwrap_or(root);
    root.join("run").join(name)
}

pub(crate) fn default_process_threads() -> usize {
    1
}

pub(crate) fn default_process_listener_tasks_per_fd() -> usize {
    1
}

pub(crate) fn default_process_upstream_keepalive_pool_size() -> usize {
    128
}

pub(crate) fn default_process_max_retries() -> usize {
    16
}

pub(crate) fn validate_process_usize(
    field: &'static str,
    value: usize,
    min: usize,
    max: usize,
) -> Result<(), ConfigError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError::InvalidProcessSetting { field })
    }
}

pub(crate) fn validate_process_optional_duration(
    field: &'static str,
    value: Option<u64>,
) -> Result<(), ConfigError> {
    match value {
        Some(0) => Err(ConfigError::InvalidProcessSetting { field }),
        Some(_) | None => Ok(()),
    }
}

pub(crate) fn default_true() -> bool {
    true
}

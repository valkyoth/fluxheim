use std::path::{Path, PathBuf};

use fluxheim_config::Config;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessSpec {
    daemon: bool,
    error_log: Option<PathBuf>,
    pid_file: PathBuf,
    upgrade_sock: PathBuf,
    certificate_reload_sock: PathBuf,
    threads: usize,
    listener_tasks_per_fd: usize,
    work_stealing: bool,
    upstream_keepalive_pool_size: usize,
    max_retries: usize,
    grace_period_seconds: Option<u64>,
    graceful_shutdown_timeout_seconds: Option<u64>,
}

impl Default for ProcessSpec {
    fn default() -> Self {
        Self {
            daemon: false,
            error_log: None,
            pid_file: PathBuf::from("/run/fluxheim/fluxheim.pid"),
            upgrade_sock: PathBuf::from("/run/fluxheim/fluxheim-upgrade.sock"),
            certificate_reload_sock: PathBuf::from("/run/fluxheim/fluxheim-cert-reload.sock"),
            threads: 1,
            listener_tasks_per_fd: 1,
            work_stealing: true,
            upstream_keepalive_pool_size: 128,
            max_retries: 16,
            grace_period_seconds: None,
            graceful_shutdown_timeout_seconds: None,
        }
    }
}

impl ProcessSpec {
    pub(crate) fn from_config(config: &Config) -> Self {
        let process = &config.server.process;
        Self {
            daemon: process.daemon,
            error_log: process.error_log.clone(),
            pid_file: process.pid_file.clone(),
            upgrade_sock: process.upgrade_sock.clone(),
            certificate_reload_sock: process.certificate_reload_sock.clone(),
            threads: process.threads,
            listener_tasks_per_fd: process.listener_tasks_per_fd,
            work_stealing: process.work_stealing,
            upstream_keepalive_pool_size: process.upstream_keepalive_pool_size,
            max_retries: process.max_retries,
            grace_period_seconds: process.grace_period_seconds,
            graceful_shutdown_timeout_seconds: process.graceful_shutdown_timeout_seconds,
        }
    }

    pub const fn daemon(&self) -> bool {
        self.daemon
    }

    pub fn error_log(&self) -> Option<&Path> {
        self.error_log.as_deref()
    }

    pub fn pid_file(&self) -> &Path {
        &self.pid_file
    }

    pub fn upgrade_sock(&self) -> &Path {
        &self.upgrade_sock
    }

    pub fn certificate_reload_sock(&self) -> &Path {
        &self.certificate_reload_sock
    }

    pub const fn threads(&self) -> usize {
        self.threads
    }

    pub const fn listener_tasks_per_fd(&self) -> usize {
        self.listener_tasks_per_fd
    }

    pub const fn work_stealing(&self) -> bool {
        self.work_stealing
    }

    pub const fn upstream_keepalive_pool_size(&self) -> usize {
        self.upstream_keepalive_pool_size
    }

    pub const fn max_retries(&self) -> usize {
        self.max_retries
    }

    pub const fn grace_period_seconds(&self) -> Option<u64> {
        self.grace_period_seconds
    }

    pub const fn graceful_shutdown_timeout_seconds(&self) -> Option<u64> {
        self.graceful_shutdown_timeout_seconds
    }
}

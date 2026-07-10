use std::io;
use std::sync::Arc;

use fluxheim_config::{PhpConfig, PhpFpmMode};

use crate::managed_config::{managed_php_fpm_config, managed_php_fpm_instance_name};
#[cfg(unix)]
use crate::managed_spawn::{ensure_managed_php_fpm_directory, write_managed_php_fpm_config_file};
#[cfg(unix)]
use crate::request_body::{
    create_php_request_body_spool_dir_sync, ensure_php_request_body_spool_dir,
};

#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Mutex;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
#[path = "managed_process_lifecycle.rs"]
mod managed_process_lifecycle;
#[cfg(unix)]
use managed_process_lifecycle::{
    cleanup_managed_php_fpm_files, spawn_managed_php_fpm_child, spawn_managed_php_fpm_cleanup,
    spawn_managed_php_fpm_watchdog, terminate_managed_php_fpm_child,
};

pub struct ManagedPhpFpmProcess {
    #[cfg(unix)]
    child: Arc<Mutex<Option<std::process::Child>>>,
    #[cfg(unix)]
    shutdown: Arc<AtomicBool>,
    #[cfg(unix)]
    plan: Arc<ManagedPhpFpmSpawnPlan>,
}

#[cfg(unix)]
pub(super) struct ManagedPhpFpmSpawnPlan {
    scope: String,
    binary: PathBuf,
    socket: PathBuf,
    config_path: PathBuf,
    pid_path: PathBuf,
    connect_timeout_secs: Option<u64>,
}

impl std::fmt::Debug for ManagedPhpFpmProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(unix)]
        {
            formatter
                .debug_struct("ManagedPhpFpmProcess")
                .field("socket", &self.plan.socket)
                .field("config_path", &self.plan.config_path)
                .field("pid_path", &self.plan.pid_path)
                .finish_non_exhaustive()
        }
        #[cfg(not(unix))]
        {
            formatter
                .debug_struct("ManagedPhpFpmProcess")
                .finish_non_exhaustive()
        }
    }
}

#[cfg(unix)]
impl Drop for ManagedPhpFpmProcess {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let child = match self.child.lock() {
            Ok(mut child) => child.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(child) = child {
            spawn_managed_php_fpm_cleanup(
                child,
                self.plan.socket.clone(),
                self.plan.config_path.clone(),
                self.plan.pid_path.clone(),
            );
        } else {
            cleanup_managed_php_fpm_files(
                &self.plan.socket,
                &self.plan.config_path,
                &self.plan.pid_path,
            );
        }
    }
}

pub fn managed_php_fpm_from_config(
    scope: &str,
    metric_pool: &str,
    config: &mut PhpConfig,
) -> io::Result<Option<Arc<ManagedPhpFpmProcess>>> {
    if !matches!(config.fpm.mode, PhpFpmMode::Managed) {
        return Ok(None);
    }
    #[cfg(not(unix))]
    {
        let _ = (scope, metric_pool, config);
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "managed php-fpm requires Unix sockets",
        ));
    }
    #[cfg(unix)]
    {
        let process = ManagedPhpFpmProcess::start(scope, metric_pool, config)?;
        config.fpm.socket = Some(process.socket_path().to_path_buf());
        config.fpm.tcp = None;
        config.fpm.tcp_upstreams.clear();
        Ok(Some(Arc::new(process)))
    }
}

#[cfg(unix)]
impl ManagedPhpFpmProcess {
    fn socket_path(&self) -> &Path {
        &self.plan.socket
    }

    fn start(scope: &str, metric_pool: &str, config: &PhpConfig) -> io::Result<Self> {
        let binary = config.fpm.php_fpm_binary.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{scope}: managed php-fpm requires php_fpm_binary"),
            )
        })?;
        let socket_dir = config.fpm.socket_dir.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{scope}: managed php-fpm requires socket_dir"),
            )
        })?;
        create_php_request_body_spool_dir_sync(socket_dir).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "{scope}: failed to create managed php-fpm socket_dir {}: {error}",
                    socket_dir.display()
                ),
            )
        })?;
        ensure_php_request_body_spool_dir(socket_dir).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "{scope}: managed php-fpm socket_dir {} is unsafe: {error}",
                    socket_dir.display()
                ),
            )
        })?;
        let name = managed_php_fpm_instance_name(metric_pool)?;
        let socket = socket_dir.join(format!("{name}.sock"));
        rustix::net::SocketAddrUnix::new(&socket).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{scope}: managed php-fpm socket path {} is not supported: {error}",
                    socket.display()
                ),
            )
        })?;
        let config_path = socket_dir.join(format!("{name}.conf"));
        let pid_path = socket_dir.join(format!("{name}.pid"));
        let error_log = socket_dir.join(format!("{name}.log"));
        let slow_log = config
            .fpm
            .request_slowlog_timeout_secs
            .map(|_| socket_dir.join(format!("{name}.slow.log")));
        ensure_managed_php_fpm_directory(
            scope,
            "php.fpm.session_save_path",
            config.fpm.session_save_path.as_deref(),
        )?;
        ensure_managed_php_fpm_directory(
            scope,
            "php.fpm.upload_tmp_dir",
            config.fpm.upload_tmp_dir.as_deref(),
        )?;
        let php_config = managed_php_fpm_config(
            &socket,
            &pid_path,
            &error_log,
            slow_log.as_deref(),
            &config.fpm,
        )?;
        write_managed_php_fpm_config_file(&config_path, php_config.as_bytes()).map_err(
            |error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "{scope}: failed to write managed php-fpm config {}: {error}",
                        config_path.display()
                    ),
                )
            },
        )?;
        let plan = Arc::new(ManagedPhpFpmSpawnPlan {
            scope: scope.to_owned(),
            binary: binary.to_path_buf(),
            socket,
            config_path,
            pid_path,
            connect_timeout_secs: config.fpm.connect_timeout_secs,
        });
        let (child, started_at) = spawn_managed_php_fpm_child(&plan, None)?;
        let child = Arc::new(Mutex::new(Some(child)));
        let shutdown = Arc::new(AtomicBool::new(false));
        if let Err(error) = spawn_managed_php_fpm_watchdog(
            Arc::clone(&child),
            Arc::clone(&shutdown),
            Arc::clone(&plan),
            started_at,
        ) {
            shutdown.store(true, Ordering::Release);
            let child = match child.lock() {
                Ok(mut guard) => guard.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            if let Some(mut child) = child {
                terminate_managed_php_fpm_child(&mut child);
            }
            cleanup_managed_php_fpm_files(&plan.socket, &plan.config_path, &plan.pid_path);
            return Err(error);
        }
        Ok(Self {
            child,
            shutdown,
            plan,
        })
    }
}

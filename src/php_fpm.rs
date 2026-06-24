use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::http_types::{PingoraResponseHeader as ResponseHeader, StatusCode};

use crate::config::{PhpConfig, PhpFpmConfig, PhpFpmMode};
use crate::flux_error::{FluxError, FluxResult};
#[cfg(unix)]
pub(crate) use fluxheim_php_fpm::create_php_request_body_spool_dir_sync;
#[cfg(test)]
pub(crate) use fluxheim_php_fpm::php_fpm_retry_attempts;
#[cfg(test)]
pub(crate) use fluxheim_php_fpm::push_php_fpm_stream_chunk;
#[cfg(test)]
pub(crate) use fluxheim_php_fpm::safe_php_header_value;
pub(crate) use fluxheim_php_fpm::{
    PhpFpmEndpoint, PhpFpmPool, PhpFpmPoolMetrics, PhpFpmTimeoutKind, PhpRequestBody,
    collect_php_fpm_response_stream, create_php_request_body_spool_file,
    ensure_php_request_body_spool_dir, managed_php_fpm_config, managed_php_fpm_instance_name,
    managed_php_fpm_path_env_from, managed_php_fpm_restart_backoff_secs,
    php_fpm_effective_connect_timeout, php_fpm_effective_request_timeout,
    php_fpm_endpoints_from_config, php_fpm_error_outcome,
    php_fpm_retry_attempts_for_endpoint_count, php_fpm_retry_deadline,
    php_fpm_retry_deadline_allows, php_fpm_retryable_error, php_fpm_retryable_status,
    php_fpm_timeout_error,
};

const MANAGED_PHP_FPM_STABLE_RESTART_SECS: u64 = 30;

pub(crate) struct PhpFpmParsedResponse {
    pub(crate) response: ResponseHeader,
    pub(crate) body: Vec<u8>,
    pub(crate) stderr: Option<Vec<u8>>,
}

pub(crate) fn php_fpm_keepalive_pools_from_config(
    config: &PhpConfig,
    metric_vhost: &str,
    metric_pool: &str,
) -> Vec<Arc<PhpFpmPool>> {
    fluxheim_php_fpm::php_fpm_keepalive_pools_from_config(
        config,
        metric_vhost,
        metric_pool,
        php_fpm_pool_metrics(),
    )
}

fn php_fpm_pool_metrics() -> PhpFpmPoolMetrics {
    #[cfg(feature = "metrics")]
    {
        PhpFpmPoolMetrics::new(
            crate::metrics::record_php_fpm_pool_event,
            crate::metrics::record_php_fpm_pool_idle,
        )
    }
    #[cfg(not(feature = "metrics"))]
    {
        PhpFpmPoolMetrics::default()
    }
}

pub(crate) async fn execute_php_fpm_once(
    pool: Option<&PhpFpmPool>,
    endpoint: &PhpFpmEndpoint,
    params: fastcgi_client::Params<'_>,
    body: &PhpRequestBody,
    connect_timeout: Duration,
    timeout: Duration,
    max_response_bytes: u64,
) -> io::Result<fastcgi_client::Response> {
    if let Some(pool) = pool {
        return pool.execute(params, body, connect_timeout, timeout).await;
    }

    match endpoint {
        PhpFpmEndpoint::Tcp(address) => {
            let stream =
                tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(address))
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Connect))??;
            execute_php_fpm_stream(stream, params, body, timeout, max_response_bytes).await
        }
        #[cfg(unix)]
        PhpFpmEndpoint::Unix(socket) => {
            let stream =
                tokio::time::timeout(connect_timeout, tokio::net::UnixStream::connect(socket))
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Connect))??;
            execute_php_fpm_stream(stream, params, body, timeout, max_response_bytes).await
        }
    }
}

pub(crate) fn php_fpm_retryable_response(fpm: &PhpFpmConfig, status: StatusCode) -> bool {
    php_fpm_retryable_status(fpm, status.as_u16())
}

async fn execute_php_fpm_stream<S>(
    stream: S,
    params: fastcgi_client::Params<'_>,
    body: &PhpRequestBody,
    timeout: Duration,
    max_response_bytes: u64,
) -> io::Result<fastcgi_client::Response>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let client = fastcgi_client::Client::new_tokio(stream);
    let request = fastcgi_client::Request::new(params, body.reader().await?);
    let stream = tokio::time::timeout(timeout, client.execute_once_stream(request))
        .await
        .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Request))?
        .map_err(|error| io::Error::other(error.to_string()))?;
    collect_php_fpm_response_stream(stream, max_response_bytes).await
}

pub(crate) fn parse_php_response(
    stdout: &[u8],
    max_response_bytes: u64,
    max_response_header_bytes: u64,
) -> io::Result<(ResponseHeader, Vec<u8>)> {
    let parsed = fluxheim_php_fpm::parse_php_response(
        stdout,
        max_response_bytes,
        max_response_header_bytes,
    )?;
    let mut response = php_response_header(parsed.status).map_err(FluxError::into_io)?;
    for (name, value) in parsed.headers {
        response
            .append_header(name, value)
            .map_err(|error| io::Error::other(error.to_string()))?;
    }

    Ok((response, parsed.body))
}

pub fn fuzz_parse_php_response(stdout: &[u8]) -> io::Result<()> {
    let _ = parse_php_response(stdout, 1024 * 1024, 64 * 1024)?;
    Ok(())
}

pub(crate) fn php_response_header(status: u16) -> FluxResult<ResponseHeader> {
    ResponseHeader::build(status, Some(8))
        .map_err(|error| FluxError::invalid_input(error.to_string()))
}

pub(crate) struct ManagedPhpFpmProcess {
    child: Arc<Mutex<Option<std::process::Child>>>,
    shutdown: Arc<AtomicBool>,
    plan: Arc<ManagedPhpFpmSpawnPlan>,
}

struct ManagedPhpFpmSpawnPlan {
    scope: String,
    binary: PathBuf,
    socket: PathBuf,
    config_path: PathBuf,
    pid_path: PathBuf,
    connect_timeout_secs: Option<u64>,
}

impl std::fmt::Debug for ManagedPhpFpmProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedPhpFpmProcess")
            .field("socket", &self.plan.socket)
            .field("config_path", &self.plan.config_path)
            .field("pid_path", &self.plan.pid_path)
            .finish_non_exhaustive()
    }
}

impl Drop for ManagedPhpFpmProcess {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let child = match self.child.lock() {
            Ok(mut child) => child.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(child) = child {
            let socket = self.plan.socket.clone();
            let config_path = self.plan.config_path.clone();
            let pid_path = self.plan.pid_path.clone();
            spawn_managed_php_fpm_cleanup(child, socket, config_path, pid_path);
        } else {
            cleanup_managed_php_fpm_files(
                &self.plan.socket,
                &self.plan.config_path,
                &self.plan.pid_path,
            );
        }
    }
}

pub(crate) fn managed_php_fpm_from_config(
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

#[cfg(unix)]
fn spawn_managed_php_fpm_cleanup(
    child: std::process::Child,
    socket: PathBuf,
    config_path: PathBuf,
    pid_path: PathBuf,
) {
    let child = Arc::new(Mutex::new(Some(child)));
    let cleanup_child = Arc::clone(&child);
    let cleanup_socket = socket.clone();
    let cleanup_config_path = config_path.clone();
    let cleanup_pid_path = pid_path.clone();

    match std::thread::Builder::new()
        .name("fluxheim-php-fpm-stop".to_owned())
        .spawn(move || {
            let child = match cleanup_child.lock() {
                Ok(mut guard) => guard.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            if let Some(mut child) = child {
                terminate_managed_php_fpm_child(&mut child);
            }
            cleanup_managed_php_fpm_files(&cleanup_socket, &cleanup_config_path, &cleanup_pid_path);
        }) {
        Ok(_) => {}
        Err(error) => {
            log::warn!(
                target: "fluxheim::php_fpm",
                "failed to spawn managed php-fpm cleanup thread; sending managed php-fpm kill inline without blocking wait: {error}"
            );
            let child = match child.lock() {
                Ok(mut guard) => guard.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            if let Some(mut child) = child {
                // Drop can run on a Tokio worker after the last request releases an
                // old runtime snapshot. If cleanup-thread creation fails, do not
                // block that worker on Child::wait().
                let _ = child.kill();
            }
            cleanup_managed_php_fpm_files(&socket, &config_path, &pid_path);
        }
    }
}

#[cfg(unix)]
fn cleanup_managed_php_fpm_files(socket: &Path, config_path: &Path, pid_path: &Path) {
    let _ = std::fs::remove_file(socket);
    let _ = std::fs::remove_file(config_path);
    let _ = std::fs::remove_file(pid_path);
}

#[cfg(unix)]
fn terminate_managed_php_fpm_child(child: &mut std::process::Child) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
    }

    let _ = rustix::process::kill_process(
        rustix::process::Pid::from_child(child),
        rustix::process::Signal::TERM,
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        }
    }
}

#[cfg(unix)]
fn spawn_managed_php_fpm_child(
    plan: &ManagedPhpFpmSpawnPlan,
    shutdown: Option<&AtomicBool>,
) -> io::Result<(std::process::Child, Instant)> {
    ensure_managed_php_fpm_binary_spawn_safe(&plan.scope, &plan.binary)?;
    let _ = std::fs::remove_file(&plan.socket);
    let _ = std::fs::remove_file(&plan.pid_path);

    let mut child = std::process::Command::new(&plan.binary)
        .arg("-F")
        .arg("-y")
        .arg(&plan.config_path)
        .env_clear()
        .env("PATH", managed_php_fpm_path_env())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "{}: failed to start managed php-fpm binary {}: {error}",
                    plan.scope,
                    plan.binary.display()
                ),
            )
        })?;

    match wait_for_managed_php_fpm_socket(
        &mut child,
        &plan.socket,
        plan.connect_timeout_secs,
        shutdown,
    ) {
        Ok(()) => Ok((child, Instant::now())),
        Err(error) => {
            terminate_managed_php_fpm_child(&mut child);
            let _ = std::fs::remove_file(&plan.socket);
            let _ = std::fs::remove_file(&plan.pid_path);
            Err(io::Error::new(
                error.kind(),
                format!(
                    "{}: managed php-fpm failed to become ready: {error}",
                    plan.scope
                ),
            ))
        }
    }
}

#[cfg(unix)]
fn ensure_managed_php_fpm_binary_spawn_safe(scope: &str, binary: &Path) -> io::Result<()> {
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
fn spawn_managed_php_fpm_watchdog(
    child: Arc<Mutex<Option<std::process::Child>>>,
    shutdown: Arc<AtomicBool>,
    plan: Arc<ManagedPhpFpmSpawnPlan>,
    started_at: Instant,
) -> io::Result<()> {
    std::thread::Builder::new()
        .name("fluxheim-php-fpm-watchdog".to_owned())
        .spawn(move || run_managed_php_fpm_watchdog(child, shutdown, plan, started_at))
        .map(|_| ())
        .map_err(|error| {
            io::Error::other(format!("failed to start managed php-fpm watchdog: {error}"))
        })
}

#[cfg(unix)]
fn run_managed_php_fpm_watchdog(
    child: Arc<Mutex<Option<std::process::Child>>>,
    shutdown: Arc<AtomicBool>,
    plan: Arc<ManagedPhpFpmSpawnPlan>,
    started_at: Instant,
) {
    let mut restart_failures = 0_usize;
    let mut last_started = started_at;
    loop {
        if managed_php_fpm_shutdown_requested(&shutdown) {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
        if managed_php_fpm_shutdown_requested(&shutdown) {
            return;
        }

        let exited = {
            let mut guard = match child.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            match guard.as_mut().map(std::process::Child::try_wait) {
                Some(Ok(Some(status))) => {
                    *guard = None;
                    Some(format!("exited with status {status}"))
                }
                Some(Ok(None)) => None,
                Some(Err(error)) => {
                    *guard = None;
                    Some(format!("status check failed: {error}"))
                }
                None => Some("missing child process handle".to_owned()),
            }
        };

        let Some(reason) = exited else {
            if last_started.elapsed() >= Duration::from_secs(MANAGED_PHP_FPM_STABLE_RESTART_SECS) {
                restart_failures = 0;
            }
            continue;
        };

        if managed_php_fpm_shutdown_requested(&shutdown) {
            return;
        }

        log::warn!(
            target: "fluxheim::php_fpm",
            "{}: managed php-fpm stopped ({reason}); attempting restart",
            plan.scope
        );

        if last_started.elapsed() < Duration::from_secs(MANAGED_PHP_FPM_STABLE_RESTART_SECS) {
            restart_failures = restart_failures.saturating_add(1);
        } else {
            restart_failures = 0;
        }

        if !managed_php_fpm_sleep_until_restart(&shutdown, restart_failures) {
            return;
        }

        match spawn_managed_php_fpm_child(&plan, Some(shutdown.as_ref())) {
            Ok((new_child, started_at)) => {
                let mut guard = match child.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if managed_php_fpm_shutdown_requested(&shutdown) {
                    drop(guard);
                    let mut new_child = new_child;
                    terminate_managed_php_fpm_child(&mut new_child);
                    return;
                }
                *guard = Some(new_child);
                last_started = started_at;
                log::info!(
                    target: "fluxheim::php_fpm",
                    "{}: managed php-fpm restarted",
                    plan.scope
                );
            }
            Err(error) => {
                restart_failures = restart_failures.saturating_add(1);
                log::error!(
                    target: "fluxheim::php_fpm",
                    "{}: managed php-fpm restart failed: {error}",
                    plan.scope
                );
            }
        }
    }
}

#[cfg(unix)]
fn managed_php_fpm_shutdown_requested(shutdown: &AtomicBool) -> bool {
    shutdown.load(Ordering::Acquire)
}

#[cfg(unix)]
fn managed_php_fpm_sleep_until_restart(shutdown: &AtomicBool, restart_failures: usize) -> bool {
    let delay = Duration::from_secs(managed_php_fpm_restart_backoff_secs(restart_failures));
    let deadline = Instant::now() + delay;
    loop {
        if managed_php_fpm_shutdown_requested(shutdown) {
            return false;
        }
        let now = Instant::now();
        if now >= deadline {
            return true;
        }
        std::thread::sleep((deadline - now).min(Duration::from_millis(100)));
    }
}

#[cfg(unix)]
fn managed_php_fpm_path_env() -> String {
    managed_php_fpm_path_env_from(std::env::var("PATH").ok())
}

#[cfg(unix)]
fn write_managed_php_fpm_config_file(path: &Path, contents: &[u8]) -> io::Result<()> {
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

#[cfg(unix)]
fn ensure_managed_php_fpm_directory(
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

#[cfg(unix)]
fn wait_for_managed_php_fpm_socket(
    child: &mut std::process::Child,
    socket: &Path,
    connect_timeout_secs: Option<u64>,
    shutdown: Option<&AtomicBool>,
) -> io::Result<()> {
    let deadline =
        Instant::now() + Duration::from_secs(connect_timeout_secs.unwrap_or(5).clamp(1, 60));
    loop {
        if shutdown.is_some_and(managed_php_fpm_shutdown_requested) {
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

#[cfg(all(test, unix))]
mod tests {
    use super::ensure_managed_php_fpm_binary_spawn_safe;
    use crate::test_support::{safe_child_path, unique_temp_path};

    #[test]
    fn managed_php_fpm_spawn_rejects_symlinked_binary() {
        let root = unique_temp_path("managed-php-fpm-spawn-binary");
        std::fs::create_dir_all(&root).unwrap();
        let real_binary = safe_child_path(&root, "php-fpm.real");
        let symlink_binary = safe_child_path(&root, "php-fpm");
        std::fs::write(&real_binary, b"#!/bin/sh\n").unwrap();
        std::os::unix::fs::symlink(&real_binary, &symlink_binary).unwrap();

        let error = ensure_managed_php_fpm_binary_spawn_safe("test", &symlink_binary).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("must not be or be below a symlink")
        );
    }
}

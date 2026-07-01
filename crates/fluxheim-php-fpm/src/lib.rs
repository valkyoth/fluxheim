#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fluxheim_config::{PhpConfig, PhpFpmConfig, PhpFpmMode};
use zeroize::Zeroizing;

mod managed_config;
mod params;
mod policy;
mod response;
mod script;

#[cfg(test)]
pub(crate) use self::managed_config::managed_php_fpm_instance_name_from_parts;
pub use self::managed_config::{
    managed_php_fpm_config, managed_php_fpm_instance_name, managed_php_fpm_path_env_from,
    managed_php_fpm_restart_backoff_secs,
};
pub use self::params::{
    php_content_type_param_value, php_custom_params, php_header_param_name, php_host_param,
    php_request_header_params, php_server_name_param, safe_php_header_name, safe_php_header_value,
    safe_php_param_value,
};
pub use self::policy::{
    PhpFpmEndpoint, PhpFpmTimeoutKind, php_fpm_effective_connect_timeout,
    php_fpm_effective_request_timeout, php_fpm_endpoints_from_config, php_fpm_error_outcome,
    php_fpm_retry_attempts, php_fpm_retry_attempts_for_endpoint_count, php_fpm_retry_deadline,
    php_fpm_retry_deadline_allows, php_fpm_retryable_error, php_fpm_retryable_status,
    php_fpm_timeout_error, php_fpm_timeout_kind,
};
pub use self::response::{
    ParsedPhpResponse, parse_php_response, parse_php_status,
    php_origin_cache_policy_is_restrictive, php_response_headers_to_strip,
    php_should_intercept_error_status, php_static_offload_file_allowed,
    php_static_offload_uri_target, php_static_offload_x_sendfile_local_path,
    php_x_accel_expires_ttl_secs, split_first_colon, split_php_response, trim_ascii, trim_ascii_cr,
};
pub use self::script::{
    PhpScriptName, php_fpm_path_translated, php_fpm_script_filename, php_script_name_denied,
    php_script_name_for_request, php_segment_has_allowed_extension,
    php_should_redirect_directory_index, php_static_file_script_name,
};

static PHP_REQUEST_BODY_SPOOL_COUNTER: AtomicUsize = AtomicUsize::new(0);
pub const MAX_PHP_PARAM_VALUE_BYTES: usize = 16 * 1024;
pub const PHP_HOP_BY_HOP_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];
pub const PHP_STATIC_OFFLOAD_RESPONSE_HEADERS: &[&str] = &["x-accel-redirect", "x-sendfile"];
const MANAGED_PHP_FPM_STABLE_RESTART_SECS: u64 = 30;

#[derive(Clone)]
pub struct PhpRequestBody {
    inner: Arc<PhpRequestBodyInner>,
    len: usize,
}

#[derive(Clone, Default)]
pub struct PhpFpmPoolMetrics {
    event: Option<Arc<PhpFpmPoolEventRecorder>>,
    idle: Option<Arc<PhpFpmPoolIdleRecorder>>,
}

type PhpFpmPoolEventRecorder = dyn Fn(&str, &str, &str) + Send + Sync;
type PhpFpmPoolIdleRecorder = dyn Fn(&str, &str, usize) + Send + Sync;

pub struct PhpFpmPool {
    endpoint: PhpFpmEndpoint,
    metric_vhost: String,
    metric_pool: String,
    max_idle: usize,
    idle_timeout: Duration,
    max_response_bytes: u64,
    metrics: PhpFpmPoolMetrics,
    idle: tokio::sync::Mutex<Vec<PhpFpmPoolEntry>>,
}

pub struct ManagedPhpFpmProcess {
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

struct PhpFpmPoolEntry {
    client: PhpFpmPooledClient,
    last_used: Instant,
}

enum PhpFpmPooledClient {
    Tcp(
        fastcgi_client::Client<
            fastcgi_client::io::TokioCompat<tokio::net::TcpStream>,
            fastcgi_client::conn::KeepAlive,
        >,
    ),
    #[cfg(unix)]
    Unix(
        fastcgi_client::Client<
            fastcgi_client::io::TokioCompat<tokio::net::UnixStream>,
            fastcgi_client::conn::KeepAlive,
        >,
    ),
}

enum PhpRequestBodyInner {
    Memory(Zeroizing<Vec<u8>>),
    Spool(PhpRequestBodySpool),
}

struct PhpRequestBodySpool {
    path: PathBuf,
}

impl Drop for PhpRequestBodySpool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl std::fmt::Debug for PhpFpmPoolMetrics {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PhpFpmPoolMetrics")
            .field("event", &self.event.is_some())
            .field("idle", &self.idle.is_some())
            .finish()
    }
}

impl PhpFpmPoolMetrics {
    pub fn new<E, I>(event: E, idle: I) -> Self
    where
        E: Fn(&str, &str, &str) + Send + Sync + 'static,
        I: Fn(&str, &str, usize) + Send + Sync + 'static,
    {
        Self {
            event: Some(Arc::new(event)),
            idle: Some(Arc::new(idle)),
        }
    }

    fn record_event(&self, vhost: &str, pool: &str, event: &str) {
        if let Some(recorder) = &self.event {
            recorder(vhost, pool, event);
        }
    }

    fn record_idle(&self, vhost: &str, pool: &str, idle_connections: usize) {
        if let Some(recorder) = &self.idle {
            recorder(vhost, pool, idle_connections);
        }
    }
}

impl PhpRequestBody {
    pub fn memory(body: Vec<u8>) -> Self {
        Self::memory_zeroizing(Zeroizing::new(body))
    }

    pub fn memory_zeroizing(body: Zeroizing<Vec<u8>>) -> Self {
        Self {
            len: body.len(),
            inner: Arc::new(PhpRequestBodyInner::Memory(body)),
        }
    }

    pub fn spooled(path: PathBuf, len: usize) -> Self {
        Self {
            len,
            inner: Arc::new(PhpRequestBodyInner::Spool(PhpRequestBodySpool { path })),
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub async fn reader(
        &self,
    ) -> io::Result<Box<dyn fastcgi_client::io::AsyncRead + Unpin + Send>> {
        match self.inner.as_ref() {
            PhpRequestBodyInner::Memory(body) => {
                Ok(Box::new(fastcgi_client::io::Cursor::new(body.clone())))
            }
            PhpRequestBodyInner::Spool(spool) => {
                let file = tokio::fs::File::open(&spool.path).await?;
                Ok(Box::new(
                    fastcgi_client::io::TokioAsyncReadCompatExt::compat(file),
                ))
            }
        }
    }
}

impl std::fmt::Debug for PhpFpmPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PhpFpmPool")
            .field("endpoint", &self.endpoint)
            .field("metric_vhost", &self.metric_vhost)
            .field("metric_pool", &self.metric_pool)
            .field("max_idle", &self.max_idle)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
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
pub fn ensure_managed_php_fpm_binary_spawn_safe(scope: &str, binary: &Path) -> io::Result<()> {
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

pub fn php_fpm_keepalive_pools_from_config(
    config: &PhpConfig,
    metric_vhost: &str,
    metric_pool: &str,
    metrics: PhpFpmPoolMetrics,
) -> Vec<Arc<PhpFpmPool>> {
    if !config.fpm.keepalive {
        return Vec::new();
    }
    let endpoints = php_fpm_endpoints_from_config(&config.fpm);
    let multiple_endpoints = endpoints.len() > 1;
    endpoints
        .into_iter()
        .enumerate()
        .map(|(index, endpoint)| {
            let pool_label = if multiple_endpoints {
                format!("{metric_pool}-{index}")
            } else {
                metric_pool.to_owned()
            };
            Arc::new(PhpFpmPool::from_endpoint(
                endpoint,
                &config.fpm,
                metric_vhost,
                &pool_label,
                config.max_response_bytes.as_u64(),
                metrics.clone(),
            ))
        })
        .collect()
}

impl PhpFpmPool {
    pub fn metric_pool(&self) -> &str {
        &self.metric_pool
    }

    fn from_endpoint(
        endpoint: PhpFpmEndpoint,
        config: &PhpFpmConfig,
        metric_vhost: &str,
        metric_pool: &str,
        max_response_bytes: u64,
        metrics: PhpFpmPoolMetrics,
    ) -> Self {
        Self {
            endpoint,
            metric_vhost: metric_vhost.to_owned(),
            metric_pool: metric_pool.to_owned(),
            max_idle: config.pool_max_idle,
            idle_timeout: Duration::from_secs(config.idle_timeout_secs),
            max_response_bytes,
            metrics,
            idle: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    fn record_pool_event(&self, event: &str) {
        self.metrics
            .record_event(&self.metric_vhost, &self.metric_pool, event);
    }

    fn record_pool_idle(&self, idle_connections: usize) {
        self.metrics
            .record_idle(&self.metric_vhost, &self.metric_pool, idle_connections);
    }

    pub async fn execute(
        &self,
        params: fastcgi_client::Params<'_>,
        body: &PhpRequestBody,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> io::Result<fastcgi_client::Response> {
        let mut entry = self.checkout(connect_timeout).await?;
        let result = entry
            .execute(params, body, request_timeout, self.max_response_bytes)
            .await;
        if result.is_ok() {
            self.checkin(entry).await;
        }
        result
    }

    async fn checkout(&self, connect_timeout: Duration) -> io::Result<PhpFpmPoolEntry> {
        let now = Instant::now();
        {
            let mut idle = self.idle.lock().await;
            let before_retain = idle.len();
            idle.retain(|entry| now.duration_since(entry.last_used) <= self.idle_timeout);
            if before_retain > idle.len() {
                self.record_pool_event("drop_stale");
            }
            if let Some(entry) = idle.pop() {
                self.record_pool_event("reuse");
                self.record_pool_idle(idle.len());
                return Ok(entry);
            }
            self.record_pool_idle(idle.len());
        }
        let client = self.connect_client(connect_timeout).await?;
        self.record_pool_event("connect");
        Ok(PhpFpmPoolEntry {
            client,
            last_used: now,
        })
    }

    async fn checkin(&self, mut entry: PhpFpmPoolEntry) {
        entry.last_used = Instant::now();
        let mut idle = self.idle.lock().await;
        let before_retain = idle.len();
        idle.retain(|entry| entry.last_used.elapsed() <= self.idle_timeout);
        if before_retain > idle.len() {
            self.record_pool_event("drop_stale");
        }
        if idle.len() < self.max_idle {
            idle.push(entry);
            self.record_pool_event("return");
        } else {
            self.record_pool_event("discard_full");
        }
        self.record_pool_idle(idle.len());
    }

    async fn connect_client(&self, timeout: Duration) -> io::Result<PhpFpmPooledClient> {
        match &self.endpoint {
            PhpFpmEndpoint::Tcp(address) => {
                let stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address))
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Connect))??;
                Ok(PhpFpmPooledClient::Tcp(
                    fastcgi_client::Client::new_keep_alive_tokio(stream),
                ))
            }
            #[cfg(unix)]
            PhpFpmEndpoint::Unix(socket) => {
                let stream = tokio::time::timeout(timeout, tokio::net::UnixStream::connect(socket))
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Connect))??;
                Ok(PhpFpmPooledClient::Unix(
                    fastcgi_client::Client::new_keep_alive_tokio(stream),
                ))
            }
        }
    }
}

pub async fn execute_php_fpm_once(
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

impl PhpFpmPoolEntry {
    async fn execute(
        &mut self,
        params: fastcgi_client::Params<'_>,
        body: &PhpRequestBody,
        timeout: Duration,
        max_response_bytes: u64,
    ) -> io::Result<fastcgi_client::Response> {
        self.client
            .execute(params, body, timeout, max_response_bytes)
            .await
    }
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

impl PhpFpmPooledClient {
    async fn execute(
        &mut self,
        params: fastcgi_client::Params<'_>,
        body: &PhpRequestBody,
        timeout: Duration,
        max_response_bytes: u64,
    ) -> io::Result<fastcgi_client::Response> {
        let request = fastcgi_client::Request::new(params, body.reader().await?);
        match self {
            Self::Tcp(client) => {
                let stream = tokio::time::timeout(timeout, client.execute_stream(request))
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Request))?
                    .map_err(|error| io::Error::other(error.to_string()))?;
                collect_php_fpm_response_stream(stream, max_response_bytes).await
            }
            #[cfg(unix)]
            Self::Unix(client) => {
                let stream = tokio::time::timeout(timeout, client.execute_stream(request))
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Request))?
                    .map_err(|error| io::Error::other(error.to_string()))?;
                collect_php_fpm_response_stream(stream, max_response_bytes).await
            }
        }
    }
}

pub async fn collect_php_fpm_response_stream<S>(
    mut stream: S,
    max_response_bytes: u64,
) -> io::Result<fastcgi_client::Response>
where
    S: fastcgi_client::StreamExt<
            Item = fastcgi_client::ClientResult<fastcgi_client::response::Content>,
        > + Unpin,
{
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut total_bytes = 0_u64;
    while let Some(content) = stream.next().await {
        match content.map_err(|error| io::Error::other(error.to_string()))? {
            fastcgi_client::response::Content::Stdout(chunk) => {
                push_php_fpm_stream_chunk(
                    &mut stdout,
                    &chunk,
                    &mut total_bytes,
                    max_response_bytes,
                )?;
            }
            fastcgi_client::response::Content::Stderr(chunk) => {
                push_php_fpm_stream_chunk(
                    &mut stderr,
                    &chunk,
                    &mut total_bytes,
                    max_response_bytes,
                )?;
            }
        }
    }

    let mut response = fastcgi_client::Response::default();
    response.stdout = (!stdout.is_empty()).then_some(stdout);
    response.stderr = (!stderr.is_empty()).then_some(stderr);
    Ok(response)
}

pub fn push_php_fpm_stream_chunk(
    target: &mut Vec<u8>,
    chunk: &[u8],
    total_bytes: &mut u64,
    max_response_bytes: u64,
) -> io::Result<()> {
    let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
    let Some(next_total) = total_bytes.checked_add(chunk_len) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "php-fpm response exceeds maximum buffered size",
        ));
    };
    if next_total > max_response_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "php-fpm response exceeds maximum buffered size",
        ));
    }
    *total_bytes = next_total;
    target.extend_from_slice(chunk);
    Ok(())
}

#[cfg(not(unix))]
fn php_request_body_spool_path(spool_dir: &Path) -> io::Result<PathBuf> {
    Ok(spool_dir.join(php_request_body_spool_filename()?))
}

fn php_request_body_spool_filename() -> io::Result<String> {
    let counter = PHP_REQUEST_BODY_SPOOL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|error| {
        io::Error::other(format!(
            "failed to generate PHP spool filename entropy: {error}"
        ))
    })?;
    let random = u64::from_le_bytes(random);
    Ok(format!(
        ".fluxheim-php-body-{}-{counter}-{random:016x}.tmp",
        std::process::id()
    ))
}

pub async fn create_php_request_body_spool_file(
    spool_dir: &Path,
) -> io::Result<(PathBuf, tokio::fs::File)> {
    create_php_request_body_spool_dir(spool_dir).await?;
    ensure_php_request_body_spool_dir(spool_dir)?;

    #[cfg(unix)]
    {
        create_php_request_body_spool_file_at(spool_dir)
    }

    #[cfg(not(unix))]
    {
        create_php_request_body_spool_file_by_path(spool_dir).await
    }
}

#[cfg(unix)]
async fn create_php_request_body_spool_dir(spool_dir: &Path) -> io::Result<()> {
    create_php_request_body_spool_dir_sync(spool_dir)
}

#[cfg(not(unix))]
async fn create_php_request_body_spool_dir(spool_dir: &Path) -> io::Result<()> {
    tokio::fs::create_dir_all(spool_dir).await
}

#[cfg(unix)]
pub fn create_php_request_body_spool_dir_sync(spool_dir: &Path) -> io::Result<()> {
    use rustix::fs::Mode;

    if spool_dir.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PHP request body spool directory cannot be empty",
        ));
    }

    let mut current = PathBuf::new();
    for component in spool_dir.components() {
        current.push(component.as_os_str());
        match rustix::fs::mkdir(&current, Mode::from_raw_mode(0o700)) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(io::Error::from(error)),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
async fn create_php_request_body_spool_file_by_path(
    spool_dir: &Path,
) -> io::Result<(PathBuf, tokio::fs::File)> {
    let mut last_error = None;
    for _ in 0..16 {
        let path = php_request_body_spool_path(spool_dir)?;
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        match options.open(&path).await {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate PHP request body spool file",
        )
    }))
}

#[cfg(unix)]
fn create_php_request_body_spool_file_at(
    spool_dir: &Path,
) -> io::Result<(PathBuf, tokio::fs::File)> {
    use rustix::fs::{Mode, OFlags};

    let directory = rustix::fs::openat(
        rustix::fs::CWD,
        spool_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    ensure_php_request_body_spool_dir_fd(&directory)?;

    let mut last_error = None;
    for _ in 0..16 {
        let filename = php_request_body_spool_filename()?;
        let path = spool_dir.join(&filename);
        match rustix::fs::openat(
            &directory,
            filename.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(file) => {
                let file = tokio::fs::File::from_std(std::fs::File::from(file));
                return Ok((path, file));
            }
            Err(error) if error == rustix::io::Errno::EXIST => {
                last_error = Some(io::Error::from(error));
            }
            Err(error) => return Err(io::Error::from(error)),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate PHP request body spool file",
        )
    }))
}

#[cfg(unix)]
fn ensure_php_request_body_spool_dir_fd<Fd: rustix::fd::AsFd>(directory: Fd) -> io::Result<()> {
    let stat = rustix::fs::fstat(directory).map_err(io::Error::from)?;
    if stat.st_mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PHP request body spool directory is group/world writable",
        ));
    }
    Ok(())
}

pub fn ensure_php_request_body_spool_dir(spool_dir: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(spool_dir)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PHP request body spool path is not a directory",
        ));
    }
    #[cfg(unix)]
    if fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(spool_dir)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PHP request body spool directory is group/world writable",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;

    use super::{
        MAX_PHP_PARAM_VALUE_BYTES, PhpFpmEndpoint, PhpFpmTimeoutKind, PhpRequestBody,
        create_php_request_body_spool_file, managed_php_fpm_config,
        managed_php_fpm_instance_name_from_parts, managed_php_fpm_path_env_from,
        managed_php_fpm_restart_backoff_secs, parse_php_status, php_content_type_param_value,
        php_custom_params, php_fpm_effective_connect_timeout, php_fpm_effective_request_timeout,
        php_fpm_endpoints_from_config, php_fpm_error_outcome, php_fpm_path_translated,
        php_fpm_retry_attempts, php_fpm_retry_attempts_for_endpoint_count, php_fpm_retryable_error,
        php_fpm_retryable_status, php_fpm_script_filename, php_fpm_timeout_error,
        php_header_param_name, php_host_param, php_request_header_params, php_script_name_denied,
        php_script_name_for_request, php_segment_has_allowed_extension, php_server_name_param,
        php_should_redirect_directory_index, php_static_file_script_name,
        push_php_fpm_stream_chunk, safe_php_header_name, safe_php_header_value,
        safe_php_param_value, split_first_colon, split_php_response, trim_ascii, trim_ascii_cr,
    };
    use fluxheim_config::{PhpConfig, PhpFpmConfig, PhpFpmProcessManager, PhpPathInfoMode};

    #[test]
    fn php_request_body_replays_memory_body() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("test runtime");
        let body = PhpRequestBody::memory(b"body".to_vec());

        let mut reader = runtime.block_on(body.reader()).expect("memory reader");
        let mut replayed = Vec::new();
        runtime
            .block_on(fastcgi_client::io::AsyncReadExt::read_to_end(
                &mut reader,
                &mut replayed,
            ))
            .expect("read memory body");

        assert_eq!(body.len(), 4);
        assert_eq!(replayed, b"body");
    }

    #[test]
    fn php_request_body_spool_replays_and_cleans_up_file() {
        let spool_dir = tempfile::TempDir::new().expect("spool dir");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("test runtime");
        let (path, mut file) = runtime
            .block_on(create_php_request_body_spool_file(spool_dir.path()))
            .expect("create spool file");
        runtime.block_on(async {
            use tokio::io::AsyncWriteExt;

            file.write_all(b"spooled-body").await.expect("write spool");
            file.flush().await.expect("flush spool");
        });

        let body = PhpRequestBody::spooled(path.clone(), "spooled-body".len());
        let mut reader = runtime.block_on(body.reader()).expect("spool reader");
        let mut replayed = Vec::new();
        runtime
            .block_on(fastcgi_client::io::AsyncReadExt::read_to_end(
                &mut reader,
                &mut replayed,
            ))
            .expect("read spool body");

        assert_eq!(replayed, b"spooled-body");
        assert!(path.exists());
        drop(reader);
        drop(body);
        assert!(!path.exists());
    }

    #[test]
    fn php_fpm_stream_chunk_limit_counts_stdout_and_stderr() {
        let mut total = 0;
        let mut stdout = Vec::new();
        push_php_fpm_stream_chunk(&mut stdout, b"1234", &mut total, 6).unwrap();
        let mut stderr = Vec::new();
        let error = push_php_fpm_stream_chunk(&mut stderr, b"567", &mut total, 6)
            .expect_err("combined FastCGI output should be bounded");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(stdout, b"1234");
        assert!(stderr.is_empty());
    }

    #[test]
    fn php_fpm_keepalive_pool_labels_are_distinct_for_tcp_upstreams() {
        let php = PhpConfig {
            fpm: PhpFpmConfig {
                tcp_upstreams: vec!["127.0.0.1:9000".to_owned(), "127.0.0.1:9001".to_owned()],
                keepalive: true,
                ..PhpFpmConfig::default()
            },
            ..PhpConfig::default()
        };

        let pools = super::php_fpm_keepalive_pools_from_config(
            &php,
            "vhost",
            "default",
            Default::default(),
        );

        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0].metric_pool(), "default-0");
        assert_eq!(pools[1].metric_pool(), "default-1");
    }

    #[cfg(unix)]
    #[test]
    fn managed_php_fpm_spawn_rejects_symlinked_binary() {
        let root = tempfile::TempDir::new().expect("temp dir");
        let real_binary = root.path().join("php-fpm.real");
        let symlink_binary = root.path().join("php-fpm");
        std::fs::write(&real_binary, b"#!/bin/sh\n").expect("write real binary");
        std::os::unix::fs::symlink(&real_binary, &symlink_binary).expect("create symlink");

        let error = super::ensure_managed_php_fpm_binary_spawn_safe("test", &symlink_binary)
            .expect_err("symlinked php-fpm binary should be rejected");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("must not be or be below a symlink")
        );
    }

    #[test]
    fn php_fpm_error_outcomes_are_bounded() {
        assert_eq!(
            php_fpm_error_outcome(&php_fpm_timeout_error(PhpFpmTimeoutKind::Connect)),
            "connect_timeout"
        );
        assert_eq!(
            php_fpm_error_outcome(&php_fpm_timeout_error(PhpFpmTimeoutKind::Request)),
            "request_timeout"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "connection refused",
            )),
            "connection_error"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::new(io::ErrorKind::InvalidInput, "missing fpm")),
            "configuration_error"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::new(io::ErrorKind::InvalidData, "bad response")),
            "invalid_response"
        );
        assert_eq!(
            php_fpm_error_outcome(&io::Error::other("backend failed")),
            "fpm_error"
        );
    }

    #[test]
    fn managed_php_fpm_path_env_falls_back_for_control_bytes() {
        assert_eq!(
            managed_php_fpm_path_env_from(Some("/usr/bin\n/tmp".to_owned())),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        );
    }

    #[test]
    fn managed_php_fpm_restart_backoff_is_bounded() {
        assert_eq!(managed_php_fpm_restart_backoff_secs(0), 1);
        assert_eq!(managed_php_fpm_restart_backoff_secs(1), 2);
        assert_eq!(managed_php_fpm_restart_backoff_secs(4), 16);
        assert_eq!(managed_php_fpm_restart_backoff_secs(64), 30);
    }

    #[test]
    fn managed_php_fpm_instance_names_are_sanitized_and_bounded() {
        assert_eq!(
            managed_php_fpm_instance_name_from_parts("pool/main:php", 42, 7, 0xfeed).unwrap(),
            "fluxheim-php-fpm-pool-main-php-42-7-000000000000feed"
        );
        assert_eq!(
            managed_php_fpm_instance_name_from_parts("", 42, 7, 0xfeed).unwrap(),
            "fluxheim-php-fpm-php-42-7-000000000000feed"
        );

        let long_name =
            managed_php_fpm_instance_name_from_parts(&"a".repeat(96), 42, 7, 0xfeed).unwrap();
        assert!(long_name.contains(&"a".repeat(48)));
        assert!(!long_name.contains(&"a".repeat(49)));
    }

    #[test]
    fn php_fpm_endpoints_include_tcp_upstreams() {
        let fpm = PhpFpmConfig {
            tcp: Some("127.0.0.1:9000".to_owned()),
            tcp_upstreams: vec!["127.0.0.1:9000".to_owned(), "127.0.0.1:9001".to_owned()],
            ..PhpFpmConfig::default()
        };

        assert_eq!(
            php_fpm_endpoints_from_config(&fpm),
            vec![
                PhpFpmEndpoint::Tcp("127.0.0.1:9000".to_owned()),
                PhpFpmEndpoint::Tcp("127.0.0.1:9001".to_owned()),
            ]
        );
    }

    #[test]
    fn php_fpm_retry_attempts_respect_method_allowlist_and_failover() {
        let mut fpm = PhpFpmConfig {
            max_retries: 2,
            retry_methods: vec!["GET".to_owned()],
            ..PhpFpmConfig::default()
        };

        assert_eq!(php_fpm_retry_attempts(&fpm, "GET"), 2);
        assert_eq!(php_fpm_retry_attempts(&fpm, "POST"), 0);
        assert_eq!(php_fpm_retry_attempts_for_endpoint_count(&fpm, "GET", 4), 3);

        fpm.retry_methods.clear();
        assert_eq!(php_fpm_retry_attempts_for_endpoint_count(&fpm, "GET", 4), 0);
    }

    #[test]
    fn php_fpm_effective_timeouts_are_capped_by_request_timeout() {
        let request_timeout = std::time::Duration::from_secs(10);
        let mut fpm = PhpFpmConfig {
            connect_timeout_secs: Some(20),
            read_timeout_secs: Some(7),
            write_timeout_secs: Some(4),
            ..PhpFpmConfig::default()
        };

        assert_eq!(
            php_fpm_effective_connect_timeout(&fpm, request_timeout),
            request_timeout
        );
        assert_eq!(
            php_fpm_effective_request_timeout(&fpm, request_timeout),
            std::time::Duration::from_secs(4)
        );

        fpm.connect_timeout_secs = Some(3);
        assert_eq!(
            php_fpm_effective_connect_timeout(&fpm, request_timeout),
            std::time::Duration::from_secs(3)
        );
    }

    #[test]
    fn php_fpm_retryable_statuses_and_errors_are_explicit() {
        let fpm = PhpFpmConfig {
            retry_statuses: vec![502, 503],
            ..PhpFpmConfig::default()
        };

        assert!(php_fpm_retryable_status(&fpm, 502));
        assert!(php_fpm_retryable_status(&fpm, 503));
        assert!(!php_fpm_retryable_status(&fpm, 404));
        assert!(php_fpm_retryable_error(&io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "refused"
        )));
        assert!(!php_fpm_retryable_error(&php_fpm_timeout_error(
            PhpFpmTimeoutKind::Request
        )));
    }

    #[test]
    fn php_header_guards_reject_injection_bytes() {
        assert!(safe_php_header_name(b"X-PHP-Header"));
        assert!(safe_php_header_name(b"X_PHP.Token"));
        assert!(!safe_php_header_name(b""));
        assert!(!safe_php_header_name(b"bad:name"));
        assert!(!safe_php_header_name(b"bad name"));

        assert!(safe_php_header_value(b"session=ok; Path=/"));
        assert!(safe_php_header_value(b"tab\tallowed"));
        assert!(!safe_php_header_value(b"bad\x0binject"));
        assert!(!safe_php_header_value(b"bad\x7fdelete"));
        assert!(!safe_php_header_value(b"bad\r\ninject"));
        assert!(!safe_php_header_value("bad-é".as_bytes()));
    }

    #[test]
    fn php_param_values_are_bounded_and_control_free() {
        assert!(safe_php_param_value("content-type-value"));
        assert!(safe_php_param_value(&"a".repeat(MAX_PHP_PARAM_VALUE_BYTES)));
        assert!(!safe_php_param_value(
            &"a".repeat(MAX_PHP_PARAM_VALUE_BYTES + 1)
        ));
        assert!(!safe_php_param_value("bad\nvalue"));
        assert!(!safe_php_param_value("bad\x7fvalue"));
    }

    #[test]
    fn php_header_param_names_are_bounded_and_predictable() {
        assert_eq!(
            php_header_param_name("x-request-id").as_deref(),
            Some("HTTP_X_REQUEST_ID")
        );
        assert_eq!(php_header_param_name("proxy"), None);
        assert_eq!(php_header_param_name("content-type"), None);
        assert_eq!(php_header_param_name("content-length"), None);
        assert_eq!(php_header_param_name("bad name"), None);
        assert_eq!(php_header_param_name("bad_name"), None);
    }

    #[test]
    fn php_server_name_prefers_safe_host_then_safe_fallback() {
        assert_eq!(
            php_server_name_param("example.test", "fallback.test"),
            "example.test"
        );
        assert_eq!(
            php_server_name_param("bad\nhost", "fallback.test"),
            "fallback.test"
        );
        assert_eq!(
            php_server_name_param("bad\nhost", "bad\rfallback"),
            "localhost"
        );
    }

    #[test]
    fn php_request_header_params_join_duplicate_headers_and_block_proxy() {
        let params = php_request_header_params([
            ("cookie", "wordpress_logged_in=abc"),
            ("cookie", "wordpress_sec=def"),
            ("proxy", "http://attacker.invalid"),
            ("x-request-id", "req-1"),
            ("x-request-id", "req-2"),
        ]);

        assert_eq!(
            params,
            vec![
                (
                    "HTTP_COOKIE".to_owned(),
                    "wordpress_logged_in=abc; wordpress_sec=def".to_owned()
                ),
                ("HTTP_X_REQUEST_ID".to_owned(), "req-1, req-2".to_owned())
            ]
        );
    }

    #[test]
    fn php_request_header_params_cap_joined_values() {
        let cookie = "a".repeat(MAX_PHP_PARAM_VALUE_BYTES / 2);
        let params = php_request_header_params([
            ("cookie", cookie.as_str()),
            ("cookie", cookie.as_str()),
            ("cookie", cookie.as_str()),
        ]);
        let (_, value) = params
            .iter()
            .find(|(name, _)| name == "HTTP_COOKIE")
            .expect("cookie param should be present");
        assert!(value.len() <= MAX_PHP_PARAM_VALUE_BYTES);
    }

    #[test]
    fn php_host_content_type_and_custom_params_share_runtime_policy() {
        assert_eq!(
            php_host_param("example.test"),
            Some(("HTTP_HOST".to_owned(), "example.test".to_owned()))
        );
        assert_eq!(php_host_param("bad\nhost"), None);
        assert_eq!(
            php_content_type_param_value(["text/plain", "charset=utf-8"]),
            "text/plain, charset=utf-8"
        );
        assert_eq!(php_content_type_param_value(["text/plain\nbad"]), "");
        assert_eq!(
            php_content_type_param_value(["a".repeat(MAX_PHP_PARAM_VALUE_BYTES + 1).as_str()]),
            ""
        );
        let half = "a".repeat(MAX_PHP_PARAM_VALUE_BYTES / 2);
        assert_eq!(
            php_content_type_param_value([half.as_str(), half.as_str(), half.as_str()]),
            ""
        );

        let (accepted, dropped) = php_custom_params([
            ("SAFE_PARAM", "ok"),
            ("SCRIPT_FILENAME", "/tmp/bypass.php"),
            ("PHP_VALUE", "memory_limit=256M"),
            ("BAD_VALUE", "bad\nvalue"),
        ]);
        assert_eq!(accepted, vec![("SAFE_PARAM".to_owned(), "ok".to_owned())]);
        assert_eq!(
            dropped,
            vec![
                "SCRIPT_FILENAME".to_owned(),
                "PHP_VALUE".to_owned(),
                "BAD_VALUE".to_owned()
            ]
        );
    }

    #[test]
    fn php_fpm_path_mapping_supports_split_container_roots_and_rejects_unsafe_path_info() {
        let root = Path::new("site/root");
        let fpm_root = Path::new("container/root");
        let local_script = Path::new("site/root/public/index.php");

        assert_eq!(
            php_fpm_script_filename(root, fpm_root, local_script).as_deref(),
            Some("container/root/public/index.php")
        );
        assert_eq!(
            php_fpm_script_filename(Path::new("other/root"), fpm_root, local_script),
            None
        );
        assert_eq!(
            php_fpm_path_translated(fpm_root, "/uploads/file.txt").as_deref(),
            Some("container/root/uploads/file.txt")
        );
        assert!(php_fpm_path_translated(fpm_root, "/uploads/../wp-config.php").is_none());
        assert!(php_fpm_path_translated(fpm_root, "/uploads/.secret").is_none());
        assert!(php_fpm_path_translated(fpm_root, "/uploads\\wp-config.php").is_none());
        assert!(php_fpm_path_translated(fpm_root, "/uploads/file\x01.txt").is_none());
    }

    #[test]
    fn php_script_name_parser_accepts_direct_script_and_front_controller() {
        let allowed = vec!["php".to_owned()];

        let direct = php_script_name_for_request(
            "/app.php",
            "index.php",
            PhpPathInfoMode::Disabled,
            &allowed,
        )
        .expect("direct PHP script should parse");
        assert_eq!(direct.script_name, "/app.php");
        assert_eq!(direct.path_info, "");
        assert!(direct.explicit_php);

        let front = php_script_name_for_request(
            "/missing/page",
            "index.php",
            PhpPathInfoMode::Disabled,
            &allowed,
        )
        .expect("front controller fallback should parse");
        assert_eq!(front.script_name, "/index.php");
        assert_eq!(front.path_info, "");
        assert!(!front.explicit_php);
    }

    #[test]
    fn php_script_name_parser_rejects_unsafe_segments_and_controls() {
        let allowed = vec!["php".to_owned()];

        assert!(
            php_script_name_for_request(
                "/../app.php",
                "index.php",
                PhpPathInfoMode::Disabled,
                &allowed
            )
            .is_none()
        );
        assert!(
            php_script_name_for_request(
                "/app.php/.hidden",
                "index.php",
                PhpPathInfoMode::Split,
                &allowed
            )
            .is_none()
        );
        assert!(
            php_script_name_for_request(
                "/app.php/user%01admin",
                "index.php",
                PhpPathInfoMode::Split,
                &allowed
            )
            .is_none()
        );
        assert!(
            php_script_name_for_request(
                "/app.php/user%7Fadmin",
                "index.php",
                PhpPathInfoMode::Split,
                &allowed
            )
            .is_none()
        );
    }

    #[test]
    fn php_script_name_parser_respects_path_info_and_deny_prefixes() {
        let allowed = vec!["php".to_owned()];

        assert!(
            php_script_name_for_request(
                "/app.php/user/1",
                "index.php",
                PhpPathInfoMode::Disabled,
                &allowed
            )
            .is_none()
        );
        let split = php_script_name_for_request(
            "/app.php/user/1",
            "index.php",
            PhpPathInfoMode::Split,
            &allowed,
        )
        .expect("split PATH_INFO should parse");
        assert_eq!(split.script_name, "/app.php");
        assert_eq!(split.path_info, "/user/1");
        assert!(split.explicit_php);

        let deny = vec!["/wp-content/uploads/".to_owned()];
        assert!(php_script_name_denied(
            &deny,
            "/wp-content/uploads/shell.php"
        ));
        assert!(!php_script_name_denied(
            &deny,
            "/wp-content/uploads2/app.php"
        ));
        assert!(php_segment_has_allowed_extension("index.PHP", &allowed));
        assert!(!php_segment_has_allowed_extension("style.css", &allowed));
    }

    #[test]
    fn php_static_file_script_names_are_rooted_and_hidden_safe() {
        let allowed = vec!["php".to_owned()];
        let root = Path::new("/srv/www");

        assert_eq!(
            php_static_file_script_name(root, Path::new("/srv/www/blog/index.php"), &allowed),
            Some("/blog/index.php".to_owned())
        );
        assert_eq!(
            php_static_file_script_name(root, Path::new("/srv/www/admin.PHP"), &allowed),
            Some("/admin.PHP".to_owned())
        );
        assert!(
            php_static_file_script_name(root, Path::new("/srv/www/assets/style.css"), &allowed)
                .is_none()
        );
        assert!(
            php_static_file_script_name(root, Path::new("/srv/www/.hidden/index.php"), &allowed)
                .is_none()
        );
        assert!(
            php_static_file_script_name(root, Path::new("/srv/other/index.php"), &allowed)
                .is_none()
        );
    }

    #[test]
    fn php_directory_index_redirect_policy_matches_runtime() {
        assert!(php_should_redirect_directory_index(
            "/blog",
            "/blog/index.php",
            "index.php"
        ));
        assert!(!php_should_redirect_directory_index(
            "/blog/",
            "/blog/index.php",
            "index.php"
        ));
        assert!(!php_should_redirect_directory_index(
            "/blog\\",
            "/blog/index.php",
            "index.php"
        ));
        assert!(!php_should_redirect_directory_index(
            "/blog",
            "/blog/admin.php",
            "index.php"
        ));
    }

    #[test]
    fn php_static_offload_policy_rejects_controls_and_script_targets() {
        let allowed = vec!["php".to_owned()];

        assert_eq!(
            super::php_static_offload_uri_target("/style.css").unwrap(),
            "/style.css"
        );
        assert!(super::php_static_offload_uri_target("/style.css\nbad").is_err());
        assert!(super::php_static_offload_file_allowed(
            Path::new("/srv/www/style.css"),
            &allowed
        ));
        assert!(!super::php_static_offload_file_allowed(
            Path::new("/srv/www/app.PHP"),
            &allowed
        ));
        assert!(!super::php_static_offload_file_allowed(
            Path::new("/srv/www/wp-config"),
            &allowed
        ));
        assert!(!super::php_static_offload_file_allowed(
            Path::new("/srv/www/file."),
            &allowed
        ));
    }

    #[test]
    fn php_x_sendfile_targets_map_from_fpm_root_to_local_root() {
        let root = Path::new("/srv/www");
        let fpm_root = Path::new("/app/public");

        assert_eq!(
            super::php_static_offload_x_sendfile_local_path(
                root,
                fpm_root,
                "/app/public/assets/style.css"
            )
            .unwrap(),
            Path::new("/srv/www/assets/style.css")
        );
        assert_eq!(
            super::php_static_offload_x_sendfile_local_path(
                root,
                fpm_root,
                "/app/public/../secret.txt"
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            super::php_static_offload_x_sendfile_local_path(root, fpm_root, "/other/style.css")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            super::php_static_offload_x_sendfile_local_path(
                root,
                fpm_root,
                "/app/public/style.css\nbad"
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn php_x_accel_expires_ttl_parser_is_bounded() {
        let future = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        let ttl = super::php_x_accel_expires_ttl_secs(&format!("@{future}")).unwrap();

        assert!(ttl <= 60);
        assert!(ttl > 0);
        assert_eq!(super::php_x_accel_expires_ttl_secs("120"), Some(120));
        assert_eq!(super::php_x_accel_expires_ttl_secs("0"), Some(0));
        assert_eq!(super::php_x_accel_expires_ttl_secs("-1"), Some(0));
        assert_eq!(super::php_x_accel_expires_ttl_secs("bad"), None);
    }

    #[test]
    fn php_origin_cache_policy_detects_restrictive_directives() {
        assert!(super::php_origin_cache_policy_is_restrictive(
            ["public, private=max-age=1"],
            []
        ));
        assert!(super::php_origin_cache_policy_is_restrictive(
            ["public, no-store"],
            []
        ));
        assert!(super::php_origin_cache_policy_is_restrictive(
            ["public"],
            ["no-cache"]
        ));
        assert!(!super::php_origin_cache_policy_is_restrictive(
            ["public, max-age=60"],
            []
        ));
    }

    #[test]
    fn php_response_header_strip_policy_includes_connection_tokens_and_hidden_names() {
        let hidden = vec!["x-powered-by".to_owned()];
        let headers =
            super::php_response_headers_to_strip(["x-hop, keep-alive, bad token"], &hidden);

        assert!(headers.iter().any(|header| header == "connection"));
        assert!(headers.iter().any(|header| header == "transfer-encoding"));
        assert!(headers.iter().any(|header| header == "x-hop"));
        assert!(headers.iter().any(|header| header == "keep-alive"));
        assert!(!headers.iter().any(|header| header == "bad token"));
        assert!(headers.iter().any(|header| header == "x-powered-by"));
    }

    #[test]
    fn php_static_offload_header_names_are_shared_policy() {
        assert_eq!(
            super::PHP_STATIC_OFFLOAD_RESPONSE_HEADERS,
            &["x-accel-redirect", "x-sendfile"]
        );
    }

    #[test]
    fn php_error_page_or_intercept_status_enables_interception() {
        assert!(super::php_should_intercept_error_status(502, [502], &[]));
        assert!(super::php_should_intercept_error_status(503, [], &[503]));
        assert!(!super::php_should_intercept_error_status(
            404,
            [502],
            &[503]
        ));
    }

    #[test]
    fn php_response_primitives_parse_headers_status_and_body() {
        let (headers, body) = split_php_response(b"Status: 201 Created\r\nX-Test: ok\r\n\r\nbody")
            .expect("response should split");
        assert_eq!(headers, b"Status: 201 Created\r\nX-Test: ok");
        assert_eq!(body, b"body");
        assert_eq!(parse_php_status(b"201 Created").unwrap(), 201);
        assert_eq!(trim_ascii_cr(b"value\r"), b"value");
        assert_eq!(trim_ascii(b" \tvalue\t "), b"value");
        assert_eq!(
            split_first_colon(b"x-test: value"),
            Some((&b"x-test"[..], &b" value"[..]))
        );
    }

    #[test]
    fn php_response_primitives_reject_invalid_status() {
        assert!(split_php_response(b"missing terminator").is_err());
        assert!(parse_php_status(b"99").is_err());
        assert!(parse_php_status(b"600").is_err());
        assert!(parse_php_status(b"not-a-status").is_err());
        assert!(parse_php_status(&[0xff]).is_err());
    }

    #[test]
    fn php_response_parser_returns_plain_status_headers_and_body() {
        let response = super::parse_php_response(
            b"X-Before: yes\r\nStatus: 201 Created\r\nX-After: ok\r\n\r\nbody",
            64 * 1024,
            64 * 1024,
        )
        .expect("PHP response should parse");

        assert_eq!(response.status, 201);
        assert_eq!(response.body, b"body");
        assert_eq!(
            response.headers,
            vec![
                ("X-Before".to_owned(), "yes".to_owned()),
                ("X-After".to_owned(), "ok".to_owned())
            ]
        );
    }

    #[test]
    fn php_response_parser_rejects_unsafe_headers_and_size_overflow() {
        let error = super::parse_php_response(b"X-Test: ok\rbad\r\n\r\nbody", 64 * 1024, 64 * 1024)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let error =
            super::parse_php_response(b"Content-Type: text/plain\r\n\r\nbody", 8, 64 * 1024)
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let error = super::parse_php_response(
            b"X-Very-Long-Header: abc\r\n\r\nbody",
            64 * 1024,
            "X-Very-Long-Header: abc".len() as u64 - 1,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn managed_php_fpm_config_contains_private_pool_settings() {
        let fpm = PhpFpmConfig {
            process_manager: PhpFpmProcessManager::Dynamic,
            workers: 8,
            min_spare_servers: Some(2),
            max_spare_servers: Some(6),
            start_servers: Some(4),
            max_spawn_rate: Some(16),
            listen_backlog: Some(128),
            listen_owner: Some("fluxheim".to_owned()),
            listen_group: Some("www-data".to_owned()),
            listen_mode: Some("0660".to_owned()),
            user: Some("fluxheim".to_owned()),
            group: Some("www-data".to_owned()),
            request_terminate_timeout_secs: Some(30),
            request_terminate_timeout_track_finished: true,
            request_slowlog_timeout_secs: Some(5),
            session_save_path: Some(Path::new("/run/fluxheim/php/session").to_path_buf()),
            upload_tmp_dir: Some(Path::new("/run/fluxheim/php/upload").to_path_buf()),
            clear_env: false,
            ..PhpFpmConfig::default()
        };

        let config = managed_php_fpm_config(
            Path::new("/run/fluxheim/php/php-fpm.sock"),
            Path::new("/run/fluxheim/php/php-fpm.pid"),
            Path::new("/run/fluxheim/php/php-fpm.log"),
            Some(Path::new("/run/fluxheim/php/php-fpm.slow.log")),
            &fpm,
        )
        .expect("managed php-fpm config should render");

        assert!(config.contains("listen.mode = 0660\n"));
        assert!(config.contains("listen.owner = fluxheim\n"));
        assert!(config.contains("listen.group = www-data\n"));
        assert!(config.contains("listen.backlog = 128\n"));
        assert!(config.contains("user = fluxheim\n"));
        assert!(config.contains("group = www-data\n"));
        assert!(config.contains("pm = dynamic\n"));
        assert!(config.contains("pm.max_children = 8\n"));
        assert!(config.contains("pm.start_servers = 4\n"));
        assert!(config.contains("pm.min_spare_servers = 2\n"));
        assert!(config.contains("pm.max_spare_servers = 6\n"));
        assert!(config.contains("pm.max_spawn_rate = 16\n"));
        assert!(config.contains("request_terminate_timeout = 30s\n"));
        assert!(config.contains("request_terminate_timeout_track_finished = yes\n"));
        assert!(config.contains("request_slowlog_timeout = 5s\n"));
        assert!(config.contains("slowlog = /run/fluxheim/php/php-fpm.slow.log\n"));
        assert!(config.contains("clear_env = no\n"));
        assert!(config.contains("catch_workers_output = yes\n"));
        assert!(config.contains("decorate_workers_output = yes\n"));
        assert!(config.contains("security.limit_extensions = .php\n"));
        assert!(config.contains("php_value[session.save_path] = /run/fluxheim/php/session\n"));
        assert!(config.contains("php_admin_value[upload_tmp_dir] = /run/fluxheim/php/upload\n"));
    }

    #[test]
    fn managed_php_fpm_config_rejects_unsafe_path_bytes() {
        let error = managed_php_fpm_config(
            Path::new("/run/fluxheim/php/php-fpm.sock"),
            Path::new("/run/fluxheim/php/php-fpm.pid"),
            Path::new("/run/fluxheim/php/php-fpm\".log"),
            None,
            &PhpFpmConfig::default(),
        )
        .expect_err("unsafe config paths should be rejected");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

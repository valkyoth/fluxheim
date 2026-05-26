use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{PhpConfig, PhpFpmConfig, PhpFpmMode, PhpFpmProcessManager};

const MANAGED_PHP_FPM_STABLE_RESTART_SECS: u64 = 30;
static MANAGED_PHP_FPM_INSTANCE_COUNTER: AtomicUsize = AtomicUsize::new(0);
static PHP_REQUEST_BODY_SPOOL_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
pub(crate) struct PhpRequestBody {
    inner: Arc<PhpRequestBodyInner>,
    len: usize,
}

enum PhpRequestBodyInner {
    Memory(Vec<u8>),
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

impl PhpRequestBody {
    pub(crate) fn memory(body: Vec<u8>) -> Self {
        Self {
            len: body.len(),
            inner: Arc::new(PhpRequestBodyInner::Memory(body)),
        }
    }

    pub(crate) fn spooled(path: PathBuf, len: usize) -> Self {
        Self {
            len,
            inner: Arc::new(PhpRequestBodyInner::Spool(PhpRequestBodySpool { path })),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) async fn reader(
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

pub(crate) async fn create_php_request_body_spool_file(
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
pub(crate) fn create_php_request_body_spool_dir_sync(spool_dir: &Path) -> io::Result<()> {
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

pub(crate) fn ensure_php_request_body_spool_dir(spool_dir: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(spool_dir)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PHP request body spool path is not a directory",
        ));
    }
    #[cfg(unix)]
    if crate::fs_trust::existing_path_or_parent_has_insecure_write_permissions(spool_dir)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PHP request body spool directory is group/world writable",
        ));
    }
    Ok(())
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
pub(crate) fn managed_php_fpm_restart_backoff_secs(restart_failures: usize) -> u64 {
    2_u64.saturating_pow(restart_failures.min(5) as u32).min(30)
}

#[cfg(unix)]
fn managed_php_fpm_path_env() -> String {
    managed_php_fpm_path_env_from(std::env::var("PATH").ok())
}

#[cfg(unix)]
pub(crate) fn managed_php_fpm_path_env_from(value: Option<String>) -> String {
    const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

    value
        .filter(|value| {
            !value.is_empty() && value.bytes().all(|byte| !matches!(byte, 0..=31 | 127))
        })
        .unwrap_or_else(|| DEFAULT_PATH.to_owned())
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
fn managed_php_fpm_instance_name(metric_pool: &str) -> io::Result<String> {
    let counter = MANAGED_PHP_FPM_INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|error| {
        io::Error::other(format!(
            "failed to generate managed php-fpm instance entropy: {error}"
        ))
    })?;
    let random = u64::from_le_bytes(random);
    let sanitized = metric_pool
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' => byte as char,
            _ => '-',
        })
        .take(48)
        .collect::<String>();
    let sanitized = if sanitized.is_empty() {
        "php".to_owned()
    } else {
        sanitized
    };
    Ok(format!(
        "fluxheim-php-fpm-{sanitized}-{}-{counter}-{random:016x}",
        std::process::id()
    ))
}

#[cfg(unix)]
pub(crate) fn managed_php_fpm_config(
    socket: &Path,
    pid_path: &Path,
    error_log: &Path,
    slow_log: Option<&Path>,
    fpm: &PhpFpmConfig,
) -> io::Result<String> {
    let socket = php_fpm_config_path_value(socket)?;
    let pid_path = php_fpm_config_path_value(pid_path)?;
    let error_log = php_fpm_config_path_value(error_log)?;
    let slow_log = slow_log.map(php_fpm_config_path_value).transpose()?;
    let session_save_path = fpm
        .session_save_path
        .as_deref()
        .map(php_fpm_config_path_value)
        .transpose()?;
    let upload_tmp_dir = fpm
        .upload_tmp_dir
        .as_deref()
        .map(php_fpm_config_path_value)
        .transpose()?;

    let mut config = String::new();
    config.push_str("[global]\n");
    config.push_str("daemonize = no\n");
    config.push_str(&format!("pid = {pid_path}\n"));
    config.push_str(&format!("error_log = {error_log}\n"));
    config.push('\n');
    config.push_str("[fluxheim]\n");
    config.push_str(&format!("listen = {socket}\n"));
    let listen_mode = match fpm.listen_mode.as_deref() {
        Some(value) => php_fpm_config_listen_mode_value(value)?,
        None => "0600",
    };
    config.push_str(&format!("listen.mode = {}\n", listen_mode));
    if let (Some(listen_owner), Some(listen_group)) = (&fpm.listen_owner, &fpm.listen_group) {
        let listen_owner = php_fpm_config_identity_value(listen_owner)?;
        let listen_group = php_fpm_config_identity_value(listen_group)?;
        config.push_str(&format!("listen.owner = {listen_owner}\n"));
        config.push_str(&format!("listen.group = {listen_group}\n"));
    }
    if let Some(listen_backlog) = fpm.listen_backlog {
        config.push_str(&format!("listen.backlog = {listen_backlog}\n"));
    }
    config.push_str(&managed_php_fpm_identity_config(
        fpm.user.as_deref(),
        fpm.group.as_deref(),
    )?);
    config.push_str(&managed_php_fpm_pool_config(fpm));
    if let Some(request_terminate_timeout_secs) = fpm.request_terminate_timeout_secs {
        config.push_str(&format!(
            "request_terminate_timeout = {request_terminate_timeout_secs}s\n"
        ));
    }
    if fpm.request_terminate_timeout_track_finished {
        config.push_str("request_terminate_timeout_track_finished = yes\n");
    }
    if let Some(request_slowlog_timeout_secs) = fpm.request_slowlog_timeout_secs {
        if let Some(slow_log) = slow_log {
            config.push_str(&format!("slowlog = {slow_log}\n"));
        }
        config.push_str(&format!(
            "request_slowlog_timeout = {request_slowlog_timeout_secs}s\n"
        ));
        config.push_str(&format!(
            "request_slowlog_trace_depth = {}\n",
            fpm.request_slowlog_trace_depth
        ));
    }
    config.push_str(&format!(
        "clear_env = {}\n",
        managed_php_fpm_bool(fpm.clear_env)
    ));
    config.push_str(&format!(
        "catch_workers_output = {}\n",
        managed_php_fpm_bool(fpm.catch_workers_output)
    ));
    config.push_str(&format!(
        "decorate_workers_output = {}\n",
        managed_php_fpm_bool(fpm.decorate_workers_output)
    ));
    config.push_str("chdir = /\n");
    config.push_str("security.limit_extensions = .php\n");
    if let Some(session_save_path) = session_save_path {
        config.push_str(&format!(
            "php_value[session.save_path] = {session_save_path}\n"
        ));
    }
    if let Some(upload_tmp_dir) = upload_tmp_dir {
        config.push_str(&format!(
            "php_admin_value[upload_tmp_dir] = {upload_tmp_dir}\n"
        ));
    }
    Ok(config)
}

#[cfg(unix)]
fn managed_php_fpm_pool_config(fpm: &PhpFpmConfig) -> String {
    let mut config = String::new();
    match fpm.process_manager {
        PhpFpmProcessManager::Static => {
            config.push_str("pm = static\n");
            config.push_str(&format!("pm.max_children = {}\n", fpm.workers));
        }
        PhpFpmProcessManager::Dynamic => {
            let min_spare = fpm.min_spare_servers.unwrap_or(1);
            let max_spare = fpm.max_spare_servers.unwrap_or(fpm.workers.max(min_spare));
            let start_servers = fpm
                .start_servers
                .unwrap_or_else(|| (min_spare.saturating_add(max_spare) / 2).max(1));
            config.push_str("pm = dynamic\n");
            config.push_str(&format!("pm.max_children = {}\n", fpm.workers));
            config.push_str(&format!("pm.start_servers = {start_servers}\n"));
            config.push_str(&format!("pm.min_spare_servers = {min_spare}\n"));
            config.push_str(&format!("pm.max_spare_servers = {max_spare}\n"));
            if let Some(max_spawn_rate) = fpm.max_spawn_rate {
                config.push_str(&format!("pm.max_spawn_rate = {max_spawn_rate}\n"));
            }
        }
        PhpFpmProcessManager::Ondemand => {
            config.push_str("pm = ondemand\n");
            config.push_str(&format!("pm.max_children = {}\n", fpm.workers));
            if let Some(process_idle_timeout_secs) = fpm.process_idle_timeout_secs {
                config.push_str(&format!(
                    "pm.process_idle_timeout = {process_idle_timeout_secs}s\n"
                ));
            }
        }
    }
    config.push_str(&format!(
        "pm.max_requests = {}\n",
        fpm.max_requests_per_worker
    ));
    config
}

#[cfg(unix)]
fn managed_php_fpm_bool(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
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
fn managed_php_fpm_identity_config(user: Option<&str>, group: Option<&str>) -> io::Result<String> {
    match (user, group) {
        (Some(user), Some(group)) => {
            let user = php_fpm_config_identity_value(user)?;
            let group = php_fpm_config_identity_value(group)?;
            Ok(format!("user = {user}\ngroup = {group}\n"))
        }
        _ => Ok(String::new()),
    }
}

#[cfg(unix)]
fn php_fpm_config_identity_value(value: &str) -> io::Result<&str> {
    if value.is_empty()
        || value.len() > 64
        || value.starts_with('-')
        || !value.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.' | b'-'),
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed php-fpm identity contains bytes unsafe for php-fpm config",
        ));
    }
    Ok(value)
}

#[cfg(unix)]
fn php_fpm_config_listen_mode_value(value: &str) -> io::Result<&str> {
    match value {
        "0600" | "0660" => Ok(value),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed php-fpm listen mode must be 0600 or 0660",
        )),
    }
}

#[cfg(unix)]
fn php_fpm_config_path_value(path: &Path) -> io::Result<&str> {
    let value = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed php-fpm path is not valid UTF-8",
        )
    })?;
    if value
        .bytes()
        .any(|byte| matches!(byte, 0..=31 | 127 | b'\'' | b'"'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "managed php-fpm path contains bytes unsafe for php-fpm config",
        ));
    }
    Ok(value)
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

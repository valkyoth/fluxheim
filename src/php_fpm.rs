use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::http_types::{PingoraResponseHeader as ResponseHeader, StatusCode};

use crate::config::{PhpConfig, PhpFpmConfig, PhpFpmMode};
use crate::flux_error::{FluxError, FluxResult};
#[cfg(test)]
pub(crate) use fluxheim_php_fpm::php_fpm_retry_attempts;
pub(crate) use fluxheim_php_fpm::{
    PhpFpmEndpoint, PhpFpmTimeoutKind, managed_php_fpm_config, managed_php_fpm_instance_name,
    managed_php_fpm_path_env_from, managed_php_fpm_restart_backoff_secs,
    php_fpm_effective_connect_timeout, php_fpm_effective_request_timeout,
    php_fpm_endpoints_from_config, php_fpm_error_outcome,
    php_fpm_retry_attempts_for_endpoint_count, php_fpm_retry_deadline,
    php_fpm_retry_deadline_allows, php_fpm_retryable_error, php_fpm_retryable_status,
    php_fpm_timeout_error, safe_php_header_name, safe_php_header_value, split_first_colon,
    split_php_response, trim_ascii, trim_ascii_cr,
};

const MANAGED_PHP_FPM_STABLE_RESTART_SECS: u64 = 30;
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

pub(crate) struct PhpFpmPool {
    endpoint: PhpFpmEndpoint,
    metric_vhost: String,
    metric_pool: String,
    max_idle: usize,
    idle_timeout: Duration,
    max_response_bytes: u64,
    idle: tokio::sync::Mutex<Vec<PhpFpmPoolEntry>>,
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
            ))
        })
        .collect()
}

impl PhpFpmPool {
    #[cfg(test)]
    pub(crate) fn metric_pool(&self) -> &str {
        &self.metric_pool
    }

    fn from_endpoint(
        endpoint: PhpFpmEndpoint,
        config: &PhpFpmConfig,
        metric_vhost: &str,
        metric_pool: &str,
        max_response_bytes: u64,
    ) -> Self {
        Self {
            endpoint,
            metric_vhost: metric_vhost.to_owned(),
            metric_pool: metric_pool.to_owned(),
            max_idle: config.pool_max_idle,
            idle_timeout: Duration::from_secs(config.idle_timeout_secs),
            max_response_bytes,
            idle: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    fn record_pool_event(&self, event: &str) {
        #[cfg(feature = "metrics")]
        crate::metrics::record_php_fpm_pool_event(&self.metric_vhost, &self.metric_pool, event);
        let _ = event;
    }

    fn record_pool_idle(&self, idle_connections: usize) {
        #[cfg(feature = "metrics")]
        crate::metrics::record_php_fpm_pool_idle(
            &self.metric_vhost,
            &self.metric_pool,
            idle_connections,
        );
        let _ = idle_connections;
    }

    pub(crate) async fn execute(
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

pub(crate) async fn collect_php_fpm_response_stream<S>(
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

pub(crate) fn push_php_fpm_stream_chunk(
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
    if stdout.len() as u64 > max_response_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "php-fpm response exceeds maximum buffered size",
        ));
    }
    let (header_bytes, body) = split_php_response(stdout)?;
    if header_bytes.len() as u64 > max_response_header_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "php-fpm response headers exceed maximum size",
        ));
    }

    let mut status = 200;
    let mut response = php_response_header(status).map_err(FluxError::into_io)?;
    for line in header_bytes.split(|byte| *byte == b'\n') {
        let line = trim_ascii_cr(line);
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = split_first_colon(line) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "php-fpm response header is malformed",
            ));
        };
        let name = trim_ascii(name);
        let value = trim_ascii(value);
        if !safe_php_header_name(name) || !safe_php_header_value(value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "php-fpm response header contains unsafe bytes",
            ));
        }
        if name.eq_ignore_ascii_case(b"status") {
            status = fluxheim_php_fpm::parse_php_status(value)?;
            response.status = StatusCode::from_u16(status)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            continue;
        }
        let name = std::str::from_utf8(name)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let value = std::str::from_utf8(value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        response
            .append_header(name.to_owned(), value.to_owned())
            .map_err(|error| io::Error::other(error.to_string()))?;
    }

    Ok((response, body.to_vec()))
}

pub fn fuzz_parse_php_response(stdout: &[u8]) -> io::Result<()> {
    let _ = parse_php_response(stdout, 1024 * 1024, 64 * 1024)?;
    Ok(())
}

pub(crate) fn php_response_header(status: u16) -> FluxResult<ResponseHeader> {
    ResponseHeader::build(status, Some(8))
        .map_err(|error| FluxError::invalid_input(error.to_string()))
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

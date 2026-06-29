use std::error::Error;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
#[cfg(feature = "proxy")]
use std::process;
#[cfg(feature = "proxy")]
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

#[cfg(feature = "proxy")]
use crate::background::{FluxBackgroundReady, FluxBackgroundTask, FluxShutdown};
use fluxheim_server::NativeHttp1Response;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts,
};
use sanitization::ct::ConstantTimeEq;
use sha2::{Digest, Sha256};
#[cfg(feature = "proxy")]
use tokio::net::TcpListener;
use zeroize::Zeroizing;

static PROXY_REQUESTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static HOST_ROUTING_REJECTIONS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static EDGE_POLICY_EVENTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static LOAD_BALANCER_EVENTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static LOAD_BALANCER_QUEUE_WAIT_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static LOAD_BALANCER_POOLS: OnceLock<IntGaugeVec> = OnceLock::new();
static RESPONSE_COMPRESSIONS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static STREAM_CONNECTIONS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static STREAM_BYTES_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static UDP_DATAGRAMS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static UDP_DROPS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static UDP_ACTIVE_SESSIONS: OnceLock<IntGaugeVec> = OnceLock::new();
static ADMIN_AUTH_EVENTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static ACME_EVENTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static PHP_REQUESTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static PHP_REQUEST_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static PHP_STDERR_EVENTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static PHP_FPM_RETRIES_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static PHP_FPM_POOL_IDLE_CONNECTIONS: OnceLock<IntGaugeVec> = OnceLock::new();
static PHP_FPM_POOL_EVENTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CACHE_VHOSTS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_ENABLED_VHOSTS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_TIERED_VHOSTS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_CONFIGURED_ROUTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_POLICY_ROUTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_ENABLED_ROUTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_TIERED_ROUTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_MEMORY_TIERS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_TIERS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_LOCK_ENABLED_POLICIES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_LOCK_WAIT_TIMEOUT_MAX_SECONDS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_ORIGIN_PROTECTION_ENABLED_POLICIES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_ORIGIN_PROTECTION_MAX_CONCURRENT_FILLS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_PEER_FILL_ENABLED_POLICIES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_PEER_FILL_PEERS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_PEER_FILL_MAX_CONCURRENT_REQUESTS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_MEMORY_ENTRIES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_MEMORY_WEIGHTED_SIZE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_MEMORY_MAX_SIZE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_MEMORY_FILL_RATIO_PER_MILLE: OnceLock<IntGauge> = OnceLock::new();
static CACHE_MEMORY_PURGE_INDEX_ENTRIES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_ENTRIES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_SIZE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_ALLOCATED_SIZE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_FREE_SIZE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_FREE_RANGE_COUNT: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_LARGEST_FREE_RANGE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_BIN_FILES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_MAX_SIZE_BYTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_FILL_RATIO_PER_MILLE: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_PURGE_INDEX_ENTRIES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_ACTIVITY_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CACHE_ACTIVITY_SCOPE_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CACHE_OPERATION_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static CACHE_PURGES_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CACHE_PURGER_RUNS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CACHE_PURGER_ENTRIES_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CACHE_PURGER_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static METRICS_OTLP_EXPORTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

const MAX_METRICS_TOKEN_BYTES: usize = 8 * 1024;
const MAX_METRICS_TOKEN_FILE_BYTES: u64 = MAX_METRICS_TOKEN_BYTES as u64;

pub fn enabled() -> bool {
    true
}

pub fn prometheus_text() -> Result<Vec<u8>, prometheus::Error> {
    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new().encode(&metric_families, &mut output)?;
    Ok(output)
}

pub fn native_prometheus_response() -> Result<NativeHttp1Response, prometheus::Error> {
    Ok(NativeHttp1Response::new(200, "OK", prometheus_text()?)
        .with_header("content-type", prometheus::TextEncoder::new().format_type()))
}

fn native_prometheus_head_response() -> Result<NativeHttp1Response, prometheus::Error> {
    let body = prometheus_text()?;
    Ok(NativeHttp1Response::new(200, "OK", Vec::new())
        .with_content_length(body.len() as u64)
        .with_header("content-type", prometheus::TextEncoder::new().format_type()))
}

fn native_metrics_target_allowed(target: &str) -> bool {
    let path = native_metrics_target_path(target);
    path.split_once('?').map_or(path, |(path, _)| path) == "/metrics"
}

fn native_metrics_target_path(target: &str) -> &str {
    if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        return rest.find('/').map_or("/", |index| &rest[index..]);
    }
    target
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct NativeMetricsApp {
    bearer_token: Option<Zeroizing<String>>,
}

impl fmt::Debug for NativeMetricsApp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeMetricsApp")
            .field("bearer_token_configured", &self.bearer_token.is_some())
            .finish()
    }
}

impl NativeMetricsApp {
    pub const fn new() -> Self {
        Self { bearer_token: None }
    }

    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(Zeroizing::new(token.into()));
        self
    }
}

pub(crate) fn native_metrics_app_from_config(
    config: &crate::config::MetricsConfig,
) -> Result<NativeMetricsApp, Box<dyn Error + Send + Sync>> {
    let Some(token) = load_native_metrics_token(config)? else {
        return Ok(NativeMetricsApp::new());
    };
    Ok(NativeMetricsApp {
        bearer_token: Some(token),
    })
}

#[cfg(feature = "proxy")]
pub(crate) fn metrics_background_service_from_config(
    config: &crate::config::MetricsConfig,
) -> Result<
    Option<crate::background::FluxBackgroundService<NativeMetricsTask>>,
    Box<dyn Error + Send + Sync>,
> {
    if !config.enabled {
        return Ok(None);
    }
    let app = native_metrics_app_from_config(config)?;
    Ok(Some(crate::background::FluxBackgroundService::new(
        "Fluxheim metrics HTTP",
        NativeMetricsTask {
            listen: config.listen.clone(),
            app: Arc::new(app),
        },
    )))
}

#[cfg(feature = "proxy")]
pub(crate) struct NativeMetricsTask {
    listen: String,
    app: Arc<NativeMetricsApp>,
}

#[cfg(feature = "proxy")]
#[async_trait::async_trait]
impl FluxBackgroundTask for NativeMetricsTask {
    async fn start(&self, mut shutdown: FluxShutdown, mut ready: FluxBackgroundReady) {
        let listener = match TcpListener::bind(&self.listen).await {
            Ok(listener) => listener,
            Err(error) => {
                log::error!(
                    target: "fluxheim::metrics",
                    "failed to bind native metrics listener {}: {error}",
                    self.listen
                );
                process::exit(1);
            }
        };
        ready.notify_ready();
        if let Err(error) = fluxheim_server::serve_native_http1_listener(
            listener,
            fluxheim_server::DownstreamHttp1Policy::default(),
            self.app.clone(),
            async move {
                let _ = shutdown.wait_for_shutdown().await;
            },
        )
        .await
        {
            log::error!(
                target: "fluxheim::metrics",
                "native metrics listener {} stopped unexpectedly: {error}",
                self.listen
            );
            process::exit(1);
        }
    }
}

fn load_native_metrics_token(
    config: &crate::config::MetricsConfig,
) -> Result<Option<Zeroizing<String>>, Box<dyn Error + Send + Sync>> {
    let raw = match (&config.token_env, &config.token_file) {
        (Some(_), None) => {
            return Err(
                "metrics.token_env is disabled; use metrics.token_file for bearer auth".into(),
            );
        }
        (None, Some(path)) => Some(read_metrics_secret_file(path)?),
        (None, None) => None,
        (Some(_), Some(_)) => return Err("metrics token source is invalid".into()),
    };
    let Some(raw) = raw else {
        return Ok(None);
    };
    let token = Zeroizing::new(raw.trim().to_owned());
    if token.is_empty() {
        Err("metrics token cannot be empty".into())
    } else if token.len() > MAX_METRICS_TOKEN_BYTES {
        Err(format!("metrics token cannot exceed {MAX_METRICS_TOKEN_BYTES} bytes").into())
    } else {
        Ok(Some(token))
    }
}

fn read_metrics_secret_file(
    path: &Path,
) -> Result<Zeroizing<String>, Box<dyn Error + Send + Sync>> {
    if metrics_secret_parent_path_contains_symlink(path).map_err(|error| {
        format!(
            "failed to inspect metrics token parent path {}: {error}",
            path.display()
        )
    })? {
        return Err(format!(
            "metrics token file {} must not be below a symlinked directory",
            path.display()
        )
        .into());
    }

    #[cfg(unix)]
    if crate::fs_trust::existing_parent_has_insecure_write_permissions(path).map_err(|error| {
        format!(
            "failed to inspect metrics token parent path {}: {error}",
            path.display()
        )
    })? {
        return Err(format!(
            "metrics token file {} must not be below a group- or world-writable directory",
            path.display()
        )
        .into());
    }

    let file = open_regular_metrics_secret_file(path)?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "failed to inspect metrics token file {}: {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "metrics token file {} must be a regular file",
            path.display()
        )
        .into());
    }
    if metadata.len() > MAX_METRICS_TOKEN_FILE_BYTES {
        return Err(format!(
            "metrics token file {} is too large; limit is {MAX_METRICS_TOKEN_FILE_BYTES} bytes",
            path.display()
        )
        .into());
    }

    read_bounded_metrics_secret_file(file, path, MAX_METRICS_TOKEN_FILE_BYTES)
}

fn read_bounded_metrics_secret_file(
    file: fs::File,
    path: &Path,
    max_bytes: u64,
) -> Result<Zeroizing<String>, Box<dyn Error + Send + Sync>> {
    let mut token = Zeroizing::new(String::new());
    let mut limited = file.take(max_bytes.saturating_add(1));
    limited.read_to_string(&mut token).map_err(|error| {
        format!(
            "failed to read metrics token file {}: {error}",
            path.display()
        )
    })?;
    if token.len() as u64 > max_bytes {
        return Err(format!(
            "metrics token file {} changed while reading and exceeded {max_bytes} bytes",
            path.display(),
        )
        .into());
    }
    Ok(token)
}

fn metrics_secret_parent_path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let Some(parent) = path.parent() else {
        return Ok(false);
    };
    if parent.as_os_str().is_empty() {
        return Ok(false);
    }

    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

#[cfg(unix)]
fn open_regular_metrics_secret_file(path: &Path) -> Result<fs::File, Box<dyn Error + Send + Sync>> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(rustix_to_io_error)
    .map_err(|error| {
        format!(
            "failed to open metrics token file {} without following symlinks: {error}",
            path.display()
        )
    })?;
    Ok(fd.into())
}

#[cfg(not(unix))]
fn open_regular_metrics_secret_file(path: &Path) -> Result<fs::File, Box<dyn Error + Send + Sync>> {
    if fs::symlink_metadata(path)
        .map_err(|error| {
            format!(
                "failed to inspect metrics token file {}: {error}",
                path.display()
            )
        })?
        .file_type()
        .is_symlink()
    {
        return Err(format!(
            "metrics token file {} must not be a symlink",
            path.display()
        )
        .into());
    }
    fs::File::open(path).map_err(|error| {
        format!(
            "failed to open metrics token file {}: {error}",
            path.display()
        )
        .into()
    })
}

#[cfg(unix)]
fn rustix_to_io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

fn native_metrics_authorized(request: &fluxheim_server::NativeHttp1Request, token: &str) -> bool {
    request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("authorization")
            && native_metrics_bearer_token_matches(value, token)
    })
}

fn native_metrics_bearer_token_matches(value: &str, token: &str) -> bool {
    let Some(candidate) = value.trim().strip_prefix("Bearer ") else {
        return false;
    };
    let candidate = Zeroizing::new(candidate.as_bytes().to_vec());
    let candidate_digest = metrics_bearer_token_digest(candidate.as_slice());
    let token_digest = metrics_bearer_token_digest(token.as_bytes());
    candidate_digest
        .ct_eq(&token_digest)
        .declassify("native metrics bearer-token comparison result is public")
}

fn metrics_bearer_token_digest(token: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((token.len() as u64).to_le_bytes());
    hasher.update(token);
    hasher.finalize().into()
}

impl fluxheim_server::NativeHttp1Handler for NativeMetricsApp {
    fn handle<'a>(
        &'a self,
        request: fluxheim_server::NativeHttp1Request,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = fluxheim_server::NativeHttp1Response> + Send + 'a>,
    > {
        Box::pin(async move {
            if !native_metrics_target_allowed(&request.target) {
                return fluxheim_server::NativeHttp1Response::new(404, "Not Found", b"not found\n")
                    .close_connection();
            }
            if let Some(token) = &self.bearer_token
                && !native_metrics_authorized(&request, token)
            {
                return fluxheim_server::NativeHttp1Response::new(
                    401,
                    "Unauthorized",
                    b"unauthorized\n",
                )
                .with_header("www-authenticate", "Bearer realm=\"metrics\"")
                .close_connection();
            }
            let response = match request.method.as_str() {
                "GET" => native_prometheus_response(),
                "HEAD" => native_prometheus_head_response(),
                _ => {
                    return fluxheim_server::NativeHttp1Response::new(
                        405,
                        "Method Not Allowed",
                        b"method not allowed\n",
                    )
                    .with_header("allow", "GET, HEAD")
                    .close_connection();
                }
            };
            response.unwrap_or_else(|error| {
                log::debug!("native metrics response unavailable: {error}");
                fluxheim_server::NativeHttp1Response::new(
                    500,
                    "Internal Server Error",
                    b"metrics unavailable\n",
                )
                .close_connection()
            })
        })
    }
}

pub fn init() -> Result<(), prometheus::Error> {
    proxy_requests_total()?;
    host_routing_rejections_total()?;
    edge_policy_events_total()?;
    load_balancer_events_total()?;
    load_balancer_queue_wait_seconds()?;
    load_balancer_pools()?;
    response_compressions_total()?;
    stream_connections_total()?;
    stream_bytes_total()?;
    udp_datagrams_total()?;
    udp_drops_total()?;
    udp_active_sessions()?;
    admin_auth_events_total()?;
    acme_events_total()?;
    php_requests_total()?;
    php_request_duration_seconds()?;
    php_stderr_events_total()?;
    php_fpm_retries_total()?;
    php_fpm_pool_idle_connections()?;
    php_fpm_pool_events_total()?;
    cache_vhosts()?;
    cache_enabled_vhosts()?;
    cache_tiered_vhosts()?;
    cache_configured_routes()?;
    cache_policy_routes()?;
    cache_enabled_routes()?;
    cache_tiered_routes()?;
    cache_memory_tiers()?;
    cache_disk_tiers()?;
    cache_lock_enabled_policies()?;
    cache_lock_wait_timeout_max_seconds()?;
    cache_peer_fill_enabled_policies()?;
    cache_peer_fill_peers()?;
    cache_peer_fill_max_concurrent_requests()?;
    cache_memory_entries()?;
    cache_memory_weighted_size_bytes()?;
    cache_memory_max_size_bytes()?;
    cache_memory_fill_ratio_per_mille()?;
    cache_memory_purge_index_entries()?;
    cache_disk_entries()?;
    cache_disk_size_bytes()?;
    cache_disk_allocated_size_bytes()?;
    cache_disk_free_size_bytes()?;
    cache_disk_free_range_count()?;
    cache_disk_largest_free_range_bytes()?;
    cache_disk_bin_files()?;
    cache_disk_max_size_bytes()?;
    cache_disk_fill_ratio_per_mille()?;
    cache_disk_purge_index_entries()?;
    cache_activity_total()?;
    cache_activity_scope_total()?;
    cache_operation_duration_seconds()?;
    cache_purges_total()?;
    cache_purger_runs_total()?;
    cache_purger_entries_total()?;
    cache_purger_duration_seconds()?;
    metrics_otlp_exports_total()?;
    Ok(())
}

pub fn record_config(config: &crate::config::Config) {
    let stats = crate::config::cache_config_stats(config);
    set_gauge(cache_vhosts(), stats.vhosts);
    set_gauge(cache_enabled_vhosts(), stats.enabled_vhosts);
    set_gauge(cache_tiered_vhosts(), stats.tiered_vhosts);
    set_gauge(cache_configured_routes(), stats.configured_routes);
    set_gauge(cache_policy_routes(), stats.policy_routes);
    set_gauge(cache_enabled_routes(), stats.enabled_routes);
    set_gauge(cache_tiered_routes(), stats.tiered_routes);
    set_gauge(cache_memory_tiers(), stats.memory_tiers);
    set_gauge(cache_disk_tiers(), stats.disk_tiers);
    set_gauge(cache_lock_enabled_policies(), stats.lock_enabled_policies);
    set_gauge(
        cache_lock_wait_timeout_max_seconds(),
        stats.lock_wait_timeout_max_secs,
    );
    set_gauge(
        cache_origin_protection_enabled_policies(),
        stats.origin_protection_enabled_policies,
    );
    set_gauge(
        cache_origin_protection_max_concurrent_fills(),
        stats.origin_protection_max_concurrent_fills,
    );
    set_gauge(
        cache_peer_fill_enabled_policies(),
        stats.peer_fill_enabled_policies,
    );
    set_gauge(cache_peer_fill_peers(), stats.peer_fill_peers);
    set_gauge(
        cache_peer_fill_max_concurrent_requests(),
        stats.peer_fill_max_concurrent_requests,
    );
    record_load_balancer_config_stats(&crate::config::load_balancer_config_stats(config));
}

#[cfg(all(feature = "proxy", feature = "cache"))]
pub fn record_cache_runtime_totals(totals: &crate::proxy::CacheRuntimeTotals) {
    set_gauge(cache_memory_entries(), totals.memory_entries);
    set_gauge(
        cache_memory_weighted_size_bytes(),
        totals.memory_weighted_size_bytes,
    );
    set_gauge(cache_memory_max_size_bytes(), totals.memory_max_size_bytes);
    set_gauge(
        cache_memory_fill_ratio_per_mille(),
        ratio_per_mille(
            totals.memory_weighted_size_bytes,
            totals.memory_max_size_bytes,
        ),
    );
    set_gauge(
        cache_memory_purge_index_entries(),
        totals.memory_purge_index_entries,
    );
    set_gauge(cache_disk_entries(), totals.disk_entries);
    set_gauge(cache_disk_size_bytes(), totals.disk_size_bytes);
    set_gauge(
        cache_disk_allocated_size_bytes(),
        totals.disk_allocated_size_bytes,
    );
    set_gauge(cache_disk_free_size_bytes(), totals.disk_free_size_bytes);
    set_gauge(cache_disk_free_range_count(), totals.disk_free_range_count);
    set_gauge(
        cache_disk_largest_free_range_bytes(),
        totals.disk_largest_free_range_bytes,
    );
    set_gauge(cache_disk_bin_files(), totals.disk_bin_files);
    set_gauge(cache_disk_max_size_bytes(), totals.disk_max_size_bytes);
    set_gauge(
        cache_disk_fill_ratio_per_mille(),
        ratio_per_mille(totals.disk_size_bytes, totals.disk_max_size_bytes),
    );
    set_gauge(
        cache_disk_purge_index_entries(),
        totals.disk_purge_index_entries,
    );
}

pub fn record_native_cache_runtime_totals(totals: &fluxheim_server::NativeCacheRuntimeTotals) {
    set_gauge(cache_memory_entries(), totals.memory_entries);
    set_gauge(
        cache_memory_weighted_size_bytes(),
        totals.memory_weighted_size_bytes,
    );
    set_gauge(cache_memory_max_size_bytes(), totals.memory_max_size_bytes);
    set_gauge(cache_memory_tiers(), totals.memory_tiers);
    set_gauge(
        cache_memory_purge_index_entries(),
        totals.memory_purge_index_entries,
    );
    set_gauge(
        cache_memory_fill_ratio_per_mille(),
        ratio_per_mille(
            totals.memory_weighted_size_bytes,
            totals.memory_max_size_bytes,
        ),
    );
    set_gauge(cache_disk_entries(), totals.disk_entries);
    set_gauge(cache_disk_size_bytes(), totals.disk_size_bytes);
    set_gauge(
        cache_disk_allocated_size_bytes(),
        totals.disk_allocated_size_bytes,
    );
    set_gauge(cache_disk_free_size_bytes(), totals.disk_free_size_bytes);
    set_gauge(cache_disk_free_range_count(), totals.disk_free_range_count);
    set_gauge(
        cache_disk_largest_free_range_bytes(),
        totals.disk_largest_free_range_bytes,
    );
    set_gauge(cache_disk_bin_files(), totals.disk_bin_files);
    set_gauge(cache_disk_max_size_bytes(), totals.disk_max_size_bytes);
    set_gauge(
        cache_disk_fill_ratio_per_mille(),
        ratio_per_mille(totals.disk_size_bytes, totals.disk_max_size_bytes),
    );
    set_gauge(
        cache_disk_purge_index_entries(),
        totals.disk_purge_index_entries,
    );
}

pub fn record_proxy_outcome(vhost: &str, method: &str, status: Option<u16>, error: bool) {
    match proxy_requests_total() {
        Ok(counter) => counter
            .with_label_values(&[
                vhost,
                method_bucket(method),
                outcome_class(status, error),
                status_class(status),
            ])
            .inc(),
        Err(error) => log::debug!("metrics counter unavailable: {error}"),
    }
}

pub fn record_host_routing_rejection(reason: &str) {
    match host_routing_rejections_total() {
        Ok(counter) => counter
            .with_label_values(&[host_routing_reason_label(reason)])
            .inc(),
        Err(error) => log::debug!("metrics counter unavailable: {error}"),
    }
}

pub fn record_edge_policy_event(vhost: &str, route: Option<&str>, policy: &str, outcome: &str) {
    match edge_policy_events_total() {
        Ok(counter) => counter
            .with_label_values(&[
                cache_scope_label(route),
                vhost,
                route.unwrap_or(""),
                edge_policy_label(policy),
                edge_policy_outcome_label(outcome),
            ])
            .inc(),
        Err(error) => log::debug!("metrics edge policy counter unavailable: {error}"),
    }
}

pub fn record_load_balancer_event(
    vhost: &str,
    route: Option<&str>,
    upstream: Option<&str>,
    event: &str,
) {
    match load_balancer_events_total() {
        Ok(counter) => counter
            .with_label_values(&[
                cache_scope_label(route),
                vhost,
                route.unwrap_or(""),
                load_balancer_upstream_label(upstream),
                load_balancer_event_label(event),
            ])
            .inc(),
        Err(error) => log::debug!("metrics load balancer counter unavailable: {error}"),
    }
}

pub fn record_load_balancer_queue_wait(
    vhost: &str,
    route: Option<&str>,
    outcome: &str,
    duration: Duration,
) {
    match load_balancer_queue_wait_seconds() {
        Ok(histogram) => histogram
            .with_label_values(&[
                cache_scope_label(route),
                vhost,
                route.unwrap_or(""),
                load_balancer_queue_outcome_label(outcome),
            ])
            .observe(duration.as_secs_f64()),
        Err(error) => log::debug!("metrics load balancer queue histogram unavailable: {error}"),
    }
}

pub fn record_response_compression(vhost: &str, route: Option<&str>, encoding: &str) {
    match response_compressions_total() {
        Ok(counter) => counter
            .with_label_values(&[
                cache_scope_label(route),
                vhost,
                route.unwrap_or(""),
                compression_encoding_label(encoding),
            ])
            .inc(),
        Err(error) => log::debug!("metrics response compression counter unavailable: {error}"),
    }
}

pub fn record_stream_connection(route: &str, outcome: &str) {
    match stream_connections_total() {
        Ok(counter) => counter
            .with_label_values(&[route, stream_outcome_label(outcome)])
            .inc(),
        Err(error) => log::debug!("metrics stream connection counter unavailable: {error}"),
    }
}

pub fn record_stream_bytes(route: &str, direction: &str, bytes: u64) {
    match stream_bytes_total() {
        Ok(counter) => counter
            .with_label_values(&[route, stream_direction_label(direction)])
            .inc_by(bytes),
        Err(error) => log::debug!("metrics stream bytes counter unavailable: {error}"),
    }
}

pub fn record_udp_datagram(route: &str, mode: &str, direction: &str, outcome: &str) {
    match udp_datagrams_total() {
        Ok(counter) => counter
            .with_label_values(&[
                route,
                udp_mode_label(mode),
                udp_direction_label(direction),
                udp_outcome_label(outcome),
            ])
            .inc(),
        Err(error) => log::debug!("metrics UDP datagram counter unavailable: {error}"),
    }
}

pub fn record_udp_drop(route: &str, reason: &str) {
    match udp_drops_total() {
        Ok(counter) => counter
            .with_label_values(&[route, udp_drop_reason_label(reason)])
            .inc(),
        Err(error) => log::debug!("metrics UDP drop counter unavailable: {error}"),
    }
}

pub fn set_udp_active_sessions(route: &str, active_sessions: usize) {
    match udp_active_sessions() {
        Ok(gauge) => gauge
            .with_label_values(&[route])
            .set(usize_to_i64_saturating(active_sessions)),
        Err(error) => log::debug!("metrics UDP active session gauge unavailable: {error}"),
    }
}

pub fn record_admin_auth_event(event: &str, scope: &str) {
    match admin_auth_events_total() {
        Ok(counter) => counter
            .with_label_values(&[admin_auth_event_label(event), admin_auth_scope_label(scope)])
            .inc(),
        Err(error) => log::debug!("metrics admin auth counter unavailable: {error}"),
    }
}

pub fn record_acme_event(event: &str) {
    match acme_events_total() {
        Ok(counter) => counter.with_label_values(&[acme_event_label(event)]).inc(),
        Err(error) => log::debug!("metrics ACME event counter unavailable: {error}"),
    }
}

pub fn record_php_request(
    vhost: &str,
    method: &str,
    status: Option<u16>,
    outcome: &str,
    duration: Duration,
) {
    match php_requests_total() {
        Ok(counter) => counter
            .with_label_values(&[
                vhost,
                method_bucket(method),
                php_outcome_label(outcome),
                status_class(status),
            ])
            .inc(),
        Err(error) => log::debug!("metrics PHP request counter unavailable: {error}"),
    }
    match php_request_duration_seconds() {
        Ok(histogram) => histogram
            .with_label_values(&[
                vhost,
                method_bucket(method),
                php_outcome_label(outcome),
                status_class(status),
            ])
            .observe(duration.as_secs_f64()),
        Err(error) => log::debug!("metrics PHP request duration unavailable: {error}"),
    }
}

pub fn record_php_fpm_retry(vhost: &str, reason: &str) {
    match php_fpm_retries_total() {
        Ok(counter) => counter
            .with_label_values(&[vhost, php_fpm_retry_reason_label(reason)])
            .inc(),
        Err(error) => log::debug!("metrics PHP FPM retry counter unavailable: {error}"),
    }
}

pub fn record_php_fpm_pool_idle(vhost: &str, pool: &str, idle_connections: usize) {
    match php_fpm_pool_idle_connections() {
        Ok(gauge) => gauge
            .with_label_values(&[vhost, pool])
            .set(usize_to_i64_saturating(idle_connections)),
        Err(error) => log::debug!("metrics PHP FPM pool idle gauge unavailable: {error}"),
    }
}

pub fn record_php_fpm_pool_event(vhost: &str, pool: &str, event: &str) {
    match php_fpm_pool_events_total() {
        Ok(counter) => counter
            .with_label_values(&[vhost, pool, php_fpm_pool_event_label(event)])
            .inc(),
        Err(error) => log::debug!("metrics PHP FPM pool event counter unavailable: {error}"),
    }
}

pub fn record_php_stderr(vhost: &str, state: &str) {
    match php_stderr_events_total() {
        Ok(counter) => counter
            .with_label_values(&[vhost, php_stderr_state_label(state)])
            .inc(),
        Err(error) => log::debug!("metrics PHP STDERR counter unavailable: {error}"),
    }
}

pub fn record_cache_activity(tier: &str, event: &str) {
    match cache_activity_total() {
        Ok(counter) => counter
            .with_label_values(&[cache_tier_label(tier), cache_event_label(event)])
            .inc(),
        Err(error) => log::debug!("metrics counter unavailable: {error}"),
    }
}

pub fn record_cache_activity_scope(vhost: &str, route: Option<&str>, tier: &str, event: &str) {
    match cache_activity_scope_total() {
        Ok(counter) => counter
            .with_label_values(&[
                cache_scope_label(route),
                vhost,
                route.unwrap_or(""),
                cache_tier_label(tier),
                cache_event_label(event),
            ])
            .inc(),
        Err(error) => log::debug!("metrics scoped cache counter unavailable: {error}"),
    }
}

#[cfg(feature = "proxy")]
struct NativeCachePrometheusRecorder;

#[cfg(feature = "proxy")]
impl fluxheim_server::NativeCacheMetricsRecorder for NativeCachePrometheusRecorder {
    fn record_activity(&self, tier: &str, event: &str) {
        record_cache_activity(tier, event);
    }

    fn record_activity_scope(&self, vhost: &str, route: Option<&str>, tier: &str, event: &str) {
        record_cache_activity_scope(vhost, route, tier, event);
    }

    fn record_operation_duration(
        &self,
        vhost: &str,
        route: Option<&str>,
        phase: &str,
        operation: &str,
        duration: Duration,
    ) {
        record_cache_operation_duration(vhost, route, phase, operation, duration);
    }
}

#[cfg(feature = "proxy")]
struct NativeProxyPrometheusRecorder;

#[cfg(feature = "proxy")]
impl fluxheim_server::NativeProxyMetricsRecorder for NativeProxyPrometheusRecorder {
    fn record_outcome(&self, vhost: &str, method: &str, status: u16) {
        record_proxy_outcome(vhost, method, Some(status), false);
    }
}

#[cfg(feature = "proxy")]
pub fn install_native_cache_metrics_recorder() {
    let _ = fluxheim_server::install_native_cache_metrics_recorder(Arc::new(
        NativeCachePrometheusRecorder,
    ));
    let _ = fluxheim_server::install_native_proxy_metrics_recorder(Arc::new(
        NativeProxyPrometheusRecorder,
    ));
}

pub fn record_cache_operation_duration(
    vhost: &str,
    route: Option<&str>,
    phase: &str,
    operation: &str,
    duration: Duration,
) {
    match cache_operation_duration_seconds() {
        Ok(histogram) => histogram
            .with_label_values(&[
                cache_scope_label(route),
                vhost,
                route.unwrap_or(""),
                cache_phase_label(phase),
                cache_operation_label(operation),
            ])
            .observe(duration.as_secs_f64()),
        Err(error) => log::debug!("metrics cache duration histogram unavailable: {error}"),
    }
}

pub fn record_cache_purge(operation: &str, vhost: &str, route: Option<&str>, mode: &str) {
    match cache_purges_total() {
        Ok(counter) => counter
            .with_label_values(&[
                cache_purge_operation_label(operation),
                cache_scope_label(route),
                vhost,
                route.unwrap_or(""),
                cache_purge_mode_label(mode),
            ])
            .inc(),
        Err(error) => log::debug!("metrics cache purge counter unavailable: {error}"),
    }
}

pub fn record_cache_purger_run(outcome: &str) {
    match cache_purger_runs_total() {
        Ok(counter) => counter
            .with_label_values(&[cache_purger_outcome_label(outcome)])
            .inc(),
        Err(error) => log::debug!("metrics cache purger run counter unavailable: {error}"),
    }
}

pub fn record_cache_purger_entries(result: &str, amount: u64) {
    if amount == 0 {
        return;
    }
    match cache_purger_entries_total() {
        Ok(counter) => counter
            .with_label_values(&[cache_purger_entry_result_label(result)])
            .inc_by(amount),
        Err(error) => log::debug!("metrics cache purger entry counter unavailable: {error}"),
    }
}

pub fn record_cache_purger_duration(outcome: &str, duration: Duration) {
    match cache_purger_duration_seconds() {
        Ok(histogram) => histogram
            .with_label_values(&[cache_purger_outcome_label(outcome)])
            .observe(duration.as_secs_f64()),
        Err(error) => log::debug!("metrics cache purger duration histogram unavailable: {error}"),
    }
}

pub fn record_metrics_otlp_export(outcome: &str) {
    match metrics_otlp_exports_total() {
        Ok(counter) => counter
            .with_label_values(&[metrics_otlp_export_outcome_label(outcome)])
            .inc(),
        Err(error) => log::debug!("metrics OTLP exporter counter unavailable: {error}"),
    }
}

fn record_load_balancer_config_stats(stats: &crate::config::LoadBalancerConfigStats) {
    match load_balancer_pools() {
        Ok(gauge) => {
            gauge.reset();
            for ((scope, selection), count) in &stats.pools_by_scope_selection {
                gauge
                    .with_label_values(&[scope, selection])
                    .set(u64_to_i64_saturating(*count));
            }
        }
        Err(error) => log::debug!("metrics load balancer pool gauge unavailable: {error}"),
    }
}

fn set_gauge(gauge: Result<&'static IntGauge, prometheus::Error>, value: u64) {
    match gauge {
        Ok(gauge) => gauge.set(u64_to_i64_saturating(value)),
        Err(error) => log::debug!("metrics gauge unavailable: {error}"),
    }
}

#[cfg(all(feature = "proxy", feature = "cache"))]
fn ratio_per_mille(value: u64, max: u64) -> u64 {
    fluxheim_observability::metrics_ratio_per_mille(value, max)
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    fluxheim_observability::metrics_u64_to_i64_saturating(value)
}

fn usize_to_i64_saturating(value: usize) -> i64 {
    fluxheim_observability::metrics_usize_to_i64_saturating(value)
}

fn proxy_requests_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = PROXY_REQUESTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_proxy_requests_total",
            "Total Fluxheim proxy requests by virtual host, method bucket, outcome class, and status class.",
        ),
        &["vhost", "method", "class", "status_class"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PROXY_REQUESTS_TOTAL.set(counter);
    PROXY_REQUESTS_TOTAL
        .get()
        .ok_or_else(|| prometheus::Error::Msg("metrics counter failed to initialize".to_owned()))
}

fn host_routing_rejections_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = HOST_ROUTING_REJECTIONS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_host_routing_rejections_total",
            "Total Fluxheim strict host-routing rejections by reason.",
        ),
        &["reason"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = HOST_ROUTING_REJECTIONS_TOTAL.set(counter);
    HOST_ROUTING_REJECTIONS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("host routing counter failed to initialize".to_owned())
    })
}

fn edge_policy_events_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = EDGE_POLICY_EVENTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_edge_policy_events_total",
            "Total Fluxheim edge policy enforcement events by configured vhost, optional route, bounded policy, and bounded outcome.",
        ),
        &["scope", "vhost", "route", "policy", "outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = EDGE_POLICY_EVENTS_TOTAL.set(counter);
    EDGE_POLICY_EVENTS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_edge_policy_events_total failed to initialize".to_owned())
    })
}

fn load_balancer_events_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = LOAD_BALANCER_EVENTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_load_balancer_events_total",
            "Total Fluxheim load-balancer events by configured vhost, optional route, optional upstream alias, and bounded event.",
        ),
        &["scope", "vhost", "route", "upstream", "event"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = LOAD_BALANCER_EVENTS_TOTAL.set(counter);
    LOAD_BALANCER_EVENTS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_load_balancer_events_total failed to initialize".to_owned(),
        )
    })
}

fn load_balancer_queue_wait_seconds() -> Result<&'static HistogramVec, prometheus::Error> {
    if let Some(histogram) = LOAD_BALANCER_QUEUE_WAIT_SECONDS.get() {
        return Ok(histogram);
    }

    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "fluxheim_load_balancer_queue_wait_seconds",
            "Fluxheim load-balancer queue wait duration by configured vhost, optional route, and bounded queue outcome.",
        )
        .buckets(vec![
            0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
            60.0,
        ]),
        &["scope", "vhost", "route", "outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(histogram.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = LOAD_BALANCER_QUEUE_WAIT_SECONDS.set(histogram);
    LOAD_BALANCER_QUEUE_WAIT_SECONDS.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_load_balancer_queue_wait_seconds failed to initialize".to_owned(),
        )
    })
}

fn load_balancer_pools() -> Result<&'static IntGaugeVec, prometheus::Error> {
    if let Some(gauge) = LOAD_BALANCER_POOLS.get() {
        return Ok(gauge);
    }

    let gauge = IntGaugeVec::new(
        Opts::new(
            "fluxheim_load_balancer_pools",
            "Configured Fluxheim load-balancer pools by scope and bounded selection algorithm.",
        ),
        &["scope", "selection"],
    )?;
    match prometheus::default_registry().register(Box::new(gauge.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = LOAD_BALANCER_POOLS.set(gauge);
    LOAD_BALANCER_POOLS.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_load_balancer_pools failed to initialize".to_owned())
    })
}

fn response_compressions_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = RESPONSE_COMPRESSIONS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_response_compressions_total",
            "Total Fluxheim-applied response compressions by configured vhost, optional route, and bounded encoding.",
        ),
        &["scope", "vhost", "route", "encoding"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = RESPONSE_COMPRESSIONS_TOTAL.set(counter);
    RESPONSE_COMPRESSIONS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_response_compressions_total failed to initialize".to_owned(),
        )
    })
}

fn stream_connections_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = STREAM_CONNECTIONS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_stream_connections_total",
            "Total Fluxheim TCP stream proxy connections by configured stream route and bounded outcome.",
        ),
        &["route", "outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = STREAM_CONNECTIONS_TOTAL.set(counter);
    STREAM_CONNECTIONS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_stream_connections_total failed to initialize".to_owned())
    })
}

fn stream_bytes_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = STREAM_BYTES_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_stream_bytes_total",
            "Total Fluxheim TCP stream proxy bytes by configured stream route and bounded direction.",
        ),
        &["route", "direction"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = STREAM_BYTES_TOTAL.set(counter);
    STREAM_BYTES_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_stream_bytes_total failed to initialize".to_owned())
    })
}

fn udp_datagrams_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = UDP_DATAGRAMS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_udp_datagrams_total",
            "Total Fluxheim UDP datagrams by configured route, bounded mode, direction, and bounded outcome.",
        ),
        &["route", "mode", "direction", "outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = UDP_DATAGRAMS_TOTAL.set(counter);
    UDP_DATAGRAMS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_udp_datagrams_total failed to initialize".to_owned())
    })
}

fn udp_drops_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = UDP_DROPS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_udp_drops_total",
            "Total Fluxheim UDP datagram drops by configured route and bounded reason.",
        ),
        &["route", "reason"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = UDP_DROPS_TOTAL.set(counter);
    UDP_DROPS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_udp_drops_total failed to initialize".to_owned())
    })
}

fn udp_active_sessions() -> Result<&'static IntGaugeVec, prometheus::Error> {
    if let Some(gauge) = UDP_ACTIVE_SESSIONS.get() {
        return Ok(gauge);
    }

    let gauge = IntGaugeVec::new(
        Opts::new(
            "fluxheim_udp_active_sessions",
            "Current Fluxheim UDP active datagram sessions by configured route.",
        ),
        &["route"],
    )?;
    match prometheus::default_registry().register(Box::new(gauge.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = UDP_ACTIVE_SESSIONS.set(gauge);
    UDP_ACTIVE_SESSIONS.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_udp_active_sessions failed to initialize".to_owned())
    })
}

fn admin_auth_events_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = ADMIN_AUTH_EVENTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_admin_auth_events_total",
            "Total Fluxheim admin authentication security events by event and throttle scope.",
        ),
        &["event", "scope"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = ADMIN_AUTH_EVENTS_TOTAL.set(counter);
    ADMIN_AUTH_EVENTS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("admin auth event counter failed to initialize".to_owned())
    })
}

fn acme_events_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = ACME_EVENTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_acme_events_total",
            "Total Fluxheim managed-ACME lifecycle events by bounded event.",
        ),
        &["event"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = ACME_EVENTS_TOTAL.set(counter);
    ACME_EVENTS_TOTAL
        .get()
        .ok_or_else(|| prometheus::Error::Msg("ACME event counter failed to initialize".to_owned()))
}

fn php_requests_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = PHP_REQUESTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_php_requests_total",
            "Total Fluxheim PHP handler requests by virtual host, method bucket, bounded outcome, and status class.",
        ),
        &["vhost", "method", "outcome", "status_class"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PHP_REQUESTS_TOTAL.set(counter);
    PHP_REQUESTS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("PHP request counter failed to initialize".to_owned())
    })
}

fn php_request_duration_seconds() -> Result<&'static HistogramVec, prometheus::Error> {
    if let Some(histogram) = PHP_REQUEST_DURATION_SECONDS.get() {
        return Ok(histogram);
    }

    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "fluxheim_php_request_duration_seconds",
            "Fluxheim PHP handler request duration by virtual host, method bucket, bounded outcome, and status class.",
        )
        .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        &["vhost", "method", "outcome", "status_class"],
    )?;
    match prometheus::default_registry().register(Box::new(histogram.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PHP_REQUEST_DURATION_SECONDS.set(histogram);
    PHP_REQUEST_DURATION_SECONDS.get().ok_or_else(|| {
        prometheus::Error::Msg("PHP request duration histogram failed to initialize".to_owned())
    })
}

fn php_stderr_events_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = PHP_STDERR_EVENTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_php_stderr_events_total",
            "Total Fluxheim PHP FastCGI STDERR events by virtual host and bounded state.",
        ),
        &["vhost", "state"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PHP_STDERR_EVENTS_TOTAL.set(counter);
    PHP_STDERR_EVENTS_TOTAL
        .get()
        .ok_or_else(|| prometheus::Error::Msg("PHP STDERR counter failed to initialize".to_owned()))
}

fn cache_vhosts() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_VHOSTS,
        "fluxheim_cache_vhosts",
        "Configured Fluxheim virtual hosts visible to cache metrics.",
    )
}

fn cache_enabled_vhosts() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_ENABLED_VHOSTS,
        "fluxheim_cache_enabled_vhosts",
        "Configured Fluxheim virtual hosts with cache enabled.",
    )
}

fn cache_tiered_vhosts() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_TIERED_VHOSTS,
        "fluxheim_cache_tiered_vhosts",
        "Configured Fluxheim virtual hosts using both memory and disk cache tiers.",
    )
}

fn cache_configured_routes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_CONFIGURED_ROUTES,
        "fluxheim_cache_configured_routes",
        "Configured Fluxheim routes visible to cache metrics.",
    )
}

fn cache_policy_routes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_POLICY_ROUTES,
        "fluxheim_cache_policy_routes",
        "Configured Fluxheim routes with an explicit cache policy.",
    )
}

fn cache_enabled_routes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_ENABLED_ROUTES,
        "fluxheim_cache_enabled_routes",
        "Configured Fluxheim routes with an explicit enabled cache policy.",
    )
}

fn cache_tiered_routes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_TIERED_ROUTES,
        "fluxheim_cache_tiered_routes",
        "Configured Fluxheim routes using both memory and disk cache tiers.",
    )
}

fn cache_memory_tiers() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_MEMORY_TIERS,
        "fluxheim_cache_memory_tiers",
        "Configured Fluxheim cache memory tiers across vhosts and routes.",
    )
}

fn cache_disk_tiers() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_TIERS,
        "fluxheim_cache_disk_tiers",
        "Configured Fluxheim cache disk tiers across vhosts and routes.",
    )
}

fn cache_lock_enabled_policies() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_LOCK_ENABLED_POLICIES,
        "fluxheim_cache_lock_enabled_policies",
        "Configured Fluxheim cache policies with request-collapsing locks enabled and at least one storage tier.",
    )
}

fn cache_lock_wait_timeout_max_seconds() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_LOCK_WAIT_TIMEOUT_MAX_SECONDS,
        "fluxheim_cache_lock_wait_timeout_max_seconds",
        "Maximum configured Fluxheim cache request-collapsing wait timeout across lock-enabled cache policies.",
    )
}

fn cache_origin_protection_enabled_policies() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_ORIGIN_PROTECTION_ENABLED_POLICIES,
        "fluxheim_cache_origin_protection_enabled_policies",
        "Configured Fluxheim cache policies with origin fill protection enabled.",
    )
}

fn cache_origin_protection_max_concurrent_fills() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_ORIGIN_PROTECTION_MAX_CONCURRENT_FILLS,
        "fluxheim_cache_origin_protection_max_concurrent_fills",
        "Maximum configured Fluxheim cache origin-fill concurrency budget across protected cache policies.",
    )
}

fn cache_peer_fill_enabled_policies() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_PEER_FILL_ENABLED_POLICIES,
        "fluxheim_cache_peer_fill_enabled_policies",
        "Configured Fluxheim cache policies with distributed peer fill enabled.",
    )
}

fn cache_peer_fill_peers() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_PEER_FILL_PEERS,
        "fluxheim_cache_peer_fill_peers",
        "Configured Fluxheim cache peer-fill peers across enabled cache policies.",
    )
}

fn cache_peer_fill_max_concurrent_requests() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_PEER_FILL_MAX_CONCURRENT_REQUESTS,
        "fluxheim_cache_peer_fill_max_concurrent_requests",
        "Maximum configured Fluxheim cache peer-fill concurrency across enabled cache policies.",
    )
}

fn cache_memory_entries() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_MEMORY_ENTRIES,
        "fluxheim_cache_memory_entries",
        "Current aggregate Fluxheim memory-cache object count.",
    )
}

fn cache_memory_weighted_size_bytes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_MEMORY_WEIGHTED_SIZE_BYTES,
        "fluxheim_cache_memory_weighted_size_bytes",
        "Current aggregate Fluxheim memory-cache weighted size in bytes.",
    )
}

fn cache_memory_max_size_bytes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_MEMORY_MAX_SIZE_BYTES,
        "fluxheim_cache_memory_max_size_bytes",
        "Configured aggregate Fluxheim memory-cache size budget in bytes.",
    )
}

fn cache_memory_fill_ratio_per_mille() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_MEMORY_FILL_RATIO_PER_MILLE,
        "fluxheim_cache_memory_fill_ratio_per_mille",
        "Current aggregate Fluxheim memory-cache fill ratio in per-mille units.",
    )
}

fn cache_memory_purge_index_entries() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_MEMORY_PURGE_INDEX_ENTRIES,
        "fluxheim_cache_memory_purge_index_entries",
        "Current aggregate Fluxheim memory-cache purge-index entry count.",
    )
}

fn cache_disk_entries() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_ENTRIES,
        "fluxheim_cache_disk_entries",
        "Current aggregate Fluxheim disk-cache object count.",
    )
}

fn cache_disk_size_bytes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_SIZE_BYTES,
        "fluxheim_cache_disk_size_bytes",
        "Current aggregate Fluxheim disk-cache size in bytes.",
    )
}

fn cache_disk_allocated_size_bytes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_ALLOCATED_SIZE_BYTES,
        "fluxheim_cache_disk_allocated_size_bytes",
        "Current aggregate Fluxheim disk-cache allocated storage bytes.",
    )
}

fn cache_disk_free_size_bytes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_FREE_SIZE_BYTES,
        "fluxheim_cache_disk_free_size_bytes",
        "Current aggregate Fluxheim disk-cache free allocated bytes.",
    )
}

fn cache_disk_free_range_count() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_FREE_RANGE_COUNT,
        "fluxheim_cache_disk_free_range_count",
        "Current aggregate Fluxheim storage-bin disk-cache free range count.",
    )
}

fn cache_disk_largest_free_range_bytes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_LARGEST_FREE_RANGE_BYTES,
        "fluxheim_cache_disk_largest_free_range_bytes",
        "Largest Fluxheim storage-bin disk-cache free range in bytes across configured tiers.",
    )
}

fn cache_disk_bin_files() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_BIN_FILES,
        "fluxheim_cache_disk_bin_files",
        "Current aggregate Fluxheim storage-bin disk-cache bin file count.",
    )
}

fn cache_disk_max_size_bytes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_MAX_SIZE_BYTES,
        "fluxheim_cache_disk_max_size_bytes",
        "Configured aggregate Fluxheim disk-cache size budget in bytes.",
    )
}

fn cache_disk_fill_ratio_per_mille() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_FILL_RATIO_PER_MILLE,
        "fluxheim_cache_disk_fill_ratio_per_mille",
        "Current aggregate Fluxheim disk-cache fill ratio in per-mille units.",
    )
}

fn cache_disk_purge_index_entries() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_PURGE_INDEX_ENTRIES,
        "fluxheim_cache_disk_purge_index_entries",
        "Current aggregate Fluxheim disk-cache purge-index entry count.",
    )
}

fn php_fpm_retries_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = PHP_FPM_RETRIES_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_php_fpm_retries_total",
            "Total Fluxheim php-fpm retry attempts by virtual host and bounded reason.",
        ),
        &["vhost", "reason"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PHP_FPM_RETRIES_TOTAL.set(counter);
    PHP_FPM_RETRIES_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("PHP FPM retry counter failed to initialize".to_owned())
    })
}

fn php_fpm_pool_idle_connections() -> Result<&'static IntGaugeVec, prometheus::Error> {
    if let Some(gauge) = PHP_FPM_POOL_IDLE_CONNECTIONS.get() {
        return Ok(gauge);
    }

    let gauge = IntGaugeVec::new(
        Opts::new(
            "fluxheim_php_fpm_pool_idle_connections",
            "Current idle php-fpm keepalive connections by virtual host and configured pool.",
        ),
        &["vhost", "pool"],
    )?;
    match prometheus::default_registry().register(Box::new(gauge.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PHP_FPM_POOL_IDLE_CONNECTIONS.set(gauge);
    PHP_FPM_POOL_IDLE_CONNECTIONS.get().ok_or_else(|| {
        prometheus::Error::Msg("PHP FPM pool idle gauge failed to initialize".to_owned())
    })
}

fn php_fpm_pool_events_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = PHP_FPM_POOL_EVENTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_php_fpm_pool_events_total",
            "Total Fluxheim php-fpm keepalive pool events by virtual host, configured pool, and bounded event.",
        ),
        &["vhost", "pool", "event"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PHP_FPM_POOL_EVENTS_TOTAL.set(counter);
    PHP_FPM_POOL_EVENTS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("PHP FPM pool event counter failed to initialize".to_owned())
    })
}

fn cache_activity_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = CACHE_ACTIVITY_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_cache_activity_total",
            "Fluxheim cache activity events by storage tier and bounded event name.",
        ),
        &["tier", "event"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_ACTIVITY_TOTAL.set(counter);
    CACHE_ACTIVITY_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_cache_activity_total failed to initialize".to_owned())
    })
}

fn cache_activity_scope_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = CACHE_ACTIVITY_SCOPE_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_cache_activity_scope_total",
            "Fluxheim cache activity events by configured vhost, optional route, storage tier, and bounded event name.",
        ),
        &["scope", "vhost", "route", "tier", "event"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_ACTIVITY_SCOPE_TOTAL.set(counter);
    CACHE_ACTIVITY_SCOPE_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_cache_activity_scope_total failed to initialize".to_owned(),
        )
    })
}

fn cache_operation_duration_seconds() -> Result<&'static HistogramVec, prometheus::Error> {
    if let Some(histogram) = CACHE_OPERATION_DURATION_SECONDS.get() {
        return Ok(histogram);
    }

    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "fluxheim_cache_operation_duration_seconds",
            "Fluxheim cache lookup and request-collapsing wait durations with bounded labels.",
        )
        .buckets(vec![
            0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ]),
        &["scope", "vhost", "route", "phase", "operation"],
    )?;
    match prometheus::default_registry().register(Box::new(histogram.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_OPERATION_DURATION_SECONDS.set(histogram);
    CACHE_OPERATION_DURATION_SECONDS.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_cache_operation_duration_seconds failed to initialize".to_owned(),
        )
    })
}

fn cache_purges_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = CACHE_PURGES_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_cache_purges_total",
            "Fluxheim cache purge admin commands by bounded operation, configured cache scope, and purge mode.",
        ),
        &["operation", "scope", "vhost", "route", "mode"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_PURGES_TOTAL.set(counter);
    CACHE_PURGES_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_cache_purges_total failed to initialize".to_owned())
    })
}

fn cache_purger_runs_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = CACHE_PURGER_RUNS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_cache_purger_runs_total",
            "Fluxheim background stale disk cache purger runs by bounded outcome.",
        ),
        &["outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_PURGER_RUNS_TOTAL.set(counter);
    CACHE_PURGER_RUNS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_cache_purger_runs_total failed to initialize".to_owned())
    })
}

fn cache_purger_entries_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = CACHE_PURGER_ENTRIES_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_cache_purger_entries_total",
            "Fluxheim background stale disk cache purger entry counts by bounded result.",
        ),
        &["result"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_PURGER_ENTRIES_TOTAL.set(counter);
    CACHE_PURGER_ENTRIES_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_cache_purger_entries_total failed to initialize".to_owned(),
        )
    })
}

fn cache_purger_duration_seconds() -> Result<&'static HistogramVec, prometheus::Error> {
    if let Some(histogram) = CACHE_PURGER_DURATION_SECONDS.get() {
        return Ok(histogram);
    }

    let histogram = HistogramVec::new(
        HistogramOpts::new(
            "fluxheim_cache_purger_duration_seconds",
            "Fluxheim background stale disk cache purger run duration by bounded outcome.",
        )
        .buckets(vec![
            0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            30.0,
        ]),
        &["outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(histogram.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_PURGER_DURATION_SECONDS.set(histogram);
    CACHE_PURGER_DURATION_SECONDS.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_cache_purger_duration_seconds failed to initialize".to_owned(),
        )
    })
}

fn metrics_otlp_exports_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = METRICS_OTLP_EXPORTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_metrics_otlp_exports_total",
            "Fluxheim OTLP metrics exporter attempts by bounded outcome.",
        ),
        &["outcome"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = METRICS_OTLP_EXPORTS_TOTAL.set(counter);
    METRICS_OTLP_EXPORTS_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_metrics_otlp_exports_total failed to initialize".to_owned(),
        )
    })
}

fn int_gauge(
    cell: &'static OnceLock<IntGauge>,
    name: &'static str,
    help: &'static str,
) -> Result<&'static IntGauge, prometheus::Error> {
    if let Some(gauge) = cell.get() {
        return Ok(gauge);
    }

    let gauge = IntGauge::new(name, help)?;
    match prometheus::default_registry().register(Box::new(gauge.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = cell.set(gauge);
    cell.get()
        .ok_or_else(|| prometheus::Error::Msg(format!("{name} failed to initialize")))
}

fn outcome_class(status: Option<u16>, error: bool) -> &'static str {
    fluxheim_observability::metrics_outcome_class(status, error)
}

fn method_bucket(method: &str) -> &'static str {
    fluxheim_observability::metrics_method_bucket(method)
}

fn status_class(status: Option<u16>) -> &'static str {
    fluxheim_observability::metrics_status_class(status)
}

fn host_routing_reason_label(reason: &str) -> &'static str {
    fluxheim_observability::metrics_host_routing_reason_label(reason)
}

fn admin_auth_event_label(event: &str) -> &'static str {
    fluxheim_observability::metrics_admin_auth_event_label(event)
}

fn admin_auth_scope_label(scope: &str) -> &'static str {
    fluxheim_observability::metrics_admin_auth_scope_label(scope)
}

fn cache_tier_label(tier: &str) -> &'static str {
    fluxheim_cache::cache_tier_label(tier)
}

fn cache_scope_label(route: Option<&str>) -> &'static str {
    fluxheim_cache::cache_scope_label(route)
}

fn compression_encoding_label(encoding: &str) -> &'static str {
    fluxheim_observability::metrics_compression_encoding_label(encoding)
}

fn edge_policy_label(policy: &str) -> &'static str {
    fluxheim_observability::metrics_edge_policy_label(policy)
}

fn edge_policy_outcome_label(outcome: &str) -> &'static str {
    fluxheim_observability::metrics_edge_policy_outcome_label(outcome)
}

fn load_balancer_event_label(event: &str) -> &'static str {
    fluxheim_observability::metrics_load_balancer_event_label(event)
}

fn load_balancer_queue_outcome_label(outcome: &str) -> &'static str {
    fluxheim_observability::metrics_load_balancer_queue_outcome_label(outcome)
}

fn load_balancer_upstream_label(upstream: Option<&str>) -> &str {
    fluxheim_observability::metrics_load_balancer_upstream_label(upstream)
}

fn cache_event_label(event: &str) -> &'static str {
    fluxheim_cache::cache_event_label(event)
}

fn cache_phase_label(phase: &str) -> &'static str {
    fluxheim_cache::cache_phase_label(phase)
}

fn cache_operation_label(operation: &str) -> &'static str {
    fluxheim_cache::cache_operation_label(operation)
}

fn cache_purge_operation_label(operation: &str) -> &'static str {
    fluxheim_cache::cache_purge_operation_label(operation)
}

fn cache_purge_mode_label(mode: &str) -> &'static str {
    fluxheim_cache::cache_purge_mode_label(mode)
}

fn cache_purger_outcome_label(outcome: &str) -> &'static str {
    fluxheim_cache::cache_purger_outcome_label(outcome)
}

fn cache_purger_entry_result_label(result: &str) -> &'static str {
    fluxheim_cache::cache_purger_entry_result_label(result)
}

fn php_outcome_label(outcome: &str) -> &'static str {
    fluxheim_observability::metrics_php_outcome_label(outcome)
}

fn php_fpm_retry_reason_label(reason: &str) -> &'static str {
    fluxheim_observability::metrics_php_fpm_retry_reason_label(reason)
}

fn php_fpm_pool_event_label(event: &str) -> &'static str {
    fluxheim_observability::metrics_php_fpm_pool_event_label(event)
}

fn php_stderr_state_label(state: &str) -> &'static str {
    fluxheim_observability::metrics_php_stderr_state_label(state)
}

fn metrics_otlp_export_outcome_label(outcome: &str) -> &'static str {
    fluxheim_observability::metrics_otlp_export_outcome_label(outcome)
}

fn stream_outcome_label(outcome: &str) -> &'static str {
    fluxheim_observability::metrics_stream_outcome_label(outcome)
}

fn stream_direction_label(direction: &str) -> &'static str {
    fluxheim_observability::metrics_stream_direction_label(direction)
}

fn udp_mode_label(mode: &str) -> &'static str {
    match mode {
        "dns_load_balance" => "dns_load_balance",
        "syslog_forward" => "syslog_forward",
        "quic_pass_through" => "quic_pass_through",
        "game_proxy" => "game_proxy",
        _ => "other",
    }
}

fn udp_direction_label(direction: &str) -> &'static str {
    match direction {
        "downstream" => "downstream",
        "upstream" => "upstream",
        _ => "other",
    }
}

fn udp_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "accepted" => "accepted",
        "sent" => "sent",
        "error" => "error",
        _ => "other",
    }
}

fn udp_drop_reason_label(reason: &str) -> &'static str {
    match reason {
        "max_sessions" => "max_sessions",
        "max_sessions_per_source" => "max_sessions_per_source",
        "oversized_downstream" => "oversized_downstream",
        "oversized_upstream" => "oversized_upstream",
        "response_rate_limited" => "response_rate_limited",
        _ => "other",
    }
}

fn acme_event_label(event: &str) -> &'static str {
    fluxheim_observability::metrics_acme_event_label(event)
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::Duration;

    use fluxheim_common::test_support::unique_temp_path;
    use prometheus::Encoder;
    use zeroize::Zeroizing;

    use crate::config::{
        CacheConfig, CacheDiskConfig, CacheMemoryConfig, CachePeerConfig, CachePeerFillConfig,
        Config, ProxyConfig, RouteConfig, VhostAcmeChallengeConfig, VhostConfig,
        VhostHeaderPolicyConfig, VhostRedirectConfig, VhostTlsConfig, WebConfig,
    };

    #[cfg(all(feature = "proxy", feature = "cache"))]
    use super::record_cache_runtime_totals;
    use super::{
        NativeMetricsApp, init, method_bucket, metrics_background_service_from_config,
        native_metrics_app_from_config, native_prometheus_response, record_acme_event,
        record_admin_auth_event, record_cache_activity, record_cache_activity_scope,
        record_cache_operation_duration, record_cache_purge, record_cache_purger_duration,
        record_cache_purger_entries, record_cache_purger_run, record_config,
        record_edge_policy_event, record_host_routing_rejection, record_load_balancer_event,
        record_load_balancer_queue_wait, record_metrics_otlp_export, record_php_fpm_pool_event,
        record_php_fpm_pool_idle, record_php_fpm_retry, record_php_request, record_php_stderr,
        record_proxy_outcome, record_response_compression, record_stream_bytes,
        record_stream_connection, record_udp_datagram, record_udp_drop, set_udp_active_sessions,
        status_class,
    };

    #[test]
    fn records_proxy_outcome_counter() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_proxy_outcome("metrics-test", "GET", Some(502), false);

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_proxy_requests_total"));
        assert!(output.contains(r#"vhost="metrics-test""#));
        assert!(output.contains(r#"method="GET""#));
        assert!(output.contains(r#"class="server_error""#));
        assert!(output.contains(r#"status_class="5xx""#));
        assert!(!output.contains(r#"status="502""#));
    }

    #[test]
    fn records_response_compression_metrics_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_response_compression("compression-test", Some("assets"), "gzip");
        record_response_compression("compression-test", None, "br");
        record_response_compression("compression-test", Some("assets"), "attacker-encoding");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_response_compressions_total"));
        assert!(output.contains(r#"scope="route""#));
        assert!(output.contains(r#"scope="vhost""#));
        assert!(output.contains(r#"vhost="compression-test""#));
        assert!(output.contains(r#"route="assets""#));
        assert!(output.contains(r#"encoding="gzip""#));
        assert!(output.contains(r#"encoding="br""#));
        assert!(output.contains(r#"encoding="other""#));
        assert!(!output.contains("attacker-encoding"));
    }

    #[test]
    fn records_stream_metrics_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_stream_connection("postgres", "completed");
        record_stream_connection("postgres", "timeout");
        record_stream_connection("postgres", "attacker-outcome");
        record_stream_bytes("postgres", "downstream_to_upstream", 128);
        record_stream_bytes("postgres", "upstream_to_downstream", 256);
        record_stream_bytes("postgres", "attacker-direction", 512);

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_stream_connections_total"));
        assert!(output.contains("fluxheim_stream_bytes_total"));
        assert!(output.contains(r#"route="postgres""#));
        assert!(output.contains(r#"outcome="completed""#));
        assert!(output.contains(r#"outcome="timeout""#));
        assert!(output.contains(r#"outcome="error""#));
        assert!(output.contains(r#"direction="downstream_to_upstream""#));
        assert!(output.contains(r#"direction="upstream_to_downstream""#));
        assert!(output.contains(r#"direction="other""#));
        assert!(!output.contains("attacker-outcome"));
        assert!(!output.contains("attacker-direction"));
    }

    #[test]
    fn records_udp_metrics_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_udp_datagram("dns", "dns_load_balance", "downstream", "accepted");
        record_udp_datagram("dns", "syslog_forward", "upstream", "sent");
        record_udp_datagram(
            "dns",
            "attacker-mode",
            "attacker-direction",
            "attacker-outcome",
        );
        record_udp_drop("dns", "max_sessions");
        record_udp_drop("dns", "max_sessions_per_source");
        record_udp_drop("dns", "response_rate_limited");
        record_udp_drop("dns", "attacker-reason");
        set_udp_active_sessions("dns", 2);

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_udp_datagrams_total"));
        assert!(output.contains("fluxheim_udp_drops_total"));
        assert!(output.contains("fluxheim_udp_active_sessions"));
        assert!(output.contains(r#"route="dns""#));
        assert!(output.contains(r#"mode="dns_load_balance""#));
        assert!(output.contains(r#"mode="syslog_forward""#));
        assert!(output.contains(r#"mode="other""#));
        assert!(output.contains(r#"direction="downstream""#));
        assert!(output.contains(r#"direction="upstream""#));
        assert!(output.contains(r#"direction="other""#));
        assert!(output.contains(r#"outcome="accepted""#));
        assert!(output.contains(r#"outcome="sent""#));
        assert!(output.contains(r#"outcome="other""#));
        assert!(output.contains(r#"reason="max_sessions""#));
        assert!(output.contains(r#"reason="max_sessions_per_source""#));
        assert!(output.contains(r#"reason="response_rate_limited""#));
        assert!(output.contains(r#"reason="other""#));
        assert!(!output.contains("attacker-mode"));
        assert!(!output.contains("attacker-direction"));
        assert!(!output.contains("attacker-outcome"));
        assert!(!output.contains("attacker-reason"));
    }

    #[test]
    fn records_edge_policy_metrics_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_edge_policy_event("edge-policy-test", Some("assets"), "access", "deny");
        record_edge_policy_event("edge-policy-test", Some("assets"), "auth_request", "allow");
        record_edge_policy_event("edge-policy-test", Some("assets"), "auth_request", "error");
        record_edge_policy_event("edge-policy-test", Some("assets"), "rate_limit", "delay");
        record_edge_policy_event("edge-policy-test", None, "concurrency", "reject");
        record_edge_policy_event("edge-policy-test", Some("assets"), "mirror", "success");
        record_edge_policy_event("edge-policy-test", Some("assets"), "mirror", "skipped");
        record_edge_policy_event(
            "edge-policy-test",
            Some("assets"),
            "attacker-policy",
            "attacker-outcome",
        );

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_edge_policy_events_total"));
        assert!(output.contains(r#"scope="route""#));
        assert!(output.contains(r#"scope="vhost""#));
        assert!(output.contains(r#"vhost="edge-policy-test""#));
        assert!(output.contains(r#"route="assets""#));
        assert!(output.contains(r#"policy="access""#));
        assert!(output.contains(r#"policy="auth_request""#));
        assert!(output.contains(r#"policy="rate_limit""#));
        assert!(output.contains(r#"policy="concurrency""#));
        assert!(output.contains(r#"policy="mirror""#));
        assert!(output.contains(r#"policy="other""#));
        assert!(output.contains(r#"outcome="deny""#));
        assert!(output.contains(r#"outcome="allow""#));
        assert!(output.contains(r#"outcome="delay""#));
        assert!(output.contains(r#"outcome="reject""#));
        assert!(output.contains(r#"outcome="error""#));
        assert!(output.contains(r#"outcome="success""#));
        assert!(output.contains(r#"outcome="skipped""#));
        assert!(output.contains(r#"outcome="other""#));
        assert!(!output.contains("attacker-policy"));
        assert!(!output.contains("attacker-outcome"));
    }

    #[test]
    fn records_load_balancer_metrics_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "selected");
        record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "retry");
        record_load_balancer_event("lb-test", None, None, "unavailable");
        record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "success");
        record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "failure");
        record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "ejected");
        record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "member_state");
        record_load_balancer_event(
            "lb-test",
            Some("api"),
            Some("origin-a"),
            "member_state_invalid",
        );
        record_load_balancer_event(
            "lb-test",
            Some("api"),
            Some("origin-a"),
            "member_state_not_found",
        );
        record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "persistence_hit");
        record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "persistence_miss");
        record_load_balancer_event(
            "lb-test",
            Some("api"),
            Some("origin-a"),
            "persistence_fallback",
        );
        record_load_balancer_event(
            "lb-test",
            Some("api"),
            Some("origin-a"),
            "persistence_clear",
        );
        record_load_balancer_event(
            "lb-test",
            Some("api"),
            Some("origin-a"),
            "persistence_clear_invalid",
        );
        record_load_balancer_event(
            "lb-test",
            Some("api"),
            Some("origin-a"),
            "persistence_clear_not_found",
        );
        record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "queue_waited");
        record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "queue_full");
        record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "queue_timeout");
        record_load_balancer_event("lb-test", Some("api"), None, "discovery_success");
        record_load_balancer_event("lb-test", Some("api"), None, "discovery_failure");
        record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "attacker-event");
        record_load_balancer_event("lb-test", Some("api"), Some("http://raw:3000"), "selected");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_load_balancer_events_total"));
        assert!(output.contains(r#"scope="route""#));
        assert!(output.contains(r#"scope="vhost""#));
        assert!(output.contains(r#"vhost="lb-test""#));
        assert!(output.contains(r#"route="api""#));
        assert!(output.contains(r#"upstream="origin-a""#));
        assert!(output.contains(r#"upstream="other""#));
        assert!(output.contains(r#"event="selected""#));
        assert!(output.contains(r#"event="unavailable""#));
        assert!(output.contains(r#"event="retry""#));
        assert!(output.contains(r#"event="success""#));
        assert!(output.contains(r#"event="failure""#));
        assert!(output.contains(r#"event="ejected""#));
        assert!(output.contains(r#"event="member_state""#));
        assert!(output.contains(r#"event="member_state_invalid""#));
        assert!(output.contains(r#"event="member_state_not_found""#));
        assert!(output.contains(r#"event="persistence_hit""#));
        assert!(output.contains(r#"event="persistence_miss""#));
        assert!(output.contains(r#"event="persistence_fallback""#));
        assert!(output.contains(r#"event="persistence_clear""#));
        assert!(output.contains(r#"event="persistence_clear_invalid""#));
        assert!(output.contains(r#"event="persistence_clear_not_found""#));
        assert!(output.contains(r#"event="queue_waited""#));
        assert!(output.contains(r#"event="queue_full""#));
        assert!(output.contains(r#"event="queue_timeout""#));
        assert!(output.contains(r#"event="discovery_success""#));
        assert!(output.contains(r#"event="discovery_failure""#));
        assert!(output.contains(r#"event="other""#));
        assert!(!output.contains("attacker-event"));
        assert!(!output.contains("http://raw:3000"));
    }

    #[test]
    fn records_load_balancer_queue_wait_histogram_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_load_balancer_queue_wait(
            "lb-queue-test",
            Some("api"),
            "queue_waited",
            Duration::from_millis(25),
        );
        record_load_balancer_queue_wait(
            "lb-queue-test",
            Some("api"),
            "queue_timeout",
            Duration::from_millis(250),
        );
        record_load_balancer_queue_wait(
            "lb-queue-test",
            Some("api"),
            "attacker-outcome",
            Duration::from_millis(5),
        );

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_load_balancer_queue_wait_seconds"));
        assert!(output.contains(r#"scope="route""#));
        assert!(output.contains(r#"vhost="lb-queue-test""#));
        assert!(output.contains(r#"route="api""#));
        assert!(output.contains(r#"outcome="waited""#));
        assert!(output.contains(r#"outcome="timeout""#));
        assert!(output.contains(r#"outcome="other""#));
        assert!(!output.contains("attacker-outcome"));
    }

    #[test]
    fn records_php_request_metrics_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_php_request(
            "php-metrics-test",
            "POST",
            Some(502),
            "connect_timeout",
            Duration::from_millis(25),
        );
        record_php_request(
            "php-metrics-test",
            "GET",
            Some(200),
            "offload",
            Duration::from_millis(10),
        );
        record_php_request(
            "php-metrics-test",
            "BREW",
            Some(200),
            "attacker-outcome",
            Duration::from_millis(1),
        );

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_php_requests_total"));
        assert!(output.contains("fluxheim_php_request_duration_seconds"));
        assert!(output.contains(r#"vhost="php-metrics-test""#));
        assert!(output.contains(r#"method="POST""#));
        assert!(output.contains(r#"outcome="connect_timeout""#));
        assert!(output.contains(r#"outcome="offload""#));
        assert!(output.contains(r#"status_class="5xx""#));
        assert!(output.contains(r#"method="OTHER""#));
        assert!(output.contains(r#"outcome="other""#));
        assert!(!output.contains("attacker-outcome"));
    }

    #[test]
    fn records_php_fpm_retry_counter_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_php_fpm_retry("php-retry-test", "connect_timeout");
        record_php_fpm_retry("php-retry-test", "connection_error");
        record_php_fpm_retry("php-retry-test", "attacker-reason");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_php_fpm_retries_total"));
        assert!(output.contains(r#"vhost="php-retry-test""#));
        assert!(output.contains(r#"reason="connect_timeout""#));
        assert!(output.contains(r#"reason="connection_error""#));
        assert!(output.contains(r#"reason="other""#));
        assert!(!output.contains("attacker-reason"));
    }

    #[test]
    fn records_php_fpm_pool_metrics_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_php_fpm_pool_idle("php-pool-test", "default", 2);
        record_php_fpm_pool_event("php-pool-test", "default", "connect");
        record_php_fpm_pool_event("php-pool-test", "default", "reuse");
        record_php_fpm_pool_event("php-pool-test", "default", "attacker-event");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_php_fpm_pool_idle_connections"));
        assert!(output.contains("fluxheim_php_fpm_pool_events_total"));
        assert!(output.contains(r#"vhost="php-pool-test""#));
        assert!(output.contains(r#"pool="default""#));
        assert!(output.contains(r#"event="connect""#));
        assert!(output.contains(r#"event="reuse""#));
        assert!(output.contains(r#"event="other""#));
        assert!(!output.contains("attacker-event"));
    }

    #[test]
    fn records_php_stderr_counter_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_php_stderr("php-stderr-test", "emitted");
        record_php_stderr("php-stderr-test", "truncated");
        record_php_stderr("php-stderr-test", "attacker-state");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_php_stderr_events_total"));
        assert!(output.contains(r#"vhost="php-stderr-test""#));
        assert!(output.contains(r#"state="emitted""#));
        assert!(output.contains(r#"state="truncated""#));
        assert!(output.contains(r#"state="other""#));
        assert!(!output.contains("attacker-state"));
    }

    #[test]
    fn records_host_routing_rejection_counter() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_host_routing_rejection("missing");
        record_host_routing_rejection("attacker-reason");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_host_routing_rejections_total"));
        assert!(output.contains(r#"reason="missing""#));
        assert!(output.contains(r#"reason="other""#));
    }

    #[test]
    fn records_admin_auth_event_counter() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_admin_auth_event("failure", "source");
        record_admin_auth_event("throttled", "global");
        record_admin_auth_event("attacker-event", "attacker-scope");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_admin_auth_events_total"));
        assert!(output.contains(r#"event="failure",scope="source""#));
        assert!(output.contains(r#"event="throttled",scope="global""#));
        assert!(output.contains(r#"event="other",scope="other""#));
    }

    #[test]
    fn native_prometheus_response_exposes_text_metrics() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_admin_auth_event("failure", "source");
        let response = native_prometheus_response().unwrap();
        let output = String::from_utf8(response.body().to_vec()).unwrap();

        assert_eq!(response.status(), 200);
        assert!(
            response
                .headers()
                .iter()
                .any(|(name, value)| name == "content-type" && value.starts_with("text/plain"))
        );
        assert!(output.contains("fluxheim_admin_auth_events_total"));
        assert!(output.contains(r#"event="failure",scope="source""#));
    }

    #[test]
    fn native_metrics_app_serves_prometheus_response() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_admin_auth_event("failure", "source");
        let request = fluxheim_server::NativeHttp1Request {
            method: "GET".to_owned(),
            peer_addr: None,
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: false,
            tls_identity: None,
            geo_context: None,
            target: "/metrics".to_owned(),
            version: fluxheim_protocol::Http1Version::Http11,
            headers: vec![("host".to_owned(), "metrics.test".to_owned())],
            body: Zeroizing::new(Vec::new()),
            trailers: Vec::new(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
            &NativeMetricsApp::new(),
            request,
        ));
        let output = String::from_utf8(response.body().to_vec()).unwrap();

        assert_eq!(response.status(), 200);
        assert!(
            response
                .headers()
                .iter()
                .any(|(name, value)| name == "content-type" && value.starts_with("text/plain"))
        );
        assert!(output.contains("fluxheim_admin_auth_events_total"));
        assert!(output.contains(r#"event="failure",scope="source""#));
    }

    #[test]
    fn native_metrics_app_restricts_method_and_target() {
        let _guard = metrics_test_lock();
        init().unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let app = NativeMetricsApp::new();

        let head = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
            &app,
            native_metrics_request("HEAD", "/metrics"),
        ));
        assert_eq!(head.status(), 200);
        assert_eq!(head.body(), b"");
        assert!(head.content_length().is_some_and(|length| length > 0));

        let absolute = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
            &app,
            native_metrics_request("GET", "http://metrics.test/metrics?format=prometheus"),
        ));
        assert_eq!(absolute.status(), 200);

        let wrong_path = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
            &app,
            native_metrics_request("GET", "/"),
        ));
        assert_eq!(wrong_path.status(), 404);

        let wrong_method = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
            &app,
            native_metrics_request("POST", "/metrics"),
        ));
        assert_eq!(wrong_method.status(), 405);
        assert!(
            wrong_method
                .headers()
                .iter()
                .any(|(name, value)| name == "allow" && value == "GET, HEAD")
        );
    }

    #[test]
    fn native_metrics_app_can_require_bearer_token() {
        let _guard = metrics_test_lock();
        init().unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let app = NativeMetricsApp::new().with_bearer_token("metrics-secret");

        let missing = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
            &app,
            native_metrics_request("GET", "/metrics"),
        ));
        assert_eq!(missing.status(), 401);
        assert!(
            missing
                .headers()
                .iter()
                .any(|(name, value)| name == "www-authenticate"
                    && value == "Bearer realm=\"metrics\"")
        );

        let mut wrong = native_metrics_request("GET", "/metrics");
        wrong
            .headers
            .push(("authorization".to_owned(), "Bearer wrong".to_owned()));
        let wrong = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(&app, wrong));
        assert_eq!(wrong.status(), 401);

        let mut authorized = native_metrics_request("GET", "/metrics");
        authorized.headers.push((
            "authorization".to_owned(),
            "Bearer metrics-secret".to_owned(),
        ));
        let authorized = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
            &app, authorized,
        ));
        assert_eq!(authorized.status(), 200);
    }

    #[test]
    fn native_metrics_app_loads_bearer_token_from_config_file() {
        let _guard = metrics_test_lock();
        init().unwrap();

        let token_file = unique_temp_path("native-metrics-token-file");
        std::fs::write(&token_file, "metrics-file-secret\n").unwrap();
        let config = crate::config::MetricsConfig {
            token_file: Some(token_file.clone()),
            ..crate::config::MetricsConfig::default()
        };
        let app = native_metrics_app_from_config(&config).unwrap();
        let _ = std::fs::remove_file(&token_file);
        let debug = format!("{app:?}");
        assert!(debug.contains("bearer_token_configured: true"));
        assert!(!debug.contains("metrics-file-secret"));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let missing = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
            &app,
            native_metrics_request("GET", "/metrics"),
        ));
        assert_eq!(missing.status(), 401);

        let mut authorized = native_metrics_request("GET", "/metrics");
        authorized.headers.push((
            "authorization".to_owned(),
            "Bearer metrics-file-secret".to_owned(),
        ));
        let authorized = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
            &app, authorized,
        ));
        assert_eq!(authorized.status(), 200);
    }

    #[test]
    fn native_metrics_background_service_binds_and_stops() {
        let _guard = metrics_test_lock();
        init().unwrap();

        let config = crate::config::MetricsConfig {
            enabled: true,
            listen: "127.0.0.1:0".to_owned(),
            ..crate::config::MetricsConfig::default()
        };
        let service = metrics_background_service_from_config(&config)
            .unwrap()
            .expect("metrics service");
        assert_eq!(service.name(), "Fluxheim metrics HTTP");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let supervisor = fluxheim_runtime::NativeBackgroundSupervisor::new();
            let (ready_tx, mut ready_rx) = tokio::sync::watch::channel(false);
            let handle = supervisor.spawn_service_with_ready(service.into_native(), move || {
                let _ = ready_tx.send(true);
            });
            ready_rx.changed().await.unwrap();
            assert!(*ready_rx.borrow());
            assert!(supervisor.shutdown());
            handle.join().await.unwrap();
        });
    }

    #[test]
    fn native_metrics_app_serves_prometheus_response_through_listener() {
        let _guard = metrics_test_lock();
        init().unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = runtime.block_on(async {
            record_admin_auth_event("failure", "source");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            tokio::spawn(async move {
                fluxheim_server::serve_native_http1_listener(
                    listener,
                    fluxheim_server::DownstreamHttp1Policy::default(),
                    std::sync::Arc::new(NativeMetricsApp::new()),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
                .unwrap();
            });

            let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(
                &mut client,
                b"GET /metrics HTTP/1.1\r\nHost: metrics.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
            let mut response = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut client, &mut response)
                .await
                .unwrap();
            let _ = shutdown_tx.send(());
            String::from_utf8(response).unwrap()
        });

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("content-type: text/plain"));
        assert!(response.contains("fluxheim_admin_auth_events_total"));
        assert!(response.contains(r#"event="failure",scope="source""#));
    }

    #[test]
    fn native_metrics_listener_enforces_bearer_token() {
        let _guard = metrics_test_lock();
        init().unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (missing, authorized) = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            tokio::spawn(async move {
                fluxheim_server::serve_native_http1_listener(
                    listener,
                    fluxheim_server::DownstreamHttp1Policy::default(),
                    std::sync::Arc::new(
                        NativeMetricsApp::new().with_bearer_token("listener-secret"),
                    ),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
                .unwrap();
            });

            let missing = native_metrics_listener_request(
                addr,
                b"GET /metrics HTTP/1.1\r\nHost: metrics.test\r\nConnection: close\r\n\r\n",
            )
            .await;
            let authorized = native_metrics_listener_request(
                addr,
                b"GET /metrics HTTP/1.1\r\nHost: metrics.test\r\nAuthorization: Bearer listener-secret\r\nConnection: close\r\n\r\n",
            )
            .await;
            let _ = shutdown_tx.send(());
            (missing, authorized)
        });

        assert!(missing.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        assert!(missing.contains("www-authenticate: Bearer realm=\"metrics\""));
        assert!(authorized.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(authorized.contains("content-type: text/plain"));
    }

    fn native_metrics_request(method: &str, target: &str) -> fluxheim_server::NativeHttp1Request {
        fluxheim_server::NativeHttp1Request {
            method: method.to_owned(),
            peer_addr: None,
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: false,
            tls_identity: None,
            geo_context: None,
            target: target.to_owned(),
            version: fluxheim_protocol::Http1Version::Http11,
            headers: vec![("host".to_owned(), "metrics.test".to_owned())],
            body: Zeroizing::new(Vec::new()),
            trailers: Vec::new(),
        }
    }

    async fn native_metrics_listener_request(addr: std::net::SocketAddr, request: &[u8]) -> String {
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut client, request)
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client, &mut response)
            .await
            .unwrap();
        String::from_utf8(response).unwrap()
    }

    #[test]
    fn records_acme_event_counter_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_acme_event("pending");
        record_acme_event("renewed");
        record_acme_event("failed");
        record_acme_event("reload_failed");
        record_acme_event("attacker-event");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(r#"fluxheim_acme_events_total{event="pending"}"#));
        assert!(output.contains(r#"fluxheim_acme_events_total{event="renewed"}"#));
        assert!(output.contains(r#"fluxheim_acme_events_total{event="failed"}"#));
        assert!(output.contains(r#"fluxheim_acme_events_total{event="reload_failed"}"#));
        assert!(output.contains(r#"fluxheim_acme_events_total{event="other"}"#));
        assert!(!output.contains("attacker-event"));
    }

    #[test]
    fn records_cache_configuration_gauges() {
        let _guard = metrics_test_lock();
        init().unwrap();

        let config = cache_metrics_config();
        record_config(&config);

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_cache_vhosts 1"));
        assert!(output.contains("fluxheim_cache_enabled_vhosts 1"));
        assert!(output.contains("fluxheim_cache_tiered_vhosts 1"));
        assert!(output.contains("fluxheim_cache_configured_routes 2"));
        assert!(output.contains("fluxheim_cache_policy_routes 1"));
        assert!(output.contains("fluxheim_cache_enabled_routes 1"));
        assert!(output.contains("fluxheim_cache_tiered_routes 0"));
        assert!(output.contains("fluxheim_cache_memory_tiers 2"));
        assert!(output.contains("fluxheim_cache_disk_tiers 1"));
        assert!(output.contains("fluxheim_cache_lock_enabled_policies 2"));
        assert!(output.contains("fluxheim_cache_lock_wait_timeout_max_seconds 30"));
        assert!(output.contains("fluxheim_cache_peer_fill_enabled_policies 2"));
        assert!(output.contains("fluxheim_cache_peer_fill_peers 3"));
        assert!(output.contains("fluxheim_cache_peer_fill_max_concurrent_requests 128"));
        assert!(!output.contains("cache_key"));
        assert!(!output.contains("path="));
    }

    #[test]
    fn records_load_balancer_pool_configuration_gauge() {
        let _guard = metrics_test_lock();
        init().unwrap();

        let config = load_balancer_metrics_config();
        record_config(&config);

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(
            output.contains(
                r#"fluxheim_load_balancer_pools{scope="vhost",selection="least_time"} 1"#
            )
        );
        assert!(output.contains(
            r#"fluxheim_load_balancer_pools{scope="route",selection="consistent_uri_hash"} 1"#
        ));
        assert!(!output.contains("single-upstream"));
        assert!(!output.contains("app-a.example"));
        assert!(!output.contains("path="));
    }

    #[cfg(all(feature = "proxy", feature = "cache"))]
    #[test]
    fn records_cache_runtime_storage_pressure_gauges() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_cache_runtime_totals(&crate::proxy::CacheRuntimeTotals {
            memory_entries: 3,
            memory_weighted_size_bytes: 512,
            memory_max_size_bytes: 1024,
            memory_purge_index_entries: 4,
            disk_entries: 5,
            disk_size_bytes: 2048,
            disk_allocated_size_bytes: 3072,
            disk_free_size_bytes: 1024,
            disk_free_range_count: 2,
            disk_largest_free_range_bytes: 768,
            disk_bin_files: 3,
            disk_max_size_bytes: 4096,
            disk_purge_index_entries: 6,
            ..crate::proxy::CacheRuntimeTotals::default()
        });

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_cache_memory_entries 3"));
        assert!(output.contains("fluxheim_cache_memory_weighted_size_bytes 512"));
        assert!(output.contains("fluxheim_cache_memory_max_size_bytes 1024"));
        assert!(output.contains("fluxheim_cache_memory_fill_ratio_per_mille 500"));
        assert!(output.contains("fluxheim_cache_memory_purge_index_entries 4"));
        assert!(output.contains("fluxheim_cache_disk_entries 5"));
        assert!(output.contains("fluxheim_cache_disk_size_bytes 2048"));
        assert!(output.contains("fluxheim_cache_disk_allocated_size_bytes 3072"));
        assert!(output.contains("fluxheim_cache_disk_free_size_bytes 1024"));
        assert!(output.contains("fluxheim_cache_disk_free_range_count 2"));
        assert!(output.contains("fluxheim_cache_disk_largest_free_range_bytes 768"));
        assert!(output.contains("fluxheim_cache_disk_bin_files 3"));
        assert!(output.contains("fluxheim_cache_disk_max_size_bytes 4096"));
        assert!(output.contains("fluxheim_cache_disk_fill_ratio_per_mille 500"));
        assert!(output.contains("fluxheim_cache_disk_purge_index_entries 6"));
        assert!(!output.contains("cache_key"));
        assert!(!output.contains("path="));
    }

    #[test]
    fn records_cache_activity_counter_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_cache_activity("memory", "hit");
        record_cache_activity("disk", "store_refusal");
        record_cache_activity("policy", "pass");
        record_cache_activity("policy", "bypass");
        record_cache_activity("policy", "stale");
        record_cache_activity("policy", "revalidate");
        record_cache_activity("policy", "peer_fill_hit");
        record_cache_activity("policy", "peer_fill_miss");
        record_cache_activity("policy", "peer_fill_error");
        record_cache_activity("policy", "peer_fill_fallback");
        record_cache_activity("policy", "peer_fill_fail_closed");
        record_cache_activity("attacker-tier", "attacker-event");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(r#"fluxheim_cache_activity_total{event="hit",tier="memory"}"#));
        assert!(
            output.contains(r#"fluxheim_cache_activity_total{event="store_refusal",tier="disk"}"#)
        );
        assert!(output.contains(r#"fluxheim_cache_activity_total{event="pass",tier="policy"}"#));
        assert!(output.contains(r#"fluxheim_cache_activity_total{event="bypass",tier="policy"}"#));
        assert!(output.contains(r#"fluxheim_cache_activity_total{event="stale",tier="policy"}"#));
        assert!(
            output.contains(r#"fluxheim_cache_activity_total{event="revalidate",tier="policy"}"#)
        );
        assert!(
            output
                .contains(r#"fluxheim_cache_activity_total{event="peer_fill_hit",tier="policy"}"#)
        );
        assert!(
            output
                .contains(r#"fluxheim_cache_activity_total{event="peer_fill_miss",tier="policy"}"#)
        );
        assert!(
            output.contains(
                r#"fluxheim_cache_activity_total{event="peer_fill_error",tier="policy"}"#
            )
        );
        assert!(output.contains(
            r#"fluxheim_cache_activity_total{event="peer_fill_fallback",tier="policy"}"#
        ));
        assert!(output.contains(
            r#"fluxheim_cache_activity_total{event="peer_fill_fail_closed",tier="policy"}"#
        ));
        assert!(output.contains(r#"fluxheim_cache_activity_total{event="other",tier="other"}"#));
        assert!(!output.contains("attacker-tier"));
        assert!(!output.contains("attacker-event"));
    }

    #[test]
    fn records_cache_activity_scope_counter_with_configured_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_cache_activity_scope("cached", None, "memory", "hit");
        record_cache_activity_scope("cached", Some("assets"), "disk", "purge");
        record_cache_activity_scope("cached", Some("assets"), "policy", "bypass");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(
            r#"fluxheim_cache_activity_scope_total{event="hit",route="",scope="vhost",tier="memory",vhost="cached"}"#
        ));
        assert!(output.contains(
            r#"fluxheim_cache_activity_scope_total{event="purge",route="assets",scope="route",tier="disk",vhost="cached"}"#
        ));
        assert!(output.contains(
            r#"fluxheim_cache_activity_scope_total{event="bypass",route="assets",scope="route",tier="policy",vhost="cached"}"#
        ));
        assert!(!output.contains("cache_key"));
        assert!(!output.contains("path="));
    }

    #[test]
    fn records_cache_operation_duration_histogram_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_cache_operation_duration(
            "cached",
            Some("assets"),
            "hit",
            "lookup",
            std::time::Duration::from_millis(12),
        );
        record_cache_operation_duration(
            "cached",
            None,
            "attacker-phase",
            "attacker-operation",
            std::time::Duration::from_millis(30),
        );

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_cache_operation_duration_seconds_bucket"));
        assert!(output.contains(r#"phase="hit""#));
        assert!(output.contains(r#"route="assets""#));
        assert!(output.contains(r#"scope="route""#));
        assert!(output.contains(r#"vhost="cached""#));
        assert!(output.contains(r#"operation="lookup""#));
        assert!(output.contains(r#"operation="other""#));
        assert!(output.contains(r#"phase="other""#));
        assert!(!output.contains("attacker-phase"));
        assert!(!output.contains("attacker-operation"));
        assert!(!output.contains("cache_key"));
    }

    #[test]
    fn records_cache_purge_counter_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_cache_purge("prefix", "cached", Some("assets"), "soft");
        record_cache_purge("attacker-operation", "cached", None, "attacker-mode");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(
            r#"fluxheim_cache_purges_total{mode="soft",operation="prefix",route="assets",scope="route",vhost="cached"}"#
        ));
        assert!(output.contains(
            r#"fluxheim_cache_purges_total{mode="other",operation="other",route="",scope="vhost",vhost="cached"}"#
        ));
        assert!(!output.contains("attacker-operation"));
        assert!(!output.contains("attacker-mode"));
        assert!(!output.contains("cache_key"));
        assert!(!output.contains("path="));
    }

    #[test]
    fn records_cache_purger_counters_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_cache_purger_run("truncated");
        record_cache_purger_run("attacker-outcome");
        record_cache_purger_entries("scanned", 7);
        record_cache_purger_entries("purged", 2);
        record_cache_purger_entries("attacker-result", 3);
        record_cache_purger_duration("truncated", std::time::Duration::from_millis(25));
        record_cache_purger_duration("attacker-outcome", std::time::Duration::from_millis(50));

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(r#"fluxheim_cache_purger_runs_total{outcome="truncated"}"#));
        assert!(output.contains(r#"fluxheim_cache_purger_runs_total{outcome="other"}"#));
        assert!(output.contains(r#"fluxheim_cache_purger_entries_total{result="scanned"} 7"#));
        assert!(output.contains(r#"fluxheim_cache_purger_entries_total{result="purged"} 2"#));
        assert!(output.contains(r#"fluxheim_cache_purger_entries_total{result="other"} 3"#));
        assert!(
            output.contains(r#"fluxheim_cache_purger_duration_seconds_bucket{outcome="truncated""#)
        );
        assert!(
            output.contains(r#"fluxheim_cache_purger_duration_seconds_bucket{outcome="other""#)
        );
        assert!(!output.contains("attacker-outcome"));
        assert!(!output.contains("attacker-result"));
        assert!(!output.contains("cache_key"));
        assert!(!output.contains("path="));
    }

    #[test]
    fn records_metrics_otlp_exporter_health_counter() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_metrics_otlp_export("success");
        record_metrics_otlp_export("failure");
        record_metrics_otlp_export("attacker-outcome");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(r#"fluxheim_metrics_otlp_exports_total{outcome="success"}"#));
        assert!(output.contains(r#"fluxheim_metrics_otlp_exports_total{outcome="failure"}"#));
        assert!(output.contains(r#"fluxheim_metrics_otlp_exports_total{outcome="other"}"#));
        assert!(!output.contains("attacker-outcome"));
    }

    #[test]
    fn status_class_is_bounded() {
        assert_eq!(status_class(Some(101)), "1xx");
        assert_eq!(status_class(Some(204)), "2xx");
        assert_eq!(status_class(Some(304)), "3xx");
        assert_eq!(status_class(Some(404)), "4xx");
        assert_eq!(status_class(Some(503)), "5xx");
        assert_eq!(status_class(Some(799)), "other");
        assert_eq!(status_class(None), "unknown");
    }

    #[test]
    fn method_bucket_is_bounded() {
        assert_eq!(method_bucket("GET"), "GET");
        assert_eq!(method_bucket("POST"), "POST");
        assert_eq!(method_bucket("PROPFIND"), "OTHER");
        assert_eq!(method_bucket("attacker-controlled-method"), "OTHER");
    }

    fn cache_metrics_config() -> Config {
        Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                tls: VhostTlsConfig::default(),
                acme_challenge: VhostAcmeChallengeConfig::default(),
                redirect: VhostRedirectConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: CacheMemoryConfig {
                        enabled: true,
                        ..CacheMemoryConfig::default()
                    },
                    disk: CacheDiskConfig {
                        enabled: true,
                        ..CacheDiskConfig::default()
                    },
                    peer_fill: CachePeerFillConfig {
                        enabled: true,
                        peers: vec![
                            CachePeerConfig {
                                name: "cache-a".to_owned(),
                                base_url: "https://cache-a.example:8443".to_owned(),
                            },
                            CachePeerConfig {
                                name: "cache-b".to_owned(),
                                base_url: "https://cache-b.example:8443".to_owned(),
                            },
                        ],
                        max_concurrent_requests: 128,
                        ..CachePeerFillConfig::default()
                    },
                    ..CacheConfig::default()
                },
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![cached_route(), uncached_route()],
            }],
            ..Config::default()
        }
    }

    fn load_balancer_metrics_config() -> Config {
        Config {
            vhosts: vec![VhostConfig {
                name: "lb".to_owned(),
                hosts: vec!["lb.example".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                tls: VhostTlsConfig::default(),
                acme_challenge: VhostAcmeChallengeConfig::default(),
                redirect: VhostRedirectConfig::default(),
                proxy: ProxyConfig {
                    upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
                    load_balance: crate::config::LoadBalanceConfig {
                        selection: crate::config::LoadBalanceSelection::LeastTime,
                        ..crate::config::LoadBalanceConfig::default()
                    },
                    ..ProxyConfig::default()
                },
                cache: CacheConfig::default(),
                compression: None,
                headers: VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: vec![load_balancer_route(), single_upstream_route()],
            }],
            ..Config::default()
        }
    }

    fn load_balancer_route() -> RouteConfig {
        RouteConfig {
            name: "route-lb".to_owned(),
            path_exact: None,
            path_prefix: Some("/route-lb/".to_owned()),
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(ProxyConfig {
                upstreams: vec!["127.0.0.1:4001".to_owned(), "127.0.0.1:4002".to_owned()],
                load_balance: crate::config::LoadBalanceConfig {
                    selection: crate::config::LoadBalanceSelection::ConsistentUriHash,
                    ..crate::config::LoadBalanceConfig::default()
                },
                ..ProxyConfig::default()
            }),
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
        }
    }

    fn single_upstream_route() -> RouteConfig {
        RouteConfig {
            name: "single-upstream".to_owned(),
            path_exact: None,
            path_prefix: Some("/single/".to_owned()),
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(ProxyConfig {
                upstreams: vec!["127.0.0.1:5001".to_owned()],
                ..ProxyConfig::default()
            }),
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
        }
    }

    fn cached_route() -> RouteConfig {
        RouteConfig {
            name: "assets".to_owned(),
            path_exact: None,
            path_prefix: Some("/assets/".to_owned()),
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(ProxyConfig::default()),
            web: None,
            php: None,
            cache: Some(CacheConfig {
                enabled: true,
                memory: CacheMemoryConfig {
                    enabled: true,
                    ..CacheMemoryConfig::default()
                },
                peer_fill: CachePeerFillConfig {
                    enabled: true,
                    peers: vec![CachePeerConfig {
                        name: "route-cache".to_owned(),
                        base_url: "https://route-cache.example:8443".to_owned(),
                    }],
                    ..CachePeerFillConfig::default()
                },
                ..CacheConfig::default()
            }),
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
        }
    }

    fn uncached_route() -> RouteConfig {
        RouteConfig {
            name: "api".to_owned(),
            path_exact: None,
            path_prefix: Some("/api/".to_owned()),
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(ProxyConfig::default()),
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
        }
    }

    fn metrics_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }
}

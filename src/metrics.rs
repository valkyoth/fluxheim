#[cfg(feature = "proxy")]
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts,
};

use crate::metrics_labels::{
    acme_event_label, admin_auth_event_label, admin_auth_scope_label, cache_event_label,
    cache_operation_label, cache_phase_label, cache_purge_mode_label, cache_purge_operation_label,
    cache_purger_entry_result_label, cache_purger_outcome_label, cache_scope_label,
    cache_tier_label, compression_encoding_label, edge_policy_label, edge_policy_outcome_label,
    host_routing_reason_label, load_balancer_event_label, load_balancer_queue_outcome_label,
    load_balancer_upstream_label, metrics_otlp_export_outcome_label, outcome_class,
    php_fpm_pool_event_label, php_fpm_retry_reason_label, php_outcome_label,
    php_stderr_state_label, stream_direction_label, stream_outcome_label, udp_direction_label,
    udp_drop_reason_label, udp_mode_label, udp_outcome_label,
};
pub(crate) use crate::metrics_labels::{method_bucket, status_class};
#[cfg(feature = "proxy")]
pub(crate) use crate::metrics_native::metrics_background_service_from_config;
#[cfg(test)]
pub(crate) use crate::metrics_native::native_metrics_app_from_config;
pub use crate::metrics_native::{NativeMetricsApp, native_prometheus_response};

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

pub fn enabled() -> bool {
    true
}

pub fn prometheus_text() -> Result<Vec<u8>, prometheus::Error> {
    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new().encode(&metric_families, &mut output)?;
    Ok(output)
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
pub fn record_cache_runtime_totals(totals: &fluxheim_cache::CacheRuntimeTotals) {
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

#[cfg(test)]
#[path = "metrics_tests.rs"]
mod tests;

use std::time::Duration;

use fluxheim_observability::{
    metrics_acme_event_label as acme_event_label,
    metrics_admin_auth_event_label as admin_auth_event_label,
    metrics_admin_auth_scope_label as admin_auth_scope_label,
    metrics_compression_encoding_label as compression_encoding_label,
    metrics_edge_policy_label as edge_policy_label,
    metrics_edge_policy_outcome_label as edge_policy_outcome_label,
    metrics_host_routing_reason_label as host_routing_reason_label,
    metrics_load_balancer_event_label as load_balancer_event_label,
    metrics_load_balancer_queue_outcome_label as load_balancer_queue_outcome_label,
    metrics_load_balancer_upstream_label as load_balancer_upstream_label,
    metrics_otlp_export_outcome_label, metrics_outcome_class as outcome_class,
    metrics_php_fpm_pool_event_label as php_fpm_pool_event_label,
    metrics_php_fpm_retry_reason_label as php_fpm_retry_reason_label,
    metrics_php_outcome_label as php_outcome_label,
    metrics_php_stderr_state_label as php_stderr_state_label,
    metrics_stream_direction_label as stream_direction_label,
    metrics_stream_outcome_label as stream_outcome_label,
    metrics_udp_direction_label as udp_direction_label,
    metrics_udp_drop_reason_label as udp_drop_reason_label,
    metrics_udp_mode_label as udp_mode_label, metrics_udp_outcome_label as udp_outcome_label,
};
use prometheus::{Encoder, IntGauge};

#[cfg(feature = "proxy")]
pub(crate) use crate::metrics_native::metrics_background_service_from_config;
#[cfg(test)]
pub(crate) use crate::metrics_native::native_metrics_app_from_config;
pub use crate::metrics_native::{NativeMetricsApp, native_prometheus_response};
use fluxheim_cache::cache_scope_label;
pub(crate) use fluxheim_observability::{
    metrics_method_bucket as method_bucket, metrics_status_class as status_class,
};

#[path = "metrics_registry.rs"]
mod metrics_registry;
use metrics_registry::*;

#[path = "metrics_cache.rs"]
mod metrics_cache;
pub use metrics_cache::*;

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
    wasm_plugin_executions_total()?;
    wasm_plugin_execution_seconds()?;
    wasm_plugin_admission_rejections_total()?;
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

pub fn record_wasm_plugin_execution(plugin: &str, phase: &str, outcome: &str, duration: Duration) {
    let plugin = wasm_plugin_label(plugin);
    let phase = wasm_phase_metric_label(phase);
    let outcome = wasm_outcome_metric_label(outcome);
    match wasm_plugin_executions_total() {
        Ok(counter) => counter.with_label_values(&[plugin, phase, outcome]).inc(),
        Err(error) => log::debug!("metrics Wasm plugin execution counter unavailable: {error}"),
    }
    match wasm_plugin_execution_seconds() {
        Ok(histogram) => histogram
            .with_label_values(&[plugin, phase, outcome])
            .observe(duration.as_secs_f64()),
        Err(error) => log::debug!("metrics Wasm plugin execution histogram unavailable: {error}"),
    }
}

pub fn record_wasm_plugin_admission_rejection(plugin: &str, phase: &str, scope: &str) {
    match wasm_plugin_admission_rejections_total() {
        Ok(counter) => counter
            .with_label_values(&[
                wasm_plugin_label(plugin),
                wasm_phase_metric_label(phase),
                wasm_admission_scope_metric_label(scope),
            ])
            .inc(),
        Err(error) => log::debug!("metrics Wasm plugin admission counter unavailable: {error}"),
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

fn wasm_plugin_label(plugin: &str) -> &str {
    if plugin.len() <= crate::config::MAX_WASM_PLUGIN_NAME_BYTES
        && plugin
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        plugin
    } else {
        "other"
    }
}

fn wasm_phase_metric_label(phase: &str) -> &'static str {
    match phase {
        "request-headers" => "request-headers",
        "response-headers" => "response-headers",
        "access-decision" => "access-decision",
        "route-decision" => "route-decision",
        "cache-lookup" => "cache-lookup",
        "cache-store" => "cache-store",
        _ => "other",
    }
}

fn wasm_outcome_metric_label(outcome: &str) -> &'static str {
    match outcome {
        "allow" => "allow",
        "deny" => "deny",
        "continue" => "continue",
        "mutate" => "mutate",
        "bypass" => "bypass",
        "pass" => "pass",
        "synthetic" => "synthetic",
        "timeout" => "timeout",
        "trap" => "trap",
        "fuel_exhausted" => "fuel_exhausted",
        "fail_open" => "fail_open",
        "fail_closed" => "fail_closed",
        "error" => "error",
        _ => "other",
    }
}

fn wasm_admission_scope_metric_label(scope: &str) -> &'static str {
    match scope {
        "global" => "global",
        "plugin" => "plugin",
        "attachment" => "attachment",
        _ => "other",
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

#[cfg(test)]
#[path = "metrics_tests.rs"]
mod tests;

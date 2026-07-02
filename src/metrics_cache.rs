#[cfg(feature = "proxy")]
use std::sync::Arc;
use std::time::Duration;

use crate::metrics_labels::{
    cache_event_label, cache_operation_label, cache_phase_label, cache_purge_mode_label,
    cache_purge_operation_label, cache_purger_entry_result_label, cache_purger_outcome_label,
    cache_scope_label, cache_tier_label,
};

use super::*;

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

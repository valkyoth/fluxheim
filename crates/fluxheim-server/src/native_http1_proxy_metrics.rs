use std::sync::{Arc, OnceLock};
use std::time::Duration;

static NATIVE_CACHE_METRICS_RECORDER: OnceLock<Arc<dyn NativeCacheMetricsRecorder>> =
    OnceLock::new();
static NATIVE_PROXY_METRICS_RECORDER: OnceLock<Arc<dyn NativeProxyMetricsRecorder>> =
    OnceLock::new();

pub trait NativeCacheMetricsRecorder: Send + Sync + 'static {
    fn record_activity(&self, tier: &str, event: &str);

    fn record_activity_scope(&self, vhost: &str, route: Option<&str>, tier: &str, event: &str);

    fn record_operation_duration(
        &self,
        vhost: &str,
        route: Option<&str>,
        phase: &str,
        operation: &str,
        duration: Duration,
    );
}

pub trait NativeProxyMetricsRecorder: Send + Sync + 'static {
    fn record_outcome(&self, vhost: &str, method: &str, status: u16);

    fn record_host_routing_rejection(&self, _reason: &str) {}
}

pub trait NativeWasmMetricsRecorder: Send + Sync + 'static {
    fn record_execution(&self, plugin: &str, phase: &str, outcome: &str, duration: Duration);

    fn record_admission_rejection(&self, plugin: &str, phase: &str, scope: &str);
}

pub fn install_native_cache_metrics_recorder(
    recorder: Arc<dyn NativeCacheMetricsRecorder>,
) -> bool {
    NATIVE_CACHE_METRICS_RECORDER.set(recorder).is_ok()
}

pub fn install_native_proxy_metrics_recorder(
    recorder: Arc<dyn NativeProxyMetricsRecorder>,
) -> bool {
    NATIVE_PROXY_METRICS_RECORDER.set(recorder).is_ok()
}

static NATIVE_WASM_METRICS_RECORDER: OnceLock<Arc<dyn NativeWasmMetricsRecorder>> = OnceLock::new();

pub fn install_native_wasm_metrics_recorder(recorder: Arc<dyn NativeWasmMetricsRecorder>) -> bool {
    NATIVE_WASM_METRICS_RECORDER.set(recorder).is_ok()
}

pub(crate) fn record_native_cache_activity(tier: &'static str, event: &'static str) {
    if let Some(recorder) = NATIVE_CACHE_METRICS_RECORDER.get() {
        recorder.record_activity(tier, event);
    }
}

pub(crate) fn record_native_cache_activity_scope(
    vhost: &str,
    route: Option<&str>,
    tier: &'static str,
    event: &'static str,
) {
    if let Some(recorder) = NATIVE_CACHE_METRICS_RECORDER.get() {
        recorder.record_activity_scope(vhost, route, tier, event);
    }
}

pub(crate) fn record_native_cache_operation_duration(
    vhost: &str,
    route: Option<&str>,
    phase: &'static str,
    operation: &'static str,
    duration: Duration,
) {
    if let Some(recorder) = NATIVE_CACHE_METRICS_RECORDER.get() {
        recorder.record_operation_duration(vhost, route, phase, operation, duration);
    }
}

pub(crate) fn record_native_proxy_outcome(vhost: &str, method: &str, status: u16) {
    if let Some(recorder) = NATIVE_PROXY_METRICS_RECORDER.get() {
        recorder.record_outcome(vhost, method, status);
    }
}

pub(crate) fn record_native_host_routing_rejection(reason: &'static str) {
    if let Some(recorder) = NATIVE_PROXY_METRICS_RECORDER.get() {
        recorder.record_host_routing_rejection(reason);
    }
}

#[cfg(feature = "wasm")]
pub(crate) fn record_native_wasm_execution(
    plugin: &str,
    phase: &'static str,
    outcome: &'static str,
    duration: Duration,
) {
    if let Some(recorder) = NATIVE_WASM_METRICS_RECORDER.get() {
        recorder.record_execution(plugin, phase, outcome, duration);
    }
}

#[cfg(feature = "wasm")]
pub(crate) fn record_native_wasm_admission_rejection(
    plugin: &str,
    phase: &'static str,
    scope: &'static str,
) {
    if let Some(recorder) = NATIVE_WASM_METRICS_RECORDER.get() {
        recorder.record_admission_rejection(plugin, phase, scope);
    }
}

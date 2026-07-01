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

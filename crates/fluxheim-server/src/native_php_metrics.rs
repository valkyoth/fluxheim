use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

static RECORDER: OnceLock<Arc<dyn NativePhpMetricsRecorder>> = OnceLock::new();

pub trait NativePhpMetricsRecorder: Send + Sync + 'static {
    fn record_request(
        &self,
        vhost: &str,
        method: &str,
        status: Option<u16>,
        outcome: &'static str,
        duration: Duration,
    );
}

pub fn install_native_php_metrics_recorder(recorder: Arc<dyn NativePhpMetricsRecorder>) -> bool {
    RECORDER.set(recorder).is_ok()
}

pub(crate) struct PhpRequestMetrics<'a> {
    recorder: Option<&'a dyn NativePhpMetricsRecorder>,
    vhost: &'a str,
    method: &'static str,
    started: Instant,
    status: Option<u16>,
}

impl<'a> PhpRequestMetrics<'a> {
    pub(crate) fn start(vhost: &'a str, method: &str) -> Self {
        Self {
            recorder: RECORDER.get().map(Arc::as_ref),
            vhost,
            method: fluxheim_observability::metrics_method_bucket(method),
            started: Instant::now(),
            status: None,
        }
    }

    pub(crate) fn finish(mut self, status: u16) {
        self.status = Some(status);
    }
}

impl Drop for PhpRequestMetrics<'_> {
    fn drop(&mut self) {
        if let Some(recorder) = self.recorder {
            recorder.record_request(
                self.vhost,
                self.method,
                self.status,
                if self.status.is_some() {
                    "response"
                } else {
                    "cancelled"
                },
                self.started.elapsed(),
            );
        }
    }
}

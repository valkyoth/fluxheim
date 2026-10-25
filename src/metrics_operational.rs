use fluxheim_observability::event::{AccessOutcome, EventData};
use fluxheim_observability::operational::metrics::{HandshakeOutcome, Measurement};
use prometheus::core::{Collector, Desc};
use prometheus::proto::MetricFamily;
use prometheus::{Error, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts};
use std::sync::OnceLock;

static METRICS: OnceLock<Operational> = OnceLock::new();
const BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

#[derive(Clone)]
struct Operational {
    requests: IntCounterVec,
    duration: HistogramVec,
    bytes: IntCounter,
    active: IntGauge,
    attempts: IntCounterVec,
    attempt_duration: HistogramVec,
    active_attempts: IntGauge,
    failures: IntCounterVec,
    security: IntCounterVec,
    audit: IntCounterVec,
    connections: IntCounterVec,
    active_connections: IntGauge,
    tls: IntCounterVec,
}

impl Operational {
    fn new() -> Result<Self, Error> {
        let counter =
            |name, help, labels: &[&str]| IntCounterVec::new(Opts::new(name, help), labels);
        let histogram = |name, help| {
            HistogramVec::new(
                HistogramOpts::new(name, help).buckets(BUCKETS.to_vec()),
                &["outcome"],
            )
        };
        Ok(Self {
            requests: counter(
                "fluxheim_http_requests_total",
                "Logical routed HTTP requests completed, failed, or cancelled at the downstream boundary.",
                &["method", "status_class", "outcome"],
            )?,
            duration: histogram(
                "fluxheim_http_request_duration_seconds",
                "Monotonic logical request duration through downstream completion or cancellation.",
            )?,
            bytes: IntCounter::new(
                "fluxheim_http_response_body_bytes_total",
                "Response body bytes accounted on successful downstream completion; excludes partial failed writes and tunnels.",
            )?,
            active: IntGauge::new(
                "fluxheim_http_requests_active",
                "Routed HTTP requests awaiting downstream completion, including upgraded tunnels.",
            )?,
            attempts: counter(
                "fluxheim_upstream_attempts_total",
                "Transport attempts including explicit retries, scoped to a routed request.",
                &["outcome"],
            )?,
            attempt_duration: histogram(
                "fluxheim_upstream_attempt_duration_seconds",
                "Monotonic upstream attempt duration including connection acquisition.",
            )?,
            active_attempts: IntGauge::new(
                "fluxheim_upstream_attempts_active",
                "In-flight request-scoped transport attempts.",
            )?,
            failures: counter(
                "fluxheim_operational_failures_total",
                "Typed failure observations at runtime owners, independent of log admission.",
                &["reason"],
            )?,
            security: counter(
                "fluxheim_security_events_total",
                "Typed security observations independent of log admission.",
                &["reason"],
            )?,
            audit: counter(
                "fluxheim_admin_operations_total",
                "Reported administrative operation outcomes; not durable audit delivery acknowledgements.",
                &["operation", "outcome"],
            )?,
            connections: counter(
                "fluxheim_listener_connections_total",
                "Native HTTP listener connections including management listeners, by admission result.",
                &["outcome"],
            )?,
            active_connections: IntGauge::new(
                "fluxheim_listener_connections_active",
                "Admitted native HTTP listener tasks including TLS handshakes and management connections.",
            )?,
            tls: counter(
                "fluxheim_downstream_tls_handshakes_total",
                "Native downstream TLS handshake results, excluding cancelled handshakes and pre-handshake setup failures.",
                &["outcome"],
            )?,
        })
    }

    fn record(&self, measurement: Measurement) {
        match measurement {
            Measurement::Event(EventData::Access {
                outcome,
                method,
                status,
                duration_micros,
                bytes_sent,
                ..
            }) => {
                self.active.dec();
                self.requests
                    .with_label_values(&[
                        method.metric_label(),
                        super::status_class(status.map(|s| s.as_u16())),
                        outcome.metric_label(),
                    ])
                    .inc();
                self.duration
                    .with_label_values(&[outcome.metric_label()])
                    .observe(duration_micros as f64 / 1_000_000.0);
                if matches!(outcome, AccessOutcome::Completed) {
                    self.bytes.inc_by(bytes_sent);
                }
            }
            Measurement::Event(EventData::Error { reason, .. }) => self
                .failures
                .with_label_values(&[reason.metric_label()])
                .inc(),
            Measurement::Event(EventData::Security { reason }) => self
                .security
                .with_label_values(&[reason.metric_label()])
                .inc(),
            Measurement::Event(EventData::Audit {
                operation, outcome, ..
            }) => self
                .audit
                .with_label_values(&[operation.metric_label(), outcome.metric_label()])
                .inc(),
            Measurement::RequestStarted => self.active.inc(),
            Measurement::AttemptStarted => self.active_attempts.inc(),
            Measurement::AttemptFinished {
                failed,
                cancelled,
                duration,
            } => {
                self.active_attempts.dec();
                let outcome = if cancelled {
                    "cancelled"
                } else if failed {
                    "failed"
                } else {
                    "completed"
                };
                self.attempts.with_label_values(&[outcome]).inc();
                self.attempt_duration
                    .with_label_values(&[outcome])
                    .observe(duration.as_secs_f64());
            }
            Measurement::ConnectionStarted => {
                self.connections.with_label_values(&["accepted"]).inc();
                self.active_connections.inc();
            }
            Measurement::ConnectionFinished => self.active_connections.dec(),
            Measurement::ConnectionRejected => {
                self.connections.with_label_values(&["rejected"]).inc()
            }
            Measurement::TlsHandshake(outcome) => self
                .tls
                .with_label_values(&[match outcome {
                    HandshakeOutcome::Succeeded => "succeeded",
                    HandshakeOutcome::Failed => "failed",
                    HandshakeOutcome::Timeout => "timeout",
                }])
                .inc(),
        }
    }

    fn collectors(&self) -> [&dyn Collector; 13] {
        [
            &self.requests,
            &self.duration,
            &self.bytes,
            &self.active,
            &self.attempts,
            &self.attempt_duration,
            &self.active_attempts,
            &self.failures,
            &self.security,
            &self.audit,
            &self.connections,
            &self.active_connections,
            &self.tls,
        ]
    }
}
impl Collector for Operational {
    fn desc(&self) -> Vec<&Desc> {
        self.collectors().iter().flat_map(|c| c.desc()).collect()
    }
    fn collect(&self) -> Vec<MetricFamily> {
        self.collectors().iter().flat_map(|c| c.collect()).collect()
    }
}

pub(super) fn init() -> Result<(), Error> {
    if METRICS.get().is_none() {
        let metrics = Operational::new()?;
        prometheus::default_registry().register(Box::new(super::health::Health::new()?))?;
        prometheus::default_registry().register(Box::new(metrics.clone()))?;
        let _ = METRICS.set(metrics);
        fluxheim_observability::operational::metrics::install(|measurement| {
            if let Some(metrics) = METRICS.get() {
                metrics.record(measurement);
            }
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "metrics_operational_tests.rs"]
mod tests;

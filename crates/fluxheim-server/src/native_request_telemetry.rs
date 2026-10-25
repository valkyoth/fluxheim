//! Request-local provenance and completion. No raw target, headers, body or peer is retained.
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Instant;

use crate::{NativeHttp1Request, NativeHttp1Response, ProxyProtocolTrustedSource};
use fluxheim_observability::TraceContext;
use fluxheim_observability::event::{
    AccessOutcome, CapturePolicy, CorrelationInput, EventData, HttpStatus, Method,
};
use fluxheim_observability::operational::metrics::{Measurement, record};

tokio::task_local! {
    static CURRENT: Arc<RequestContext>;
    static ATTEMPT: std::cell::RefCell<Attempt>;
}

#[derive(Clone, Debug)]
pub(crate) struct RequestTelemetry {
    access: fluxheim_config::AccessLoggingConfig,
    trace: bool,
    log_trace: bool,
    trusted: Vec<ProxyProtocolTrustedSource>,
    #[cfg(feature = "otel-otlp")]
    exporter: Option<fluxheim_observability::TraceExporter>,
}

impl RequestTelemetry {
    pub(crate) fn new(
        config: &fluxheim_config::Config,
        trusted: Vec<ProxyProtocolTrustedSource>,
    ) -> std::io::Result<Self> {
        config.logging.access.validate().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid request correlation configuration",
            )
        })?;
        Ok(Self {
            access: config.logging.access.clone(),
            trace: cfg!(feature = "otel-tracing")
                && !cfg!(feature = "privacy-mode")
                && config.tracing.enabled,
            log_trace: config.tracing.log_trace_id,
            trusted,
            #[cfg(feature = "otel-otlp")]
            exporter: if cfg!(feature = "privacy-mode") {
                None
            } else {
                fluxheim_observability::TraceExporter::from_config(&config.tracing.otlp)?
            },
        })
    }

    pub(crate) fn begin(&self, request: &mut NativeHttp1Request) -> Completion {
        let trusted = !cfg!(feature = "privacy-mode")
            && request
                .peer_addr
                .is_some_and(|peer| self.trusted.iter().any(|source| source.contains(peer.ip())));
        let request_id = if self.access.request_id && !cfg!(feature = "privacy-mode") {
            let inbound = unique_header(request, &self.access.request_id_header);
            let id = inbound
                .filter(|id| trusted && fluxheim_observability::access_log_request_id_valid(id))
                .map(str::to_owned)
                .or_else(fluxheim_observability::generate_access_log_request_id);
            request
                .headers
                .retain(|(name, _)| !name.eq_ignore_ascii_case(&self.access.request_id_header));
            if let Some(id) = &id {
                request
                    .headers
                    .push((self.access.request_id_header.clone(), id.clone()));
            }
            id
        } else {
            None
        };
        let trace = if self.trace {
            unique_header(request, "traceparent")
                .filter(|value| trusted && value.len() == 55)
                .and_then(|value| TraceContext::parse_traceparent(value, true))
                .or_else(TraceContext::generate)
        } else {
            None
        };
        request
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("traceparent"));
        if let Some(trace) = trace {
            request
                .headers
                .push(("traceparent".to_owned(), trace.to_traceparent()));
        }
        // No baggage or vendor state crosses the boundary implicitly.
        request.headers.retain(|(name, _)| {
            !name.eq_ignore_ascii_case("tracestate") && !name.eq_ignore_ascii_case("baggage")
        });
        record(Measurement::RequestStarted);
        Completion(Arc::new(CompletionState {
            context: Arc::new(RequestContext {
                request_id,
                trace,
                method: Method::from_request(&request.method),
                request_bytes: request.body.len() as u64,
                policy: CapturePolicy {
                    access_enabled: self.access.enabled,
                    include_request_id: self.access.request_id,
                    include_trace_ids: self.log_trace,
                    privacy_mode: cfg!(feature = "privacy-mode"),
                    ..CapturePolicy::default()
                },
                attempts: AtomicU32::new(0),
                #[cfg(feature = "otel-otlp")]
                exporter: self.exporter.clone(),
            }),
            started: Instant::now(),
            timestamp: fluxheim_observability::unix_time_nanos(),
            finished: AtomicBool::new(false),
        }))
    }
}

pub(crate) fn unique_header<'a>(request: &'a NativeHttp1Request, name: &str) -> Option<&'a str> {
    let mut values = request
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name));
    let value = values.next()?.1.as_str();
    values.next().is_none().then_some(value)
}

struct RequestContext {
    request_id: Option<String>,
    trace: Option<TraceContext>,
    method: Method,
    request_bytes: u64,
    policy: CapturePolicy,
    attempts: AtomicU32,
    #[cfg(feature = "otel-otlp")]
    exporter: Option<fluxheim_observability::TraceExporter>,
}

/// Task-local scope is deliberately not inherited by tokio::spawn background work.
#[cfg(any(feature = "otel-tracing", test))]
pub(crate) fn current_trace() -> Option<Option<TraceContext>> {
    CURRENT.try_with(|context| context.trace).ok()
}

#[derive(Clone)]
pub(crate) struct Completion(Arc<CompletionState>);

impl std::fmt::Debug for Completion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Completion([REDACTED])")
    }
}
impl PartialEq for Completion {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for Completion {}

struct CompletionState {
    context: Arc<RequestContext>,
    started: Instant,
    timestamp: u128,
    finished: AtomicBool,
}

impl Completion {
    pub(crate) async fn scope<T>(&self, future: impl Future<Output = T>) -> T {
        let context = &self.0.context;
        let trace = context.trace.map(|trace| trace.trace_id_hex());
        let span = context.trace.map(|trace| trace.span_id_hex());
        CURRENT
            .scope(
                context.clone(),
                fluxheim_observability::operational::scope(
                    CorrelationInput {
                        trusted: true,
                        request_id: context.request_id.as_deref(),
                        trace_id: trace.as_deref(),
                        span_id: span.as_deref(),
                    },
                    context.policy,
                    future,
                ),
            )
            .await
    }

    pub(crate) fn finish(&self, status: Option<u16>, bytes: u64, success: bool) {
        self.0.finish(
            status,
            bytes,
            if success {
                AccessOutcome::Completed
            } else {
                AccessOutcome::Failed
            },
        );
    }

    pub(crate) fn attach(self, mut response: NativeHttp1Response) -> NativeHttp1Response {
        response.completion = Some(self);
        response
    }
}

impl CompletionState {
    fn finish(&self, status: Option<u16>, bytes: u64, outcome: AccessOutcome) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        let context = &self.context;
        let trace_id = context.trace.map(|trace| trace.trace_id_hex());
        let span_id = context.trace.map(|trace| trace.span_id_hex());
        fluxheim_observability::operational::emit_correlated(
            EventData::Access {
                outcome,
                method: context.method,
                status: status.and_then(HttpStatus::new),
                duration_micros: u64::try_from(self.started.elapsed().as_micros())
                    .unwrap_or(u64::MAX),
                bytes_sent: bytes,
                attempts: context.attempts.load(Ordering::Relaxed),
            },
            CorrelationInput {
                trusted: true,
                request_id: context.request_id.as_deref(),
                trace_id: trace_id.as_deref(),
                span_id: span_id.as_deref(),
            },
            context.policy,
        );
        #[cfg(feature = "otel-otlp")]
        if let Some(exporter) = &context.exporter
            && let Some(trace) = context.trace.filter(|trace| trace.sampled())
        {
            exporter.try_export(request_span(
                context,
                trace,
                status,
                bytes,
                !matches!(outcome, AccessOutcome::Completed),
                self.timestamp,
            ));
        }
        #[cfg(not(feature = "otel-otlp"))]
        let _ = (context.request_bytes, self.timestamp);
    }
}

impl Drop for CompletionState {
    fn drop(&mut self) {
        self.finish(None, 0, AccessOutcome::Cancelled);
    }
}

#[cfg(feature = "otel-otlp")]
fn request_span(
    context: &RequestContext,
    trace: TraceContext,
    status: Option<u16>,
    bytes: u64,
    error: bool,
    start: u128,
) -> fluxheim_observability::TraceSpan {
    fluxheim_observability::TraceSpan {
        trace_id: trace.trace_id_hex(),
        span_id: trace.span_id_hex(),
        parent_span_id: trace.parent_span_id_hex(),
        name: "HTTP request".to_owned(),
        method: format!("{:?}", context.method),
        vhost: String::new(),
        route: None,
        status_code: status,
        error: error || status.is_some_and(|status| status >= 500),
        start_time_unix_nanos: start,
        end_time_unix_nanos: fluxheim_observability::unix_time_nanos().max(start),
        request_body_bytes: context.request_bytes,
        response_body_bytes: bytes,
        load_balancer_upstream_alias: None,
        load_balancer_retries: None,
        cache_phase: None,
        cache_lookup_duration_ms: None,
        cache_lock_wait_duration_ms: None,
        compression_encoding: None,
        php_runtime: None,
        php_outcome: None,
        client: false,
        attempt: None,
    }
}

/// One transport attempt, including connection acquisition. Explicit safe retries
/// finish the previous child before generating another; no request completion here.
pub(crate) async fn upstream_attempt(
    future: impl Future<Output = Result<NativeHttp1Response, crate::NativeHttp1Error>>,
) -> Result<NativeHttp1Response, crate::NativeHttp1Error> {
    transport_attempt(future, |response| Some(response.status())).await
}

pub(crate) async fn transport_attempt<T, E>(
    future: impl Future<Output = Result<T, E>>,
    status: impl FnOnce(&T) -> Option<u16>,
) -> Result<T, E> {
    let Ok(context) = CURRENT.try_with(Arc::clone) else {
        return future.await;
    };
    ATTEMPT
        .scope(std::cell::RefCell::new(Attempt::new(context)), async {
            let result = future.await;
            ATTEMPT.with(|attempt| {
                attempt
                    .borrow_mut()
                    .finish(result.as_ref().ok().and_then(status), result.is_err())
            });
            result
        })
        .await
}

pub(crate) fn retry_attempt() {
    let _ = ATTEMPT.try_with(|attempt| {
        let mut attempt = attempt.borrow_mut();
        attempt.finish(None, true);
        *attempt = Attempt::new(attempt.context.clone());
    });
}

pub(crate) fn attempt_traceparent() -> Option<String> {
    ATTEMPT
        .try_with(|attempt| attempt.borrow().trace.map(TraceContext::to_traceparent))
        .ok()
        .flatten()
}

struct Attempt {
    context: Arc<RequestContext>,
    trace: Option<TraceContext>,
    start: u128,
    number: u32,
    finished: bool,
    monotonic_start: Instant,
}

impl Attempt {
    fn new(context: Arc<RequestContext>) -> Self {
        record(Measurement::AttemptStarted);
        let number = context
            .attempts
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            })
            .unwrap_or_else(|n| n)
            .saturating_add(1);
        Self {
            trace: context.trace.and_then(TraceContext::child),
            context,
            start: fluxheim_observability::unix_time_nanos(),
            number,
            finished: false,
            monotonic_start: Instant::now(),
        }
    }

    fn finish(&mut self, status: Option<u16>, error: bool) {
        self.finish_outcome(status, error, false);
    }

    fn finish_outcome(&mut self, status: Option<u16>, error: bool, cancelled: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        record(Measurement::AttemptFinished {
            failed: error || status.is_some_and(|status| status >= 500),
            cancelled,
            duration: self.monotonic_start.elapsed(),
        });
        #[cfg(feature = "otel-otlp")]
        if let Some(exporter) = &self.context.exporter
            && let Some(trace) = self.trace.filter(|trace| trace.sampled())
        {
            let mut span = request_span(&self.context, trace, status, 0, error, self.start);
            span.name = "Upstream attempt".to_owned();
            span.client = true;
            span.attempt = Some(self.number);
            exporter.try_export(span);
        }
        #[cfg(not(feature = "otel-otlp"))]
        let _ = (status, error, self.start, self.number);
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        self.finish_outcome(None, true, true);
    }
}

#[cfg(test)]
#[path = "native_request_telemetry_tests.rs"]
mod tests;

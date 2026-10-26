use std::time::Duration;

use serde_json::json;

use fluxheim_config::OtlpTraceExportConfig;

#[derive(Debug, Clone)]
pub struct TraceExporter {
    worker: crate::ExportWorker,
    service_name: String,
}

impl TraceExporter {
    pub fn from_config(config: &OtlpTraceExportConfig) -> std::io::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }

        if config.service_name.is_empty()
            || config.service_name.len() > 128
            || !config
                .service_name
                .bytes()
                .all(|b| b.is_ascii_graphic() || b == b' ')
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid OTLP service name",
            ));
        }
        let service_name = config.service_name.clone();
        let timeout = Duration::from_secs(config.timeout_secs);
        let worker = crate::ExportWorker::new(crate::ExportOptions {
            endpoint: &config.endpoint,
            ca: config.tls_ca_cert_path.as_deref(),
            token: config.bearer_token_file.as_deref(),
            signal: crate::ExportSignal::Traces,
            queue_size: config.queue_size,
            timeout,
            on_complete: None,
        })?;
        Ok(Some(Self {
            worker,
            service_name,
        }))
    }

    pub fn try_export(&self, span: TraceSpan) {
        if !bounded_span(&span) {
            self.worker.record_drop();
            return;
        }
        self.worker
            .try_export(build_trace_payload(span, &self.service_name));
    }
}

fn bounded_span(span: &TraceSpan) -> bool {
    let required = [
        &span.trace_id,
        &span.span_id,
        &span.name,
        &span.method,
        &span.vhost,
    ];
    let optional = [
        &span.parent_span_id,
        &span.route,
        &span.load_balancer_upstream_alias,
        &span.cache_phase,
        &span.compression_encoding,
        &span.php_runtime,
        &span.php_outcome,
    ];
    required.into_iter().all(|v| v.len() <= 256)
        && optional.into_iter().flatten().all(|v| v.len() <= 256)
}

#[derive(Debug, Clone, PartialEq)]
pub struct TraceSpan {
    pub client: bool,
    pub attempt: Option<u32>,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub method: String,
    pub vhost: String,
    pub route: Option<String>,
    pub status_code: Option<u16>,
    pub error: bool,
    pub start_time_unix_nanos: u128,
    pub end_time_unix_nanos: u128,
    pub request_body_bytes: u64,
    pub response_body_bytes: u64,
    pub load_balancer_upstream_alias: Option<String>,
    pub load_balancer_retries: Option<u8>,
    pub cache_phase: Option<String>,
    pub cache_lookup_duration_ms: Option<f64>,
    pub cache_lock_wait_duration_ms: Option<f64>,
    pub compression_encoding: Option<String>,
    pub php_runtime: Option<String>,
    pub php_outcome: Option<String>,
}

fn build_trace_payload(span: TraceSpan, service_name: &str) -> String {
    let mut span_json = json!({
        "traceId": span.trace_id,
        "spanId": span.span_id,
        "name": span.name,
        "kind": if span.client { "SPAN_KIND_CLIENT" } else { "SPAN_KIND_SERVER" },
        "startTimeUnixNano": span.start_time_unix_nanos.to_string(),
        "endTimeUnixNano": span.end_time_unix_nanos.to_string(),
        "attributes": [
            string_attr("http.request.method", span.method),
            string_attr("fluxheim.vhost", span.vhost),
            bool_attr("error", span.error),
            int_attr("http.request.body.size", span.request_body_bytes),
            int_attr("http.response.body.size", span.response_body_bytes),
        ],
        "status": {
            "code": if span.error { "STATUS_CODE_ERROR" } else { "STATUS_CODE_OK" }
        }
    });

    if let Some(attempt) = span.attempt
        && let Some(attributes) = span_json["attributes"].as_array_mut()
    {
        attributes.push(int_attr("fluxheim.upstream.attempt", u64::from(attempt)));
    }

    if let Some(parent_span_id) = span.parent_span_id
        && let Some(object) = span_json.as_object_mut()
    {
        object.insert("parentSpanId".to_owned(), json!(parent_span_id));
    }
    if let Some(status_code) = span.status_code
        && let Some(attributes) = span_json
            .as_object_mut()
            .and_then(|object| object.get_mut("attributes"))
            .and_then(|attributes| attributes.as_array_mut())
    {
        attributes.push(int_attr("http.response.status_code", status_code as u64));
    }
    if let Some(route) = span.route
        && let Some(attributes) = span_json
            .as_object_mut()
            .and_then(|object| object.get_mut("attributes"))
            .and_then(|attributes| attributes.as_array_mut())
    {
        attributes.push(string_attr("fluxheim.route", route));
    }
    if let Some(upstream_alias) = span
        .load_balancer_upstream_alias
        .filter(|value| safe_low_cardinality_name(value))
        && let Some(attributes) = span_json
            .as_object_mut()
            .and_then(|object| object.get_mut("attributes"))
            .and_then(|attributes| attributes.as_array_mut())
    {
        attributes.push(string_attr(
            "fluxheim.load_balancer.upstream",
            upstream_alias,
        ));
    }
    if let Some(retries) = span.load_balancer_retries
        && let Some(attributes) = span_json
            .as_object_mut()
            .and_then(|object| object.get_mut("attributes"))
            .and_then(|attributes| attributes.as_array_mut())
    {
        attributes.push(int_attr("fluxheim.load_balancer.retries", retries as u64));
    }
    if let Some(cache_phase) = span.cache_phase
        && let Some(attributes) = span_json
            .as_object_mut()
            .and_then(|object| object.get_mut("attributes"))
            .and_then(|attributes| attributes.as_array_mut())
    {
        attributes.push(string_attr("fluxheim.cache.phase", cache_phase));
    }
    if let Some(duration_ms) = span.cache_lookup_duration_ms
        && let Some(attributes) = span_json
            .as_object_mut()
            .and_then(|object| object.get_mut("attributes"))
            .and_then(|attributes| attributes.as_array_mut())
    {
        attributes.push(double_attr(
            "fluxheim.cache.lookup.duration_ms",
            duration_ms,
        ));
    }
    if let Some(duration_ms) = span.cache_lock_wait_duration_ms
        && let Some(attributes) = span_json
            .as_object_mut()
            .and_then(|object| object.get_mut("attributes"))
            .and_then(|attributes| attributes.as_array_mut())
    {
        attributes.push(double_attr(
            "fluxheim.cache.lock_wait.duration_ms",
            duration_ms,
        ));
    }
    if let Some(compression_encoding) = span.compression_encoding
        && let Some(attributes) = span_json
            .as_object_mut()
            .and_then(|object| object.get_mut("attributes"))
            .and_then(|attributes| attributes.as_array_mut())
    {
        attributes.push(string_attr(
            "fluxheim.compression.encoding",
            compression_encoding,
        ));
    }
    if let Some(php_runtime) = span.php_runtime
        && let Some(attributes) = span_json
            .as_object_mut()
            .and_then(|object| object.get_mut("attributes"))
            .and_then(|attributes| attributes.as_array_mut())
    {
        attributes.push(string_attr("fluxheim.php.runtime", php_runtime));
    }
    if let Some(php_outcome) = span.php_outcome
        && let Some(attributes) = span_json
            .as_object_mut()
            .and_then(|object| object.get_mut("attributes"))
            .and_then(|attributes| attributes.as_array_mut())
    {
        attributes.push(string_attr("fluxheim.php.outcome", php_outcome));
    }

    json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    string_attr("service.name", service_name),
                    string_attr("service.version", env!("CARGO_PKG_VERSION")),
                ]
            },
            "scopeSpans": [{
                "scope": {
                    "name": "fluxheim",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "spans": [span_json]
            }]
        }]
    })
    .to_string()
}

fn string_attr(key: &str, value: impl Into<String>) -> serde_json::Value {
    json!({
        "key": key,
        "value": {
            "stringValue": value.into()
        }
    })
}

fn int_attr(key: &str, value: u64) -> serde_json::Value {
    json!({
        "key": key,
        "value": {
            "intValue": value.to_string()
        }
    })
}

fn bool_attr(key: &str, value: bool) -> serde_json::Value {
    json!({
        "key": key,
        "value": {
            "boolValue": value
        }
    })
}

fn double_attr(key: &str, value: f64) -> serde_json::Value {
    json!({
        "key": key,
        "value": {
            "doubleValue": value
        }
    })
}

fn safe_low_cardinality_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OtlpHttpEndpoint as HttpEndpoint;

    #[test]
    fn parses_http_otlp_endpoint() {
        let endpoint = HttpEndpoint::parse("http://127.0.0.1:4318/v1/traces").unwrap();

        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 4318);
        assert_eq!(endpoint.path, "/v1/traces");
    }

    #[test]
    fn parses_https_otlp_endpoint() {
        let endpoint = HttpEndpoint::parse("https://collector.example.test/v1/traces").unwrap();

        assert_eq!(endpoint.host, "collector.example.test");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.path, "/v1/traces");
    }

    #[test]
    fn trace_payload_contains_required_otlp_fields() {
        let payload = build_trace_payload(
            TraceSpan {
                client: false,
                attempt: None,
                trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_owned(),
                span_id: "00f067aa0ba902b7".to_owned(),
                parent_span_id: None,
                name: "HTTP GET".to_owned(),
                method: "GET".to_owned(),
                vhost: "example.test".to_owned(),
                route: Some("root".to_owned()),
                status_code: Some(200),
                error: false,
                start_time_unix_nanos: 1,
                end_time_unix_nanos: 2,
                request_body_bytes: 0,
                response_body_bytes: 42,
                load_balancer_upstream_alias: Some("origin-a".to_owned()),
                load_balancer_retries: Some(2),
                cache_phase: Some("hit".to_owned()),
                cache_lookup_duration_ms: Some(1.5),
                cache_lock_wait_duration_ms: Some(0.25),
                compression_encoding: Some("gzip".to_owned()),
                php_runtime: Some("php-fpm".to_owned()),
                php_outcome: Some("response".to_owned()),
            },
            "fluxheim",
        );

        assert!(payload.contains(r#""resourceSpans""#));
        assert!(payload.contains(r#""traceId":"4bf92f3577b34da6a3ce929d0e0e4736""#));
        assert!(payload.contains(r#""name":"HTTP GET""#));
        assert!(payload.contains(r#""key":"fluxheim.vhost""#));
        assert!(payload.contains(r#""key":"fluxheim.load_balancer.upstream""#));
        assert!(payload.contains(r#""stringValue":"origin-a""#));
        assert!(payload.contains(r#""key":"fluxheim.load_balancer.retries""#));
        assert!(payload.contains(r#""key":"fluxheim.cache.phase""#));
        assert!(payload.contains(r#""key":"fluxheim.cache.lookup.duration_ms""#));
        assert!(payload.contains(r#""key":"fluxheim.compression.encoding""#));
        assert!(payload.contains(r#""key":"fluxheim.cache.lock_wait.duration_ms""#));
        assert!(payload.contains(r#""key":"fluxheim.php.runtime""#));
        assert!(payload.contains(r#""key":"fluxheim.php.outcome""#));
        assert!(payload.contains(r#""intValue":"200""#));
        let decoded: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let span = &decoded["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/observability/trace-span.json"
        ))
        .unwrap();
        assert_eq!(span, &expected);
    }

    #[test]
    fn trace_payload_rejects_raw_load_balancer_upstream_attribute() {
        let payload = build_trace_payload(
            TraceSpan {
                client: false,
                attempt: None,
                trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_owned(),
                span_id: "00f067aa0ba902b7".to_owned(),
                parent_span_id: None,
                name: "HTTP GET".to_owned(),
                method: "GET".to_owned(),
                vhost: "example.test".to_owned(),
                route: Some("root".to_owned()),
                status_code: Some(200),
                error: false,
                start_time_unix_nanos: 1,
                end_time_unix_nanos: 2,
                request_body_bytes: 0,
                response_body_bytes: 42,
                load_balancer_upstream_alias: Some(
                    "http://secret-canary:password@10.0.0.5:8080".to_owned(),
                ),
                load_balancer_retries: Some(0),
                cache_phase: None,
                cache_lookup_duration_ms: None,
                cache_lock_wait_duration_ms: None,
                compression_encoding: None,
                php_runtime: None,
                php_outcome: None,
            },
            "fluxheim",
        );

        assert!(!payload.contains("http://10.0.0.5:8080"));
        assert!(!payload.contains("secret-canary"));
        assert!(!payload.contains("password"));
        assert!(!payload.contains(r#""key":"fluxheim.load_balancer.upstream""#));
        assert!(payload.contains(r#""key":"fluxheim.load_balancer.retries""#));
    }
}

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::time::Duration;

use serde_json::json;

use crate::config::OtlpTraceExportConfig;

#[derive(Debug, Clone)]
pub struct TraceExporter {
    sender: SyncSender<TraceSpan>,
}

impl TraceExporter {
    pub fn from_config(config: &OtlpTraceExportConfig) -> std::io::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }

        let endpoint = HttpEndpoint::parse(&config.endpoint).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid OTLP trace endpoint",
            )
        })?;
        let service_name = config.service_name.clone();
        let timeout = Duration::from_secs(config.timeout_secs);
        let (sender, receiver) = sync_channel(config.queue_size);

        std::thread::Builder::new()
            .name("Fluxheim OTLP".to_owned())
            .spawn(move || {
                while let Ok(span) = receiver.recv() {
                    if let Err(error) = post_otlp_trace(
                        &endpoint,
                        timeout,
                        build_trace_payload(span, &service_name),
                    ) {
                        log::debug!("OTLP trace export failed: {error}");
                    }
                }
            })
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("failed to spawn OTLP trace exporter: {error}"),
                )
            })?;

        Ok(Some(Self { sender }))
    }

    pub fn try_export(&self, span: TraceSpan) {
        if let Err(error) = self.sender.try_send(span) {
            log::debug!("dropping OTLP trace span: {error}");
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TraceSpan {
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
    pub cache_phase: Option<String>,
    pub cache_lookup_duration_ms: Option<f64>,
    pub cache_lock_wait_duration_ms: Option<f64>,
    pub php_runtime: Option<String>,
    pub php_outcome: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct HttpEndpoint {
    host: String,
    port: u16,
    path: String,
    authority: String,
}

impl HttpEndpoint {
    fn parse(endpoint: &str) -> Option<Self> {
        let rest = endpoint.strip_prefix("http://")?;
        let (authority, path) = rest.split_once('/')?;
        if authority.is_empty() || path.is_empty() {
            return None;
        }
        let (host, port) = parse_authority(authority)?;
        Some(Self {
            host,
            port,
            path: format!("/{path}"),
            authority: authority.to_owned(),
        })
    }
}

fn parse_authority(authority: &str) -> Option<(String, u16)> {
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, tail) = stripped.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = if tail.is_empty() {
            80
        } else {
            tail.strip_prefix(':')?.parse::<u16>().ok()?
        };
        return (port != 0).then(|| (host.to_owned(), port));
    }

    let Some((host, port)) = authority.rsplit_once(':') else {
        return Some((authority.to_owned(), 80));
    };
    if host.is_empty() {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    (port != 0).then(|| (host.to_owned(), port))
}

fn build_trace_payload(span: TraceSpan, service_name: &str) -> String {
    let mut span_json = json!({
        "traceId": span.trace_id,
        "spanId": span.span_id,
        "name": span.name,
        "kind": "SPAN_KIND_SERVER",
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

fn post_otlp_trace(
    endpoint: &HttpEndpoint,
    timeout: Duration,
    body: String,
) -> std::io::Result<()> {
    let mut stream = TcpStream::connect((endpoint.host.as_str(), endpoint.port))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        endpoint.path,
        endpoint.authority,
        body.len(),
        body
    )?;
    stream.flush()?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let Some(status_line) = response.lines().next() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "empty OTLP response",
        ));
    };
    if status_line.contains(" 2") {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "OTLP endpoint returned {status_line}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_otlp_endpoint() {
        let endpoint = HttpEndpoint::parse("http://127.0.0.1:4318/v1/traces").unwrap();

        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 4318);
        assert_eq!(endpoint.path, "/v1/traces");
    }

    #[test]
    fn trace_payload_contains_required_otlp_fields() {
        let payload = build_trace_payload(
            TraceSpan {
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
                cache_phase: Some("hit".to_owned()),
                cache_lookup_duration_ms: Some(1.5),
                cache_lock_wait_duration_ms: Some(0.25),
                php_runtime: Some("php-fpm".to_owned()),
                php_outcome: Some("response".to_owned()),
            },
            "fluxheim",
        );

        assert!(payload.contains(r#""resourceSpans""#));
        assert!(payload.contains(r#""traceId":"4bf92f3577b34da6a3ce929d0e0e4736""#));
        assert!(payload.contains(r#""name":"HTTP GET""#));
        assert!(payload.contains(r#""key":"fluxheim.vhost""#));
        assert!(payload.contains(r#""key":"fluxheim.cache.phase""#));
        assert!(payload.contains(r#""key":"fluxheim.cache.lookup.duration_ms""#));
        assert!(payload.contains(r#""key":"fluxheim.cache.lock_wait.duration_ms""#));
        assert!(payload.contains(r#""key":"fluxheim.php.runtime""#));
        assert!(payload.contains(r#""key":"fluxheim.php.outcome""#));
        assert!(payload.contains(r#""intValue":"200""#));
    }
}

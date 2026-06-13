#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::fmt::Write as _;

#[cfg(feature = "otlp-http")]
pub use otlp_http::OtlpHttpEndpoint;
#[cfg(feature = "otlp-http")]
pub use otlp_http::agent;
#[cfg(feature = "otlp-metrics")]
pub use otlp_metrics::build_metrics_payload;
#[cfg(feature = "otlp-trace")]
pub use otlp_trace::{TraceExporter, TraceSpan};

const TRACEPARENT_VERSION: &str = "00";
const TRACE_ID_HEX_LEN: usize = 32;
const SPAN_ID_HEX_LEN: usize = 16;
const FLAGS_HEX_LEN: usize = 2;
const TRACEPARENT_LEN: usize = 2 + 1 + TRACE_ID_HEX_LEN + 1 + SPAN_ID_HEX_LEN + 1 + FLAGS_HEX_LEN;
const SAMPLED_FLAG: u8 = 0x01;
const RANDOM_ID_ATTEMPTS: usize = 8;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TraceContext {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    flags: u8,
}

impl TraceContext {
    pub fn generate() -> Option<Self> {
        Some(Self {
            trace_id: non_zero_random_16()?,
            span_id: non_zero_random_8()?,
            parent_span_id: None,
            flags: 0,
        })
    }

    pub fn parse_traceparent(value: &str, trusted_peer: bool) -> Option<Self> {
        let value = value.trim();
        if value.len() != TRACEPARENT_LEN {
            return None;
        }
        let bytes = value.as_bytes();
        if bytes.get(0..2)? != TRACEPARENT_VERSION.as_bytes()
            || bytes.get(2) != Some(&b'-')
            || bytes.get(35) != Some(&b'-')
            || bytes.get(52) != Some(&b'-')
        {
            return None;
        }

        let trace_id = parse_hex_array::<16>(&value[3..35])?;
        if trace_id.iter().all(|byte| *byte == 0) {
            return None;
        }
        let span_id = parse_hex_array::<8>(&value[36..52])?;
        if span_id.iter().all(|byte| *byte == 0) {
            return None;
        }
        let regenerated_span_id = non_zero_random_8()?;
        let flags = parse_hex_byte(&value[53..55])?;
        Some(Self {
            trace_id,
            span_id: regenerated_span_id,
            parent_span_id: Some(span_id),
            flags: if trusted_peer {
                flags & SAMPLED_FLAG
            } else {
                0
            },
        })
    }

    pub fn trace_id_hex(&self) -> String {
        hex_bytes(&self.trace_id)
    }

    pub fn span_id_hex(&self) -> String {
        hex_bytes(&self.span_id)
    }

    pub fn parent_span_id_hex(&self) -> Option<String> {
        self.parent_span_id.map(|span_id| hex_bytes(&span_id))
    }

    pub fn to_traceparent(self) -> String {
        format!(
            "{TRACEPARENT_VERSION}-{}-{}-{:02x}",
            hex_bytes(&self.trace_id),
            hex_bytes(&self.span_id),
            self.flags & SAMPLED_FLAG
        )
    }
}

pub fn context_from_traceparent(value: Option<&str>, trusted_peer: bool) -> Option<TraceContext> {
    value
        .and_then(|value| TraceContext::parse_traceparent(value, trusted_peer))
        .or_else(TraceContext::generate)
}

pub fn unix_time_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

pub fn access_log_status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

pub fn metrics_outcome_class(status: Option<u16>, error: bool) -> &'static str {
    if error {
        return "proxy_error";
    }

    match status {
        Some(100..=199) => "informational",
        Some(200..=299) => "success",
        Some(300..=399) => "redirect",
        Some(400..=499) => "client_error",
        Some(500..=599) => "server_error",
        Some(_) => "other",
        None => "unknown",
    }
}

pub fn metrics_method_bucket(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "CONNECT" => "CONNECT",
        _ => "OTHER",
    }
}

pub fn metrics_status_class(status: Option<u16>) -> &'static str {
    status.map(access_log_status_class).unwrap_or("unknown")
}

pub fn metrics_ratio_per_mille(value: u64, max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    value.saturating_mul(1000) / max
}

pub fn metrics_u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub fn metrics_usize_to_i64_saturating(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub fn metrics_host_routing_reason_label(reason: &str) -> &'static str {
    match reason {
        "missing" => "missing",
        "invalid" => "invalid",
        "unknown" => "unknown",
        _ => "other",
    }
}

pub fn metrics_admin_auth_event_label(event: &str) -> &'static str {
    match event {
        "failure" => "failure",
        "throttled" => "throttled",
        _ => "other",
    }
}

pub fn metrics_admin_auth_scope_label(scope: &str) -> &'static str {
    match scope {
        "source" => "source",
        "global" => "global",
        _ => "other",
    }
}

pub fn metrics_compression_encoding_label(encoding: &str) -> &'static str {
    match encoding {
        "gzip" => "gzip",
        "zstd" => "zstd",
        "br" => "br",
        _ => "other",
    }
}

pub fn metrics_edge_policy_label(policy: &str) -> &'static str {
    match policy {
        "access" => "access",
        "rate_limit" => "rate_limit",
        "concurrency" => "concurrency",
        "auth_request" => "auth_request",
        "mirror" => "mirror",
        _ => "other",
    }
}

pub fn metrics_edge_policy_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "deny" => "deny",
        "allow" => "allow",
        "delay" => "delay",
        "reject" => "reject",
        "error" => "error",
        "success" => "success",
        "skipped" => "skipped",
        _ => "other",
    }
}

pub fn metrics_load_balancer_event_label(event: &str) -> &'static str {
    match event {
        "selected" => "selected",
        "unavailable" => "unavailable",
        "retry" => "retry",
        "success" => "success",
        "failure" => "failure",
        "ejected" => "ejected",
        "member_state" => "member_state",
        "member_state_invalid" => "member_state_invalid",
        "member_state_not_found" => "member_state_not_found",
        "member_weight" => "member_weight",
        "member_weight_invalid" => "member_weight_invalid",
        "member_weight_not_found" => "member_weight_not_found",
        "persistence_hit" => "persistence_hit",
        "persistence_miss" => "persistence_miss",
        "persistence_fallback" => "persistence_fallback",
        "persistence_clear" => "persistence_clear",
        "persistence_clear_invalid" => "persistence_clear_invalid",
        "persistence_clear_not_found" => "persistence_clear_not_found",
        "queue_waited" => "queue_waited",
        "queue_full" => "queue_full",
        "queue_timeout" => "queue_timeout",
        "discovery_success" => "discovery_success",
        "discovery_failure" => "discovery_failure",
        _ => "other",
    }
}

pub fn metrics_load_balancer_queue_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "queue_waited" | "waited" => "waited",
        "queue_timeout" | "timeout" => "timeout",
        _ => "other",
    }
}

pub fn metrics_load_balancer_upstream_label(upstream: Option<&str>) -> &str {
    let Some(upstream) = upstream else {
        return "";
    };
    if upstream.is_empty()
        || upstream.len() > 64
        || upstream
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
    {
        return "other";
    }
    upstream
}

pub fn metrics_stream_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "completed" => "completed",
        "rejected" => "rejected",
        "connect_error" => "connect_error",
        "timeout" => "timeout",
        "shutdown" => "shutdown",
        _ => "error",
    }
}

pub fn metrics_stream_direction_label(direction: &str) -> &'static str {
    match direction {
        "downstream_to_upstream" => "downstream_to_upstream",
        "upstream_to_downstream" => "upstream_to_downstream",
        _ => "other",
    }
}

pub fn metrics_otlp_export_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "success" => "success",
        "failure" => "failure",
        _ => "other",
    }
}

pub fn metrics_php_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "declined" => "declined",
        "redirect" => "redirect",
        "forbidden" => "forbidden",
        "not_found" => "not_found",
        "fpm_error" => "fpm_error",
        "connect_timeout" => "connect_timeout",
        "request_timeout" => "request_timeout",
        "connection_error" => "connection_error",
        "configuration_error" => "configuration_error",
        "invalid_response" => "invalid_response",
        "intercepted" => "intercepted",
        "offload" => "offload",
        "offload_error" => "offload_error",
        "response" => "response",
        _ => "other",
    }
}

pub fn metrics_php_fpm_retry_reason_label(reason: &str) -> &'static str {
    match reason {
        "connect_timeout" => "connect_timeout",
        "connection_error" => "connection_error",
        _ => "other",
    }
}

pub fn metrics_php_fpm_pool_event_label(event: &str) -> &'static str {
    match event {
        "connect" => "connect",
        "reuse" => "reuse",
        "return" => "return",
        "drop_stale" => "drop_stale",
        "discard_full" => "discard_full",
        _ => "other",
    }
}

pub fn metrics_php_stderr_state_label(state: &str) -> &'static str {
    match state {
        "emitted" => "emitted",
        "truncated" => "truncated",
        _ => "other",
    }
}

pub fn metrics_acme_event_label(event: &str) -> &'static str {
    match event {
        "pending" => "pending",
        "renewed" => "renewed",
        "failed" => "failed",
        "reload_success" => "reload_success",
        "reload_failed" => "reload_failed",
        "reload_unavailable" => "reload_unavailable",
        "tick_error" => "tick_error",
        _ => "other",
    }
}

pub fn access_log_request_id_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

pub fn generate_access_log_request_id() -> Option<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).ok()?;

    let mut id = String::with_capacity(35);
    id.push_str("fh-");
    for byte in random {
        let _ = write!(&mut id, "{byte:02x}");
    }
    Some(id)
}

pub fn count_access_log_response_body_bytes(bytes_seen: &mut u64, bytes: usize) {
    *bytes_seen = bytes_seen.saturating_add(bytes as u64);
}

fn non_zero_random_16() -> Option<[u8; 16]> {
    for _ in 0..RANDOM_ID_ATTEMPTS {
        let mut bytes = [0_u8; 16];
        if getrandom::fill(&mut bytes).is_ok() && bytes.iter().any(|byte| *byte != 0) {
            return Some(bytes);
        }
    }
    log::error!("trace context: CSPRNG unavailable after {RANDOM_ID_ATTEMPTS} attempts");
    None
}

fn non_zero_random_8() -> Option<[u8; 8]> {
    for _ in 0..RANDOM_ID_ATTEMPTS {
        let mut bytes = [0_u8; 8];
        if getrandom::fill(&mut bytes).is_ok() && bytes.iter().any(|byte| *byte != 0) {
            return Some(bytes);
        }
    }
    log::error!("trace context: CSPRNG unavailable after {RANDOM_ID_ATTEMPTS} attempts");
    None
}

fn parse_hex_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut bytes = [0_u8; N];
    for index in 0..N {
        bytes[index] = parse_hex_byte(&value[index * 2..index * 2 + 2])?;
    }
    Some(bytes)
}

fn parse_hex_byte(value: &str) -> Option<u8> {
    let bytes = value.as_bytes();
    if bytes.len() != 2 {
        return None;
    }
    let high = hex_nibble(bytes[0])?;
    let low = hex_nibble(bytes[1])?;
    Some((high << 4) | low)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(feature = "otlp-http")]
mod otlp_http {
    use std::fs::OpenOptions;
    use std::io::{self, Read};
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use std::time::Duration;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const O_NOFOLLOW: i32 = 0o400000;

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    const O_NOFOLLOW: i32 = 0x0100;

    #[cfg(all(
        unix,
        not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))
    ))]
    compile_error!(
        "O_NOFOLLOW is unknown on this Unix platform; audit symlink-safe OTLP CA loading before building Fluxheim"
    );

    const MAX_OTLP_CA_CERT_BYTES: u64 = 1024 * 1024;

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct OtlpHttpEndpoint {
        pub url: String,
        pub host: String,
        pub port: u16,
        pub path: String,
    }

    impl OtlpHttpEndpoint {
        pub fn parse(endpoint: &str) -> Option<Self> {
            let (rest, default_port) = if let Some(rest) = endpoint.strip_prefix("http://") {
                (rest, 80)
            } else if let Some(rest) = endpoint.strip_prefix("https://") {
                (rest, 443)
            } else {
                return None;
            };
            let (authority, path) = rest.split_once('/')?;
            if authority.is_empty() || path.is_empty() {
                return None;
            }
            let (host, port) = parse_authority(authority, default_port)?;
            Some(Self {
                url: endpoint.to_owned(),
                host,
                port,
                path: format!("/{path}"),
            })
        }
    }

    fn parse_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
        if let Some(stripped) = authority.strip_prefix('[') {
            let (host, tail) = stripped.split_once(']')?;
            if host.is_empty() {
                return None;
            }
            let port = if tail.is_empty() {
                default_port
            } else {
                tail.strip_prefix(':')?.parse::<u16>().ok()?
            };
            return (port != 0).then(|| (host.to_owned(), port));
        }

        let Some((host, port)) = authority.rsplit_once(':') else {
            return Some((authority.to_owned(), default_port));
        };
        if host.is_empty() {
            return None;
        }
        let port = port.parse::<u16>().ok()?;
        (port != 0).then(|| (host.to_owned(), port))
    }

    pub fn agent(timeout: Duration, tls_ca_cert_path: Option<&Path>) -> io::Result<ureq::Agent> {
        let mut builder = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .max_redirects(0)
            .http_status_as_error(false);

        if let Some(path) = tls_ca_cert_path {
            let certs = load_ca_certificates(path)?;
            builder = builder.tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::new_with_certs(&certs))
                    .build(),
            );
        }

        Ok(builder.build().into())
    }

    fn load_ca_certificates(path: &Path) -> io::Result<Vec<ureq::tls::Certificate<'static>>> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(O_NOFOLLOW);
        let file = options.open(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to read OTLP TLS CA certificate {}: {error}",
                    path.display()
                ),
            )
        })?;
        let metadata = file.metadata().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to inspect OTLP TLS CA certificate {}: {error}",
                    path.display()
                ),
            )
        })?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "OTLP TLS CA certificate {} is not a regular file",
                    path.display()
                ),
            ));
        }

        let mut contents = Vec::new();
        let mut limited = file.take(MAX_OTLP_CA_CERT_BYTES.saturating_add(1));
        limited.read_to_end(&mut contents).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to read OTLP TLS CA certificate {}: {error}",
                    path.display()
                ),
            )
        })?;
        if contents.len() as u64 > MAX_OTLP_CA_CERT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "OTLP TLS CA certificate {} exceeds {} bytes",
                    path.display(),
                    MAX_OTLP_CA_CERT_BYTES
                ),
            ));
        }
        let mut certificates = Vec::new();
        for item in ureq::tls::parse_pem(&contents) {
            match item {
                Ok(ureq::tls::PemItem::Certificate(certificate)) => {
                    certificates.push(certificate);
                }
                Ok(_) => {}
                Err(error) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "failed to parse OTLP TLS CA certificate {}: {error}",
                            path.display()
                        ),
                    ));
                }
            }
        }
        if certificates.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "OTLP TLS CA certificate {} did not contain any PEM certificates",
                    path.display()
                ),
            ));
        }
        Ok(certificates)
    }

    #[cfg(test)]
    mod tests {
        use super::{OtlpHttpEndpoint, load_ca_certificates};

        #[test]
        fn parses_prometheus_otlp_endpoint() {
            let endpoint = OtlpHttpEndpoint::parse("http://127.0.0.1:9090/api/v1/otlp/v1/metrics")
                .expect("valid endpoint");

            assert_eq!(endpoint.host, "127.0.0.1");
            assert_eq!(endpoint.port, 9090);
            assert_eq!(endpoint.path, "/api/v1/otlp/v1/metrics");
        }

        #[test]
        fn parses_https_prometheus_otlp_endpoint() {
            let endpoint =
                OtlpHttpEndpoint::parse("https://collector.example.test/api/v1/otlp/v1/metrics")
                    .expect("valid endpoint");

            assert_eq!(endpoint.host, "collector.example.test");
            assert_eq!(endpoint.port, 443);
            assert_eq!(endpoint.path, "/api/v1/otlp/v1/metrics");
        }

        #[cfg(unix)]
        #[test]
        fn rejects_symlinked_ca_certificate() {
            let target = fluxheim_common::test_support::unique_temp_path("otlp-ca-target");
            let link = fluxheim_common::test_support::unique_temp_path("otlp-ca-link");
            std::fs::write(&target, b"not a certificate\n").expect("write target");
            std::os::unix::fs::symlink(&target, &link).expect("create symlink");

            let error = load_ca_certificates(&link).expect_err("symlink must be rejected");

            assert_ne!(error.kind(), std::io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("failed to read"));
            let _ = std::fs::remove_file(target);
            let _ = std::fs::remove_file(link);
        }
    }
}

#[cfg(feature = "otlp-trace")]
mod otlp_trace;

#[cfg(feature = "otlp-metrics")]
mod otlp_metrics {
    use std::time::{SystemTime, UNIX_EPOCH};

    use prometheus::proto::MetricType;
    use serde_json::json;

    pub fn build_metrics_payload(
        families: Vec<prometheus::proto::MetricFamily>,
        service_name: &str,
    ) -> String {
        let time_unix_nanos = unix_time_nanos().to_string();
        let mut metrics = Vec::new();

        for family in families {
            match family.get_field_type() {
                MetricType::COUNTER => {
                    let mut data_points = Vec::new();
                    for metric in family.get_metric() {
                        data_points.push(number_data_point(
                            metric,
                            metric.get_counter().get_or_default().value(),
                            &time_unix_nanos,
                        ));
                    }
                    metrics.push(json!({
                        "name": family.name(),
                        "description": family.help(),
                        "unit": "1",
                        "sum": {
                            "aggregationTemporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
                            "isMonotonic": true,
                            "dataPoints": data_points,
                        }
                    }));
                }
                MetricType::GAUGE => {
                    let mut data_points = Vec::new();
                    for metric in family.get_metric() {
                        data_points.push(number_data_point(
                            metric,
                            metric.get_gauge().get_or_default().value(),
                            &time_unix_nanos,
                        ));
                    }
                    metrics.push(json!({
                        "name": family.name(),
                        "description": family.help(),
                        "unit": "1",
                        "gauge": {
                            "dataPoints": data_points,
                        }
                    }));
                }
                MetricType::HISTOGRAM => {
                    let mut data_points = Vec::new();
                    for metric in family.get_metric() {
                        data_points.push(histogram_data_point(metric, &time_unix_nanos));
                    }
                    metrics.push(json!({
                        "name": family.name(),
                        "description": family.help(),
                        "unit": "s",
                        "histogram": {
                            "aggregationTemporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
                            "dataPoints": data_points,
                        }
                    }));
                }
                _ => {}
            }
        }

        json!({
            "resourceMetrics": [{
                "resource": {
                    "attributes": [
                        string_attr("service.name", service_name),
                        string_attr("service.version", env!("CARGO_PKG_VERSION")),
                    ]
                },
                "scopeMetrics": [{
                    "scope": {
                        "name": "fluxheim",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "metrics": metrics
                }]
            }]
        })
        .to_string()
    }

    fn number_data_point(
        metric: &prometheus::proto::Metric,
        value: f64,
        time_unix_nanos: &str,
    ) -> serde_json::Value {
        json!({
            "attributes": metric
                .get_label()
                .iter()
                .map(|label| string_attr(label.name(), label.value()))
                .collect::<Vec<_>>(),
            "timeUnixNano": time_unix_nanos,
            "asDouble": value,
        })
    }

    fn histogram_data_point(
        metric: &prometheus::proto::Metric,
        time_unix_nanos: &str,
    ) -> serde_json::Value {
        let histogram = metric.get_histogram();
        let mut previous_count = 0_u64;
        let mut bucket_counts = Vec::new();
        let mut explicit_bounds = Vec::new();

        for bucket in histogram.get_bucket() {
            let cumulative_count = bucket.cumulative_count();
            bucket_counts.push(cumulative_count.saturating_sub(previous_count));
            previous_count = cumulative_count;
            explicit_bounds.push(bucket.upper_bound());
        }
        bucket_counts.push(histogram.sample_count().saturating_sub(previous_count));

        json!({
            "attributes": metric
                .get_label()
                .iter()
                .map(|label| string_attr(label.name(), label.value()))
                .collect::<Vec<_>>(),
            "timeUnixNano": time_unix_nanos,
            "count": histogram.sample_count(),
            "sum": histogram.sample_sum(),
            "bucketCounts": bucket_counts,
            "explicitBounds": explicit_bounds,
        })
    }

    fn string_attr(key: &str, value: impl Into<String>) -> serde_json::Value {
        json!({
            "key": key,
            "value": {
                "stringValue": value.into()
            }
        })
    }

    fn unix_time_nanos() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    }

    #[cfg(test)]
    mod tests {
        use prometheus::{CounterVec, Encoder, Gauge, HistogramOpts, HistogramVec, Opts};

        use super::build_metrics_payload;

        #[test]
        fn payload_contains_counter_gauge_and_histogram_metrics() {
            let registry = prometheus::Registry::new();
            let counter = CounterVec::new(
                Opts::new("fluxheim_test_counter_total", "test counter"),
                &["vhost"],
            )
            .expect("counter should build");
            counter.with_label_values(&["example"]).inc();
            registry
                .register(Box::new(counter))
                .expect("counter should register");

            let gauge =
                Gauge::new("fluxheim_test_gauge", "test gauge").expect("gauge should build");
            gauge.set(7.0);
            registry
                .register(Box::new(gauge))
                .expect("gauge should register");

            let histogram = HistogramVec::new(
                HistogramOpts::new("fluxheim_test_duration_seconds", "test duration")
                    .buckets(vec![0.01, 0.1, 1.0]),
                &["operation"],
            )
            .expect("histogram should build");
            histogram.with_label_values(&["lookup"]).observe(0.05);
            registry
                .register(Box::new(histogram))
                .expect("histogram should register");

            let payload = build_metrics_payload(registry.gather(), "fluxheim-test");

            assert!(payload.contains(r#""resourceMetrics""#));
            assert!(payload.contains(r#""service.name""#));
            assert!(payload.contains(r#""fluxheim-test""#));
            assert!(payload.contains(r#""name":"fluxheim_test_counter_total""#));
            assert!(payload.contains(r#""sum""#));
            assert!(payload.contains(r#""name":"fluxheim_test_gauge""#));
            assert!(payload.contains(r#""gauge""#));
            assert!(payload.contains(r#""name":"fluxheim_test_duration_seconds""#));
            assert!(payload.contains(r#""histogram""#));
            assert!(payload.contains(r#""bucketCounts""#));
            assert!(payload.contains(r#""explicitBounds""#));
            assert!(!payload.contains("query"));
            assert!(!payload.contains("path"));

            let mut text = Vec::new();
            prometheus::TextEncoder::new()
                .encode(&registry.gather(), &mut text)
                .expect("text encode should work");
            assert!(
                String::from_utf8(text)
                    .expect("prometheus text should be utf-8")
                    .contains("fluxheim_test_counter_total")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_traceparent_and_regenerates_span_id() {
        let context = TraceContext::parse_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            true,
        )
        .expect("valid traceparent should parse");

        assert_eq!(context.trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(
            context
                .to_traceparent()
                .starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-")
        );
        assert!(context.to_traceparent().ends_with("-01"));
        assert!(!context.to_traceparent().contains("-00f067aa0ba902b7-"));
    }

    #[test]
    fn clears_untrusted_sampled_flag() {
        let context = TraceContext::parse_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            false,
        )
        .expect("valid traceparent should parse");

        assert!(context.to_traceparent().ends_with("-00"));
    }

    #[test]
    fn rejects_malformed_or_zero_traceparent() {
        assert!(TraceContext::parse_traceparent("bad", true).is_none());
        assert!(
            TraceContext::parse_traceparent(
                "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
                true,
            )
            .is_none()
        );
        assert!(
            TraceContext::parse_traceparent(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
                true,
            )
            .is_none()
        );
    }

    #[test]
    fn generates_non_zero_context() {
        let context = TraceContext::generate().expect("trace context should generate");

        assert_ne!(context.trace_id_hex(), "00000000000000000000000000000000");
        assert_eq!(context.to_traceparent().len(), TRACEPARENT_LEN);
    }

    #[test]
    fn access_log_status_class_is_low_cardinality() {
        assert_eq!(access_log_status_class(101), "1xx");
        assert_eq!(access_log_status_class(204), "2xx");
        assert_eq!(access_log_status_class(304), "3xx");
        assert_eq!(access_log_status_class(404), "4xx");
        assert_eq!(access_log_status_class(503), "5xx");
        assert_eq!(access_log_status_class(700), "other");
    }

    #[test]
    fn metrics_proxy_labels_are_low_cardinality() {
        assert_eq!(metrics_outcome_class(Some(204), false), "success");
        assert_eq!(metrics_outcome_class(Some(302), false), "redirect");
        assert_eq!(metrics_outcome_class(Some(404), false), "client_error");
        assert_eq!(metrics_outcome_class(Some(503), false), "server_error");
        assert_eq!(metrics_outcome_class(Some(700), false), "other");
        assert_eq!(metrics_outcome_class(None, false), "unknown");
        assert_eq!(metrics_outcome_class(Some(200), true), "proxy_error");

        assert_eq!(metrics_method_bucket("GET"), "GET");
        assert_eq!(metrics_method_bucket("POST"), "POST");
        assert_eq!(metrics_method_bucket("BREW"), "OTHER");

        assert_eq!(metrics_status_class(Some(204)), "2xx");
        assert_eq!(metrics_status_class(None), "unknown");
    }

    #[test]
    fn metrics_numeric_helpers_are_bounded() {
        assert_eq!(metrics_ratio_per_mille(5, 10), 500);
        assert_eq!(metrics_ratio_per_mille(5, 0), 0);
        assert_eq!(metrics_ratio_per_mille(u64::MAX, 1), u64::MAX);
        assert_eq!(metrics_u64_to_i64_saturating(42), 42);
        assert_eq!(metrics_u64_to_i64_saturating(u64::MAX), i64::MAX);
        assert_eq!(metrics_usize_to_i64_saturating(42), 42);
    }

    #[test]
    fn metrics_general_labels_are_low_cardinality() {
        assert_eq!(metrics_host_routing_reason_label("missing"), "missing");
        assert_eq!(metrics_host_routing_reason_label("attacker"), "other");
        assert_eq!(metrics_admin_auth_event_label("failure"), "failure");
        assert_eq!(metrics_admin_auth_event_label("success"), "other");
        assert_eq!(metrics_admin_auth_scope_label("source"), "source");
        assert_eq!(metrics_admin_auth_scope_label("route"), "other");
        assert_eq!(metrics_compression_encoding_label("br"), "br");
        assert_eq!(metrics_compression_encoding_label("identity"), "other");
        assert_eq!(metrics_edge_policy_label("rate_limit"), "rate_limit");
        assert_eq!(metrics_edge_policy_label("unknown-policy"), "other");
        assert_eq!(metrics_edge_policy_outcome_label("skipped"), "skipped");
        assert_eq!(metrics_edge_policy_outcome_label("bypassed"), "other");
        assert_eq!(
            metrics_load_balancer_event_label("member_weight_invalid"),
            "member_weight_invalid"
        );
        assert_eq!(metrics_load_balancer_event_label("custom"), "other");
        assert_eq!(
            metrics_load_balancer_queue_outcome_label("queue_waited"),
            "waited"
        );
        assert_eq!(metrics_load_balancer_queue_outcome_label("other"), "other");
        assert_eq!(
            metrics_load_balancer_upstream_label(Some("backend-a_1")),
            "backend-a_1"
        );
        assert_eq!(
            metrics_load_balancer_upstream_label(Some("bad value")),
            "other"
        );
        assert_eq!(metrics_load_balancer_upstream_label(None), "");
        assert_eq!(metrics_stream_outcome_label("completed"), "completed");
        assert_eq!(metrics_stream_outcome_label("strange"), "error");
        assert_eq!(
            metrics_stream_direction_label("upstream_to_downstream"),
            "upstream_to_downstream"
        );
        assert_eq!(metrics_stream_direction_label("sideways"), "other");
        assert_eq!(metrics_otlp_export_outcome_label("success"), "success");
        assert_eq!(metrics_otlp_export_outcome_label("delayed"), "other");
        assert_eq!(
            metrics_php_outcome_label("connect_timeout"),
            "connect_timeout"
        );
        assert_eq!(metrics_php_outcome_label("surprise"), "other");
        assert_eq!(
            metrics_php_fpm_retry_reason_label("connection_error"),
            "connection_error"
        );
        assert_eq!(metrics_php_fpm_retry_reason_label("status_500"), "other");
        assert_eq!(metrics_php_fpm_pool_event_label("drop_stale"), "drop_stale");
        assert_eq!(metrics_php_fpm_pool_event_label("custom"), "other");
        assert_eq!(metrics_php_stderr_state_label("truncated"), "truncated");
        assert_eq!(metrics_php_stderr_state_label("verbose"), "other");
        assert_eq!(metrics_acme_event_label("renewed"), "renewed");
        assert_eq!(metrics_acme_event_label("surprise"), "other");
    }

    #[test]
    fn access_log_request_id_validation_is_bounded_and_low_cardinality() {
        assert!(access_log_request_id_valid("edge-req_123.456"));
        assert!(!access_log_request_id_valid(""));
        assert!(!access_log_request_id_valid("bad value"));
        assert!(!access_log_request_id_valid("https://evil.example/reset"));
        assert!(!access_log_request_id_valid("admin@example.test"));
        assert!(!access_log_request_id_valid(&"a".repeat(129)));
    }

    #[test]
    fn generated_access_log_request_id_uses_safe_prefix() {
        let request_id =
            generate_access_log_request_id().expect("request id generation should work");

        assert!(request_id.starts_with("fh-"));
        assert_eq!(request_id.len(), 35);
        assert!(access_log_request_id_valid(&request_id));
    }

    #[test]
    fn access_log_response_body_byte_counter_saturates() {
        let mut seen = u64::MAX - 1;

        count_access_log_response_body_bytes(&mut seen, 4);

        assert_eq!(seen, u64::MAX);
    }
}

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prometheus::proto::MetricType;
use serde_json::json;

use crate::config::MetricsOtlpExportConfig;

pub fn spawn_from_config(config: &MetricsOtlpExportConfig) -> std::io::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let endpoint = HttpEndpoint::parse(&config.endpoint).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid OTLP metrics endpoint",
        )
    })?;
    let service_name = config.service_name.clone();
    let interval = Duration::from_secs(config.interval_secs);
    let timeout = Duration::from_secs(config.timeout_secs);

    std::thread::Builder::new()
        .name("Fluxheim OTLP Metrics".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(interval);
                let payload = build_metrics_payload(prometheus::gather(), &service_name);
                match post_otlp_metrics(&endpoint, timeout, payload) {
                    Ok(()) => crate::metrics::record_metrics_otlp_export("success"),
                    Err(error) => {
                        crate::metrics::record_metrics_otlp_export("failure");
                        log::debug!("OTLP metrics export failed: {error}");
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("failed to spawn OTLP metrics exporter: {error}"),
            )
        })
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct HttpEndpoint {
    url: String,
    host: String,
    port: u16,
    path: String,
    authority: String,
}

impl HttpEndpoint {
    fn parse(endpoint: &str) -> Option<Self> {
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
            authority: authority.to_owned(),
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

fn build_metrics_payload(
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
                        metric.get_counter().get_value(),
                        &time_unix_nanos,
                    ));
                }
                metrics.push(json!({
                    "name": family.get_name(),
                    "description": family.get_help(),
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
                        metric.get_gauge().get_value(),
                        &time_unix_nanos,
                    ));
                }
                metrics.push(json!({
                    "name": family.get_name(),
                    "description": family.get_help(),
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
                    "name": family.get_name(),
                    "description": family.get_help(),
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
            .map(|label| string_attr(label.get_name(), label.get_value()))
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
        let cumulative_count = bucket.get_cumulative_count();
        bucket_counts.push(cumulative_count.saturating_sub(previous_count));
        previous_count = cumulative_count;
        explicit_bounds.push(bucket.get_upper_bound());
    }
    bucket_counts.push(histogram.get_sample_count().saturating_sub(previous_count));

    json!({
        "attributes": metric
            .get_label()
            .iter()
            .map(|label| string_attr(label.get_name(), label.get_value()))
            .collect::<Vec<_>>(),
        "timeUnixNano": time_unix_nanos,
        "count": histogram.get_sample_count(),
        "sum": histogram.get_sample_sum(),
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

fn post_otlp_metrics(
    endpoint: &HttpEndpoint,
    timeout: Duration,
    body: String,
) -> std::io::Result<()> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into();
    let response = agent
        .post(&endpoint.url)
        .header("content-type", "application/json")
        .send(body.as_str())
        .map_err(otlp_metrics_io_error)?;
    let status = response.status().as_u16();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "OTLP metrics endpoint returned HTTP {status}"
        )))
    }
}

fn otlp_metrics_io_error(error: ureq::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
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

    use super::*;

    #[test]
    fn parses_prometheus_otlp_endpoint() {
        let endpoint = HttpEndpoint::parse("http://127.0.0.1:9090/api/v1/otlp/v1/metrics").unwrap();

        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 9090);
        assert_eq!(endpoint.path, "/api/v1/otlp/v1/metrics");
    }

    #[test]
    fn parses_https_prometheus_otlp_endpoint() {
        let endpoint =
            HttpEndpoint::parse("https://collector.example.test/api/v1/otlp/v1/metrics").unwrap();

        assert_eq!(endpoint.host, "collector.example.test");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.path, "/api/v1/otlp/v1/metrics");
    }

    #[test]
    fn payload_contains_counter_gauge_and_histogram_metrics() {
        let registry = prometheus::Registry::new();
        let counter = CounterVec::new(
            Opts::new("fluxheim_test_counter_total", "test counter"),
            &["vhost"],
        )
        .unwrap();
        counter.with_label_values(&["example"]).inc();
        registry.register(Box::new(counter)).unwrap();

        let gauge = Gauge::new("fluxheim_test_gauge", "test gauge").unwrap();
        gauge.set(7.0);
        registry.register(Box::new(gauge)).unwrap();

        let histogram = HistogramVec::new(
            HistogramOpts::new("fluxheim_test_duration_seconds", "test duration")
                .buckets(vec![0.01, 0.1, 1.0]),
            &["operation"],
        )
        .unwrap();
        histogram.with_label_values(&["lookup"]).observe(0.05);
        registry.register(Box::new(histogram)).unwrap();

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
            .unwrap();
        assert!(
            String::from_utf8(text)
                .unwrap()
                .contains("fluxheim_test_counter_total")
        );
    }
}

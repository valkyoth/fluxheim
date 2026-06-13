use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fluxheim_observability::OtlpHttpEndpoint;
use prometheus::proto::MetricType;
use serde_json::json;

use crate::config::MetricsOtlpExportConfig;

pub fn spawn_from_config(config: &MetricsOtlpExportConfig) -> std::io::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let endpoint = OtlpHttpEndpoint::parse(&config.endpoint).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid OTLP metrics endpoint",
        )
    })?;
    let service_name = config.service_name.clone();
    let interval = Duration::from_secs(config.interval_secs);
    let timeout = Duration::from_secs(config.timeout_secs);
    let agent = crate::otlp_http::agent(timeout, config.tls_ca_cert_path.as_deref())?;

    std::thread::Builder::new()
        .name("Fluxheim OTLP Metrics".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(interval);
                let payload = build_metrics_payload(prometheus::gather(), &service_name);
                match post_otlp_metrics(&agent, &endpoint, payload) {
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

fn post_otlp_metrics(
    agent: &ureq::Agent,
    endpoint: &OtlpHttpEndpoint,
    body: String,
) -> std::io::Result<()> {
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

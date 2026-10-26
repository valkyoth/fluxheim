use std::time::{SystemTime, UNIX_EPOCH};

use prometheus::proto::MetricType;
use serde_json::json;

pub fn build_metrics_payload(
    families: Vec<prometheus::proto::MetricFamily>,
    service_name: &str,
) -> Option<String> {
    if !bounded_input(&families, service_name) {
        return None;
    }
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
                    "unit": metric_unit(family.name()),
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
                    "unit": metric_unit(family.name()),
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
                    "unit": metric_unit(family.name()),
                    "histogram": {
                        "aggregationTemporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
                        "dataPoints": data_points,
                    }
                }));
            }
            _ => {}
        }
    }

    Some(
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
        .to_string(),
    )
}

// Bound the intermediate JSON tree before copying labels, descriptions or buckets.
// Six-fold escaping plus numeric overhead stays below the 4 MiB wire cap.
fn bounded_input(families: &[prometheus::proto::MetricFamily], service: &str) -> bool {
    if service.is_empty() || service.len() > 128 || families.len() > 1024 {
        return false;
    }
    let mut budget: usize = 512 * 1024;
    for family in families {
        if family.name().len() > 256 || family.help().len() > 1024 {
            return false;
        }
        let Some(left) = budget.checked_sub(512 + family.name().len() + family.help().len()) else {
            return false;
        };
        budget = left;
        for metric in family.get_metric() {
            if metric.get_label().len() > 16 || metric.get_histogram().get_bucket().len() > 128 {
                return false;
            }
            let mut weight = 512 + metric.get_histogram().get_bucket().len() * 64;
            for label in metric.get_label() {
                if label.name().len() > 128 || label.value().len() > 256 {
                    return false;
                }
                weight += 64 + label.name().len() + label.value().len();
            }
            let Some(left) = budget.checked_sub(weight) else {
                return false;
            };
            budget = left;
        }
    }
    true
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

fn metric_unit(name: &str) -> &'static str {
    let name = name.strip_suffix("_total").unwrap_or(name);
    if name.ends_with("_bytes") {
        "By"
    } else if name.ends_with("_seconds") {
        "s"
    } else {
        "1"
    }
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
    fn oversized_metric_labels_and_snapshots_are_rejected_before_encoding() {
        let registry = prometheus::Registry::new();
        let counter = CounterVec::new(Opts::new("test_total", "test"), &["name"]).unwrap();
        counter.with_label_values(&[&"x".repeat(257)]).inc();
        registry.register(Box::new(counter)).unwrap();
        assert!(build_metrics_payload(registry.gather(), "test").is_none());
        let family = prometheus::proto::MetricFamily::default();
        assert!(build_metrics_payload(vec![family; 1025], "test").is_none());
        assert!(build_metrics_payload(Vec::new(), &"x".repeat(129)).is_none());
    }

    #[test]
    fn metric_units_follow_prometheus_names() {
        assert_eq!(
            super::metric_unit("fluxheim_http_response_body_bytes_total"),
            "By"
        );
        assert_eq!(super::metric_unit("fluxheim_cache_disk_size_bytes"), "By");
        assert_eq!(
            super::metric_unit("fluxheim_http_request_duration_seconds"),
            "s"
        );
        assert_eq!(super::metric_unit("fluxheim_upstream_attempts_active"), "1");
    }

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

        let gauge = Gauge::new("fluxheim_test_gauge", "test gauge").expect("gauge should build");
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

        let payload = build_metrics_payload(registry.gather(), "fluxheim-test").unwrap();

        let decoded: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let metrics = decoded["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap();
        assert_eq!(metrics.len(), 3);
        let histogram = metrics
            .iter()
            .find(|metric| metric["name"] == "fluxheim_test_duration_seconds")
            .unwrap();
        assert_eq!(histogram["unit"], "s");
        assert_eq!(
            histogram["histogram"]["aggregationTemporality"],
            "AGGREGATION_TEMPORALITY_CUMULATIVE"
        );
        let point = &histogram["histogram"]["dataPoints"][0];
        assert_eq!(point["bucketCounts"], serde_json::json!([0, 1, 0, 0]));
        assert_eq!(point["explicitBounds"], serde_json::json!([0.01, 0.1, 1.0]));
        assert_eq!(point["count"], 1);
        assert_eq!(point["sum"], 0.05);
        assert!(
            point["timeUnixNano"]
                .as_str()
                .unwrap()
                .parse::<u128>()
                .unwrap()
                > 0
        );
        let counter = metrics
            .iter()
            .find(|metric| metric["name"] == "fluxheim_test_counter_total")
            .unwrap();
        assert_eq!(counter["sum"]["isMonotonic"], true);
        assert_eq!(counter["sum"]["dataPoints"][0]["asDouble"], 1.0);
        let gauge = metrics
            .iter()
            .find(|metric| metric["name"] == "fluxheim_test_gauge")
            .unwrap();
        assert_eq!(gauge["gauge"]["dataPoints"][0]["asDouble"], 7.0);

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
        assert_eq!(
            String::from_utf8(text).unwrap(),
            include_str!("../../../tests/fixtures/observability/metrics.prom")
        );
    }
}

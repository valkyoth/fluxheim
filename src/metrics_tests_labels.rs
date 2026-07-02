use super::*;
#[test]
fn records_metrics_otlp_exporter_health_counter() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_metrics_otlp_export("success");
    record_metrics_otlp_export("failure");
    record_metrics_otlp_export("attacker-outcome");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains(r#"fluxheim_metrics_otlp_exports_total{outcome="success"}"#));
    assert!(output.contains(r#"fluxheim_metrics_otlp_exports_total{outcome="failure"}"#));
    assert!(output.contains(r#"fluxheim_metrics_otlp_exports_total{outcome="other"}"#));
    assert!(!output.contains("attacker-outcome"));
}

#[test]
fn status_class_is_bounded() {
    assert_eq!(status_class(Some(101)), "1xx");
    assert_eq!(status_class(Some(204)), "2xx");
    assert_eq!(status_class(Some(304)), "3xx");
    assert_eq!(status_class(Some(404)), "4xx");
    assert_eq!(status_class(Some(503)), "5xx");
    assert_eq!(status_class(Some(799)), "other");
    assert_eq!(status_class(None), "unknown");
}

#[test]
fn method_bucket_is_bounded() {
    assert_eq!(method_bucket("GET"), "GET");
    assert_eq!(method_bucket("POST"), "POST");
    assert_eq!(method_bucket("PROPFIND"), "OTHER");
    assert_eq!(method_bucket("attacker-controlled-method"), "OTHER");
}

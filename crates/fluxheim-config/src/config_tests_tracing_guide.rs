use super::*;
use crate::TracingMode;

const EXAMPLE: &str = include_str!("../../../examples/tracing/proxy.toml");

#[test]
fn tracing_guide_actual_example_obeys_feature_and_privacy_gates() {
    let dir = TestDir::new("tracing-guide");
    fs::write(dir.child("proxy.toml"), EXAMPLE).unwrap();
    let result = Config::load(Some(&dir.child("proxy.toml")));
    if cfg!(all(
        feature = "otel-tracing",
        feature = "otel-otlp",
        not(feature = "privacy-mode")
    )) {
        let config = result.unwrap();
        assert_eq!(config.tracing.otlp.service_name, "fluxheim-tracing-guide");
        assert_eq!(config.vhosts[0].name, "tracing-guide");
        assert_eq!(config.vhosts[0].routes[0].name, "application");
        assert_eq!(config.server.trusted_proxies, ["127.0.0.1"]);
    } else {
        assert!(result.is_err());
    }
}

#[test]
fn tracing_guide_defaults_and_inactive_policy() {
    let trace = TracingConfig::default();
    assert!(!trace.enabled && !trace.otlp.enabled);
    assert_eq!(trace.mode, TracingMode::PropagateOnly);
    assert!(trace.traceparent && trace.log_trace_id);
    assert_eq!(trace.otlp.endpoint, "http://127.0.0.1:4318/v1/traces");
    assert_eq!(trace.otlp.service_name, "fluxheim");
    assert_eq!(trace.otlp.queue_size, 8192);
    assert_eq!(trace.otlp.timeout_secs, 2);
    assert!(trace.otlp.tls_ca_cert_path.is_none() && trace.otlp.bearer_token_file.is_none());
    let mut trace: TracingConfig = toml::from_str(
        "mode = 'off'\ntraceparent = false\n[otlp]\nendpoint = 'bad'\nqueue_size = 0\ntimeout_secs = 0",
    ).unwrap();
    trace.validate().unwrap();
    trace.otlp.enabled = true;
    assert!(trace.validate().is_err());
    for source in [
        "mode = 'always_on'",
        "sample_rate = 1.0",
        "[otlp]\nprotocol = 'grpc'",
        "[otlp]\nclient_cert_path = 'client.pem'",
    ] {
        assert!(toml::from_str::<TracingConfig>(source).is_err(), "{source}");
    }
}

#[test]
fn tracing_guide_propagation_and_export_gates() {
    let mut trace = TracingConfig {
        enabled: true,
        ..Default::default()
    };
    let supported = cfg!(all(feature = "otel-tracing", not(feature = "privacy-mode")));
    assert_eq!(trace.validate().is_ok(), supported);
    trace.mode = TracingMode::Off;
    assert!(trace.validate().is_err());
    trace.mode = TracingMode::PropagateOnly;
    trace.traceparent = false;
    assert!(trace.validate().is_err());
    trace.traceparent = true;
    trace.otlp.enabled = true;
    assert_eq!(
        trace.validate().is_ok(),
        supported && cfg!(feature = "otel-otlp")
    );
    for endpoint in [
        "http://localhost:4318/v1/traces",
        "http://192.0.2.1/v1/traces",
        "https://collector.example/v1/traces?token=example",
    ] {
        trace.otlp.endpoint = endpoint.into();
        assert!(trace.validate().is_err());
    }
    trace.otlp.endpoint = "http://127.0.0.1:4318/v1/traces".into();
    trace.otlp.bearer_token_file = Some("unused-token".into());
    assert!(trace.validate().is_err());
}

#[test]
fn tracing_guide_paths_and_all_fields_require_upgrade() {
    use crate::reload::{ReloadImpact, ReloadReason, classify_reload};
    let dir = TestDir::new("tracing-guide-paths");
    let mut trace: TracingConfig =
        toml::from_str("[otlp]\ntls_ca_cert_path = 'ca.pem'\nbearer_token_file = 'token'").unwrap();
    trace.resolve_relative_paths(dir.path());
    assert_eq!(trace.otlp.tls_ca_cert_path, Some(dir.child("ca.pem")));
    assert_eq!(trace.otlp.bearer_token_file, Some(dir.child("token")));
    let old = Config::default();
    for source in [
        "enabled = true",
        "mode = 'off'",
        "traceparent = false",
        "log_trace_id = false",
        "[otlp]\nenabled = true",
        "[otlp]\nendpoint = 'https://collector.example/v1/traces'",
        "[otlp]\nservice_name = 'gateway'",
        "[otlp]\nqueue_size = 16",
        "[otlp]\ntimeout_secs = 3",
        "[otlp]\ntls_ca_cert_path = 'ca.pem'",
        "[otlp]\nbearer_token_file = 'token'",
    ] {
        let mut new = old.clone();
        new.tracing = toml::from_str(source).unwrap();
        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::TracingServiceChanged],
            },
            "{source}"
        );
    }
}

#[cfg(all(
    feature = "otel-tracing",
    feature = "otel-otlp",
    not(feature = "privacy-mode")
))]
#[test]
fn tracing_guide_export_limits_validate_at_boundaries() {
    let mut trace = TracingConfig {
        enabled: true,
        ..Default::default()
    };
    trace.otlp.enabled = true;
    for size in [1, 8192, 1_000_000] {
        trace.otlp.queue_size = size;
        trace.validate().unwrap();
    }
    for size in [0, 1_000_001] {
        trace.otlp.queue_size = size;
        assert!(trace.validate().is_err());
    }
    trace.otlp.queue_size = 8192;
    for seconds in [1, 2, 60] {
        trace.otlp.timeout_secs = seconds;
        trace.validate().unwrap();
    }
    for seconds in [0, 61] {
        trace.otlp.timeout_secs = seconds;
        assert!(trace.validate().is_err());
    }
}

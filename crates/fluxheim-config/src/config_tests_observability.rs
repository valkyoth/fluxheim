use super::*;
#[cfg(all(feature = "otel-tracing", not(feature = "privacy-mode")))]
use crate::config::TracingMode;

#[test]
fn observability_baseline_defaults_are_explicit() {
    let config = Config::default();
    assert!(!config.metrics.enabled);
    assert!(!config.metrics.otlp.enabled);
    assert!(config.metrics.require_loopback);
    assert!(!config.tracing.enabled);
    assert!(!config.tracing.otlp.enabled);
    assert!(!config.logging.file.enabled);
    assert_eq!(config.logging.level.as_filter(), "info");
    assert_eq!(config.logging.format, crate::config::LoggingFormat::Json);
    assert_eq!(config.logging.target, crate::config::LoggingTarget::Stderr);
    assert_eq!(
        config.logging.access.enabled,
        !cfg!(feature = "privacy-mode")
    );
    assert!(config.logging.access.include_path);
    assert!(config.logging.access.include_client_ip);
}

#[test]
fn observability_baseline_rejects_historical_config_sketches() {
    for input in [
        "[logging]\nqueue_size = 65536",
        "[logging.spool]\nenabled = true",
        "[metrics.advanced]\nenabled = true",
        "[tracing.sampling]\nsuccess_ratio = 0.01",
    ] {
        assert!(toml::from_str::<Config>(input).is_err(), "{input}");
    }
}

#[test]
fn parses_metrics_config() {
    let config: Config = toml::from_str(
        r#"
            [metrics]
            enabled = true
            listen = "127.0.0.1:9091"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.metrics.enabled);
    assert_eq!(config.metrics.listen, "127.0.0.1:9091");
    assert!(config.metrics.token_env.is_none());
}

#[test]
fn rejects_metrics_token_env() {
    let config: Config = toml::from_str(
        r#"
            [metrics]
            enabled = true
            token_env = "FLUXHEIM_METRICS_TOKEN"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidMetricsPolicy {
            field: "metrics.token_env",
            reason: "metrics.token_env is disabled because process environments cannot be scrubbed without unsafe code; use metrics.token_file"
        })
    );
}

#[test]
fn rejects_metrics_token_env_even_when_empty() {
    let config: Config = toml::from_str(
        r#"
            [metrics]
            enabled = true
            token_env = " "
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidMetricsPolicy {
            field: "metrics.token_env",
            reason: "metrics.token_env is disabled because process environments cannot be scrubbed without unsafe code; use metrics.token_file"
        })
    );
}

#[cfg(feature = "metrics-otlp")]
#[test]
fn parses_otlp_metrics_export_config() {
    let config: Config = toml::from_str(
        r#"
            [metrics]
            enabled = true

            [metrics.otlp]
            enabled = true
            endpoint = "http://127.0.0.1:9090/api/v1/otlp/v1/metrics"
            service_name = "fluxheim-smoke"
            interval_secs = 1
            timeout_secs = 1
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.metrics.otlp.enabled);
    assert_eq!(
        config.metrics.otlp.endpoint,
        "http://127.0.0.1:9090/api/v1/otlp/v1/metrics"
    );
    assert_eq!(config.metrics.otlp.service_name, "fluxheim-smoke");
    assert_eq!(config.metrics.otlp.interval_secs, 1);
}

#[cfg(feature = "metrics-otlp")]
#[test]
fn accepts_https_otlp_metrics_endpoint() {
    let config: Config = toml::from_str(
        r#"
            [metrics]
            enabled = true

            [metrics.otlp]
            enabled = true
            endpoint = "https://collector.example.test/v1/metrics"
            tls_ca_cert_path = "fixtures/private-ca.pem"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(
        config.metrics.otlp.endpoint,
        "https://collector.example.test/v1/metrics"
    );
    assert_eq!(
        config.metrics.otlp.tls_ca_cert_path.as_deref(),
        Some(Path::new("fixtures/private-ca.pem"))
    );
}

#[cfg(not(feature = "metrics-otlp"))]
#[test]
fn rejects_otlp_metrics_export_without_feature() {
    let config: Config = toml::from_str(
        r#"
            [metrics]
            enabled = true

            [metrics.otlp]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::MetricsOtlpExportNotCompiled)
    );
}

#[cfg(all(feature = "otel-tracing", not(feature = "privacy-mode")))]
#[test]
fn parses_trace_context_config() {
    let config: Config = toml::from_str(
        r#"
            [tracing]
            enabled = true
            mode = "propagate_only"
            traceparent = true
            log_trace_id = true
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.tracing.enabled);
    assert_eq!(config.tracing.mode, TracingMode::PropagateOnly);
}

#[cfg(all(
    feature = "otel-tracing",
    feature = "otel-otlp",
    not(feature = "privacy-mode")
))]
#[test]
fn parses_otlp_trace_export_config() {
    let config: Config = toml::from_str(
        r#"
            [tracing]
            enabled = true
            mode = "propagate_only"

            [tracing.otlp]
            enabled = true
            endpoint = "http://127.0.0.1:4318/v1/traces"
            service_name = "fluxheim-smoke"
            queue_size = 64
            timeout_secs = 1
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert!(config.tracing.otlp.enabled);
    assert_eq!(
        config.tracing.otlp.endpoint,
        "http://127.0.0.1:4318/v1/traces"
    );
    assert_eq!(config.tracing.otlp.service_name, "fluxheim-smoke");
    assert_eq!(config.tracing.otlp.queue_size, 64);
}

#[cfg(all(
    feature = "otel-tracing",
    feature = "otel-otlp",
    not(feature = "privacy-mode")
))]
#[test]
fn accepts_https_otlp_trace_endpoint() {
    let config: Config = toml::from_str(
        r#"
            [tracing]
            enabled = true

            [tracing.otlp]
            enabled = true
            endpoint = "https://collector.example.test/v1/traces"
            tls_ca_cert_path = "fixtures/private-ca.pem"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(
        config.tracing.otlp.endpoint,
        "https://collector.example.test/v1/traces"
    );
    assert_eq!(
        config.tracing.otlp.tls_ca_cert_path.as_deref(),
        Some(Path::new("fixtures/private-ca.pem"))
    );
}

#[cfg(all(feature = "otel-tracing", not(feature = "otel-otlp")))]
#[test]
fn rejects_otlp_trace_export_without_feature() {
    let config: Config = toml::from_str(
        r#"
            [tracing]
            enabled = true

            [tracing.otlp]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::OtlpTraceExportNotCompiled)
    );
}

#[cfg(not(feature = "otel-tracing"))]
#[test]
fn rejects_enabled_tracing_without_feature() {
    let config: Config = toml::from_str(
        r#"
            [tracing]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(config.validate(), Err(ConfigError::TracingNotCompiled));
}

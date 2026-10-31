use super::*;

const EXAMPLE: &str = include_str!("../../../examples/metrics/proxy.toml");

#[test]
fn metrics_guide_complete_example_and_relative_token_path() {
    let dir = TestDir::new("metrics-guide");
    fs::write(dir.child("metrics-token"), "fixture-token\n").unwrap();
    let source = if cfg!(feature = "privacy-mode") {
        EXAMPLE.replace("[metrics]\nenabled = true", "[metrics]\nenabled = false")
    } else {
        EXAMPLE.to_owned()
    };
    fs::write(dir.child("proxy.toml"), source).unwrap();
    let config = Config::load(Some(&dir.child("proxy.toml"))).unwrap();
    assert_eq!(config.metrics.enabled, !cfg!(feature = "privacy-mode"));
    assert_eq!(config.metrics.token_file, Some(dir.child("metrics-token")));
    assert_eq!(config.metrics.listen, "127.0.0.1:9091");
    assert!(config.metrics.require_loopback);
    assert!(!config.metrics.otlp.enabled);
    assert_eq!(config.vhosts[0].name, "metrics-guide");
}

#[test]
fn metrics_guide_defaults_match_documented_options() {
    let metrics = MetricsConfig::default();
    assert!(!metrics.enabled);
    assert_eq!(metrics.listen, "127.0.0.1:9091");
    assert!(metrics.require_loopback);
    assert!(metrics.token_env.is_none() && metrics.token_file.is_none());
    assert!(!metrics.otlp.enabled);
    assert_eq!(
        metrics.otlp.endpoint,
        "http://127.0.0.1:9090/api/v1/otlp/v1/metrics"
    );
    assert_eq!(metrics.otlp.service_name, "fluxheim");
    assert_eq!(metrics.otlp.interval_secs, 15);
    assert_eq!(metrics.otlp.timeout_secs, 2);
    assert!(metrics.otlp.tls_ca_cert_path.is_none());
    assert!(metrics.otlp.bearer_token_file.is_none());
}

#[test]
fn metrics_guide_loopback_and_inactive_validation_boundaries() {
    for address in ["127.0.0.1:9091", "[::1]:9091", "127.0.0.1:0"] {
        let metrics = MetricsConfig {
            enabled: true,
            listen: address.into(),
            ..Default::default()
        };
        metrics.validate().unwrap();
    }
    for source in [
        "listen = 'localhost:9091'",
        "token_env = 'METRICS_TOKEN'",
        "token_file = ''",
        "[otlp]\nenabled = true",
    ] {
        let metrics: MetricsConfig = toml::from_str(source).unwrap();
        assert!(metrics.validate().is_err(), "{source}");
    }
    let mut metrics = MetricsConfig {
        listen: "0.0.0.0:9091".into(),
        ..Default::default()
    };
    metrics.validate().unwrap();
    metrics.enabled = true;
    assert!(metrics.validate().is_err());
    metrics.require_loopback = false;
    metrics.validate().unwrap(); // Remote bind does not require a token automatically.
    assert!(metrics.token_file.is_none());
    for source in ["tls = true", "scrape_interval = 10", "series_limit = 1000"] {
        assert!(toml::from_str::<MetricsConfig>(source).is_err());
    }
}

#[test]
fn metrics_guide_inactive_otlp_policy_and_relative_paths() {
    let dir = TestDir::new("metrics-otlp-guide");
    let mut metrics: MetricsConfig = toml::from_str(
        "[otlp]\nendpoint = 'not-a-url'\ninterval_secs = 0\ntimeout_secs = 0\nservice_name = ''\ntls_ca_cert_path = 'ca.pem'\nbearer_token_file = 'collector-token'",
    ).unwrap();
    metrics.resolve_relative_paths(dir.path());
    assert_eq!(metrics.otlp.tls_ca_cert_path, Some(dir.child("ca.pem")));
    assert_eq!(
        metrics.otlp.bearer_token_file,
        Some(dir.child("collector-token"))
    );
    metrics.validate().unwrap();
    metrics.enabled = true;
    metrics.otlp.enabled = true;
    assert!(metrics.validate().is_err());
}

#[test]
fn metrics_guide_all_config_changes_require_process_upgrade() {
    use crate::reload::{ReloadImpact, ReloadReason, classify_reload};
    let old = Config::default();
    for source in [
        "enabled = true",
        "listen = '[::1]:9091'",
        "require_loopback = false",
        "token_file = 'token'",
        "token_env = 'UNSUPPORTED'",
        "[otlp]\nenabled = true",
        "[otlp]\nendpoint = 'https://collector.example/v1/metrics'",
        "[otlp]\nservice_name = 'gateway'",
        "[otlp]\ninterval_secs = 20",
        "[otlp]\ntimeout_secs = 3",
        "[otlp]\ntls_ca_cert_path = 'ca.pem'",
        "[otlp]\nbearer_token_file = 'collector-token'",
    ] {
        let mut new = old.clone();
        new.metrics = toml::from_str(source).unwrap();
        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::MetricsServiceChanged],
            },
            "{source}"
        );
    }
}

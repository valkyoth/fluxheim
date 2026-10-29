use super::*;

const LOCAL: &str = include_str!("../../../examples/observability/local.toml");
const OTLP: &str = include_str!("../../../examples/observability/otlp-local.toml");

#[test]
fn observability_example_is_loopback_without_implicit_trust_or_export() {
    let config: Config = toml::from_str(LOCAL).unwrap();
    assert_eq!(config.server.listen, ["127.0.0.1:8088"]);
    assert!(config.server.trusted_proxies.is_empty());
    assert!(!config.admin.enabled);
    assert!(config.metrics.enabled && config.metrics.require_loopback);
    assert!(!config.metrics.otlp.enabled);
    assert!(!config.tracing.enabled);
    assert!(!config.logging.file.enabled);
    assert_eq!(config.vhosts[0].web.root, Some(PathBuf::from("site")));
    #[cfg(not(feature = "privacy-mode"))]
    {
        config.logging.validate().unwrap();
        config.metrics.validate().unwrap();
        config.tracing.validate().unwrap();
    }
    #[cfg(feature = "privacy-mode")]
    assert!(config.logging.validate().is_err());
}

#[test]
fn observability_export_example_parses_as_an_extension_not_a_replacement() {
    let config: Config = toml::from_str(&format!("{LOCAL}\n{OTLP}")).unwrap();
    assert_eq!(config.server.listen, ["127.0.0.1:8088"]);
    assert!(config.metrics.otlp.enabled && config.tracing.otlp.enabled);
    assert!(config.server.trusted_proxies.is_empty());
    #[cfg(all(
        feature = "metrics-otlp",
        feature = "otel-otlp",
        not(feature = "privacy-mode")
    ))]
    {
        config.metrics.validate().unwrap();
        config.tracing.validate().unwrap();
    }
    #[cfg(not(feature = "metrics-otlp"))]
    assert!(config.metrics.validate().is_err());
}

#[cfg(all(
    feature = "metrics-otlp",
    feature = "otel-otlp",
    not(feature = "privacy-mode")
))]
#[test]
fn observability_export_recipe_cannot_be_moved_to_plaintext_remote_collectors() {
    for host in ["localhost", "192.0.2.1", "collector.example.net"] {
        let example = format!("{LOCAL}\n{OTLP}").replace("127.0.0.1:4318", &format!("{host}:4318"));
        let config: Config = toml::from_str(&example).unwrap();
        assert!(config.metrics.validate().is_err());
        assert!(config.tracing.validate().is_err());
    }
}

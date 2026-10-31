use super::*;

const EXAMPLE: &str = include_str!("../../../examples/logging/proxy.toml");

#[test]
fn logging_guide_example_and_relative_sink_paths_validate() {
    let dir = TestDir::new("logging-guide");
    let source = if cfg!(feature = "privacy-mode") {
        EXAMPLE.replace(
            "[logging.access]\nenabled = true",
            "[logging.access]\nenabled = false",
        )
    } else {
        EXAMPLE.to_owned()
    };
    fs::write(dir.child("proxy.toml"), source).unwrap();
    let config = Config::load(Some(&dir.child("proxy.toml"))).unwrap();
    assert_eq!(config.server.listen, ["127.0.0.1:8080"]);
    assert_eq!(config.vhosts[0].routes[0].name, "application");
    assert!(config.logging.access.request_id);
    assert_eq!(
        config.logging.access.enabled,
        !cfg!(feature = "privacy-mode")
    );
    let mut logging = config.logging;
    logging.file.path = Some("events.log".into());
    logging.crash_file = Some("fatal.log".into());
    logging.resolve_relative_paths(dir.path());
    assert_eq!(logging.file.path, Some(dir.child("events.log")));
    assert_eq!(logging.crash_file, Some(dir.child("fatal.log")));
    assert_eq!(logging.validate().is_ok(), !cfg!(feature = "privacy-mode"));
}

#[test]
fn logging_guide_defaults_and_level_values_match() {
    let logging = LoggingConfig::default();
    assert_eq!(logging.level.as_filter(), "info");
    assert_eq!(logging.format, crate::LoggingFormat::Json);
    assert_eq!(logging.target, crate::LoggingTarget::Stderr);
    assert!(!logging.file.enabled && logging.file.append);
    assert!(logging.file.path.is_none() && logging.crash_file.is_none());
    let access = toml::Value::try_from(&logging.access).unwrap();
    for field in [
        "include_host",
        "include_client_ip",
        "include_cache_phase",
        "include_path",
        "include_route",
        "include_upstream",
        "request_id",
    ] {
        assert_eq!(access[field].as_bool(), Some(true), "{field}");
    }
    assert_eq!(logging.access.request_id_header, "x-request-id");
    for level in ["off", "error", "warn", "info", "debug", "trace"] {
        let config: Config = toml::from_str(&format!("[logging]\nlevel = {level:?}")).unwrap();
        config.logging.validate().unwrap();
        assert_eq!(config.logging.level.as_filter(), level);
    }
    for invalid in [
        "level = 'verbose'",
        "format = 'combined'",
        "target = 'syslog'",
        "queue_capacity = 4096",
    ] {
        assert!(toml::from_str::<Config>(&format!("[logging]\n{invalid}")).is_err());
    }
}

#[test]
fn logging_guide_inactive_path_and_file_requirement_are_checked() {
    let mut logging = LoggingConfig::default();
    logging.file.path = Some("".into());
    assert_eq!(logging.validate(), Err(ConfigError::EmptyLoggingFilePath));
    logging.file.path = None;
    logging.file.enabled = true;
    #[cfg(not(feature = "privacy-mode"))]
    assert_eq!(logging.validate(), Err(ConfigError::MissingLoggingFilePath));
    #[cfg(feature = "privacy-mode")]
    assert_eq!(logging.validate(), Err(ConfigError::PrivacyModeFileLogging));
}

#[test]
fn logging_guide_sink_changes_require_restart_but_access_policy_does_not() {
    use crate::reload::{ReloadImpact, ReloadReason, classify_reload};
    let old = Config::default();
    for source in [
        "level = 'off'",
        "format = 'text'",
        "target = 'stdout'",
        "crash_file = 'fatal.log'",
        "[file]\nappend = false",
    ] {
        let mut new = old.clone();
        new.logging = toml::from_str(source).unwrap();
        assert_eq!(
            classify_reload(&old, &new),
            ReloadImpact::ProcessUpgrade {
                reasons: vec![ReloadReason::LoggingRuntimeChanged],
            }
        );
    }
    let mut new = old.clone();
    new.logging.access.request_id = false;
    assert!(classify_reload(&old, &new).is_snapshot_safe());
}

use super::*;

#[test]
fn parses_access_logging_config() {
    let config: Config = toml::from_str(
        r#"
            [logging]
            level = "debug"
            format = "text"
            target = "stdout"

            [logging.access]
            enabled = false
            include_host = false
            include_client_ip = false
            include_cache_phase = false
            include_path = false
            include_route = false
            include_upstream = false
            request_id = false
            request_id_header = "x-correlation-id"
            "#,
    )
    .unwrap();

    config.validate().unwrap();
    assert_eq!(config.logging.level, crate::LoggingLevel::Debug);
    assert_eq!(config.logging.format, crate::LoggingFormat::Text);
    assert_eq!(config.logging.target, crate::LoggingTarget::Stdout);
    assert!(!config.logging.access.enabled);
    assert!(!config.logging.access.include_host);
    assert!(!config.logging.access.include_client_ip);
    assert!(!config.logging.access.include_cache_phase);
    assert!(!config.logging.access.include_path);
    assert!(!config.logging.access.include_route);
    assert!(!config.logging.access.include_upstream);
    assert!(!config.logging.access.request_id);
    assert_eq!(config.logging.access.request_id_header, "x-correlation-id");
}

#[cfg(not(feature = "privacy-mode"))]
#[test]
fn parses_file_logging_config() {
    let log_path = unique_temp_path("config-file-logging").join("fluxheim.log");
    let config: Config = toml::from_str(&format!(
        r#"
            [logging.file]
            enabled = true
            path = "{}"
            append = false
            "#,
        log_path.display()
    ))
    .unwrap();

    config.validate().unwrap();
    assert!(config.logging.file.enabled);
    assert_eq!(
        config.logging.file.path.as_deref(),
        Some(log_path.as_path())
    );
    assert!(!config.logging.file.append);
}

#[cfg(not(feature = "privacy-mode"))]
#[test]
fn rejects_file_logging_without_path() {
    let config: Config = toml::from_str(
        r#"
            [logging.file]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(config.validate(), Err(ConfigError::MissingLoggingFilePath));
}

#[test]
fn rejects_empty_file_logging_path() {
    let config: Config = toml::from_str(
        r#"
            [logging.file]
            path = ""
            "#,
    )
    .unwrap();

    assert_eq!(config.validate(), Err(ConfigError::EmptyLoggingFilePath));
}

#[test]
fn rejects_file_logging_path_traversal() {
    let config: Config = toml::from_str(
        r#"
            [logging.file]
            path = "../fluxheim.log"
            "#,
    )
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "logging.file.path"
    ));
}

#[cfg(all(not(feature = "privacy-mode"), unix))]
#[test]
fn rejects_file_logging_under_world_writable_parent() {
    let path = unique_world_writable_child("config-log-world-writable", "fluxheim.log");
    let config: Config = toml::from_str(&format!(
        r#"
            [logging.file]
            path = "{}"
            "#,
        path.display()
    ))
    .unwrap();

    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "logging.file.path"
    ));
}

#[test]
fn rejects_invalid_access_log_request_id_header() {
    let config: Config = toml::from_str(
        r#"
            [logging.access]
            request_id_header = "bad header"
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidHeaderName {
            field: "logging.access.request_id_header",
            name: "bad header".to_owned(),
        })
    );
}

#[cfg(feature = "privacy-mode")]
#[test]
fn privacy_mode_rejects_access_logging() {
    let config: Config = toml::from_str(
        r#"
            [logging.access]
            enabled = true
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::PrivacyModeAccessLogging)
    );
}

#[cfg(feature = "privacy-mode")]
#[test]
fn privacy_mode_rejects_file_logging() {
    let config: Config = toml::from_str(
        r#"
            [logging.file]
            enabled = true
            path = "/var/log/fluxheim.log"
            "#,
    )
    .unwrap();

    assert_eq!(config.validate(), Err(ConfigError::PrivacyModeFileLogging));
}

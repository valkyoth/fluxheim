use super::*;

#[test]
fn parses_admin_config_with_self_healing() {
    let snapshot_store = secure_test_dir("config-admin-self-healing-snapshots");
    let config: Config = toml::from_str(&format!(
        r#"
            [admin]
            enabled = true
            listen = "127.0.0.1:9090"
            token_env = "FLUXHEIM_ADMIN_TOKEN"
            snapshot_store = "{}"

            [admin.transport]
            mode = "local_only"

            [admin.health]
            unauthenticated = false
            response = "minimal"

            [admin.auth_throttle]
            enabled = true
            window_secs = 30
            per_source_failures = 3
            global_failures = 50
            base_lockout_secs = 10
            max_lockout_secs = 120
            max_sources = 1024

            [admin.client_certificate]
            required = true
            sha256_header = "x-client-cert-sha256"
            allow_sha256 = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]

            [admin.self_healing]
            enabled = true
            validation_window_secs = 45
            health_path = "/_fluxheim/health"
            min_successful_checks = 2
            max_error_rate_per_mille = 50
            "#,
        snapshot_store.display()
    ))
    .unwrap();

    config.validate().unwrap();
    assert!(config.admin.enabled);
    assert!(config.admin.self_healing.enabled);
    assert_eq!(
        config.admin.snapshot_store.as_deref(),
        Some(snapshot_store.as_path())
    );
    assert_eq!(
        config.admin.health.response,
        AdminHealthResponseMode::Minimal
    );
    assert_eq!(
        config.admin.transport.mode,
        AdminRemoteTransportMode::LocalOnly
    );
    assert_eq!(config.admin.auth_throttle.per_source_failures, 3);
    assert_eq!(config.admin.auth_throttle.global_failures, 50);
    assert!(config.admin.client_certificate.required);
    assert_eq!(
        config.admin.client_certificate.allow_sha256,
        vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    );
}

#[cfg(unix)]
#[test]
fn parses_admin_read_only_ops_socket() {
    let snapshot_store = secure_test_dir("config-admin-ops-snapshots");
    let socket_dir = secure_test_dir("config-admin-ops-runtime");
    let config: Config = toml::from_str(&format!(
        r#"
            [admin]
            enabled = true
            listen = "127.0.0.1:9090"
            token_env = "FLUXHEIM_ADMIN_TOKEN"
            snapshot_store = "{}"

            [admin.ops_socket]
            enabled = true
            path = "{}/fluxheim-ops.sock"
            mode = "0660"
            require_bearer_token = true
            "#,
        snapshot_store.display(),
        socket_dir.display()
    ))
    .unwrap();

    config.validate().unwrap();
    assert!(config.admin.ops_socket.enabled);
    assert_eq!(config.admin.ops_socket.mode_bits(), 0o660);
    assert!(config.admin.ops_socket.require_bearer_token);
}

#[cfg(unix)]
#[test]
fn rejects_world_accessible_admin_ops_socket() {
    let snapshot_store = secure_test_dir("config-admin-ops-world-snapshots");
    let socket_dir = secure_test_dir("config-admin-ops-world-runtime");
    let config: Config = toml::from_str(&format!(
        r#"
            [admin]
            enabled = true
            listen = "127.0.0.1:9090"
            token_env = "FLUXHEIM_ADMIN_TOKEN"
            snapshot_store = "{}"

            [admin.ops_socket]
            enabled = true
            path = "{}/fluxheim-ops.sock"
            mode = "0666"
            "#,
        snapshot_store.display(),
        socket_dir.display()
    ))
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("admin.ops_socket.mode"), "{error}");
}

#[test]
fn rejects_invalid_admin_client_certificate_fingerprint() {
    let config: Config = toml::from_str(
        r#"
            [admin.client_certificate]
            allow_sha256 = ["not-a-sha256"]
            "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("admin.client_certificate.allow_sha256"),
        "{error}"
    );
}

#[test]
fn rejects_remote_unauthenticated_admin_health() {
    let snapshot_store = secure_test_dir("config-admin-remote-health-snapshots");
    let config = Config {
        admin: AdminConfig {
            enabled: true,
            listen: "0.0.0.0:9090".to_owned(),
            require_loopback: false,
            token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
            snapshot_store: Some(snapshot_store),
            transport: AdminTransportConfig {
                mode: AdminRemoteTransportMode::TrustedTlsTerminator,
            },
            health: AdminHealthConfig {
                unauthenticated: true,
                ..AdminHealthConfig::default()
            },
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::UnauthenticatedAdminHealthNotLoopback {
            address: "0.0.0.0:9090".to_owned()
        })
    );
}

#[test]
fn rejects_invalid_admin_auth_throttle() {
    let config: Config = toml::from_str(
        r#"
            [admin.auth_throttle]
            enabled = true
            max_lockout_secs = 1
            base_lockout_secs = 2
            "#,
    )
    .unwrap();

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidAdminAuthThrottle {
            field: "admin.auth_throttle.max_lockout_secs"
        })
    );
}

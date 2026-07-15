use super::*;

#[test]
fn rejects_remote_metrics_listener_by_default() {
    let config = Config {
        metrics: MetricsConfig {
            enabled: true,
            listen: "0.0.0.0:9091".to_owned(),
            ..MetricsConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::MetricsListenNotLoopback {
            address: "0.0.0.0:9091".to_owned()
        })
    );
}

#[test]
fn rejects_enabled_admin_without_auth() {
    let snapshot_store = secure_test_dir("config-admin-missing-auth-snapshots");
    let config = Config {
        admin: AdminConfig {
            enabled: true,
            snapshot_store: Some(snapshot_store),
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(config.validate(), Err(ConfigError::MissingAdminAuth));
}

#[test]
fn rejects_enabled_admin_without_snapshot_store() {
    let config = Config {
        admin: AdminConfig {
            enabled: true,
            token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::MissingAdminSnapshotStore)
    );
}

#[test]
fn rejects_remote_admin_listener_by_default() {
    let snapshot_store = secure_test_dir("config-admin-remote-default-snapshots");
    let config = Config {
        admin: AdminConfig {
            enabled: true,
            listen: "0.0.0.0:9090".to_owned(),
            token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
            snapshot_store: Some(snapshot_store),
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::AdminListenNotLoopback {
            address: "0.0.0.0:9090".to_owned()
        })
    );
}

#[test]
fn rejects_remote_admin_without_trusted_tls_terminator() {
    let snapshot_store = secure_test_dir("config-admin-remote-insecure-snapshots");
    let config = Config {
        admin: AdminConfig {
            enabled: true,
            listen: "0.0.0.0:9090".to_owned(),
            require_loopback: false,
            token_env: Some("FLUXHEIM_ADMIN_TOKEN".to_owned()),
            snapshot_store: Some(snapshot_store),
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::RemoteAdminRequiresSecureTransport {
            address: "0.0.0.0:9090".to_owned()
        })
    );
}

#[test]
fn accepts_remote_admin_when_trusted_tls_terminator_is_explicit() {
    let snapshot_store = secure_test_dir("config-admin-remote-trusted-snapshots");
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
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_admin_paths_under_world_writable_parent() {
    let token_file = unique_world_writable_child("config-admin-token-world-writable", "token");
    let token_config = Config {
        admin: AdminConfig {
            token_file: Some(token_file),
            ..AdminConfig::default()
        },
        ..Config::default()
    };
    assert!(matches!(
        token_config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "admin.token_file"
    ));

    let snapshot_store =
        unique_world_writable_child("config-admin-snapshot-world-writable", "snapshots");
    let snapshot_config = Config {
        admin: AdminConfig {
            snapshot_store: Some(snapshot_store),
            ..AdminConfig::default()
        },
        ..Config::default()
    };
    assert!(matches!(
        snapshot_config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "admin.snapshot_store"
    ));
}

#[cfg(unix)]
#[test]
fn rejects_existing_non_private_or_root_snapshot_store() {
    use std::os::unix::fs::PermissionsExt as _;

    let snapshot_store = secure_test_dir("config-admin-snapshot-non-private");
    std::fs::set_permissions(&snapshot_store, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = Config {
        admin: AdminConfig {
            snapshot_store: Some(snapshot_store),
            ..AdminConfig::default()
        },
        ..Config::default()
    };
    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "admin.snapshot_store"
    ));

    let root = Config {
        admin: AdminConfig {
            snapshot_store: Some("/".into()),
            ..AdminConfig::default()
        },
        ..Config::default()
    };
    assert!(matches!(
        root.validate(),
        Err(ConfigError::UnsafePath { field, .. }) if field == "admin.snapshot_store"
    ));
}

#[test]
fn rejects_invalid_admin_self_healing_window() {
    let config = Config {
        admin: AdminConfig {
            self_healing: AdminSelfHealingConfig {
                validation_window_secs: 0,
                ..AdminSelfHealingConfig::default()
            },
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        config.validate(),
        Err(ConfigError::InvalidAdminSelfHealing {
            field: "admin.self_healing.validation_window_secs"
        })
    );
}

#[test]
fn rejects_unsafe_admin_health_paths() {
    for health_path in [
        "relative/path".to_owned(),
        "/_fluxheim/health query".to_owned(),
        "/_fluxheim/health\tbad".to_owned(),
        "/_fluxheim\\health".to_owned(),
        "/_fluxheim/health?ready=1".to_owned(),
        "/_fluxheim/health#ready".to_owned(),
        "/_fluxheim/status".to_owned(),
        "/_fluxheim/reload".to_owned(),
        "/".to_owned() + &"a".repeat(crate::MAX_ADMIN_HEALTH_PATH_BYTES),
    ] {
        let config = Config {
            admin: AdminConfig {
                self_healing: AdminSelfHealingConfig {
                    health_path,
                    ..AdminSelfHealingConfig::default()
                },
                ..AdminConfig::default()
            },
            ..Config::default()
        };

        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidAdminHealthPath { .. })
        ));
    }
}

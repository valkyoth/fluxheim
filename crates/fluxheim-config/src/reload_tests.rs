use crate::config::{
    AdminConfig, Config, HttpsRedirectConfig, LoggingConfig, LoggingFileConfig, LoggingFormat,
    LoggingLevel, LoggingTarget, MetricsConfig, ProxyConfig, ServerConfig, ServerProcessConfig,
    TlsBackend, TlsCipherSuite, TlsConfig, TlsCurvePreference, TlsFipsConfig, TlsPolicyProfile,
    VhostConfig, WasmConfig, WebConfig,
};
use crate::reload::{ReloadImpact, ReloadReason, classify_reload};

#[test]
fn unchanged_config_is_noop() {
    let config = Config::default();

    assert_eq!(classify_reload(&config, &config), ReloadImpact::Noop);
    assert_eq!(classify_reload(&config, &config).kind(), "noop");
    assert!(classify_reload(&config, &config).is_snapshot_safe());
}

#[test]
fn vhost_policy_change_is_snapshot_reload() {
    let old = Config::default();
    let new = Config {
        vhosts: vec![VhostConfig {
            name: "example".to_owned(),
            hosts: vec!["example.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: crate::config::CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };

    assert_eq!(classify_reload(&old, &new), ReloadImpact::Snapshot);
    assert_eq!(classify_reload(&old, &new).to_string(), "snapshot");
    assert!(classify_reload(&old, &new).is_snapshot_safe());
}

#[test]
fn https_redirect_policy_change_is_snapshot_reload() {
    let old = Config {
        server: ServerConfig {
            tls_listen: vec!["127.0.0.1:18443".to_owned()],
            ..ServerConfig::default()
        },
        tls: TlsConfig {
            enabled: true,
            certificates: vec![crate::config::StaticCertificateConfig {
                cert_path: "fullchain.pem".into(),
                key_path: "key.pem".into(),
            }],
            ..TlsConfig::default()
        },
        ..Config::default()
    };
    let new = Config {
        server: ServerConfig {
            https_redirect: HttpsRedirectConfig {
                enabled: true,
                status: 308,
                target_port: Some(8443),
            },
            ..old.server.clone()
        },
        ..old.clone()
    };

    assert_eq!(classify_reload(&old, &new), ReloadImpact::Snapshot);
    assert!(classify_reload(&old, &new).is_snapshot_safe());
}

#[test]
fn listener_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        server: ServerConfig {
            listen: vec!["127.0.0.1:18081".to_owned()],
            ..ServerConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::ListenerChanged]
        }
    );
    assert_eq!(
        classify_reload(&old, &new).to_string(),
        "process-upgrade: listener-changed"
    );
    assert!(!classify_reload(&old, &new).is_snapshot_safe());
    assert_eq!(
        classify_reload(&old, &new).reasons(),
        &[ReloadReason::ListenerChanged]
    );
}

#[test]
fn process_settings_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        server: ServerConfig {
            process: ServerProcessConfig {
                threads: 4,
                ..ServerProcessConfig::default()
            },
            ..ServerConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::ProcessSettingsChanged]
        }
    );
    assert_eq!(
        classify_reload(&old, &new).to_string(),
        "process-upgrade: process-settings-changed"
    );
}

#[test]
fn logging_runtime_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        logging: LoggingConfig {
            level: LoggingLevel::Debug,
            ..LoggingConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::LoggingRuntimeChanged]
        }
    );
    assert_eq!(
        classify_reload(&old, &new).to_string(),
        "process-upgrade: logging-runtime-changed"
    );
}

#[test]
fn logging_format_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        logging: LoggingConfig {
            format: LoggingFormat::Text,
            ..LoggingConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::LoggingRuntimeChanged]
        }
    );
}

#[test]
fn logging_target_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        logging: LoggingConfig {
            target: LoggingTarget::Stdout,
            ..LoggingConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::LoggingRuntimeChanged]
        }
    );
}

#[test]
fn logging_file_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        logging: LoggingConfig {
            file: LoggingFileConfig {
                enabled: true,
                path: Some("/var/log/fluxheim/fluxheim.log".into()),
                append: true,
            },
            ..LoggingConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::LoggingRuntimeChanged]
        }
    );
}

#[test]
fn tls_listener_address_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        server: ServerConfig {
            tls_listen: vec!["127.0.0.1:18443".to_owned()],
            ..ServerConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::ListenerChanged]
        }
    );
}

#[test]
fn tls_listener_mode_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        tls: TlsConfig {
            enabled: true,
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::TlsModeChanged]
        }
    );
}

#[test]
fn tls_backend_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        tls: TlsConfig {
            backend: TlsBackend::Openssl,
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::TlsBackendChanged]
        }
    );
}

#[test]
fn tls_policy_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        tls: TlsConfig {
            profile: TlsPolicyProfile::Modern,
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::TlsModeChanged]
        }
    );
}

#[test]
fn tls_fips_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        tls: TlsConfig {
            fips: TlsFipsConfig {
                required: true,
                require_disk_cache_encryption: false,
            },
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::TlsModeChanged]
        }
    );
}

#[test]
fn tls_cipher_and_curve_changes_require_process_upgrade() {
    let old = Config::default();
    let new = Config {
        tls: TlsConfig {
            curve_preferences: vec![TlsCurvePreference::P256],
            cipher_suites: vec![TlsCipherSuite::Tls13Aes256GcmSha384],
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::TlsModeChanged]
        }
    );
}

#[test]
fn admin_service_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        admin: AdminConfig {
            listen: "127.0.0.1:19090".to_owned(),
            ..AdminConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::AdminServiceChanged]
        }
    );
    assert_eq!(
        classify_reload(&old, &new).to_string(),
        "process-upgrade: admin-service-changed"
    );
}

#[test]
fn metrics_service_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        metrics: MetricsConfig {
            enabled: true,
            ..MetricsConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::MetricsServiceChanged]
        }
    );
    assert_eq!(
        classify_reload(&old, &new).to_string(),
        "process-upgrade: metrics-service-changed"
    );
}

#[test]
fn wasm_runtime_change_requires_process_upgrade() {
    let old = Config::default();
    let new = Config {
        wasm: WasmConfig {
            enabled: true,
            plugin_roots: vec!["/srv/fluxheim/plugins".into()],
            ..WasmConfig::default()
        },
        ..Config::default()
    };

    assert_eq!(
        classify_reload(&old, &new),
        ReloadImpact::ProcessUpgrade {
            reasons: vec![ReloadReason::WasmRuntimeChanged]
        }
    );
    assert_eq!(
        classify_reload(&old, &new).to_string(),
        "process-upgrade: wasm-runtime-changed"
    );
    assert!(!classify_reload(&old, &new).is_snapshot_safe());
}

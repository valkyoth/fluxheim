use super::runtime_logging::{log_record_json, open_log_file};
use fluxheim_common::test_support::unique_temp_path;

#[test]
fn json_log_record_escapes_fields() {
    let record = log_record_json(
        "2026-05-05T12:00:00Z",
        "INFO",
        "fluxheim::test",
        "line\n\"x\"",
    );

    assert_eq!(
        record,
        "{\"timestamp\":\"2026-05-05T12:00:00Z\",\"level\":\"INFO\",\"target\":\"fluxheim::test\",\"message\":\"line\\n\\\"x\\\"\"}"
    );
}

#[test]
fn json_escape_escapes_control_characters() {
    assert_eq!(
        fluxheim_observability::json_escape("a\u{0001}b"),
        "a\\u0001b"
    );
}

#[test]
fn native_runtime_manifest_preview_reports_ready_service_graph() {
    let mut config = crate::config::Config::default();
    config.server.listen = vec!["127.0.0.1:18080".to_owned()];
    config.admin.enabled = true;
    config.admin.listen = "127.0.0.1:19090".to_owned();
    config.metrics.enabled = true;
    config.metrics.listen = "127.0.0.1:19091".to_owned();
    config.stream.enabled = true;
    config.stream.routes = vec![crate::config::StreamRouteConfig {
        name: "tcp".to_owned(),
        listen: vec!["127.0.0.1:15432".to_owned()],
        upstream: Some("127.0.0.1:5432".to_owned()),
        ..crate::config::StreamRouteConfig::default()
    }];
    config.udp.enabled = true;
    config.udp.routes = vec![crate::config::UdpRouteConfig {
        name: "dns".to_owned(),
        mode: crate::config::UdpRouteMode::DnsLoadBalance,
        listen: vec!["127.0.0.1:15353".to_owned()],
        upstream: Some("127.0.0.1:5353".to_owned()),
        upstreams: Vec::new(),
        upstream_weights: Vec::new(),
        upstream_aliases: Vec::new(),
        idle_timeout_secs: 30,
        response_timeout_secs: 3,
        max_datagram_bytes: 1232,
        max_sessions: 4096,
        max_sessions_per_source: 64,
        max_responses_per_source_per_second: 256,
        passive_health_enabled: true,
        passive_health_failures: 3,
        passive_health_ejection_secs: 10,
    }];
    let plan = fluxheim_server::ServerPlan::from_config(&config).unwrap();

    let preview = super::native_runtime_manifest_preview(&plan).expect("ready manifest");

    assert!(preview.contains("services=5"));
    assert!(preview.contains("listeners=5"));
    assert!(preview.contains("ProxyHttp=[Http@127.0.0.1:18080]"));
    assert!(preview.contains("AdminControlPlane=[AdminHttp@127.0.0.1:19090]"));
    assert!(preview.contains("MetricsHttp=[MetricsHttp@127.0.0.1:19091]"));
    assert!(preview.contains("StreamProxy=[StreamTcp@127.0.0.1:15432]"));
    assert!(preview.contains("UdpProxy=[Udp@127.0.0.1:15353]"));
}

#[test]
fn native_runtime_manifest_preview_stays_empty_when_blocked() {
    let mut config = crate::config::Config::default();
    config.server.listen = vec!["127.0.0.1:18080".to_owned()];
    config.cache.enabled = true;
    let plan = fluxheim_server::ServerPlan::from_config(&config).unwrap();

    assert!(super::native_runtime_manifest_preview(&plan).is_none());
}

#[test]
fn native_http1_router_factory_validates_when_cutover_ready() {
    let mut config = crate::config::Config::default();
    config.server.listen = vec!["127.0.0.1:18080".to_owned()];
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    let plan = fluxheim_server::ServerPlan::from_config(&config).unwrap();

    assert_eq!(
        plan.native_http1_proxy_cutover_summary().status(),
        fluxheim_server::NativeHttp1ProxyCutoverStatus::NativeReady
    );
    super::validate_native_http1_router_factory(&config, &plan).unwrap();
}

#[test]
fn native_runtime_target_adapter_selects_native_for_ready_plan() {
    let mut config = crate::config::Config::default();
    config.server.listen = vec!["127.0.0.1:18080".to_owned()];
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    let plan = fluxheim_server::ServerPlan::from_config(&config).unwrap();

    assert_eq!(
        plan.native_runtime_target_adapter(),
        fluxheim_server::RuntimeAdapterKind::NativeRuntime
    );
}

#[test]
fn native_runtime_rejects_unsupported_certificate_background_tasks() {
    let plan = fluxheim_server::ServerPlan::with_process(
        fluxheim_server::ProcessSpec::default(),
        Vec::new(),
        Vec::new(),
        vec![fluxheim_runtime::BackgroundTaskSpec::new(
            "ACME renewal",
            fluxheim_runtime::BackgroundTaskKind::AcmeRenewal,
        )],
    );
    let launch_plan = plan.native_runtime_launch_plan().unwrap();

    let error = super::reject_unsupported_native_background_tasks(&launch_plan, false)
        .unwrap_err()
        .to_string();

    assert!(error.contains("native runtime does not yet support ACME renewal"));
    super::reject_unsupported_native_background_tasks(&launch_plan, true).unwrap();
}

#[cfg(feature = "acme-client")]
#[test]
fn acme_background_service_honors_automation_mode() {
    let mut config = crate::config::Config {
        tls: crate::config::TlsConfig {
            enabled: true,
            acme: crate::config::AcmeConfig {
                enabled: true,
                storage: Some(std::path::PathBuf::from("/var/lib/fluxheim/acme")),
                ..crate::config::AcmeConfig::default()
            },
            ..crate::config::TlsConfig::default()
        },
        vhosts: vec![crate::config::VhostConfig {
            name: "example".to_owned(),
            hosts: vec!["example.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: crate::config::VhostTlsConfig {
                enabled: true,
                acme: crate::config::VhostAcmeConfig {
                    enabled: true,
                    issuer: None,
                    domains: Vec::new(),
                },
                ..crate::config::VhostTlsConfig::default()
            },
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            proxy: crate::config::ProxyConfig::default(),
            cache: crate::config::CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: crate::config::WebConfig::default(),
            routes: Vec::new(),
        }],
        ..crate::config::Config::default()
    };

    assert!(super::acme_background_service_enabled(&config));

    config.tls.acme.automation = crate::config::AcmeAutomationMode::External;

    assert!(!super::acme_background_service_enabled(&config));
}

#[cfg(all(feature = "acme-client", unix))]
#[test]
fn certificate_reload_control_service_skips_when_acme_disabled() {
    let config = crate::config::Config::default();
    let server_plan = fluxheim_server::ServerPlan::from_config(&config).unwrap();
    let task = fluxheim_runtime::BackgroundTaskSpec::new(
        "cert-reload",
        fluxheim_runtime::BackgroundTaskKind::CertificateReload,
    );

    assert!(
        super::certificate_reload_control_service(
            task,
            server_plan.certificate_reload_control(),
            None
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn opens_regular_log_file_for_append() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = unique_temp_path("runtime-log-append").with_extension("log");
    let _ = std::fs::remove_file(&path);

    let file = open_log_file(&path, true)?;

    assert!(file.metadata()?.is_file());
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn rejects_symlink_log_file() {
    let target = unique_temp_path("runtime-log-target").with_extension("log");
    let link = unique_temp_path("runtime-log-link").with_extension("log");
    let _ = std::fs::remove_file(&target);
    let _ = std::fs::remove_file(&link);
    std::fs::write(&target, b"").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    assert!(open_log_file(&link, true).is_err());

    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_file(&target);
}

#[cfg(target_os = "linux")]
#[test]
fn rejects_symlink_log_file_parent() {
    let real_dir = unique_temp_path("runtime-log-real-parent");
    let link_dir = unique_temp_path("runtime-log-link-parent");
    let _ = std::fs::remove_dir_all(&real_dir);
    let _ = std::fs::remove_file(&link_dir);
    std::fs::create_dir(&real_dir).unwrap();
    std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();
    let log_path = link_dir.join("fluxheim.log");

    assert!(open_log_file(&log_path, true).is_err());

    let _ = std::fs::remove_file(&link_dir);
    let _ = std::fs::remove_dir_all(&real_dir);
}

#[cfg(all(
    feature = "tls-rustls-backend",
    feature = "acme",
    not(feature = "tls-openssl")
))]
#[test]
fn rustls_alpn_protocols_include_acme_tls_alpn_when_enabled() {
    let tls = crate::config::TlsConfig {
        acme: crate::config::AcmeConfig {
            enabled: true,
            challenge: crate::config::AcmeChallenge::TlsAlpn01,
            storage: Some(std::path::PathBuf::from("/var/lib/fluxheim/acme")),
            ..crate::config::AcmeConfig::default()
        },
        ..crate::config::TlsConfig::default()
    };

    let protocols =
        fluxheim_tls::rustls_alpn_protocols(&tls, Some(fluxheim_acme::acme_tls_alpn_protocol()));

    assert_eq!(
        protocols.first().map(Vec::as_slice),
        Some(fluxheim_acme::acme_tls_alpn_protocol())
    );
    assert!(protocols.iter().any(|protocol| protocol == b"h2"));
    assert!(protocols.iter().any(|protocol| protocol == b"http/1.1"));
}

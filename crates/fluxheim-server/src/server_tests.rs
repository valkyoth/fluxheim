use super::*;
use crate::http1::DEFAULT_HTTP1_MAX_CONNECTIONS;
use std::collections::BTreeMap;

use fluxheim_config::{
    CacheConfig, Config, DownstreamProxyProtocol, RouteConfig, ServerLimitsConfig,
    StreamRouteConfig, UdpRouteConfig, VhostConfig,
};
use fluxheim_runtime::{BackgroundTaskKind, BackgroundTaskSpec, ShutdownReason, ShutdownState};

struct StaticShutdown(ShutdownState);

impl ShutdownView for StaticShutdown {
    fn shutdown_state(&self) -> ShutdownState {
        self.0
    }
}

struct RecordingRunner;

impl ServerRunner for RecordingRunner {
    type Error = &'static str;

    fn run(&self, _plan: ServerPlan, shutdown: &dyn ShutdownView) -> Result<(), Self::Error> {
        if shutdown.is_shutdown_requested() {
            return Err("shutdown requested");
        }
        Ok(())
    }
}

#[test]
fn listener_spec_reports_loopback_and_proxy_protocol() {
    let spec = ListenerSpec::new("127.0.0.1:8080".parse().unwrap(), ListenerProtocol::Http)
        .with_proxy_protocol(true);

    assert!(spec.is_loopback());
    assert!(spec.proxy_protocol_enabled());
}

#[test]
fn server_plan_reports_public_listeners() {
    let public = ListenerSpec::new("0.0.0.0:443".parse().unwrap(), ListenerProtocol::Https);
    let local = ListenerSpec::new(
        "127.0.0.1:9090".parse().unwrap(),
        ListenerProtocol::MetricsHttp,
    );

    assert!(ServerPlan::new(vec![local, public], Vec::new()).has_public_listener());
    assert!(!ServerPlan::new(vec![local], Vec::new()).has_public_listener());
}

#[test]
fn downstream_http2_policy_uses_hardened_defaults() {
    let policy = DownstreamHttp2Policy::default();

    assert_eq!(policy.max_header_list_size(), 64 * 1024);
    assert_eq!(policy.max_header_count(), 100);
    assert_eq!(policy.max_uri_bytes(), 8 * 1024);
    assert_eq!(
        policy.response_write_lifetime(),
        std::time::Duration::from_secs(30)
    );
    assert_eq!(policy.handler_timeout(), std::time::Duration::from_secs(30));
    assert_eq!(policy.max_concurrent_streams(), 32);
    assert_eq!(policy.initial_window_size(), 64 * 1024);
    assert_eq!(policy.max_frame_size(), 16 * 1024);
    assert_eq!(policy.max_send_buffer_size(), 256 * 1024);
    assert_eq!(policy.max_pending_accept_reset_streams(), 8);
}

#[test]
fn downstream_http2_policy_maps_server_header_limits() {
    let policy = DownstreamHttp2Policy::from_server_limits(ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_request_headers: 7,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(2048),
    });

    assert_eq!(policy.max_header_list_size(), 4096);
    assert_eq!(policy.max_header_count(), 7);
    assert_eq!(policy.max_uri_bytes(), 1024);
    assert_eq!(policy.max_concurrent_streams(), 32);
}

#[test]
fn server_plan_exposes_native_http2_preview_gate() {
    let plan = ServerPlan::from_config(&Config::default()).expect("valid server plan");
    let preview = plan.native_http2_preview();

    assert_eq!(preview.downstream_policy(), plan.downstream_http2());
    assert!(preview.is_cutover_ready());
    assert!(preview.blocking_reports().next().is_none());
    assert!(preview.reports().iter().any(|report| {
        report.hook() == NativeHttp2SafetyHook::HeaderFieldCount
            && report.status() == NativeHttp2SafetyStatus::Satisfied
            && report.detail().contains("max_header_list_size")
    }));
}

#[test]
fn native_runtime_cutover_summary_reports_ready_when_no_services_block() {
    let plan = ServerPlan::new(Vec::new(), Vec::new());
    let summary = plan.native_runtime_cutover_summary();

    assert!(summary.is_ready());
    assert!(summary.blockers().is_empty());
}

#[test]
fn native_runtime_cutover_summary_reports_proxy_blockers() {
    let mut config = Config::default();
    config.server.listen = vec!["127.0.0.1:8080".to_owned()];
    config.proxy.upstreams = vec!["127.0.0.1:3000".to_owned()];
    config.cache.enabled = true;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let blockers = plan.native_runtime_cutover_summary().blockers().to_vec();

    assert!(blockers.contains(&NativeRuntimeCutoverBlocker::NativeHttp1Proxy));
    assert!(!blockers.contains(&NativeRuntimeCutoverBlocker::NativeHttp2));
}

#[test]
fn native_runtime_cutover_summary_reports_service_blockers() {
    let plan = ServerPlan::with_process(
        ProcessSpec::default(),
        Vec::new(),
        vec![
            ServiceSpec::new(
                "admin",
                ServiceKind::AdminControlPlane,
                &[ListenerProtocol::AdminHttp],
            ),
            ServiceSpec::new("ops", ServiceKind::AdminOpsSocket, &[]),
            ServiceSpec::new(
                "metrics",
                ServiceKind::MetricsHttp,
                &[ListenerProtocol::MetricsHttp],
            ),
            ServiceSpec::new(
                "stream",
                ServiceKind::StreamProxy,
                &[ListenerProtocol::StreamTcp],
            ),
            ServiceSpec::new("udp", ServiceKind::UdpProxy, &[ListenerProtocol::Udp]),
        ],
        Vec::new(),
    );
    let summary = plan.native_runtime_cutover_summary();

    assert!(!summary.is_ready());
    assert_eq!(
        summary.blockers(),
        &[
            NativeRuntimeCutoverBlocker::AdminControlPlane,
            NativeRuntimeCutoverBlocker::AdminOpsSocket,
            NativeRuntimeCutoverBlocker::MetricsHttp,
            NativeRuntimeCutoverBlocker::StreamProxy,
            NativeRuntimeCutoverBlocker::UdpProxy,
        ]
    );
}

#[test]
fn native_runtime_manifest_rejects_blocked_plans() {
    let mut config = Config::default();
    config.server.listen = vec!["127.0.0.1:8080".to_owned()];
    config.proxy.upstreams = vec!["127.0.0.1:3000".to_owned()];
    config.cache.enabled = true;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_runtime_target_adapter(),
        RuntimeAdapterKind::PingoraCompatibility
    );
    assert!(matches!(
        plan.native_runtime_manifest(),
        Err(NativeRuntimeManifestError::Blocked { blockers })
            if blockers == vec![NativeRuntimeCutoverBlocker::NativeHttp1Proxy]
    ));
    assert!(matches!(
        plan.native_runtime_launch_plan(),
        Err(NativeRuntimeLaunchPlanError::Blocked { blockers })
            if blockers == vec![NativeRuntimeCutoverBlocker::NativeHttp1Proxy]
    ));
}

#[test]
fn native_runtime_manifest_exports_service_listener_bindings() {
    let mut config = Config::default();
    config.server.listen = vec!["127.0.0.1:8080".to_owned()];
    config.admin.enabled = true;
    config.admin.listen = "127.0.0.1:9090".to_owned();
    config.admin.ops_socket.enabled = true;
    config.metrics.enabled = true;
    config.metrics.listen = "127.0.0.1:9091".to_owned();
    config.stream.enabled = true;
    config.stream.routes = vec![StreamRouteConfig {
        name: "tcp".to_owned(),
        listen: vec!["127.0.0.1:15432".to_owned()],
        upstream: Some("127.0.0.1:5432".to_owned()),
        ..StreamRouteConfig::default()
    }];
    config.udp.enabled = true;
    config.udp.routes = vec![UdpRouteConfig {
        name: "dns".to_owned(),
        mode: fluxheim_config::UdpRouteMode::DnsLoadBalance,
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

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let manifest = plan.native_runtime_manifest().expect("native manifest");
    let launch_plan = plan
        .native_runtime_launch_plan()
        .expect("native launch plan");

    assert_eq!(
        plan.runtime_adapter(),
        RuntimeAdapterKind::PingoraCompatibility
    );
    assert_eq!(
        plan.native_runtime_target_adapter(),
        RuntimeAdapterKind::NativeRuntime
    );
    assert_eq!(manifest.services().len(), 6);
    assert_eq!(launch_plan.manifest(), &manifest);
    assert_eq!(launch_plan.downstream_http1(), *plan.downstream_http1());
    assert_eq!(launch_plan.downstream_http2(), *plan.downstream_http2());
    assert_eq!(launch_plan.proxy_protocol(), plan.proxy_protocol());
    assert_eq!(launch_plan.listeners().len(), 5);
    assert!(
        launch_plan
            .listeners()
            .iter()
            .any(|listener| listener.service_kind() == ServiceKind::ProxyHttp
                && listener.listener_protocol() == ListenerProtocol::Http
                && listener.listener_addr().to_string() == "127.0.0.1:8080"
                && !listener.proxy_protocol_enabled())
    );
    assert!(
        launch_plan
            .listeners()
            .iter()
            .any(
                |listener| listener.service_kind() == ServiceKind::MetricsHttp
                    && listener.listener_protocol() == ListenerProtocol::MetricsHttp
                    && listener.listener_addr().to_string() == "127.0.0.1:9091"
            )
    );
    assert_eq!(
        manifest
            .service(ServiceKind::ProxyHttp)
            .expect("proxy service")
            .listeners()
            .iter()
            .map(|listener| listener.protocol())
            .collect::<Vec<_>>(),
        vec![ListenerProtocol::Http]
    );
    assert_eq!(
        manifest
            .service(ServiceKind::AdminControlPlane)
            .expect("admin service")
            .listeners()
            .iter()
            .map(|listener| listener.protocol())
            .collect::<Vec<_>>(),
        vec![ListenerProtocol::AdminHttp]
    );
    assert!(
        manifest
            .service(ServiceKind::AdminOpsSocket)
            .expect("ops service")
            .listeners()
            .is_empty()
    );
    assert_eq!(
        manifest
            .service(ServiceKind::MetricsHttp)
            .expect("metrics service")
            .listeners()
            .iter()
            .map(|listener| listener.protocol())
            .collect::<Vec<_>>(),
        vec![ListenerProtocol::MetricsHttp]
    );
    assert_eq!(
        manifest
            .service(ServiceKind::StreamProxy)
            .expect("stream service")
            .listeners()
            .iter()
            .map(|listener| listener.protocol())
            .collect::<Vec<_>>(),
        vec![ListenerProtocol::StreamTcp]
    );
    assert_eq!(
        manifest
            .service(ServiceKind::UdpProxy)
            .expect("udp service")
            .listeners()
            .iter()
            .map(|listener| listener.protocol())
            .collect::<Vec<_>>(),
        vec![ListenerProtocol::Udp]
    );

    let tsv = manifest.to_tsv();
    assert!(tsv.contains("native-runtime-manifest-service\tkind\tname\tlisteners\n"));
    assert!(tsv.contains(
        "native-runtime-manifest-service\tProxyHttp\tFluxheim HTTP Proxy\tHttp@127.0.0.1:8080\n"
    ));
    assert!(tsv.contains(
        "native-runtime-manifest-service\tAdminControlPlane\tFluxheim Admin Control Plane\tAdminHttp@127.0.0.1:9090\n"
    ));
    assert!(tsv.contains("native-runtime-manifest-background-task\tkind\tname\tcritical\n"));
    assert!(
        launch_plan
            .to_tsv()
            .contains("native-runtime-launch-plan\tready\t6\t5\t0\toff\n")
    );
    assert!(launch_plan.to_tsv().contains(
        "native-runtime-launch-listener\tProxyHttp\tFluxheim HTTP Proxy\tHttp\t127.0.0.1:8080\tfalse\n"
    ));
}

#[test]
fn native_runtime_cutover_summary_exports_stable_tsv() {
    let plan = ServerPlan::with_process(
        ProcessSpec::default(),
        Vec::new(),
        vec![
            ServiceSpec::new(
                "admin",
                ServiceKind::AdminControlPlane,
                &[ListenerProtocol::AdminHttp],
            ),
            ServiceSpec::new(
                "metrics",
                ServiceKind::MetricsHttp,
                &[ListenerProtocol::MetricsHttp],
            ),
            ServiceSpec::new("udp", ServiceKind::UdpProxy, &[ListenerProtocol::Udp]),
        ],
        Vec::new(),
    );

    assert_eq!(
        plan.native_runtime_cutover_summary().to_tsv(),
        "blocker\tdescription\ttarget_release\n\
         admin-control-plane\tnative admin control plane\t1.6.22\n\
         metrics-http\tnative metrics HTTP service\t1.6.22\n\
         udp-proxy\tnative UDP proxy service\t1.6.23\n"
    );
}

#[test]
fn native_runtime_cutover_targets_cover_every_blocker() {
    let targets = include_str!("../../../docs/native-runtime-cutover-targets.tsv");
    let mut rows = BTreeMap::new();
    for line in targets.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(fields.len(), 3, "malformed cutover target row: {line}");
        rows.insert(fields[0], (fields[1], fields[2]));
    }

    assert_eq!(rows.len(), NativeRuntimeCutoverBlocker::ALL.len());
    for blocker in NativeRuntimeCutoverBlocker::ALL {
        assert_eq!(
            rows.get(blocker.key()).copied(),
            Some((blocker.as_str(), blocker.target_release())),
            "missing or stale native runtime cutover target for {}",
            blocker.key()
        );
    }
}

#[test]
fn downstream_http1_policy_uses_bounded_native_defaults() {
    let policy = DownstreamHttp1Policy::default();

    assert_eq!(policy.max_body_bytes(), 64 * 1024 * 1024);
    assert_eq!(policy.max_head_bytes(), 64 * 1024);
    assert_eq!(policy.max_header_count(), 100);
    assert_eq!(policy.max_header_line_bytes(), 8 * 1024);
    assert_eq!(policy.max_start_line_bytes(), 8 * 1024);
    assert_eq!(policy.max_connections(), 1024);
    assert_eq!(
        policy.request_head_timeout(),
        std::time::Duration::from_secs(10)
    );
    assert_eq!(
        policy.tls_handshake_timeout(),
        std::time::Duration::from_secs(5)
    );
    assert_eq!(
        policy.request_body_timeout(),
        std::time::Duration::from_secs(30)
    );

    let plan = ServerPlan::new(Vec::new(), Vec::new());
    assert_eq!(plan.downstream_http1(), &policy);

    let limits = fluxheim_protocol::Http1HeadLimits::from(policy);
    assert_eq!(limits.max_head_bytes, policy.max_head_bytes());
    assert_eq!(limits.max_header_count, policy.max_header_count());
    assert_eq!(limits.max_header_line_bytes, policy.max_header_line_bytes());
    assert_eq!(limits.max_start_line_bytes, policy.max_start_line_bytes());
}

#[test]
fn downstream_http1_policy_preserves_tight_head_limit_invariant() {
    let policy = DownstreamHttp1Policy::from_server_limits(ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(16),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(8),
        max_request_headers: 4,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(16),
    });

    assert_eq!(policy.max_head_bytes(), 16);
    assert_eq!(policy.max_start_line_bytes(), 16);
    assert!(policy.max_start_line_bytes() <= policy.max_head_bytes());
}

#[test]
fn downstream_http1_policy_treats_zero_connection_cap_as_default() {
    let policy = DownstreamHttp1Policy::default().with_max_connections(0);

    assert_eq!(policy.max_connections(), DEFAULT_HTTP1_MAX_CONNECTIONS);
}

#[test]
fn server_plan_maps_configured_limits_to_downstream_http1_policy() {
    let mut config = Config::default();
    config.server.limits = ServerLimitsConfig {
        max_request_header_bytes: fluxheim_config::ByteSize::from_bytes(4096),
        max_uri_bytes: fluxheim_config::ByteSize::from_bytes(1024),
        max_request_headers: 32,
        max_request_body_bytes: fluxheim_config::ByteSize::from_bytes(2048),
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let policy = plan.downstream_http1();

    assert_eq!(policy.max_body_bytes(), 2048);
    assert_eq!(policy.max_head_bytes(), 4096);
    assert_eq!(policy.max_header_count(), 32);
    assert_eq!(policy.max_start_line_bytes(), 1056);
}

#[test]
fn server_plan_builds_certificate_reload_control_plan_when_enabled() {
    let mut config = Config::default();
    config.tls.acme.enabled = true;
    config.server.process.certificate_reload_sock =
        std::path::PathBuf::from("/run/fluxheim/test-cert-reload.sock");

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let control = plan
        .certificate_reload_control()
        .expect("certificate reload control plan");

    assert_eq!(
        control.socket_path(),
        std::path::Path::new("/run/fluxheim/test-cert-reload.sock")
    );
    assert_eq!(control.max_concurrent_requests(), 4);
    assert_eq!(control.read_timeout(), std::time::Duration::from_secs(5));

    config.tls.acme.renewal.reload_after_renewal = false;
    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.certificate_reload_control().is_none());
}

#[test]
fn server_runner_boundary_accepts_shutdown_view() {
    let plan = ServerPlan::new(
        Vec::new(),
        vec![BackgroundTaskSpec::new(
            "metrics-export",
            BackgroundTaskKind::MetricsExport,
        )],
    );
    let runner = RecordingRunner;

    assert!(
        runner
            .run(plan.clone(), &StaticShutdown(ShutdownState::running()))
            .is_ok()
    );
    assert_eq!(
        runner.run(
            plan,
            &StaticShutdown(ShutdownState::requested(ShutdownReason::Signal))
        ),
        Err("shutdown requested")
    );
}

#[test]
fn server_plan_from_config_collects_listener_inventory() {
    let mut config = Config::default();
    config.server.listen = vec!["127.0.0.1:8080".to_owned()];
    config.server.tls_listen = vec!["127.0.0.1:8443".to_owned()];
    config.server.proxy_protocol = DownstreamProxyProtocol::V2;
    config.admin.enabled = true;
    config.admin.listen = "127.0.0.1:8081".to_owned();
    config.metrics.enabled = true;
    config.metrics.listen = "127.0.0.1:9090".to_owned();
    config.stream.enabled = true;
    config.stream.routes = vec![StreamRouteConfig {
        name: "stream".to_owned(),
        listen: vec!["127.0.0.1:9443".to_owned()],
        upstreams: vec!["127.0.0.1:9444".to_owned()],
        ..StreamRouteConfig::default()
    }];
    config.udp.enabled = true;
    config.udp.routes = vec![UdpRouteConfig {
        name: "dns".to_owned(),
        mode: fluxheim_config::UdpRouteMode::DnsLoadBalance,
        listen: vec!["127.0.0.1:5353".to_owned()],
        upstream: None,
        upstreams: vec!["127.0.0.1:5354".to_owned()],
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

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert_eq!(
        plan.runtime_adapter(),
        RuntimeAdapterKind::PingoraCompatibility
    );
    let protocols = plan
        .listeners()
        .iter()
        .map(|listener| listener.protocol())
        .collect::<Vec<_>>();

    assert_eq!(
        protocols,
        vec![
            ListenerProtocol::Http,
            ListenerProtocol::Https,
            ListenerProtocol::AdminHttp,
            ListenerProtocol::MetricsHttp,
            ListenerProtocol::StreamTcp,
            ListenerProtocol::Udp,
        ]
    );
    assert!(
        plan.listeners()
            .iter()
            .take(2)
            .all(|listener| listener.proxy_protocol_enabled())
    );
    assert!(
        plan.listeners()
            .iter()
            .skip(2)
            .all(|listener| !listener.proxy_protocol_enabled())
    );
    assert_eq!(
        plan.listener_addrs(ListenerProtocol::Https),
        vec!["127.0.0.1:8443".to_owned()]
    );
    assert_eq!(
        plan.proxy_protocol(),
        &ProxyProtocolPolicy::V2 {
            trusted_sources: Vec::new()
        }
    );
    let services = plan
        .services()
        .iter()
        .map(|service| service.kind())
        .collect::<Vec<_>>();
    assert_eq!(
        services,
        vec![
            ServiceKind::ProxyHttp,
            ServiceKind::AdminControlPlane,
            ServiceKind::MetricsHttp,
            ServiceKind::StreamProxy,
            ServiceKind::UdpProxy,
        ]
    );
    assert!(plan.has_service(ServiceKind::ProxyHttp));
    assert!(!plan.has_service(ServiceKind::AdminOpsSocket));
    assert_eq!(
        plan.service(ServiceKind::ProxyHttp).map(ServiceSpec::name),
        Some("Fluxheim HTTP Proxy")
    );
    assert_eq!(
        plan.service(ServiceKind::ProxyHttp)
            .map(ServiceSpec::listener_protocols),
        Some(&[ListenerProtocol::Http, ListenerProtocol::Https][..])
    );
    assert_eq!(
        plan.service_listener_addrs(ServiceKind::ProxyHttp),
        vec!["127.0.0.1:8080".to_owned(), "127.0.0.1:8443".to_owned()]
    );
    assert_eq!(
        plan.service_listeners(ServiceKind::ProxyHttp)
            .map(|listener| listener.protocol())
            .collect::<Vec<_>>(),
        vec![ListenerProtocol::Http, ListenerProtocol::Https]
    );
    assert_eq!(
        plan.service_listener_addrs_for_protocol(ServiceKind::ProxyHttp, ListenerProtocol::Http),
        vec!["127.0.0.1:8080".to_owned()]
    );
    assert_eq!(
        plan.service_listeners_for_protocol(ServiceKind::ProxyHttp, ListenerProtocol::Http)
            .map(|listener| listener.addr().to_string())
            .collect::<Vec<_>>(),
        vec!["127.0.0.1:8080".to_owned()]
    );
    assert_eq!(
        plan.service_listener_addrs_for_protocol(ServiceKind::ProxyHttp, ListenerProtocol::Https),
        vec!["127.0.0.1:8443".to_owned()]
    );
    assert_eq!(
        plan.service_listener_addrs_for_protocol(ServiceKind::MetricsHttp, ListenerProtocol::Http),
        Vec::<String>::new()
    );
    assert_eq!(
        plan.service_listener_addrs(ServiceKind::AdminControlPlane),
        vec!["127.0.0.1:8081".to_owned()]
    );
    assert_eq!(
        plan.first_service_listener_addr(ServiceKind::AdminControlPlane),
        Some("127.0.0.1:8081".to_owned())
    );
    assert_eq!(
        plan.first_service_listener_addr(ServiceKind::LoadBalancerHealthChecks),
        None
    );
    assert_eq!(
        plan.service_listener_addrs(ServiceKind::MetricsHttp),
        vec!["127.0.0.1:9090".to_owned()]
    );
    assert_eq!(
        plan.service_listener_addrs(ServiceKind::LoadBalancerHealthChecks),
        Vec::<String>::new()
    );
    assert!(plan.native_admin_control_plane_ready());
    assert!(!plan.native_admin_ops_socket_ready());
    assert!(plan.native_metrics_http_ready());
}

#[test]
fn native_runtime_cutover_summary_treats_configured_admin_and_metrics_as_ready() {
    let mut config = Config::default();
    config.server.listen = vec!["127.0.0.1:8080".to_owned()];
    config.admin.enabled = true;
    config.admin.listen = "127.0.0.1:9090".to_owned();
    config.metrics.enabled = true;
    config.metrics.listen = "127.0.0.1:9091".to_owned();

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let blockers = plan.native_runtime_cutover_summary().blockers().to_vec();

    assert!(!blockers.contains(&NativeRuntimeCutoverBlocker::AdminControlPlane));
    assert!(!blockers.contains(&NativeRuntimeCutoverBlocker::MetricsHttp));
    assert!(!blockers.contains(&NativeRuntimeCutoverBlocker::NativeHttp2));
}

#[test]
fn native_runtime_cutover_summary_treats_configured_stream_and_udp_as_ready() {
    let mut config = Config::default();
    config.stream.enabled = true;
    config.stream.routes = vec![StreamRouteConfig {
        name: "tcp".to_owned(),
        listen: vec!["127.0.0.1:15432".to_owned()],
        upstream: Some("127.0.0.1:5432".to_owned()),
        ..StreamRouteConfig::default()
    }];
    config.udp.enabled = true;
    config.udp.routes = vec![UdpRouteConfig {
        name: "dns".to_owned(),
        mode: fluxheim_config::UdpRouteMode::DnsLoadBalance,
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

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let blockers = plan.native_runtime_cutover_summary().blockers().to_vec();

    assert!(plan.native_stream_proxy_ready());
    assert!(plan.native_udp_proxy_ready());
    assert!(!blockers.contains(&NativeRuntimeCutoverBlocker::StreamProxy));
    assert!(!blockers.contains(&NativeRuntimeCutoverBlocker::UdpProxy));
}

#[test]
fn server_plan_collects_admin_ops_socket_plan() {
    let mut config = Config::default();
    config.admin.enabled = true;
    config.admin.ops_socket.enabled = true;
    config.admin.ops_socket.path = std::path::PathBuf::from("/run/fluxheim/admin.sock");
    config.admin.ops_socket.mode = "0660".to_owned();

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let ops_socket = plan.admin_ops_socket().expect("ops socket plan");

    assert!(plan.has_service(ServiceKind::AdminOpsSocket));
    assert!(plan.native_admin_ops_socket_ready());
    assert_eq!(
        ops_socket.path(),
        std::path::Path::new("/run/fluxheim/admin.sock")
    );
    assert_eq!(ops_socket.mode_bits(), 0o660);
}

#[test]
fn server_plan_collects_load_balancer_service_intent() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert_eq!(
        plan.service(ServiceKind::LoadBalancerHealthChecks)
            .map(ServiceSpec::name),
        Some("Fluxheim Load Balancer Health Checks")
    );

    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.vhosts = vec![VhostConfig {
        name: "route-lb.test".to_owned(),
        hosts: vec!["route-lb.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: Default::default(),
        acme_challenge: Default::default(),
        redirect: Default::default(),
        proxy: Default::default(),
        cache: CacheConfig::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: vec![RouteConfig {
            name: "api".to_owned(),
            path_exact: None,
            path_prefix: Some("/api/".to_owned()),
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(fluxheim_config::ProxyConfig {
                upstreams_http_url: Some("https://discovery.example/upstreams".to_owned()),
                ..Default::default()
            }),
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: Default::default(),
        }],
    }];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.has_service(ServiceKind::LoadBalancerHealthChecks));
}

#[test]
fn server_plan_parses_proxy_protocol_trusted_sources() {
    let mut config = Config::default();
    config.server.proxy_protocol = DownstreamProxyProtocol::V1;
    config.server.trusted_proxies = vec!["127.0.0.1/32".to_owned(), "::1".to_owned()];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.proxy_protocol(),
        &ProxyProtocolPolicy::V1 {
            trusted_sources: vec![
                ProxyProtocolTrustedSource::Cidr {
                    network: "127.0.0.1".parse().unwrap(),
                    prefix: 32,
                },
                ProxyProtocolTrustedSource::Ip("::1".parse().unwrap()),
            ],
        }
    );
}

#[test]
fn server_plan_rejects_invalid_proxy_protocol_trusted_sources() {
    let mut config = Config::default();
    config.server.proxy_protocol = DownstreamProxyProtocol::V1;
    config.server.trusted_proxies = vec!["not-a-source".to_owned()];

    assert!(matches!(
        ServerPlan::from_config(&config),
        Err(ServerPlanError::InvalidProxyProtocolTrustedSource { .. })
    ));
}

#[test]
fn server_plan_from_config_rejects_invalid_listener_address() {
    let mut config = Config::default();
    config.server.listen = vec!["not a listener".to_owned()];

    assert_eq!(
        ServerPlan::from_config(&config),
        Err(ServerPlanError::InvalidListenerAddress {
            address: "not a listener".to_owned(),
        })
    );
}

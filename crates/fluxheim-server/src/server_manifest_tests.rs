use super::*;

use fluxheim_config::{Config, StreamRouteConfig, UdpRouteConfig};
use fluxheim_runtime::{BackgroundTaskKind, BackgroundTaskSpec};

#[test]
fn native_runtime_manifest_rejects_blocked_plans() {
    let mut config = Config::default();
    config.server.listen = vec!["127.0.0.1:8080".to_owned()];
    config.proxy.upstreams = vec!["127.0.0.1:3000".to_owned()];
    config.cache.enabled = true;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert_eq!(
        plan.native_runtime_target_adapter(),
        RuntimeAdapterKind::NativeRuntimeBlocked
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
    #[cfg(unix)]
    {
        config.admin.ops_socket.enabled = true;
    }
    config.metrics.enabled = true;
    config.metrics.listen = "127.0.0.1:9091".to_owned();
    config.metrics.token_file = Some("/run/secrets/fluxheim-metrics-token".into());
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
        RuntimeAdapterKind::NativeRuntimeBlocked
    );
    assert_eq!(
        plan.native_runtime_target_adapter(),
        RuntimeAdapterKind::NativeRuntime
    );
    let expected_service_count = if cfg!(unix) { 6 } else { 5 };
    assert_eq!(manifest.services().len(), expected_service_count);
    assert_eq!(launch_plan.manifest(), &manifest);
    assert_eq!(launch_plan.downstream_http1(), *plan.downstream_http1());
    assert_eq!(launch_plan.downstream_http2(), *plan.downstream_http2());
    assert_eq!(launch_plan.proxy_protocol(), plan.proxy_protocol());
    assert!(plan.native_metrics_http_auth_required());
    assert!(launch_plan.metrics_bearer_token_required());
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
    #[cfg(unix)]
    {
        assert!(
            manifest
                .service(ServiceKind::AdminOpsSocket)
                .expect("ops service")
                .listeners()
                .is_empty()
        );
    }
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
    assert!(launch_plan.to_tsv().contains(&format!(
        "native-runtime-launch-plan\tready\t{expected_service_count}\t5\t0\toff\n"
    )));
    assert!(
        launch_plan
            .to_tsv()
            .contains("native-runtime-launch-policy\tprotocol\tfield\tvalue\n")
    );
    assert!(
        launch_plan
            .to_tsv()
            .contains("native-runtime-launch-policy\thttp1\tmax_header_count\t100\n")
    );
    assert!(
        launch_plan
            .to_tsv()
            .contains("native-runtime-launch-policy\thttp2\tmax_concurrent_streams\t32\n")
    );
    assert!(launch_plan.to_tsv().contains(
        "native-runtime-launch-service-policy\tMetricsHttp\tbearer_token_required\ttrue\n"
    ));
    assert!(launch_plan.to_tsv().contains(
        "native-runtime-launch-listener\tProxyHttp\tFluxheim HTTP Proxy\tHttp\t127.0.0.1:8080\tfalse\n"
    ));
    assert!(
        launch_plan
            .to_tsv()
            .contains("native-runtime-launch-background-task\tkind\tname\tcritical\n")
    );
}

#[test]
fn native_runtime_launch_plan_rejects_duplicate_tcp_listener_bindings() {
    let mut config = Config::default();
    config.server.listen = vec!["127.0.0.1:8080".to_owned()];
    config.proxy.upstreams = vec!["127.0.0.1:3000".to_owned()];
    config.admin.enabled = true;
    config.admin.listen = "127.0.0.1:8080".to_owned();

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.native_runtime_cutover_summary().is_ready());
    assert_eq!(
        plan.native_runtime_target_adapter(),
        RuntimeAdapterKind::NativeRuntimeBlocked
    );
    assert!(matches!(
        plan.native_runtime_launch_plan(),
        Err(NativeRuntimeLaunchPlanError::DuplicateListener {
            transport: NativeRuntimeListenerTransport::Tcp,
            address,
            first_service: ServiceKind::ProxyHttp,
            second_service: ServiceKind::AdminControlPlane,
        }) if address.to_string() == "127.0.0.1:8080"
    ));
}

#[test]
fn native_runtime_launch_plan_rejects_duplicate_service_kinds() {
    let plan = ServerPlan::with_process(
        ProcessSpec::default(),
        Vec::new(),
        vec![
            ServiceSpec::new("Proxy one", ServiceKind::ProxyHttp, &[]),
            ServiceSpec::new("Proxy two", ServiceKind::ProxyHttp, &[]),
        ],
        Vec::new(),
    );

    assert!(plan.native_runtime_cutover_summary().is_ready());
    assert!(matches!(
        plan.native_runtime_launch_plan(),
        Err(NativeRuntimeLaunchPlanError::DuplicateService {
            kind: ServiceKind::ProxyHttp,
            first_name: "Proxy one",
            second_name: "Proxy two",
        })
    ));
}

#[test]
fn native_runtime_launch_plan_rejects_duplicate_background_task_kinds() {
    let task = BackgroundTaskKind::CacheMetrics;
    let plan = ServerPlan::new(
        Vec::new(),
        vec![
            BackgroundTaskSpec::new("Cache runtime metrics", task),
            BackgroundTaskSpec::new("Duplicate cache metrics", task),
        ],
    );

    assert!(plan.native_runtime_cutover_summary().is_ready());
    assert!(matches!(
        plan.native_runtime_launch_plan(),
        Err(NativeRuntimeLaunchPlanError::DuplicateBackgroundTask {
            kind: BackgroundTaskKind::CacheMetrics,
            first_name: "Cache runtime metrics",
            second_name: "Duplicate cache metrics",
        })
    ));
}

#[test]
fn native_runtime_launch_plan_allows_tcp_and_udp_on_same_address() {
    let mut config = Config::default();
    config.server.listen = Vec::new();
    config.stream.enabled = true;
    config.stream.routes = vec![StreamRouteConfig {
        name: "tcp".to_owned(),
        listen: vec!["127.0.0.1:15353".to_owned()],
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
    let launch_plan = plan
        .native_runtime_launch_plan()
        .expect("native launch plan");

    assert_eq!(
        plan.native_runtime_target_adapter(),
        RuntimeAdapterKind::NativeRuntime
    );
    assert_eq!(launch_plan.listeners().len(), 2);
    assert!(
        launch_plan
            .listeners()
            .iter()
            .any(
                |listener| listener.transport() == NativeRuntimeListenerTransport::Tcp
                    && listener.listener_addr().to_string() == "127.0.0.1:15353"
            )
    );
    assert!(
        launch_plan
            .listeners()
            .iter()
            .any(
                |listener| listener.transport() == NativeRuntimeListenerTransport::Udp
                    && listener.listener_addr().to_string() == "127.0.0.1:15353"
            )
    );
}

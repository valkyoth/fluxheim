use super::*;
use std::collections::BTreeMap;

use fluxheim_config::{Config, StreamRouteConfig, TlsAlpnPolicy, UdpRouteConfig};

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
fn native_runtime_cutover_summary_accepts_tls_http2_alpn_when_proxy_is_native_ready() {
    let mut config = Config::default();
    config.server.listen.clear();
    config.server.tls_listen = vec!["127.0.0.1:8443".to_owned()];
    config.tls.enabled = true;
    config.tls.alpn = TlsAlpnPolicy::Http1AndHttp2;
    config.proxy.upstreams = vec!["127.0.0.1:3000".to_owned()];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let blockers = plan.native_runtime_cutover_summary().blockers().to_vec();

    assert!(plan.downstream_http2_required());
    assert!(!blockers.contains(&NativeRuntimeCutoverBlocker::NativeHttp2));
    assert!(plan.native_runtime_cutover_summary().is_ready());
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

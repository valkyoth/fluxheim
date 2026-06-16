use super::*;
use fluxheim_config::{CacheConfig, RouteConfig, StreamRouteConfig, UdpRouteConfig, VhostConfig};
use fluxheim_runtime::{BackgroundTaskKind, ShutdownReason, ShutdownState};

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
fn server_plan_from_config_collects_background_task_inventory() {
    let mut config = Config::default();
    config.cache_purger.enabled = true;
    config.cache.enabled = true;
    config.metrics.enabled = true;
    config.metrics.otlp.enabled = true;
    config.tls.acme.enabled = true;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    let tasks = plan
        .background_tasks()
        .iter()
        .map(|task| task.kind())
        .collect::<Vec<_>>();

    assert_eq!(
        tasks,
        vec![
            BackgroundTaskKind::CacheStalePurge,
            BackgroundTaskKind::CacheMetrics,
            BackgroundTaskKind::MetricsExport,
            BackgroundTaskKind::AcmeRenewal,
            BackgroundTaskKind::CertificateReload,
        ]
    );
    assert!(plan.has_background_task(BackgroundTaskKind::CacheMetrics));
    assert!(!plan.has_background_task(BackgroundTaskKind::LoadBalancerRefresh));
}

#[test]
fn server_plan_schedules_cache_metrics_for_route_cache_policy() {
    let mut config = Config::default();
    config.cache.enabled = false;
    config.metrics.enabled = true;
    config.vhosts = vec![VhostConfig {
        name: "cache.test".to_owned(),
        hosts: vec!["cache.test".to_owned()],
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
            name: "asset".to_owned(),
            path_exact: Some("/asset.css".to_owned()),
            path_prefix: None,
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
            proxy: None,
            web: None,
            php: None,
            cache: Some(CacheConfig {
                enabled: true,
                ..CacheConfig::default()
            }),
            compression: None,
            headers: Default::default(),
        }],
    }];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.has_background_task(BackgroundTaskKind::CacheMetrics));
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

#[cfg(unix)]
#[test]
fn private_unix_listener_replaces_socket_and_rejects_files() {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    let test_dir = unique_temp_dir("fluxheim-server-private-listener");
    std::fs::create_dir_all(&test_dir).unwrap();
    let socket_path = test_dir.join("reload.sock");

    let first = replace_private_unix_listener(&socket_path).unwrap();
    let metadata = std::fs::symlink_metadata(&socket_path).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    let second = replace_private_unix_listener(&socket_path).unwrap();
    drop(first);
    drop(second);

    let file_path = test_dir.join("not-a-socket");
    std::fs::write(&file_path, b"nope").unwrap();
    let error = match replace_private_unix_listener(&file_path) {
        Ok(listener) => {
            drop(listener);
            panic!("non-socket path accepted")
        }
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);

    std::fs::remove_dir_all(&test_dir).unwrap();
}

#[cfg(unix)]
fn unique_temp_dir(name: &str) -> std::path::PathBuf {
    let unique = format!(
        "{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    std::env::temp_dir().join(unique)
}

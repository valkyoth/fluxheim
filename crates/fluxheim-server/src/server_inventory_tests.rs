use super::*;

use fluxheim_config::{
    CacheConfig, Config, DownstreamProxyProtocol, RouteConfig, StreamRouteConfig, UdpRouteConfig,
    VhostConfig,
};

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
        RuntimeAdapterKind::NativeRuntimeBlocked
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

#[cfg(unix)]
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

#[cfg(windows)]
#[test]
fn server_plan_marks_admin_ops_socket_unavailable() {
    let mut config = Config::default();
    config.admin.enabled = true;
    config.admin.ops_socket.enabled = true;

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    assert!(plan.has_service(ServiceKind::AdminOpsSocket));
    assert!(!plan.native_admin_ops_socket_ready());
    assert!(matches!(
        plan.native_runtime_manifest(),
        Err(NativeRuntimeManifestError::Blocked { blockers })
            if blockers == vec![NativeRuntimeCutoverBlocker::AdminOpsSocket]
    ));
}

#[test]
fn server_plan_collects_load_balancer_service_intent() {
    let mut config = Config::default();
    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    #[cfg(not(feature = "load-balancer"))]
    assert_eq!(plan.service(ServiceKind::LoadBalancerHealthChecks), None);
    #[cfg(feature = "load-balancer")]
    assert_eq!(
        plan.service(ServiceKind::LoadBalancerHealthChecks)
            .map(ServiceSpec::name),
        Some("Fluxheim Load Balancer Health Checks")
    );

    config.proxy.load_balance.health_check.enabled = false;
    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(!plan.has_service(ServiceKind::LoadBalancerHealthChecks));

    config.proxy.upstreams = vec!["127.0.0.1:3001".to_owned()];
    config.proxy.load_balance.health_check.enabled = true;
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
    #[cfg(not(feature = "load-balancer"))]
    assert!(!plan.has_service(ServiceKind::LoadBalancerHealthChecks));
    #[cfg(feature = "load-balancer")]
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

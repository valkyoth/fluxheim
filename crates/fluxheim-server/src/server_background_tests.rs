use super::*;
use fluxheim_config::{
    AdminSelfHealingConfig, CacheConfig, Config, ProxyConfig, RouteConfig, VhostConfig,
};
use fluxheim_runtime::{BackgroundTaskKind, BackgroundTaskSpec};

#[test]
fn server_plan_from_config_collects_background_task_inventory() {
    let mut config = Config::default();
    config.server.listen = Vec::new();
    config.cache_purger.enabled = true;
    config.cache.enabled = true;
    config.metrics.enabled = true;
    config.metrics.otlp.enabled = true;
    config.tls.acme.enabled = true;
    config.admin.enabled = true;
    config.admin.self_healing = AdminSelfHealingConfig {
        enabled: true,
        ..AdminSelfHealingConfig::default()
    };

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
            BackgroundTaskKind::RuntimeWatchdog,
        ]
    );
    assert!(plan.has_background_task(BackgroundTaskKind::CacheMetrics));
    assert!(!plan.has_background_task(BackgroundTaskKind::LoadBalancerRefresh));
    assert_eq!(
        plan.background_task(BackgroundTaskKind::AcmeRenewal)
            .map(BackgroundTaskSpec::name),
        Some("ACME renewal")
    );
    assert_eq!(
        plan.background_task(BackgroundTaskKind::RuntimeWatchdog)
            .map(BackgroundTaskSpec::name),
        Some("Fluxheim Self-Healing Watchdog")
    );

    let launch_plan = plan
        .native_runtime_launch_plan()
        .expect("background-task launch plan");
    let launch_tasks = launch_plan
        .background_tasks()
        .iter()
        .map(|task| (task.kind(), task.name(), task.is_critical()))
        .collect::<Vec<_>>();

    assert_eq!(
        launch_tasks,
        vec![
            (
                BackgroundTaskKind::CacheStalePurge,
                "Cache stale disk purger",
                false,
            ),
            (
                BackgroundTaskKind::CacheMetrics,
                "Cache runtime metrics",
                false,
            ),
            (
                BackgroundTaskKind::MetricsExport,
                "OTLP metrics export",
                false,
            ),
            (BackgroundTaskKind::AcmeRenewal, "ACME renewal", false),
            (
                BackgroundTaskKind::CertificateReload,
                "Certificate reload control socket",
                false,
            ),
            (
                BackgroundTaskKind::RuntimeWatchdog,
                "Fluxheim Self-Healing Watchdog",
                false,
            ),
        ]
    );
    assert!(launch_plan.to_tsv().contains(
        "native-runtime-launch-background-task\tMetricsExport\tOTLP metrics export\tfalse\n"
    ));
}

#[test]
fn server_plan_schedules_load_balancer_refresh_for_pool_config() {
    let mut config = Config::default();
    config.server.listen = Vec::new();
    config.proxy = ProxyConfig {
        upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
        ..ProxyConfig::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");

    #[cfg(not(feature = "load-balancer"))]
    {
        assert!(!plan.has_background_task(BackgroundTaskKind::LoadBalancerRefresh));
        assert!(
            !plan
                .native_runtime_manifest()
                .expect("native manifest")
                .to_tsv()
                .contains("native-runtime-manifest-background-task\tLoadBalancerRefresh")
        );
    }
    #[cfg(feature = "load-balancer")]
    {
        assert!(plan.has_background_task(BackgroundTaskKind::LoadBalancerRefresh));
        assert_eq!(
            plan.background_task(BackgroundTaskKind::LoadBalancerRefresh)
                .map(BackgroundTaskSpec::name),
            Some("Load balancer refresh")
        );

        let launch_plan = plan
            .native_runtime_launch_plan()
            .expect("load-balancer launch plan");
        assert!(launch_plan.to_tsv().contains(
        "native-runtime-launch-background-task\tLoadBalancerRefresh\tLoad balancer refresh\tfalse\n"
    ));
    }
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

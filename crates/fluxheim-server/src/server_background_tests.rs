use super::*;
use fluxheim_config::{AdminSelfHealingConfig, CacheConfig, Config, RouteConfig, VhostConfig};
use fluxheim_runtime::BackgroundTaskKind;

#[test]
fn server_plan_from_config_collects_background_task_inventory() {
    let mut config = Config::default();
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

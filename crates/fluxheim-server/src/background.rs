use fluxheim_config::{AcmeAutomationMode, Config};
use fluxheim_runtime::{BackgroundTaskKind, BackgroundTaskSpec};

pub(crate) fn background_task_specs_from_config(config: &Config) -> Vec<BackgroundTaskSpec> {
    let mut tasks = Vec::new();

    if crate::service::any_load_balancer_pool_configured(config) {
        tasks.push(BackgroundTaskSpec::new(
            "Load balancer refresh",
            BackgroundTaskKind::LoadBalancerRefresh,
        ));
    }
    if config.cache_purger.enabled {
        tasks.push(BackgroundTaskSpec::new(
            "Cache stale disk purger",
            BackgroundTaskKind::CacheStalePurge,
        ));
    }
    if config.metrics.enabled {
        if any_cache_policy_enabled(config) {
            tasks.push(BackgroundTaskSpec::new(
                "Cache runtime metrics",
                BackgroundTaskKind::CacheMetrics,
            ));
        }
        if config.metrics.otlp.enabled {
            tasks.push(BackgroundTaskSpec::new(
                "OTLP metrics export",
                BackgroundTaskKind::MetricsExport,
            ));
        }
    }
    if config.tls.acme.enabled
        && config.tls.acme.automation == AcmeAutomationMode::Background
        && config.tls.acme.renewal.enabled
    {
        tasks.push(BackgroundTaskSpec::new(
            "ACME renewal",
            BackgroundTaskKind::AcmeRenewal,
        ));
    }
    if config.tls.acme.enabled && config.tls.acme.renewal.reload_after_renewal {
        tasks.push(BackgroundTaskSpec::new(
            "Certificate reload control socket",
            BackgroundTaskKind::CertificateReload,
        ));
    }
    if config.admin.enabled && config.admin.self_healing.enabled {
        tasks.push(BackgroundTaskSpec::new(
            "Fluxheim Self-Healing Watchdog",
            BackgroundTaskKind::RuntimeWatchdog,
        ));
    }

    tasks
}

fn any_cache_policy_enabled(config: &Config) -> bool {
    config.cache.enabled
        || config
            .vhosts
            .iter()
            .any(|vhost| vhost.cache.enabled || vhost.routes.iter().any(route_cache_enabled))
}

fn route_cache_enabled(route: &fluxheim_config::RouteConfig) -> bool {
    route.cache.as_ref().is_some_and(|cache| cache.enabled)
}

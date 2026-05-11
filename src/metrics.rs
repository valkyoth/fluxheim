use std::sync::OnceLock;

use prometheus::{IntCounterVec, IntGauge, Opts};

static PROXY_REQUESTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CACHE_VHOSTS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_ENABLED_VHOSTS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_TIERED_VHOSTS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_CONFIGURED_ROUTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_POLICY_ROUTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_ENABLED_ROUTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_TIERED_ROUTES: OnceLock<IntGauge> = OnceLock::new();
static CACHE_MEMORY_TIERS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_DISK_TIERS: OnceLock<IntGauge> = OnceLock::new();
static CACHE_ACTIVITY_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static CACHE_ACTIVITY_SCOPE_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

pub fn enabled() -> bool {
    true
}

pub fn init() -> Result<(), prometheus::Error> {
    proxy_requests_total()?;
    cache_vhosts()?;
    cache_enabled_vhosts()?;
    cache_tiered_vhosts()?;
    cache_configured_routes()?;
    cache_policy_routes()?;
    cache_enabled_routes()?;
    cache_tiered_routes()?;
    cache_memory_tiers()?;
    cache_disk_tiers()?;
    cache_activity_total()?;
    cache_activity_scope_total()?;
    Ok(())
}

pub fn record_config(config: &crate::config::Config) {
    let stats = cache_config_stats(config);
    set_gauge(cache_vhosts(), stats.vhosts);
    set_gauge(cache_enabled_vhosts(), stats.enabled_vhosts);
    set_gauge(cache_tiered_vhosts(), stats.tiered_vhosts);
    set_gauge(cache_configured_routes(), stats.configured_routes);
    set_gauge(cache_policy_routes(), stats.policy_routes);
    set_gauge(cache_enabled_routes(), stats.enabled_routes);
    set_gauge(cache_tiered_routes(), stats.tiered_routes);
    set_gauge(cache_memory_tiers(), stats.memory_tiers);
    set_gauge(cache_disk_tiers(), stats.disk_tiers);
}

pub fn record_proxy_outcome(vhost: &str, method: &str, status: Option<u16>, error: bool) {
    match proxy_requests_total() {
        Ok(counter) => counter
            .with_label_values(&[
                vhost,
                method_bucket(method),
                outcome_class(status, error),
                status_class(status),
            ])
            .inc(),
        Err(error) => log::debug!("metrics counter unavailable: {error}"),
    }
}

pub fn record_cache_activity(tier: &str, event: &str) {
    match cache_activity_total() {
        Ok(counter) => counter
            .with_label_values(&[cache_tier_label(tier), cache_event_label(event)])
            .inc(),
        Err(error) => log::debug!("metrics counter unavailable: {error}"),
    }
}

pub fn record_cache_activity_scope(vhost: &str, route: Option<&str>, tier: &str, event: &str) {
    match cache_activity_scope_total() {
        Ok(counter) => counter
            .with_label_values(&[
                cache_scope_label(route),
                vhost,
                route.unwrap_or(""),
                cache_tier_label(tier),
                cache_event_label(event),
            ])
            .inc(),
        Err(error) => log::debug!("metrics scoped cache counter unavailable: {error}"),
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
struct CacheConfigStats {
    vhosts: u64,
    enabled_vhosts: u64,
    tiered_vhosts: u64,
    configured_routes: u64,
    policy_routes: u64,
    enabled_routes: u64,
    tiered_routes: u64,
    memory_tiers: u64,
    disk_tiers: u64,
}

fn cache_config_stats(config: &crate::config::Config) -> CacheConfigStats {
    let mut stats = CacheConfigStats {
        vhosts: config.vhosts.len() as u64,
        ..CacheConfigStats::default()
    };
    for vhost in &config.vhosts {
        accumulate_cache_policy(&vhost.cache, true, &mut stats);
        stats.configured_routes = stats
            .configured_routes
            .saturating_add(vhost.routes.len() as u64);
        for route in &vhost.routes {
            let Some(cache) = &route.cache else {
                continue;
            };
            stats.policy_routes = stats.policy_routes.saturating_add(1);
            accumulate_cache_policy(cache, false, &mut stats);
        }
    }
    stats
}

fn accumulate_cache_policy(
    cache: &crate::config::CacheConfig,
    vhost_scope: bool,
    stats: &mut CacheConfigStats,
) {
    if !cache.enabled {
        return;
    }
    if vhost_scope {
        stats.enabled_vhosts = stats.enabled_vhosts.saturating_add(1);
    } else {
        stats.enabled_routes = stats.enabled_routes.saturating_add(1);
    }
    if cache.memory.enabled {
        stats.memory_tiers = stats.memory_tiers.saturating_add(1);
    }
    if cache.disk.enabled {
        stats.disk_tiers = stats.disk_tiers.saturating_add(1);
    }
    if cache.memory.enabled && cache.disk.enabled {
        if vhost_scope {
            stats.tiered_vhosts = stats.tiered_vhosts.saturating_add(1);
        } else {
            stats.tiered_routes = stats.tiered_routes.saturating_add(1);
        }
    }
}

fn set_gauge(gauge: Result<&'static IntGauge, prometheus::Error>, value: u64) {
    match gauge {
        Ok(gauge) => gauge.set(u64_to_i64_saturating(value)),
        Err(error) => log::debug!("metrics gauge unavailable: {error}"),
    }
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn proxy_requests_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = PROXY_REQUESTS_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_proxy_requests_total",
            "Total Fluxheim proxy requests by virtual host, method bucket, outcome class, and status class.",
        ),
        &["vhost", "method", "class", "status_class"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = PROXY_REQUESTS_TOTAL.set(counter);
    PROXY_REQUESTS_TOTAL
        .get()
        .ok_or_else(|| prometheus::Error::Msg("metrics counter failed to initialize".to_owned()))
}

fn cache_vhosts() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_VHOSTS,
        "fluxheim_cache_vhosts",
        "Configured Fluxheim virtual hosts visible to cache metrics.",
    )
}

fn cache_enabled_vhosts() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_ENABLED_VHOSTS,
        "fluxheim_cache_enabled_vhosts",
        "Configured Fluxheim virtual hosts with cache enabled.",
    )
}

fn cache_tiered_vhosts() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_TIERED_VHOSTS,
        "fluxheim_cache_tiered_vhosts",
        "Configured Fluxheim virtual hosts using both memory and disk cache tiers.",
    )
}

fn cache_configured_routes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_CONFIGURED_ROUTES,
        "fluxheim_cache_configured_routes",
        "Configured Fluxheim routes visible to cache metrics.",
    )
}

fn cache_policy_routes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_POLICY_ROUTES,
        "fluxheim_cache_policy_routes",
        "Configured Fluxheim routes with an explicit cache policy.",
    )
}

fn cache_enabled_routes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_ENABLED_ROUTES,
        "fluxheim_cache_enabled_routes",
        "Configured Fluxheim routes with an explicit enabled cache policy.",
    )
}

fn cache_tiered_routes() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_TIERED_ROUTES,
        "fluxheim_cache_tiered_routes",
        "Configured Fluxheim routes using both memory and disk cache tiers.",
    )
}

fn cache_memory_tiers() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_MEMORY_TIERS,
        "fluxheim_cache_memory_tiers",
        "Configured Fluxheim cache memory tiers across vhosts and routes.",
    )
}

fn cache_disk_tiers() -> Result<&'static IntGauge, prometheus::Error> {
    int_gauge(
        &CACHE_DISK_TIERS,
        "fluxheim_cache_disk_tiers",
        "Configured Fluxheim cache disk tiers across vhosts and routes.",
    )
}

fn cache_activity_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = CACHE_ACTIVITY_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_cache_activity_total",
            "Fluxheim cache activity events by storage tier and bounded event name.",
        ),
        &["tier", "event"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_ACTIVITY_TOTAL.set(counter);
    CACHE_ACTIVITY_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg("fluxheim_cache_activity_total failed to initialize".to_owned())
    })
}

fn cache_activity_scope_total() -> Result<&'static IntCounterVec, prometheus::Error> {
    if let Some(counter) = CACHE_ACTIVITY_SCOPE_TOTAL.get() {
        return Ok(counter);
    }

    let counter = IntCounterVec::new(
        Opts::new(
            "fluxheim_cache_activity_scope_total",
            "Fluxheim cache activity events by configured vhost, optional route, storage tier, and bounded event name.",
        ),
        &["scope", "vhost", "route", "tier", "event"],
    )?;
    match prometheus::default_registry().register(Box::new(counter.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = CACHE_ACTIVITY_SCOPE_TOTAL.set(counter);
    CACHE_ACTIVITY_SCOPE_TOTAL.get().ok_or_else(|| {
        prometheus::Error::Msg(
            "fluxheim_cache_activity_scope_total failed to initialize".to_owned(),
        )
    })
}

fn int_gauge(
    cell: &'static OnceLock<IntGauge>,
    name: &'static str,
    help: &'static str,
) -> Result<&'static IntGauge, prometheus::Error> {
    if let Some(gauge) = cell.get() {
        return Ok(gauge);
    }

    let gauge = IntGauge::new(name, help)?;
    match prometheus::default_registry().register(Box::new(gauge.clone())) {
        Ok(()) => {}
        Err(prometheus::Error::AlreadyReg) => {}
        Err(error) => return Err(error),
    }

    let _ = cell.set(gauge);
    cell.get()
        .ok_or_else(|| prometheus::Error::Msg(format!("{name} failed to initialize")))
}

fn outcome_class(status: Option<u16>, error: bool) -> &'static str {
    if error {
        return "proxy_error";
    }

    match status {
        Some(100..=199) => "informational",
        Some(200..=299) => "success",
        Some(300..=399) => "redirect",
        Some(400..=499) => "client_error",
        Some(500..=599) => "server_error",
        Some(_) => "other",
        None => "unknown",
    }
}

fn method_bucket(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "CONNECT" => "CONNECT",
        _ => "OTHER",
    }
}

fn status_class(status: Option<u16>) -> &'static str {
    match status {
        Some(100..=199) => "1xx",
        Some(200..=299) => "2xx",
        Some(300..=399) => "3xx",
        Some(400..=499) => "4xx",
        Some(500..=599) => "5xx",
        Some(_) => "other",
        None => "unknown",
    }
}

fn cache_tier_label(tier: &str) -> &'static str {
    match tier {
        "memory" => "memory",
        "disk" => "disk",
        "policy" => "policy",
        _ => "other",
    }
}

fn cache_scope_label(route: Option<&str>) -> &'static str {
    if route.is_some() { "route" } else { "vhost" }
}

fn cache_event_label(event: &str) -> &'static str {
    match event {
        "hit" => "hit",
        "miss" => "miss",
        "store" => "store",
        "store_refusal" => "store_refusal",
        "eviction" => "eviction",
        "purge" => "purge",
        "pass" => "pass",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use prometheus::Encoder;

    use crate::config::{
        CacheConfig, CacheDiskConfig, CacheMemoryConfig, Config, ProxyConfig, RouteConfig,
        VhostAcmeChallengeConfig, VhostConfig, VhostHeaderPolicyConfig, VhostRedirectConfig,
        VhostTlsConfig, WebConfig,
    };

    use super::{
        cache_config_stats, init, method_bucket, record_cache_activity,
        record_cache_activity_scope, record_config, record_proxy_outcome, status_class,
    };

    #[test]
    fn records_proxy_outcome_counter() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_proxy_outcome("metrics-test", "GET", Some(502), false);

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_proxy_requests_total"));
        assert!(output.contains(r#"vhost="metrics-test""#));
        assert!(output.contains(r#"method="GET""#));
        assert!(output.contains(r#"class="server_error""#));
        assert!(output.contains(r#"status_class="5xx""#));
        assert!(!output.contains(r#"status="502""#));
    }

    #[test]
    fn records_cache_configuration_gauges() {
        let _guard = metrics_test_lock();
        init().unwrap();

        let config = cache_metrics_config();
        record_config(&config);

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("fluxheim_cache_vhosts 1"));
        assert!(output.contains("fluxheim_cache_enabled_vhosts 1"));
        assert!(output.contains("fluxheim_cache_tiered_vhosts 1"));
        assert!(output.contains("fluxheim_cache_configured_routes 2"));
        assert!(output.contains("fluxheim_cache_policy_routes 1"));
        assert!(output.contains("fluxheim_cache_enabled_routes 1"));
        assert!(output.contains("fluxheim_cache_tiered_routes 0"));
        assert!(output.contains("fluxheim_cache_memory_tiers 2"));
        assert!(output.contains("fluxheim_cache_disk_tiers 1"));
        assert!(!output.contains("cache_key"));
        assert!(!output.contains("path="));
    }

    #[test]
    fn records_cache_activity_counter_with_bounded_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_cache_activity("memory", "hit");
        record_cache_activity("disk", "store_refusal");
        record_cache_activity("policy", "pass");
        record_cache_activity("attacker-tier", "attacker-event");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(r#"fluxheim_cache_activity_total{event="hit",tier="memory"}"#));
        assert!(
            output.contains(r#"fluxheim_cache_activity_total{event="store_refusal",tier="disk"}"#)
        );
        assert!(output.contains(r#"fluxheim_cache_activity_total{event="pass",tier="policy"}"#));
        assert!(output.contains(r#"fluxheim_cache_activity_total{event="other",tier="other"}"#));
        assert!(!output.contains("attacker-tier"));
        assert!(!output.contains("attacker-event"));
    }

    #[test]
    fn records_cache_activity_scope_counter_with_configured_labels() {
        let _guard = metrics_test_lock();
        init().unwrap();

        record_cache_activity_scope("cached", None, "memory", "hit");
        record_cache_activity_scope("cached", Some("assets"), "disk", "purge");

        let metric_families = prometheus::gather();
        let mut output = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&metric_families, &mut output)
            .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(
            r#"fluxheim_cache_activity_scope_total{event="hit",route="",scope="vhost",tier="memory",vhost="cached"}"#
        ));
        assert!(output.contains(
            r#"fluxheim_cache_activity_scope_total{event="purge",route="assets",scope="route",tier="disk",vhost="cached"}"#
        ));
        assert!(!output.contains("cache_key"));
        assert!(!output.contains("path="));
    }

    #[test]
    fn cache_configuration_stats_are_cardinality_safe_aggregates() {
        let stats = cache_config_stats(&cache_metrics_config());
        assert_eq!(stats.vhosts, 1);
        assert_eq!(stats.enabled_vhosts, 1);
        assert_eq!(stats.tiered_vhosts, 1);
        assert_eq!(stats.configured_routes, 2);
        assert_eq!(stats.policy_routes, 1);
        assert_eq!(stats.enabled_routes, 1);
        assert_eq!(stats.tiered_routes, 0);
        assert_eq!(stats.memory_tiers, 2);
        assert_eq!(stats.disk_tiers, 1);
    }

    #[test]
    fn status_class_is_bounded() {
        assert_eq!(status_class(Some(101)), "1xx");
        assert_eq!(status_class(Some(204)), "2xx");
        assert_eq!(status_class(Some(304)), "3xx");
        assert_eq!(status_class(Some(404)), "4xx");
        assert_eq!(status_class(Some(503)), "5xx");
        assert_eq!(status_class(Some(799)), "other");
        assert_eq!(status_class(None), "unknown");
    }

    #[test]
    fn method_bucket_is_bounded() {
        assert_eq!(method_bucket("GET"), "GET");
        assert_eq!(method_bucket("POST"), "POST");
        assert_eq!(method_bucket("PROPFIND"), "OTHER");
        assert_eq!(method_bucket("attacker-controlled-method"), "OTHER");
    }

    fn cache_metrics_config() -> Config {
        Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                max_request_body_bytes: None,
                tls: VhostTlsConfig::default(),
                acme_challenge: VhostAcmeChallengeConfig::default(),
                redirect: VhostRedirectConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: CacheMemoryConfig {
                        enabled: true,
                        ..CacheMemoryConfig::default()
                    },
                    disk: CacheDiskConfig {
                        enabled: true,
                        ..CacheDiskConfig::default()
                    },
                    ..CacheConfig::default()
                },
                headers: VhostHeaderPolicyConfig::default(),
                web: WebConfig::default(),
                routes: vec![cached_route(), uncached_route()],
            }],
            ..Config::default()
        }
    }

    fn cached_route() -> RouteConfig {
        RouteConfig {
            name: "assets".to_owned(),
            path_exact: None,
            path_prefix: Some("/assets/".to_owned()),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            max_request_body_bytes: None,
            redirect: None,
            proxy: Some(ProxyConfig::default()),
            web: None,
            cache: Some(CacheConfig {
                enabled: true,
                memory: CacheMemoryConfig {
                    enabled: true,
                    ..CacheMemoryConfig::default()
                },
                ..CacheConfig::default()
            }),
            headers: VhostHeaderPolicyConfig::default(),
        }
    }

    fn uncached_route() -> RouteConfig {
        RouteConfig {
            name: "api".to_owned(),
            path_exact: None,
            path_prefix: Some("/api/".to_owned()),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            max_request_body_bytes: None,
            redirect: None,
            proxy: Some(ProxyConfig::default()),
            web: None,
            cache: None,
            headers: VhostHeaderPolicyConfig::default(),
        }
    }

    fn metrics_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }
}

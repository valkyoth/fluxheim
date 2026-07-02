use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use fluxheim_common::test_support::unique_temp_path;
use prometheus::Encoder;
use zeroize::Zeroizing;

use crate::config::{
    CacheConfig, CacheDiskConfig, CacheMemoryConfig, CachePeerConfig, CachePeerFillConfig, Config,
    ProxyConfig, RouteConfig, VhostAcmeChallengeConfig, VhostConfig, VhostHeaderPolicyConfig,
    VhostRedirectConfig, VhostTlsConfig, WebConfig,
};

#[cfg(all(feature = "proxy", feature = "cache"))]
use super::record_cache_runtime_totals;
use super::{
    NativeMetricsApp, init, method_bucket, metrics_background_service_from_config,
    native_metrics_app_from_config, native_prometheus_response, record_acme_event,
    record_admin_auth_event, record_cache_activity, record_cache_activity_scope,
    record_cache_operation_duration, record_cache_purge, record_cache_purger_duration,
    record_cache_purger_entries, record_cache_purger_run, record_config, record_edge_policy_event,
    record_host_routing_rejection, record_load_balancer_event, record_load_balancer_queue_wait,
    record_metrics_otlp_export, record_php_fpm_pool_event, record_php_fpm_pool_idle,
    record_php_fpm_retry, record_php_request, record_php_stderr, record_proxy_outcome,
    record_response_compression, record_stream_bytes, record_stream_connection,
    record_udp_datagram, record_udp_drop, set_udp_active_sessions, status_class,
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
fn records_response_compression_metrics_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_response_compression("compression-test", Some("assets"), "gzip");
    record_response_compression("compression-test", None, "br");
    record_response_compression("compression-test", Some("assets"), "attacker-encoding");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_response_compressions_total"));
    assert!(output.contains(r#"scope="route""#));
    assert!(output.contains(r#"scope="vhost""#));
    assert!(output.contains(r#"vhost="compression-test""#));
    assert!(output.contains(r#"route="assets""#));
    assert!(output.contains(r#"encoding="gzip""#));
    assert!(output.contains(r#"encoding="br""#));
    assert!(output.contains(r#"encoding="other""#));
    assert!(!output.contains("attacker-encoding"));
}

#[test]
fn records_stream_metrics_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_stream_connection("postgres", "completed");
    record_stream_connection("postgres", "timeout");
    record_stream_connection("postgres", "attacker-outcome");
    record_stream_bytes("postgres", "downstream_to_upstream", 128);
    record_stream_bytes("postgres", "upstream_to_downstream", 256);
    record_stream_bytes("postgres", "attacker-direction", 512);

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_stream_connections_total"));
    assert!(output.contains("fluxheim_stream_bytes_total"));
    assert!(output.contains(r#"route="postgres""#));
    assert!(output.contains(r#"outcome="completed""#));
    assert!(output.contains(r#"outcome="timeout""#));
    assert!(output.contains(r#"outcome="error""#));
    assert!(output.contains(r#"direction="downstream_to_upstream""#));
    assert!(output.contains(r#"direction="upstream_to_downstream""#));
    assert!(output.contains(r#"direction="other""#));
    assert!(!output.contains("attacker-outcome"));
    assert!(!output.contains("attacker-direction"));
}

#[test]
fn records_udp_metrics_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_udp_datagram("dns", "dns_load_balance", "downstream", "accepted");
    record_udp_datagram("dns", "syslog_forward", "upstream", "sent");
    record_udp_datagram(
        "dns",
        "attacker-mode",
        "attacker-direction",
        "attacker-outcome",
    );
    record_udp_drop("dns", "max_sessions");
    record_udp_drop("dns", "max_sessions_per_source");
    record_udp_drop("dns", "response_rate_limited");
    record_udp_drop("dns", "attacker-reason");
    set_udp_active_sessions("dns", 2);

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_udp_datagrams_total"));
    assert!(output.contains("fluxheim_udp_drops_total"));
    assert!(output.contains("fluxheim_udp_active_sessions"));
    assert!(output.contains(r#"route="dns""#));
    assert!(output.contains(r#"mode="dns_load_balance""#));
    assert!(output.contains(r#"mode="syslog_forward""#));
    assert!(output.contains(r#"mode="other""#));
    assert!(output.contains(r#"direction="downstream""#));
    assert!(output.contains(r#"direction="upstream""#));
    assert!(output.contains(r#"direction="other""#));
    assert!(output.contains(r#"outcome="accepted""#));
    assert!(output.contains(r#"outcome="sent""#));
    assert!(output.contains(r#"outcome="other""#));
    assert!(output.contains(r#"reason="max_sessions""#));
    assert!(output.contains(r#"reason="max_sessions_per_source""#));
    assert!(output.contains(r#"reason="response_rate_limited""#));
    assert!(output.contains(r#"reason="other""#));
    assert!(!output.contains("attacker-mode"));
    assert!(!output.contains("attacker-direction"));
    assert!(!output.contains("attacker-outcome"));
    assert!(!output.contains("attacker-reason"));
}

#[test]
fn records_edge_policy_metrics_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_edge_policy_event("edge-policy-test", Some("assets"), "access", "deny");
    record_edge_policy_event("edge-policy-test", Some("assets"), "auth_request", "allow");
    record_edge_policy_event("edge-policy-test", Some("assets"), "auth_request", "error");
    record_edge_policy_event("edge-policy-test", Some("assets"), "rate_limit", "delay");
    record_edge_policy_event("edge-policy-test", None, "concurrency", "reject");
    record_edge_policy_event("edge-policy-test", Some("assets"), "mirror", "success");
    record_edge_policy_event("edge-policy-test", Some("assets"), "mirror", "skipped");
    record_edge_policy_event(
        "edge-policy-test",
        Some("assets"),
        "attacker-policy",
        "attacker-outcome",
    );

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_edge_policy_events_total"));
    assert!(output.contains(r#"scope="route""#));
    assert!(output.contains(r#"scope="vhost""#));
    assert!(output.contains(r#"vhost="edge-policy-test""#));
    assert!(output.contains(r#"route="assets""#));
    assert!(output.contains(r#"policy="access""#));
    assert!(output.contains(r#"policy="auth_request""#));
    assert!(output.contains(r#"policy="rate_limit""#));
    assert!(output.contains(r#"policy="concurrency""#));
    assert!(output.contains(r#"policy="mirror""#));
    assert!(output.contains(r#"policy="other""#));
    assert!(output.contains(r#"outcome="deny""#));
    assert!(output.contains(r#"outcome="allow""#));
    assert!(output.contains(r#"outcome="delay""#));
    assert!(output.contains(r#"outcome="reject""#));
    assert!(output.contains(r#"outcome="error""#));
    assert!(output.contains(r#"outcome="success""#));
    assert!(output.contains(r#"outcome="skipped""#));
    assert!(output.contains(r#"outcome="other""#));
    assert!(!output.contains("attacker-policy"));
    assert!(!output.contains("attacker-outcome"));
}

#[test]
fn records_load_balancer_metrics_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "selected");
    record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "retry");
    record_load_balancer_event("lb-test", None, None, "unavailable");
    record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "success");
    record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "failure");
    record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "ejected");
    record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "member_state");
    record_load_balancer_event(
        "lb-test",
        Some("api"),
        Some("origin-a"),
        "member_state_invalid",
    );
    record_load_balancer_event(
        "lb-test",
        Some("api"),
        Some("origin-a"),
        "member_state_not_found",
    );
    record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "persistence_hit");
    record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "persistence_miss");
    record_load_balancer_event(
        "lb-test",
        Some("api"),
        Some("origin-a"),
        "persistence_fallback",
    );
    record_load_balancer_event(
        "lb-test",
        Some("api"),
        Some("origin-a"),
        "persistence_clear",
    );
    record_load_balancer_event(
        "lb-test",
        Some("api"),
        Some("origin-a"),
        "persistence_clear_invalid",
    );
    record_load_balancer_event(
        "lb-test",
        Some("api"),
        Some("origin-a"),
        "persistence_clear_not_found",
    );
    record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "queue_waited");
    record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "queue_full");
    record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "queue_timeout");
    record_load_balancer_event("lb-test", Some("api"), None, "discovery_success");
    record_load_balancer_event("lb-test", Some("api"), None, "discovery_failure");
    record_load_balancer_event("lb-test", Some("api"), Some("origin-a"), "attacker-event");
    record_load_balancer_event("lb-test", Some("api"), Some("http://raw:3000"), "selected");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_load_balancer_events_total"));
    assert!(output.contains(r#"scope="route""#));
    assert!(output.contains(r#"scope="vhost""#));
    assert!(output.contains(r#"vhost="lb-test""#));
    assert!(output.contains(r#"route="api""#));
    assert!(output.contains(r#"upstream="origin-a""#));
    assert!(output.contains(r#"upstream="other""#));
    assert!(output.contains(r#"event="selected""#));
    assert!(output.contains(r#"event="unavailable""#));
    assert!(output.contains(r#"event="retry""#));
    assert!(output.contains(r#"event="success""#));
    assert!(output.contains(r#"event="failure""#));
    assert!(output.contains(r#"event="ejected""#));
    assert!(output.contains(r#"event="member_state""#));
    assert!(output.contains(r#"event="member_state_invalid""#));
    assert!(output.contains(r#"event="member_state_not_found""#));
    assert!(output.contains(r#"event="persistence_hit""#));
    assert!(output.contains(r#"event="persistence_miss""#));
    assert!(output.contains(r#"event="persistence_fallback""#));
    assert!(output.contains(r#"event="persistence_clear""#));
    assert!(output.contains(r#"event="persistence_clear_invalid""#));
    assert!(output.contains(r#"event="persistence_clear_not_found""#));
    assert!(output.contains(r#"event="queue_waited""#));
    assert!(output.contains(r#"event="queue_full""#));
    assert!(output.contains(r#"event="queue_timeout""#));
    assert!(output.contains(r#"event="discovery_success""#));
    assert!(output.contains(r#"event="discovery_failure""#));
    assert!(output.contains(r#"event="other""#));
    assert!(!output.contains("attacker-event"));
    assert!(!output.contains("http://raw:3000"));
}

#[test]
fn records_load_balancer_queue_wait_histogram_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_load_balancer_queue_wait(
        "lb-queue-test",
        Some("api"),
        "queue_waited",
        Duration::from_millis(25),
    );
    record_load_balancer_queue_wait(
        "lb-queue-test",
        Some("api"),
        "queue_timeout",
        Duration::from_millis(250),
    );
    record_load_balancer_queue_wait(
        "lb-queue-test",
        Some("api"),
        "attacker-outcome",
        Duration::from_millis(5),
    );

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_load_balancer_queue_wait_seconds"));
    assert!(output.contains(r#"scope="route""#));
    assert!(output.contains(r#"vhost="lb-queue-test""#));
    assert!(output.contains(r#"route="api""#));
    assert!(output.contains(r#"outcome="waited""#));
    assert!(output.contains(r#"outcome="timeout""#));
    assert!(output.contains(r#"outcome="other""#));
    assert!(!output.contains("attacker-outcome"));
}

#[test]
fn records_php_request_metrics_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_php_request(
        "php-metrics-test",
        "POST",
        Some(502),
        "connect_timeout",
        Duration::from_millis(25),
    );
    record_php_request(
        "php-metrics-test",
        "GET",
        Some(200),
        "offload",
        Duration::from_millis(10),
    );
    record_php_request(
        "php-metrics-test",
        "BREW",
        Some(200),
        "attacker-outcome",
        Duration::from_millis(1),
    );

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_php_requests_total"));
    assert!(output.contains("fluxheim_php_request_duration_seconds"));
    assert!(output.contains(r#"vhost="php-metrics-test""#));
    assert!(output.contains(r#"method="POST""#));
    assert!(output.contains(r#"outcome="connect_timeout""#));
    assert!(output.contains(r#"outcome="offload""#));
    assert!(output.contains(r#"status_class="5xx""#));
    assert!(output.contains(r#"method="OTHER""#));
    assert!(output.contains(r#"outcome="other""#));
    assert!(!output.contains("attacker-outcome"));
}

#[test]
fn records_php_fpm_retry_counter_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_php_fpm_retry("php-retry-test", "connect_timeout");
    record_php_fpm_retry("php-retry-test", "connection_error");
    record_php_fpm_retry("php-retry-test", "attacker-reason");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_php_fpm_retries_total"));
    assert!(output.contains(r#"vhost="php-retry-test""#));
    assert!(output.contains(r#"reason="connect_timeout""#));
    assert!(output.contains(r#"reason="connection_error""#));
    assert!(output.contains(r#"reason="other""#));
    assert!(!output.contains("attacker-reason"));
}

#[test]
fn records_php_fpm_pool_metrics_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_php_fpm_pool_idle("php-pool-test", "default", 2);
    record_php_fpm_pool_event("php-pool-test", "default", "connect");
    record_php_fpm_pool_event("php-pool-test", "default", "reuse");
    record_php_fpm_pool_event("php-pool-test", "default", "attacker-event");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_php_fpm_pool_idle_connections"));
    assert!(output.contains("fluxheim_php_fpm_pool_events_total"));
    assert!(output.contains(r#"vhost="php-pool-test""#));
    assert!(output.contains(r#"pool="default""#));
    assert!(output.contains(r#"event="connect""#));
    assert!(output.contains(r#"event="reuse""#));
    assert!(output.contains(r#"event="other""#));
    assert!(!output.contains("attacker-event"));
}

#[test]
fn records_php_stderr_counter_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_php_stderr("php-stderr-test", "emitted");
    record_php_stderr("php-stderr-test", "truncated");
    record_php_stderr("php-stderr-test", "attacker-state");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_php_stderr_events_total"));
    assert!(output.contains(r#"vhost="php-stderr-test""#));
    assert!(output.contains(r#"state="emitted""#));
    assert!(output.contains(r#"state="truncated""#));
    assert!(output.contains(r#"state="other""#));
    assert!(!output.contains("attacker-state"));
}

#[test]
fn records_host_routing_rejection_counter() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_host_routing_rejection("missing");
    record_host_routing_rejection("attacker-reason");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_host_routing_rejections_total"));
    assert!(output.contains(r#"reason="missing""#));
    assert!(output.contains(r#"reason="other""#));
}

#[test]
fn records_admin_auth_event_counter() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_admin_auth_event("failure", "source");
    record_admin_auth_event("throttled", "global");
    record_admin_auth_event("attacker-event", "attacker-scope");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_admin_auth_events_total"));
    assert!(output.contains(r#"event="failure",scope="source""#));
    assert!(output.contains(r#"event="throttled",scope="global""#));
    assert!(output.contains(r#"event="other",scope="other""#));
}

#[test]
fn native_prometheus_response_exposes_text_metrics() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_admin_auth_event("failure", "source");
    let response = native_prometheus_response().unwrap();
    let output = String::from_utf8(response.body().to_vec()).unwrap();

    assert_eq!(response.status(), 200);
    assert!(
        response
            .headers()
            .iter()
            .any(|(name, value)| name == "content-type" && value.starts_with("text/plain"))
    );
    assert!(output.contains("fluxheim_admin_auth_events_total"));
    assert!(output.contains(r#"event="failure",scope="source""#));
}

#[test]
fn native_metrics_app_serves_prometheus_response() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_admin_auth_event("failure", "source");
    let request = fluxheim_server::NativeHttp1Request {
        method: "GET".to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: "/metrics".to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![("host".to_owned(), "metrics.test".to_owned())],
        body: Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let response = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &NativeMetricsApp::new(),
        request,
    ));
    let output = String::from_utf8(response.body().to_vec()).unwrap();

    assert_eq!(response.status(), 200);
    assert!(
        response
            .headers()
            .iter()
            .any(|(name, value)| name == "content-type" && value.starts_with("text/plain"))
    );
    assert!(output.contains("fluxheim_admin_auth_events_total"));
    assert!(output.contains(r#"event="failure",scope="source""#));
}

#[test]
fn native_metrics_app_restricts_method_and_target() {
    let _guard = metrics_test_lock();
    init().unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let app = NativeMetricsApp::new();

    let head = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_metrics_request("HEAD", "/metrics"),
    ));
    assert_eq!(head.status(), 200);
    assert_eq!(head.body(), b"");
    assert!(head.content_length().is_some_and(|length| length > 0));

    let absolute = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_metrics_request("GET", "http://metrics.test/metrics?format=prometheus"),
    ));
    assert_eq!(absolute.status(), 200);

    let wrong_path = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_metrics_request("GET", "/"),
    ));
    assert_eq!(wrong_path.status(), 404);

    let wrong_method = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_metrics_request("POST", "/metrics"),
    ));
    assert_eq!(wrong_method.status(), 405);
    assert!(
        wrong_method
            .headers()
            .iter()
            .any(|(name, value)| name == "allow" && value == "GET, HEAD")
    );
}

#[test]
fn native_metrics_app_can_require_bearer_token() {
    let _guard = metrics_test_lock();
    init().unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let app = NativeMetricsApp::new().with_bearer_token("metrics-secret");

    let missing = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_metrics_request("GET", "/metrics"),
    ));
    assert_eq!(missing.status(), 401);
    assert!(
        missing
            .headers()
            .iter()
            .any(|(name, value)| name == "www-authenticate" && value == "Bearer realm=\"metrics\"")
    );

    let mut wrong = native_metrics_request("GET", "/metrics");
    wrong
        .headers
        .push(("authorization".to_owned(), "Bearer wrong".to_owned()));
    let wrong = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(&app, wrong));
    assert_eq!(wrong.status(), 401);

    let mut authorized = native_metrics_request("GET", "/metrics");
    authorized.headers.push((
        "authorization".to_owned(),
        "Bearer metrics-secret".to_owned(),
    ));
    let authorized = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app, authorized,
    ));
    assert_eq!(authorized.status(), 200);
}

#[test]
fn native_metrics_app_loads_bearer_token_from_config_file() {
    let _guard = metrics_test_lock();
    init().unwrap();

    let token_file = unique_temp_path("native-metrics-token-file");
    std::fs::write(&token_file, "metrics-file-secret\n").unwrap();
    let config = crate::config::MetricsConfig {
        token_file: Some(token_file.clone()),
        ..crate::config::MetricsConfig::default()
    };
    let app = native_metrics_app_from_config(&config).unwrap();
    let _ = std::fs::remove_file(&token_file);
    let debug = format!("{app:?}");
    assert!(debug.contains("bearer_token_configured: true"));
    assert!(!debug.contains("metrics-file-secret"));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let missing = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app,
        native_metrics_request("GET", "/metrics"),
    ));
    assert_eq!(missing.status(), 401);

    let mut authorized = native_metrics_request("GET", "/metrics");
    authorized.headers.push((
        "authorization".to_owned(),
        "Bearer metrics-file-secret".to_owned(),
    ));
    let authorized = runtime.block_on(fluxheim_server::NativeHttp1Handler::handle(
        &app, authorized,
    ));
    assert_eq!(authorized.status(), 200);
}

#[test]
fn native_metrics_background_service_binds_and_stops() {
    let _guard = metrics_test_lock();
    init().unwrap();

    let config = crate::config::MetricsConfig {
        enabled: true,
        listen: "127.0.0.1:0".to_owned(),
        ..crate::config::MetricsConfig::default()
    };
    let service = metrics_background_service_from_config(&config)
        .unwrap()
        .expect("metrics service");
    let service = service.into_native();
    assert_eq!(service.name(), "Fluxheim metrics HTTP");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let supervisor = fluxheim_runtime::NativeBackgroundSupervisor::new();
        let (ready_tx, mut ready_rx) = tokio::sync::watch::channel(false);
        let handle = supervisor.spawn_service_with_ready(service, move || {
            let _ = ready_tx.send(true);
        });
        ready_rx.changed().await.unwrap();
        assert!(*ready_rx.borrow());
        assert!(supervisor.shutdown());
        handle.join().await.unwrap();
    });
}

#[test]
fn native_metrics_app_serves_prometheus_response_through_listener() {
    let _guard = metrics_test_lock();
    init().unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let response = runtime.block_on(async {
        record_admin_auth_event("failure", "source");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            fluxheim_server::serve_native_http1_listener(
                listener,
                fluxheim_server::DownstreamHttp1Policy::default(),
                std::sync::Arc::new(NativeMetricsApp::new()),
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await
            .unwrap();
        });

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut client,
            b"GET /metrics HTTP/1.1\r\nHost: metrics.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client, &mut response)
            .await
            .unwrap();
        let _ = shutdown_tx.send(());
        String::from_utf8(response).unwrap()
    });

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: text/plain"));
    assert!(response.contains("fluxheim_admin_auth_events_total"));
    assert!(response.contains(r#"event="failure",scope="source""#));
}

#[test]
fn native_metrics_listener_enforces_bearer_token() {
    let _guard = metrics_test_lock();
    init().unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (missing, authorized) = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            tokio::spawn(async move {
                fluxheim_server::serve_native_http1_listener(
                    listener,
                    fluxheim_server::DownstreamHttp1Policy::default(),
                    std::sync::Arc::new(
                        NativeMetricsApp::new().with_bearer_token("listener-secret"),
                    ),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
                .unwrap();
            });

            let missing = native_metrics_listener_request(
                addr,
                b"GET /metrics HTTP/1.1\r\nHost: metrics.test\r\nConnection: close\r\n\r\n",
            )
            .await;
            let authorized = native_metrics_listener_request(
                addr,
                b"GET /metrics HTTP/1.1\r\nHost: metrics.test\r\nAuthorization: Bearer listener-secret\r\nConnection: close\r\n\r\n",
            )
            .await;
            let _ = shutdown_tx.send(());
            (missing, authorized)
        });

    assert!(missing.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
    assert!(missing.contains("www-authenticate: Bearer realm=\"metrics\""));
    assert!(authorized.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(authorized.contains("content-type: text/plain"));
}

fn native_metrics_request(method: &str, target: &str) -> fluxheim_server::NativeHttp1Request {
    fluxheim_server::NativeHttp1Request {
        method: method.to_owned(),
        peer_addr: None,
        local_addr: None,
        effective_client_addr: None,
        downstream_tls: false,
        tls_identity: None,
        geo_context: None,
        target: target.to_owned(),
        version: fluxheim_protocol::Http1Version::Http11,
        headers: vec![("host".to_owned(), "metrics.test".to_owned())],
        body: Zeroizing::new(Vec::new()),
        trailers: Vec::new(),
    }
}

async fn native_metrics_listener_request(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut client, request)
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut client, &mut response)
        .await
        .unwrap();
    String::from_utf8(response).unwrap()
}

#[test]
fn records_acme_event_counter_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_acme_event("pending");
    record_acme_event("renewed");
    record_acme_event("failed");
    record_acme_event("reload_failed");
    record_acme_event("attacker-event");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains(r#"fluxheim_acme_events_total{event="pending"}"#));
    assert!(output.contains(r#"fluxheim_acme_events_total{event="renewed"}"#));
    assert!(output.contains(r#"fluxheim_acme_events_total{event="failed"}"#));
    assert!(output.contains(r#"fluxheim_acme_events_total{event="reload_failed"}"#));
    assert!(output.contains(r#"fluxheim_acme_events_total{event="other"}"#));
    assert!(!output.contains("attacker-event"));
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
    assert!(output.contains("fluxheim_cache_lock_enabled_policies 2"));
    assert!(output.contains("fluxheim_cache_lock_wait_timeout_max_seconds 30"));
    assert!(output.contains("fluxheim_cache_peer_fill_enabled_policies 2"));
    assert!(output.contains("fluxheim_cache_peer_fill_peers 3"));
    assert!(output.contains("fluxheim_cache_peer_fill_max_concurrent_requests 128"));
    assert!(!output.contains("cache_key"));
    assert!(!output.contains("path="));
}

#[test]
fn records_load_balancer_pool_configuration_gauge() {
    let _guard = metrics_test_lock();
    init().unwrap();

    let config = load_balancer_metrics_config();
    record_config(&config);

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(
        output.contains(r#"fluxheim_load_balancer_pools{scope="vhost",selection="least_time"} 1"#)
    );
    assert!(output.contains(
        r#"fluxheim_load_balancer_pools{scope="route",selection="consistent_uri_hash"} 1"#
    ));
    assert!(!output.contains("single-upstream"));
    assert!(!output.contains("app-a.example"));
    assert!(!output.contains("path="));
}

#[cfg(all(feature = "proxy", feature = "cache"))]
#[test]
fn records_cache_runtime_storage_pressure_gauges() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_cache_runtime_totals(&fluxheim_cache::CacheRuntimeTotals {
        memory_entries: 3,
        memory_weighted_size_bytes: 512,
        memory_max_size_bytes: 1024,
        memory_purge_index_entries: 4,
        disk_entries: 5,
        disk_size_bytes: 2048,
        disk_allocated_size_bytes: 3072,
        disk_free_size_bytes: 1024,
        disk_free_range_count: 2,
        disk_largest_free_range_bytes: 768,
        disk_bin_files: 3,
        disk_max_size_bytes: 4096,
        disk_purge_index_entries: 6,
        ..fluxheim_cache::CacheRuntimeTotals::default()
    });

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_cache_memory_entries 3"));
    assert!(output.contains("fluxheim_cache_memory_weighted_size_bytes 512"));
    assert!(output.contains("fluxheim_cache_memory_max_size_bytes 1024"));
    assert!(output.contains("fluxheim_cache_memory_fill_ratio_per_mille 500"));
    assert!(output.contains("fluxheim_cache_memory_purge_index_entries 4"));
    assert!(output.contains("fluxheim_cache_disk_entries 5"));
    assert!(output.contains("fluxheim_cache_disk_size_bytes 2048"));
    assert!(output.contains("fluxheim_cache_disk_allocated_size_bytes 3072"));
    assert!(output.contains("fluxheim_cache_disk_free_size_bytes 1024"));
    assert!(output.contains("fluxheim_cache_disk_free_range_count 2"));
    assert!(output.contains("fluxheim_cache_disk_largest_free_range_bytes 768"));
    assert!(output.contains("fluxheim_cache_disk_bin_files 3"));
    assert!(output.contains("fluxheim_cache_disk_max_size_bytes 4096"));
    assert!(output.contains("fluxheim_cache_disk_fill_ratio_per_mille 500"));
    assert!(output.contains("fluxheim_cache_disk_purge_index_entries 6"));
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
    record_cache_activity("policy", "bypass");
    record_cache_activity("policy", "stale");
    record_cache_activity("policy", "revalidate");
    record_cache_activity("policy", "peer_fill_hit");
    record_cache_activity("policy", "peer_fill_miss");
    record_cache_activity("policy", "peer_fill_error");
    record_cache_activity("policy", "peer_fill_fallback");
    record_cache_activity("policy", "peer_fill_fail_closed");
    record_cache_activity("attacker-tier", "attacker-event");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains(r#"fluxheim_cache_activity_total{event="hit",tier="memory"}"#));
    assert!(output.contains(r#"fluxheim_cache_activity_total{event="store_refusal",tier="disk"}"#));
    assert!(output.contains(r#"fluxheim_cache_activity_total{event="pass",tier="policy"}"#));
    assert!(output.contains(r#"fluxheim_cache_activity_total{event="bypass",tier="policy"}"#));
    assert!(output.contains(r#"fluxheim_cache_activity_total{event="stale",tier="policy"}"#));
    assert!(output.contains(r#"fluxheim_cache_activity_total{event="revalidate",tier="policy"}"#));
    assert!(
        output.contains(r#"fluxheim_cache_activity_total{event="peer_fill_hit",tier="policy"}"#)
    );
    assert!(
        output.contains(r#"fluxheim_cache_activity_total{event="peer_fill_miss",tier="policy"}"#)
    );
    assert!(
        output.contains(r#"fluxheim_cache_activity_total{event="peer_fill_error",tier="policy"}"#)
    );
    assert!(
        output
            .contains(r#"fluxheim_cache_activity_total{event="peer_fill_fallback",tier="policy"}"#)
    );
    assert!(
        output.contains(
            r#"fluxheim_cache_activity_total{event="peer_fill_fail_closed",tier="policy"}"#
        )
    );
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
    record_cache_activity_scope("cached", Some("assets"), "policy", "bypass");

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
    assert!(output.contains(
            r#"fluxheim_cache_activity_scope_total{event="bypass",route="assets",scope="route",tier="policy",vhost="cached"}"#
        ));
    assert!(!output.contains("cache_key"));
    assert!(!output.contains("path="));
}

#[test]
fn records_cache_operation_duration_histogram_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_cache_operation_duration(
        "cached",
        Some("assets"),
        "hit",
        "lookup",
        std::time::Duration::from_millis(12),
    );
    record_cache_operation_duration(
        "cached",
        None,
        "attacker-phase",
        "attacker-operation",
        std::time::Duration::from_millis(30),
    );

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_cache_operation_duration_seconds_bucket"));
    assert!(output.contains(r#"phase="hit""#));
    assert!(output.contains(r#"route="assets""#));
    assert!(output.contains(r#"scope="route""#));
    assert!(output.contains(r#"vhost="cached""#));
    assert!(output.contains(r#"operation="lookup""#));
    assert!(output.contains(r#"operation="other""#));
    assert!(output.contains(r#"phase="other""#));
    assert!(!output.contains("attacker-phase"));
    assert!(!output.contains("attacker-operation"));
    assert!(!output.contains("cache_key"));
}

#[test]
fn records_cache_purge_counter_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_cache_purge("prefix", "cached", Some("assets"), "soft");
    record_cache_purge("attacker-operation", "cached", None, "attacker-mode");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains(
            r#"fluxheim_cache_purges_total{mode="soft",operation="prefix",route="assets",scope="route",vhost="cached"}"#
        ));
    assert!(output.contains(
            r#"fluxheim_cache_purges_total{mode="other",operation="other",route="",scope="vhost",vhost="cached"}"#
        ));
    assert!(!output.contains("attacker-operation"));
    assert!(!output.contains("attacker-mode"));
    assert!(!output.contains("cache_key"));
    assert!(!output.contains("path="));
}

#[test]
fn records_cache_purger_counters_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_cache_purger_run("truncated");
    record_cache_purger_run("attacker-outcome");
    record_cache_purger_entries("scanned", 7);
    record_cache_purger_entries("purged", 2);
    record_cache_purger_entries("attacker-result", 3);
    record_cache_purger_duration("truncated", std::time::Duration::from_millis(25));
    record_cache_purger_duration("attacker-outcome", std::time::Duration::from_millis(50));

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains(r#"fluxheim_cache_purger_runs_total{outcome="truncated"}"#));
    assert!(output.contains(r#"fluxheim_cache_purger_runs_total{outcome="other"}"#));
    assert!(output.contains(r#"fluxheim_cache_purger_entries_total{result="scanned"} 7"#));
    assert!(output.contains(r#"fluxheim_cache_purger_entries_total{result="purged"} 2"#));
    assert!(output.contains(r#"fluxheim_cache_purger_entries_total{result="other"} 3"#));
    assert!(
        output.contains(r#"fluxheim_cache_purger_duration_seconds_bucket{outcome="truncated""#)
    );
    assert!(output.contains(r#"fluxheim_cache_purger_duration_seconds_bucket{outcome="other""#));
    assert!(!output.contains("attacker-outcome"));
    assert!(!output.contains("attacker-result"));
    assert!(!output.contains("cache_key"));
    assert!(!output.contains("path="));
}

#[test]
fn records_metrics_otlp_exporter_health_counter() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_metrics_otlp_export("success");
    record_metrics_otlp_export("failure");
    record_metrics_otlp_export("attacker-outcome");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains(r#"fluxheim_metrics_otlp_exports_total{outcome="success"}"#));
    assert!(output.contains(r#"fluxheim_metrics_otlp_exports_total{outcome="failure"}"#));
    assert!(output.contains(r#"fluxheim_metrics_otlp_exports_total{outcome="other"}"#));
    assert!(!output.contains("attacker-outcome"));
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
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
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
                peer_fill: CachePeerFillConfig {
                    enabled: true,
                    peers: vec![
                        CachePeerConfig {
                            name: "cache-a".to_owned(),
                            base_url: "https://cache-a.example:8443".to_owned(),
                        },
                        CachePeerConfig {
                            name: "cache-b".to_owned(),
                            base_url: "https://cache-b.example:8443".to_owned(),
                        },
                    ],
                    max_concurrent_requests: 128,
                    ..CachePeerFillConfig::default()
                },
                ..CacheConfig::default()
            },
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: vec![cached_route(), uncached_route()],
        }],
        ..Config::default()
    }
}

fn load_balancer_metrics_config() -> Config {
    Config {
        vhosts: vec![VhostConfig {
            name: "lb".to_owned(),
            hosts: vec!["lb.example".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            tls: VhostTlsConfig::default(),
            acme_challenge: VhostAcmeChallengeConfig::default(),
            redirect: VhostRedirectConfig::default(),
            proxy: ProxyConfig {
                upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
                load_balance: crate::config::LoadBalanceConfig {
                    selection: crate::config::LoadBalanceSelection::LeastTime,
                    ..crate::config::LoadBalanceConfig::default()
                },
                ..ProxyConfig::default()
            },
            cache: CacheConfig::default(),
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: vec![load_balancer_route(), single_upstream_route()],
        }],
        ..Config::default()
    }
}

fn load_balancer_route() -> RouteConfig {
    RouteConfig {
        name: "route-lb".to_owned(),
        path_exact: None,
        path_prefix: Some("/route-lb/".to_owned()),
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
        proxy: Some(ProxyConfig {
            upstreams: vec!["127.0.0.1:4001".to_owned(), "127.0.0.1:4002".to_owned()],
            load_balance: crate::config::LoadBalanceConfig {
                selection: crate::config::LoadBalanceSelection::ConsistentUriHash,
                ..crate::config::LoadBalanceConfig::default()
            },
            ..ProxyConfig::default()
        }),
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: VhostHeaderPolicyConfig::default(),
    }
}

fn single_upstream_route() -> RouteConfig {
    RouteConfig {
        name: "single-upstream".to_owned(),
        path_exact: None,
        path_prefix: Some("/single/".to_owned()),
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
        proxy: Some(ProxyConfig {
            upstreams: vec!["127.0.0.1:5001".to_owned()],
            ..ProxyConfig::default()
        }),
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: VhostHeaderPolicyConfig::default(),
    }
}

fn cached_route() -> RouteConfig {
    RouteConfig {
        name: "assets".to_owned(),
        path_exact: None,
        path_prefix: Some("/assets/".to_owned()),
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
        proxy: Some(ProxyConfig::default()),
        web: None,
        php: None,
        cache: Some(CacheConfig {
            enabled: true,
            memory: CacheMemoryConfig {
                enabled: true,
                ..CacheMemoryConfig::default()
            },
            peer_fill: CachePeerFillConfig {
                enabled: true,
                peers: vec![CachePeerConfig {
                    name: "route-cache".to_owned(),
                    base_url: "https://route-cache.example:8443".to_owned(),
                }],
                ..CachePeerFillConfig::default()
            },
            ..CacheConfig::default()
        }),
        compression: None,
        headers: VhostHeaderPolicyConfig::default(),
    }
}

fn uncached_route() -> RouteConfig {
    RouteConfig {
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
        proxy: Some(ProxyConfig::default()),
        web: None,
        php: None,
        cache: None,
        compression: None,
        headers: VhostHeaderPolicyConfig::default(),
    }
}

fn metrics_test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

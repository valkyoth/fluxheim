use super::*;
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

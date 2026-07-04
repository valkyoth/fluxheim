use super::*;
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
fn records_wasm_plugin_metrics_with_bounded_labels() {
    let _guard = metrics_test_lock();
    init().unwrap();

    record_wasm_plugin_execution(
        "access_gate",
        "access-decision",
        "deny",
        std::time::Duration::from_millis(7),
    );
    record_wasm_plugin_execution(
        "bad/plugin/name",
        "attacker-phase",
        "attacker-outcome",
        std::time::Duration::from_millis(3),
    );
    record_wasm_plugin_admission_rejection("access_gate", "access-decision", "global");
    record_wasm_plugin_admission_rejection("bad/plugin/name", "attacker-phase", "attacker-scope");

    let metric_families = prometheus::gather();
    let mut output = Vec::new();
    prometheus::TextEncoder::new()
        .encode(&metric_families, &mut output)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("fluxheim_wasm_plugin_executions_total"));
    assert!(output.contains("fluxheim_wasm_plugin_execution_seconds"));
    assert!(output.contains("fluxheim_wasm_plugin_admission_rejections_total"));
    assert!(output.contains(r#"plugin="access_gate""#));
    assert!(output.contains(r#"plugin="other""#));
    assert!(output.contains(r#"phase="access-decision""#));
    assert!(output.contains(r#"phase="other""#));
    assert!(output.contains(r#"outcome="deny""#));
    assert!(output.contains(r#"outcome="other""#));
    assert!(output.contains(r#"scope="global""#));
    assert!(output.contains(r#"scope="other""#));
    assert!(!output.contains("bad/plugin/name"));
    assert!(!output.contains("attacker-phase"));
    assert!(!output.contains("attacker-outcome"));
    assert!(!output.contains("attacker-scope"));
}

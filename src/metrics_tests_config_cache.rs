use super::*;
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

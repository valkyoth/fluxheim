pub fn cache_tier_label(tier: &str) -> &'static str {
    match tier {
        "memory" => "memory",
        "disk" => "disk",
        "policy" => "policy",
        _ => "other",
    }
}

pub fn cache_scope_label(route: Option<&str>) -> &'static str {
    if route.is_some() { "route" } else { "vhost" }
}

pub fn cache_event_label(event: &str) -> &'static str {
    match event {
        "hit" => "hit",
        "miss" => "miss",
        "store" => "store",
        "store_refusal" => "store_refusal",
        "eviction" => "eviction",
        "purge" => "purge",
        "pass" => "pass",
        "bypass" => "bypass",
        "stale" => "stale",
        "revalidate" => "revalidate",
        "peer_fill_hit" => "peer_fill_hit",
        "peer_fill_miss" => "peer_fill_miss",
        "peer_fill_error" => "peer_fill_error",
        "peer_fill_fallback" => "peer_fill_fallback",
        "peer_fill_fail_closed" => "peer_fill_fail_closed",
        "origin_protected" => "origin_protected",
        _ => "other",
    }
}

pub fn cache_phase_label(phase: &str) -> &'static str {
    match phase {
        "disabled" => "disabled",
        "uninitialized" => "uninitialized",
        "bypass" => "bypass",
        "key" => "key",
        "hit" => "hit",
        "miss" => "miss",
        "stale" => "stale",
        "stale-updating" => "stale-updating",
        "expired" => "expired",
        "revalidated" => "revalidated",
        "revalidated-nocache" => "revalidated-nocache",
        _ => "other",
    }
}

pub fn cache_operation_label(operation: &str) -> &'static str {
    match operation {
        "lookup" => "lookup",
        "lock_wait" => "lock_wait",
        _ => "other",
    }
}

pub fn cache_purge_operation_label(operation: &str) -> &'static str {
    match operation {
        "exact" => "exact",
        "bulk" => "bulk",
        "index" => "index",
        "prefix" => "prefix",
        "tag" => "tag",
        "stale" => "stale",
        "wildcard" => "wildcard",
        _ => "other",
    }
}

pub fn cache_purge_mode_label(mode: &str) -> &'static str {
    match mode {
        "normal" => "normal",
        "soft" => "soft",
        "dry_run" => "dry_run",
        _ => "other",
    }
}

pub fn cache_purger_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "skipped" => "skipped",
        "clean" => "clean",
        "purged" => "purged",
        "truncated" => "truncated",
        "error" => "error",
        _ => "other",
    }
}

pub fn cache_purger_entry_result_label(result: &str) -> &'static str {
    match result {
        "scanned" => "scanned",
        "stale" => "stale",
        "purged" => "purged",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_metric_labels_are_low_cardinality() {
        assert_eq!(cache_tier_label("memory"), "memory");
        assert_eq!(cache_tier_label("remote"), "other");
        assert_eq!(cache_scope_label(Some("route-a")), "route");
        assert_eq!(cache_scope_label(None), "vhost");
        assert_eq!(cache_event_label("peer_fill_hit"), "peer_fill_hit");
        assert_eq!(cache_event_label("origin_protected"), "origin_protected");
        assert_eq!(cache_event_label("custom"), "other");
        assert_eq!(
            cache_phase_label("revalidated-nocache"),
            "revalidated-nocache"
        );
        assert_eq!(cache_phase_label("custom"), "other");
        assert_eq!(cache_operation_label("lookup"), "lookup");
        assert_eq!(cache_operation_label("write"), "other");
        assert_eq!(cache_purge_operation_label("wildcard"), "wildcard");
        assert_eq!(cache_purge_operation_label("everything"), "other");
        assert_eq!(cache_purge_mode_label("dry_run"), "dry_run");
        assert_eq!(cache_purge_mode_label("force"), "other");
        assert_eq!(cache_purger_outcome_label("truncated"), "truncated");
        assert_eq!(cache_purger_outcome_label("partial"), "other");
        assert_eq!(cache_purger_entry_result_label("stale"), "stale");
        assert_eq!(cache_purger_entry_result_label("fresh"), "other");
    }
}

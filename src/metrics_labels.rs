pub(crate) fn outcome_class(status: Option<u16>, error: bool) -> &'static str {
    fluxheim_observability::metrics_outcome_class(status, error)
}

pub(crate) fn method_bucket(method: &str) -> &'static str {
    fluxheim_observability::metrics_method_bucket(method)
}

pub(crate) fn status_class(status: Option<u16>) -> &'static str {
    fluxheim_observability::metrics_status_class(status)
}

pub(crate) fn host_routing_reason_label(reason: &str) -> &'static str {
    fluxheim_observability::metrics_host_routing_reason_label(reason)
}

pub(crate) fn admin_auth_event_label(event: &str) -> &'static str {
    fluxheim_observability::metrics_admin_auth_event_label(event)
}

pub(crate) fn admin_auth_scope_label(scope: &str) -> &'static str {
    fluxheim_observability::metrics_admin_auth_scope_label(scope)
}

pub(crate) fn cache_tier_label(tier: &str) -> &'static str {
    fluxheim_cache::cache_tier_label(tier)
}

pub(crate) fn cache_scope_label(route: Option<&str>) -> &'static str {
    fluxheim_cache::cache_scope_label(route)
}

pub(crate) fn compression_encoding_label(encoding: &str) -> &'static str {
    fluxheim_observability::metrics_compression_encoding_label(encoding)
}

pub(crate) fn edge_policy_label(policy: &str) -> &'static str {
    fluxheim_observability::metrics_edge_policy_label(policy)
}

pub(crate) fn edge_policy_outcome_label(outcome: &str) -> &'static str {
    fluxheim_observability::metrics_edge_policy_outcome_label(outcome)
}

pub(crate) fn load_balancer_event_label(event: &str) -> &'static str {
    fluxheim_observability::metrics_load_balancer_event_label(event)
}

pub(crate) fn load_balancer_queue_outcome_label(outcome: &str) -> &'static str {
    fluxheim_observability::metrics_load_balancer_queue_outcome_label(outcome)
}

pub(crate) fn load_balancer_upstream_label(upstream: Option<&str>) -> &str {
    fluxheim_observability::metrics_load_balancer_upstream_label(upstream)
}

pub(crate) fn cache_event_label(event: &str) -> &'static str {
    fluxheim_cache::cache_event_label(event)
}

pub(crate) fn cache_phase_label(phase: &str) -> &'static str {
    fluxheim_cache::cache_phase_label(phase)
}

pub(crate) fn cache_operation_label(operation: &str) -> &'static str {
    fluxheim_cache::cache_operation_label(operation)
}

pub(crate) fn cache_purge_operation_label(operation: &str) -> &'static str {
    fluxheim_cache::cache_purge_operation_label(operation)
}

pub(crate) fn cache_purge_mode_label(mode: &str) -> &'static str {
    fluxheim_cache::cache_purge_mode_label(mode)
}

pub(crate) fn cache_purger_outcome_label(outcome: &str) -> &'static str {
    fluxheim_cache::cache_purger_outcome_label(outcome)
}

pub(crate) fn cache_purger_entry_result_label(result: &str) -> &'static str {
    fluxheim_cache::cache_purger_entry_result_label(result)
}

pub(crate) fn php_outcome_label(outcome: &str) -> &'static str {
    fluxheim_observability::metrics_php_outcome_label(outcome)
}

pub(crate) fn php_fpm_retry_reason_label(reason: &str) -> &'static str {
    fluxheim_observability::metrics_php_fpm_retry_reason_label(reason)
}

pub(crate) fn php_fpm_pool_event_label(event: &str) -> &'static str {
    fluxheim_observability::metrics_php_fpm_pool_event_label(event)
}

pub(crate) fn php_stderr_state_label(state: &str) -> &'static str {
    fluxheim_observability::metrics_php_stderr_state_label(state)
}

pub(crate) fn metrics_otlp_export_outcome_label(outcome: &str) -> &'static str {
    fluxheim_observability::metrics_otlp_export_outcome_label(outcome)
}

pub(crate) fn stream_outcome_label(outcome: &str) -> &'static str {
    fluxheim_observability::metrics_stream_outcome_label(outcome)
}

pub(crate) fn stream_direction_label(direction: &str) -> &'static str {
    fluxheim_observability::metrics_stream_direction_label(direction)
}

pub(crate) fn udp_mode_label(mode: &str) -> &'static str {
    match mode {
        "dns_load_balance" => "dns_load_balance",
        "syslog_forward" => "syslog_forward",
        "quic_pass_through" => "quic_pass_through",
        "game_proxy" => "game_proxy",
        _ => "other",
    }
}

pub(crate) fn udp_direction_label(direction: &str) -> &'static str {
    match direction {
        "downstream" => "downstream",
        "upstream" => "upstream",
        _ => "other",
    }
}

pub(crate) fn udp_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "accepted" => "accepted",
        "sent" => "sent",
        "error" => "error",
        _ => "other",
    }
}

pub(crate) fn udp_drop_reason_label(reason: &str) -> &'static str {
    match reason {
        "max_sessions" => "max_sessions",
        "max_sessions_per_source" => "max_sessions_per_source",
        "oversized_downstream" => "oversized_downstream",
        "oversized_upstream" => "oversized_upstream",
        "response_rate_limited" => "response_rate_limited",
        _ => "other",
    }
}

pub(crate) fn acme_event_label(event: &str) -> &'static str {
    fluxheim_observability::metrics_acme_event_label(event)
}

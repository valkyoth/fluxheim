use crate::access_log_status_class;

pub fn metrics_outcome_class(status: Option<u16>, error: bool) -> &'static str {
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

pub fn metrics_method_bucket(method: &str) -> &'static str {
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

pub fn metrics_status_class(status: Option<u16>) -> &'static str {
    status.map(access_log_status_class).unwrap_or("unknown")
}

pub fn metrics_ratio_per_mille(value: u64, max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    value.saturating_mul(1000) / max
}

pub fn metrics_u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub fn metrics_usize_to_i64_saturating(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub fn metrics_usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

pub fn metrics_host_routing_reason_label(reason: &str) -> &'static str {
    match reason {
        "missing" => "missing",
        "invalid" => "invalid",
        "unknown" => "unknown",
        _ => "other",
    }
}

pub fn metrics_admin_auth_event_label(event: &str) -> &'static str {
    match event {
        "failure" => "failure",
        "throttled" => "throttled",
        _ => "other",
    }
}

pub fn metrics_admin_auth_scope_label(scope: &str) -> &'static str {
    match scope {
        "source" => "source",
        "global" => "global",
        _ => "other",
    }
}

pub fn metrics_compression_encoding_label(encoding: &str) -> &'static str {
    match encoding {
        "gzip" => "gzip",
        "zstd" => "zstd",
        "br" => "br",
        _ => "other",
    }
}

pub fn metrics_edge_policy_label(policy: &str) -> &'static str {
    match policy {
        "access" => "access",
        "rate_limit" => "rate_limit",
        "concurrency" => "concurrency",
        "auth_request" => "auth_request",
        "mirror" => "mirror",
        _ => "other",
    }
}

pub fn metrics_edge_policy_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "deny" => "deny",
        "allow" => "allow",
        "delay" => "delay",
        "reject" => "reject",
        "error" => "error",
        "success" => "success",
        "skipped" => "skipped",
        _ => "other",
    }
}

pub fn metrics_load_balancer_event_label(event: &str) -> &'static str {
    match event {
        "selected" => "selected",
        "unavailable" => "unavailable",
        "retry" => "retry",
        "success" => "success",
        "failure" => "failure",
        "ejected" => "ejected",
        "member_state" => "member_state",
        "member_state_invalid" => "member_state_invalid",
        "member_state_not_found" => "member_state_not_found",
        "member_weight" => "member_weight",
        "member_weight_invalid" => "member_weight_invalid",
        "member_weight_not_found" => "member_weight_not_found",
        "persistence_hit" => "persistence_hit",
        "persistence_miss" => "persistence_miss",
        "persistence_fallback" => "persistence_fallback",
        "persistence_clear" => "persistence_clear",
        "persistence_clear_invalid" => "persistence_clear_invalid",
        "persistence_clear_not_found" => "persistence_clear_not_found",
        "queue_waited" => "queue_waited",
        "queue_full" => "queue_full",
        "queue_timeout" => "queue_timeout",
        "discovery_success" => "discovery_success",
        "discovery_failure" => "discovery_failure",
        _ => "other",
    }
}

pub fn metrics_load_balancer_queue_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "queue_waited" | "waited" => "waited",
        "queue_timeout" | "timeout" => "timeout",
        _ => "other",
    }
}

pub fn metrics_load_balancer_upstream_label(upstream: Option<&str>) -> &str {
    let Some(upstream) = upstream else {
        return "";
    };
    if upstream.is_empty()
        || upstream.len() > 64
        || upstream
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
    {
        return "other";
    }
    upstream
}

pub fn metrics_stream_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "completed" => "completed",
        "rejected" => "rejected",
        "connect_error" => "connect_error",
        "timeout" => "timeout",
        "shutdown" => "shutdown",
        _ => "error",
    }
}

pub fn metrics_stream_direction_label(direction: &str) -> &'static str {
    match direction {
        "downstream_to_upstream" => "downstream_to_upstream",
        "upstream_to_downstream" => "upstream_to_downstream",
        _ => "other",
    }
}

pub fn metrics_otlp_export_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "success" => "success",
        "failure" => "failure",
        _ => "other",
    }
}

pub fn metrics_php_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "declined" => "declined",
        "redirect" => "redirect",
        "forbidden" => "forbidden",
        "not_found" => "not_found",
        "fpm_error" => "fpm_error",
        "connect_timeout" => "connect_timeout",
        "request_timeout" => "request_timeout",
        "connection_error" => "connection_error",
        "configuration_error" => "configuration_error",
        "invalid_response" => "invalid_response",
        "intercepted" => "intercepted",
        "offload" => "offload",
        "offload_error" => "offload_error",
        "response" => "response",
        _ => "other",
    }
}

pub fn metrics_php_fpm_retry_reason_label(reason: &str) -> &'static str {
    match reason {
        "connect_timeout" => "connect_timeout",
        "connection_error" => "connection_error",
        _ => "other",
    }
}

pub fn metrics_php_fpm_pool_event_label(event: &str) -> &'static str {
    match event {
        "connect" => "connect",
        "reuse" => "reuse",
        "return" => "return",
        "drop_stale" => "drop_stale",
        "discard_full" => "discard_full",
        _ => "other",
    }
}

pub fn metrics_php_stderr_state_label(state: &str) -> &'static str {
    match state {
        "emitted" => "emitted",
        "truncated" => "truncated",
        _ => "other",
    }
}

pub fn metrics_udp_mode_label(mode: &str) -> &'static str {
    match mode {
        "dns_load_balance" => "dns_load_balance",
        "syslog_forward" => "syslog_forward",
        "quic_pass_through" => "quic_pass_through",
        "game_proxy" => "game_proxy",
        _ => "other",
    }
}

pub fn metrics_udp_direction_label(direction: &str) -> &'static str {
    match direction {
        "downstream" => "downstream",
        "upstream" => "upstream",
        _ => "other",
    }
}

pub fn metrics_udp_outcome_label(outcome: &str) -> &'static str {
    match outcome {
        "accepted" => "accepted",
        "sent" => "sent",
        "error" => "error",
        _ => "other",
    }
}

pub fn metrics_udp_drop_reason_label(reason: &str) -> &'static str {
    match reason {
        "max_sessions" => "max_sessions",
        "max_sessions_per_source" => "max_sessions_per_source",
        "oversized_downstream" => "oversized_downstream",
        "oversized_upstream" => "oversized_upstream",
        "response_rate_limited" => "response_rate_limited",
        _ => "other",
    }
}

pub fn metrics_acme_event_label(event: &str) -> &'static str {
    match event {
        "pending" => "pending",
        "renewed" => "renewed",
        "failed" => "failed",
        "reload_success" => "reload_success",
        "reload_failed" => "reload_failed",
        "reload_unavailable" => "reload_unavailable",
        "tick_error" => "tick_error",
        _ => "other",
    }
}

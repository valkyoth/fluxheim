#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

pub use access_log::{
    access_log_request_id_valid, access_log_status_class, count_access_log_response_body_bytes,
    generate_access_log_request_id, json_escape, unix_time_nanos,
};
pub use metrics_labels::{
    metrics_acme_event_label, metrics_admin_auth_event_label, metrics_admin_auth_scope_label,
    metrics_compression_encoding_label, metrics_edge_policy_label,
    metrics_edge_policy_outcome_label, metrics_host_routing_reason_label,
    metrics_load_balancer_event_label, metrics_load_balancer_queue_outcome_label,
    metrics_load_balancer_upstream_label, metrics_method_bucket, metrics_otlp_export_outcome_label,
    metrics_outcome_class, metrics_php_fpm_pool_event_label, metrics_php_fpm_retry_reason_label,
    metrics_php_outcome_label, metrics_php_stderr_state_label, metrics_ratio_per_mille,
    metrics_status_class, metrics_stream_direction_label, metrics_stream_outcome_label,
    metrics_u64_to_i64_saturating, metrics_usize_to_i64_saturating,
    metrics_usize_to_u64_saturating,
};
#[cfg(feature = "otlp-http")]
pub use otlp_http::OtlpHttpEndpoint;
#[cfg(feature = "otlp-http")]
pub use otlp_http::agent;
#[cfg(feature = "otlp-metrics")]
pub use otlp_metrics::build_metrics_payload;
#[cfg(feature = "otlp-trace")]
pub use otlp_trace::{TraceExporter, TraceSpan};
pub use trace_context::{TraceContext, context_from_traceparent};

mod access_log;
mod metrics_labels;
mod trace_context;

#[cfg(feature = "otlp-http")]
mod otlp_http;

#[cfg(feature = "otlp-trace")]
mod otlp_trace;

#[cfg(feature = "otlp-metrics")]
mod otlp_metrics;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_log_status_class_is_low_cardinality() {
        assert_eq!(access_log_status_class(101), "1xx");
        assert_eq!(access_log_status_class(204), "2xx");
        assert_eq!(access_log_status_class(304), "3xx");
        assert_eq!(access_log_status_class(404), "4xx");
        assert_eq!(access_log_status_class(503), "5xx");
        assert_eq!(access_log_status_class(700), "other");
    }

    #[test]
    fn json_escape_escapes_log_fields() {
        assert_eq!(json_escape("line\n\"x\""), "line\\n\\\"x\\\"");
        assert_eq!(json_escape("a\u{0001}b"), "a\\u0001b");
        assert_eq!(json_escape("tab\tcr\rslash\\"), "tab\\tcr\\rslash\\\\");
    }

    #[test]
    fn metrics_proxy_labels_are_low_cardinality() {
        assert_eq!(metrics_outcome_class(Some(204), false), "success");
        assert_eq!(metrics_outcome_class(Some(302), false), "redirect");
        assert_eq!(metrics_outcome_class(Some(404), false), "client_error");
        assert_eq!(metrics_outcome_class(Some(503), false), "server_error");
        assert_eq!(metrics_outcome_class(Some(700), false), "other");
        assert_eq!(metrics_outcome_class(None, false), "unknown");
        assert_eq!(metrics_outcome_class(Some(200), true), "proxy_error");

        assert_eq!(metrics_method_bucket("GET"), "GET");
        assert_eq!(metrics_method_bucket("POST"), "POST");
        assert_eq!(metrics_method_bucket("BREW"), "OTHER");

        assert_eq!(metrics_status_class(Some(204)), "2xx");
        assert_eq!(metrics_status_class(None), "unknown");
    }

    #[test]
    fn metrics_numeric_helpers_are_bounded() {
        assert_eq!(metrics_ratio_per_mille(5, 10), 500);
        assert_eq!(metrics_ratio_per_mille(5, 0), 0);
        assert_eq!(metrics_ratio_per_mille(u64::MAX, 1), u64::MAX);
        assert_eq!(metrics_u64_to_i64_saturating(42), 42);
        assert_eq!(metrics_u64_to_i64_saturating(u64::MAX), i64::MAX);
        assert_eq!(metrics_usize_to_i64_saturating(42), 42);
        assert_eq!(metrics_usize_to_u64_saturating(42), 42);
    }

    #[test]
    fn metrics_general_labels_are_low_cardinality() {
        assert_eq!(metrics_host_routing_reason_label("missing"), "missing");
        assert_eq!(metrics_host_routing_reason_label("attacker"), "other");
        assert_eq!(metrics_admin_auth_event_label("failure"), "failure");
        assert_eq!(metrics_admin_auth_event_label("success"), "other");
        assert_eq!(metrics_admin_auth_scope_label("source"), "source");
        assert_eq!(metrics_admin_auth_scope_label("route"), "other");
        assert_eq!(metrics_compression_encoding_label("br"), "br");
        assert_eq!(metrics_compression_encoding_label("identity"), "other");
        assert_eq!(metrics_edge_policy_label("rate_limit"), "rate_limit");
        assert_eq!(metrics_edge_policy_label("unknown-policy"), "other");
        assert_eq!(metrics_edge_policy_outcome_label("skipped"), "skipped");
        assert_eq!(metrics_edge_policy_outcome_label("bypassed"), "other");
        assert_eq!(
            metrics_load_balancer_event_label("member_weight_invalid"),
            "member_weight_invalid"
        );
        assert_eq!(metrics_load_balancer_event_label("custom"), "other");
        assert_eq!(
            metrics_load_balancer_queue_outcome_label("queue_waited"),
            "waited"
        );
        assert_eq!(metrics_load_balancer_queue_outcome_label("other"), "other");
        assert_eq!(
            metrics_load_balancer_upstream_label(Some("backend-a_1")),
            "backend-a_1"
        );
        assert_eq!(
            metrics_load_balancer_upstream_label(Some("bad value")),
            "other"
        );
        assert_eq!(metrics_load_balancer_upstream_label(None), "");
        assert_eq!(metrics_stream_outcome_label("completed"), "completed");
        assert_eq!(metrics_stream_outcome_label("strange"), "error");
        assert_eq!(
            metrics_stream_direction_label("upstream_to_downstream"),
            "upstream_to_downstream"
        );
        assert_eq!(metrics_stream_direction_label("sideways"), "other");
        assert_eq!(metrics_otlp_export_outcome_label("success"), "success");
        assert_eq!(metrics_otlp_export_outcome_label("delayed"), "other");
        assert_eq!(
            metrics_php_outcome_label("connect_timeout"),
            "connect_timeout"
        );
        assert_eq!(metrics_php_outcome_label("surprise"), "other");
        assert_eq!(
            metrics_php_fpm_retry_reason_label("connection_error"),
            "connection_error"
        );
        assert_eq!(metrics_php_fpm_retry_reason_label("status_500"), "other");
        assert_eq!(metrics_php_fpm_pool_event_label("drop_stale"), "drop_stale");
        assert_eq!(metrics_php_fpm_pool_event_label("custom"), "other");
        assert_eq!(metrics_php_stderr_state_label("truncated"), "truncated");
        assert_eq!(metrics_php_stderr_state_label("verbose"), "other");
        assert_eq!(metrics_acme_event_label("renewed"), "renewed");
        assert_eq!(metrics_acme_event_label("surprise"), "other");
    }

    #[test]
    fn access_log_request_id_validation_is_bounded_and_low_cardinality() {
        assert!(access_log_request_id_valid("edge-req_123.456"));
        assert!(!access_log_request_id_valid(""));
        assert!(!access_log_request_id_valid("bad value"));
        assert!(!access_log_request_id_valid("https://evil.example/reset"));
        assert!(!access_log_request_id_valid("admin@example.test"));
        assert!(!access_log_request_id_valid(&"a".repeat(129)));
    }

    #[test]
    fn generated_access_log_request_id_uses_safe_prefix() {
        let request_id =
            generate_access_log_request_id().expect("request id generation should work");

        assert!(request_id.starts_with("fh-"));
        assert_eq!(request_id.len(), 35);
        assert!(access_log_request_id_valid(&request_id));
    }

    #[test]
    fn access_log_response_body_byte_counter_saturates() {
        let mut seen = u64::MAX - 1;

        count_access_log_response_body_bytes(&mut seen, 4);

        assert_eq!(seen, u64::MAX);
    }
}

use std::time::{SystemTime, UNIX_EPOCH};

use http::HeaderMap;

use serde_json::{Value, json};

#[cfg(any(feature = "udp-proxy", feature = "wasm"))]
use crate::config::Config;

use fluxheim_config::reload::ReloadReason;

use fluxheim_snapshot::{ConfigSnapshot, PendingValidation};

use super::{AdminAuthThrottleScope, header_value};

#[cfg(feature = "metrics")]
pub(super) fn record_admin_auth_event(event: &str, scope: AdminAuthThrottleScope) {
    crate::metrics::record_admin_auth_event(event, scope.as_str());
}

#[cfg(not(feature = "metrics"))]
pub(super) fn record_admin_auth_event(_event: &str, _scope: AdminAuthThrottleScope) {}

#[cfg(all(feature = "metrics", feature = "load-balancer"))]
pub(super) fn record_load_balancer_event(
    vhost: &str,
    route: Option<&str>,
    member: Option<&str>,
    event: &str,
) {
    crate::metrics::record_load_balancer_event(vhost, route, member, event);
}

#[cfg(all(not(feature = "metrics"), feature = "load-balancer"))]
pub(super) fn record_load_balancer_event(
    _vhost: &str,
    _route: Option<&str>,
    _member: Option<&str>,
    _event: &str,
) {
}

#[cfg(all(feature = "load-balancer", not(feature = "privacy-mode")))]
pub(super) fn load_balancer_metric_member_label<'a>(
    alias: Option<&'a str>,
    member: &'a str,
) -> Option<&'a str> {
    alias.or(Some(member))
}

#[cfg(all(feature = "load-balancer", feature = "privacy-mode"))]
pub(super) fn load_balancer_metric_member_label<'a>(
    alias: Option<&'a str>,
    _member: &'a str,
) -> Option<&'a str> {
    alias
}

#[cfg(all(feature = "load-balancer", not(feature = "privacy-mode")))]
pub(super) fn load_balancer_display_member(alias: Option<&str>, member: &str) -> String {
    let _ = alias;
    member.to_owned()
}

#[cfg(all(feature = "load-balancer", feature = "privacy-mode"))]
pub(super) fn load_balancer_display_member(alias: Option<&str>, _member: &str) -> String {
    alias.unwrap_or("redacted").to_owned()
}

pub(super) fn snapshot_json(snapshot: &ConfigSnapshot, current: Option<&str>) -> Value {
    json!({
        "id": snapshot.id,
        "current": current == Some(snapshot.id.as_str()),
        "created_unix_secs": snapshot.metadata.created_unix_secs,
        "message": snapshot.metadata.message.as_deref(),
    })
}

pub(super) fn pending_validation_json(pending: Option<&PendingValidation>) -> Value {
    let Some(pending) = pending else {
        return Value::Null;
    };

    let metrics = pending.metrics();

    json!({
        "target_snapshot": pending.target_snapshot,
        "previous_snapshot": pending.previous_snapshot.as_deref(),
        "impact": pending.impact,
        "expires_unix_secs": pending.expires_unix_secs,
        "successful_checks": pending.successful_checks,
        "failed_checks": pending.failed_checks,
        "error_rate_per_mille": metrics.error_rate_per_mille(),
    })
}

pub(super) fn reload_reasons_json(reasons: &[ReloadReason]) -> Vec<String> {
    reasons.iter().map(ToString::to_string).collect()
}

#[cfg(feature = "udp-proxy")]
pub(super) fn udp_status_json(config: &Config) -> Value {
    let routes = config
        .udp
        .routes
        .iter()
        .map(|route| {
            json!({
                "name": route.name,
                "mode": udp_route_mode_label(route.mode),
                "listeners": route.listen,
                "listener_count": route.listen.len(),
                "upstream_count": route.upstreams().count(),
                "idle_timeout_secs": route.idle_timeout_secs,
                "response_timeout_secs": route.response_timeout_secs,
                "max_datagram_bytes": route.max_datagram_bytes,
                "max_sessions": route.max_sessions,
                "max_sessions_per_source": route.max_sessions_per_source,
                "max_responses_per_source_per_second": route.max_responses_per_source_per_second,
                "passive_health_enabled": route.passive_health_enabled,
                "passive_health_failures": route.passive_health_failures,
                "passive_health_ejection_secs": route.passive_health_ejection_secs,
                "public_exposure_warning": route.listen.iter().filter_map(|listen| listen.parse::<std::net::SocketAddr>().ok()).any(|listen| !listen.ip().is_loopback()),
            })
        })
        .collect::<Vec<_>>();
    let route_count = routes.len();

    json!({
        "enabled": config.udp.enabled,
        "routes": routes,
        "route_count": route_count,
    })
}

#[cfg(feature = "udp-proxy")]
pub(super) fn udp_route_mode_label(mode: crate::config::UdpRouteMode) -> &'static str {
    match mode {
        crate::config::UdpRouteMode::DnsLoadBalance => "dns-load-balance",
        crate::config::UdpRouteMode::SyslogForward => "syslog-forward",
        crate::config::UdpRouteMode::QuicPassThrough => "quic-pass-through",
        crate::config::UdpRouteMode::GameProxy => "game-proxy",
    }
}

#[cfg(feature = "wasm")]
pub(super) fn wasm_status_json(config: &Config) -> Value {
    let plugins = config
        .wasm
        .plugins
        .iter()
        .map(|plugin| {
            json!({
                "name": plugin.name,
                "path": plugin.path.display().to_string(),
                "expected_sha256": plugin.sha256.as_deref(),
                "abi": wasm_abi_label(plugin.abi),
                "host_call_namespace": wasm_host_call_namespace_label(plugin.host_call_namespace),
                "phases": plugin.phases.iter().map(|phase| wasm_phase_label(*phase)).collect::<Vec<_>>(),
                "fail_mode": wasm_fail_mode_label(plugin.fail_mode),
                "has_custom_limits": plugin.limits.is_some(),
                "has_custom_admission": plugin.admission.is_some(),
            })
        })
        .collect::<Vec<_>>();
    let attachments = config
        .wasm
        .attachments
        .iter()
        .map(|attachment| {
            json!({
                "plugin": attachment.plugin,
                "vhost": attachment.vhost,
                "route": attachment.route.as_deref(),
                "phases": attachment.phases.iter().map(|phase| wasm_phase_label(*phase)).collect::<Vec<_>>(),
                "priority": attachment.priority,
                "has_custom_admission": attachment.admission.is_some(),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "enabled": config.wasm.enabled,
        "allow_preview_abi": config.wasm.allow_preview_abi,
        "max_total_concurrent_executions": config.wasm.max_total_concurrent_executions,
        "plugin_root_count": config.wasm.plugin_roots.len(),
        "plugin_count": plugins.len(),
        "attachment_count": attachments.len(),
        "plugins": plugins,
        "attachments": attachments,
    })
}

#[cfg(feature = "wasm")]
fn wasm_abi_label(abi: crate::config::WasmPluginAbi) -> &'static str {
    match abi {
        crate::config::WasmPluginAbi::FluxheimPolicyV1 => "fluxheim-policy-v1",
        crate::config::WasmPluginAbi::ProxyWasmPreview => "proxy-wasm-preview",
        crate::config::WasmPluginAbi::WasiPreview => "wasi-preview",
    }
}

#[cfg(feature = "wasm")]
fn wasm_host_call_namespace_label(namespace: crate::config::WasmHostCallNamespace) -> &'static str {
    match namespace {
        crate::config::WasmHostCallNamespace::FluxheimPolicyV1 => "fluxheim-policy-v1",
    }
}

#[cfg(feature = "wasm")]
fn wasm_phase_label(phase: crate::config::WasmPluginPhase) -> &'static str {
    match phase {
        crate::config::WasmPluginPhase::RequestHeaders => "request-headers",
        crate::config::WasmPluginPhase::ResponseHeaders => "response-headers",
        crate::config::WasmPluginPhase::AccessDecision => "access-decision",
        crate::config::WasmPluginPhase::RouteDecision => "route-decision",
        crate::config::WasmPluginPhase::CacheLookup => "cache-lookup",
        crate::config::WasmPluginPhase::CacheStore => "cache-store",
    }
}

#[cfg(feature = "wasm")]
fn wasm_fail_mode_label(fail_mode: crate::config::WasmPluginFailMode) -> &'static str {
    match fail_mode {
        crate::config::WasmPluginFailMode::FailClosed => "fail-closed",
        crate::config::WasmPluginFailMode::FailOpen => "fail-open",
    }
}

pub(super) fn query_param<'a>(query: Option<&'a str>, name: &str) -> Option<&'a str> {
    query_params(query, name).into_iter().next()
}

pub(super) fn query_params<'a>(query: Option<&'a str>, name: &str) -> Vec<&'a str> {
    query
        .map(|query| {
            query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .filter_map(|(key, value)| if key == name { Some(value) } else { None })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(feature = "load-balancer")]
pub(super) fn parse_load_balancer_runtime_weight(
    value: &str,
) -> Result<Option<usize>, &'static str> {
    fluxheim_load_balancer::parse_load_balancer_runtime_weight(value)
}

#[cfg(feature = "load-balancer")]
pub(super) fn parse_load_balancer_member_weight(value: &str) -> Result<usize, &'static str> {
    fluxheim_load_balancer::parse_load_balancer_member_weight(value)
}

pub(super) fn cache_purge_paths<'a>(
    headers: &'a HeaderMap,
    query: Option<&'a str>,
) -> Vec<&'a str> {
    let query_paths = query_params(query, "path");
    if !query_paths.is_empty() {
        return query_paths;
    }

    header_value(headers, "x-fluxheim-cache-paths")
        .or_else(|| header_value(headers, "x-fluxheim-cache-path"))
        .map(|paths| paths.split(',').collect())
        .unwrap_or_default()
}

pub(super) fn truthy_header(headers: &HeaderMap, name: &str) -> bool {
    header_value(headers, name).is_some_and(truthy)
}

pub(super) fn truthy_query_param(query: Option<&str>, name: &str) -> bool {
    query_param(query, name).is_some_and(truthy)
}

pub(super) fn truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub(super) fn parse_health_signal(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "ok" | "success" | "successful" | "healthy" | "true" | "1" | "yes" | "on" => Some(true),
        "error" | "fail" | "failed" | "unhealthy" | "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub(super) fn unix_secs() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(error) => {
            log::error!(
                target: "fluxheim::security",
                "system clock is before Unix epoch; aborting because admin time-based controls are unreliable: {error}"
            );
            std::process::abort();
        }
    }
}

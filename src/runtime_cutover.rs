use std::error::Error;

use crate::config::Config;

pub(super) fn log_native_runtime_cutover_summary(server_plan: &fluxheim_server::ServerPlan) {
    let summary = server_plan.native_runtime_cutover_summary();
    if summary.is_ready() {
        log::info!("native runtime cutover preview: no blockers detected");
        return;
    }

    let blockers = summary
        .blockers()
        .iter()
        .map(|blocker| blocker.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    log::info!(
        "native runtime cutover preview: compatibility adapter retained; blockers={blockers}"
    );
}

pub(super) fn log_native_runtime_manifest_preview(server_plan: &fluxheim_server::ServerPlan) {
    if let Some(summary) = native_runtime_manifest_preview(server_plan) {
        log::info!("native runtime manifest preview: {summary}");
    }
}

pub(super) fn native_runtime_manifest_preview(
    server_plan: &fluxheim_server::ServerPlan,
) -> Option<String> {
    let manifest = server_plan.native_runtime_manifest().ok()?;
    let service_count = manifest.services().len();
    let listener_count: usize = manifest
        .services()
        .iter()
        .map(|service| service.listeners().len())
        .sum();
    let background_task_count = manifest.background_tasks().len();
    let services = manifest
        .services()
        .iter()
        .map(|service| {
            let listeners = service
                .listeners()
                .iter()
                .map(|listener| format!("{:?}@{}", listener.protocol(), listener.addr()))
                .collect::<Vec<_>>()
                .join(",");
            format!("{:?}=[{}]", service.kind(), listeners)
        })
        .collect::<Vec<_>>()
        .join("; ");
    Some(format!(
        "services={service_count} listeners={listener_count} background_tasks={background_task_count} graph={services}"
    ))
}

pub(super) fn log_native_http1_proxy_cutover_summary(server_plan: &fluxheim_server::ServerPlan) {
    let summary = server_plan.native_http1_proxy_cutover_summary();
    match summary.status() {
        fluxheim_server::NativeHttp1ProxyCutoverStatus::NoProxy => {}
        fluxheim_server::NativeHttp1ProxyCutoverStatus::NativeReady => {
            log::info!(
                "native HTTP/1 proxy cutover ready for {} configured proxy path(s)",
                summary.total()
            );
        }
        fluxheim_server::NativeHttp1ProxyCutoverStatus::Mixed => {
            log::info!(
                "native HTTP/1 proxy cutover mixed: {} eligible, {} compatibility-only",
                summary.eligible(),
                summary.unsupported()
            );
        }
        fluxheim_server::NativeHttp1ProxyCutoverStatus::CompatibilityRequired => {
            log::info!(
                "native HTTP/1 proxy cutover not ready: {} configured proxy path(s) require compatibility adapter",
                summary.unsupported()
            );
        }
    }

    for candidate in server_plan.native_http1_proxy_candidates() {
        if let Some(reason) = candidate.unsupported_reason() {
            log::info!(
                "native HTTP/1 proxy compatibility path retained for {}: {}",
                candidate.scope(),
                reason
            );
        }
    }
}

pub(super) fn validate_native_http1_router_factory(
    config: &Config,
    server_plan: &fluxheim_server::ServerPlan,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !server_plan.has_service(fluxheim_server::ServiceKind::ProxyHttp) {
        return Ok(());
    }
    match server_plan.native_http1_proxy_cutover_summary().status() {
        fluxheim_server::NativeHttp1ProxyCutoverStatus::NoProxy
        | fluxheim_server::NativeHttp1ProxyCutoverStatus::NativeReady => {}
        fluxheim_server::NativeHttp1ProxyCutoverStatus::Mixed
        | fluxheim_server::NativeHttp1ProxyCutoverStatus::CompatibilityRequired => {
            return Ok(());
        }
    }

    let _router = fluxheim_server::NativeHttp1HostRouter::from_config(
        config,
        *server_plan.downstream_http1(),
        server_plan.process().upstream_keepalive_pool_size(),
    )?;
    log::debug!("native HTTP/1 host-router factory validated for proxy service");
    Ok(())
}

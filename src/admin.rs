use std::error::Error;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::{HeaderMap, StatusCode};
#[cfg(feature = "load-balancer")]
use serde_json::Value;
use serde_json::json;

use crate::config::{AdminHealthResponseMode, Config};
use crate::native_proxy::FluxProxy;
use fluxheim_config::reload::classify_reload;
#[cfg(feature = "load-balancer")]
use fluxheim_load_balancer::{
    LoadBalancerMemberAddRequest, LoadBalancerMemberRemoveRequest,
    LoadBalancerMemberSetMutationResult, LoadBalancerMemberStateRequest,
    LoadBalancerMemberUpdateRequest, LoadBalancerMemberWeightRequest,
    LoadBalancerPersistenceClearRequest, LoadBalancerRuntimeBackendState,
};
use fluxheim_snapshot::{
    ConfigSnapshot, PendingValidation, SnapshotApplyMode, SnapshotError,
    SnapshotHealthSignalOutcome, SnapshotRuntimeState, SnapshotStore,
};

#[cfg(feature = "cache")]
mod cache_helpers;
#[cfg(feature = "cache")]
use cache_helpers::*;
mod cache_purge_exact;
mod cache_purge_fallbacks;
mod cache_purge_indexed;
mod cache_status_endpoints;
mod security;
use security::*;
mod response_helpers;
use response_helpers::*;
mod misc_helpers;
use misc_helpers::*;
mod load_balancer_mutations;
mod load_balancer_status;
mod request_router;

const MAX_ADMIN_PATH_BYTES: usize = 2048;
const MAX_ADMIN_QUERY_BYTES: usize = 16 * 1024;
const MAX_ADMIN_JSON_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_ADMIN_ERROR_MESSAGE_CHARS: usize = 4096;
#[cfg(feature = "cache")]
const MAX_CACHE_PURGE_HOST_BYTES: usize = 255;
#[cfg(feature = "cache")]
const MAX_CACHE_PURGE_METHOD_BYTES: usize = 32;
#[cfg(feature = "cache")]
const MAX_CACHE_PURGE_PATH_BYTES: usize = 4096;
#[cfg(feature = "cache")]
const MAX_CACHE_PURGE_QUERY_BYTES: usize = 8192;
#[cfg(feature = "cache")]
const MAX_CACHE_PURGE_TAG_BYTES: usize = 128;
#[cfg(feature = "cache")]
const MAX_CACHE_PURGE_BULK_PATHS: usize = 256;
#[cfg(feature = "cache")]
const DEFAULT_CACHE_INDEXED_PURGE_LIMIT: usize = 1024;
#[cfg(feature = "cache")]
const MAX_CACHE_INDEXED_PURGE_LIMIT: usize = 10_000;
#[cfg(feature = "cache")]
const DEFAULT_CACHE_INDEXED_PURGE_BATCHES: usize = 1;
#[cfg(feature = "cache")]
const MAX_CACHE_INDEXED_PURGE_BATCHES: usize = 64;

#[derive(Clone)]
pub struct AdminApp {
    token: AdminToken,
    client_certificate: AdminClientCertificatePolicy,
    store: SnapshotStore,
    current_config: Arc<ArcSwap<Config>>,
    proxy: FluxProxy,
    health_path: String,
    health_unauthenticated: bool,
    health_response: AdminHealthResponseMode,
    self_healing_enabled: bool,
    validation_window_secs: u64,
    min_successful_checks: usize,
    max_error_rate_per_mille: u16,
    state: Arc<Mutex<SnapshotRuntimeState>>,
    auth_throttle: AdminAuthThrottle,
}

pub(crate) struct NativeAdminServices {
    pub(crate) control_plane: AdminApp,
    #[cfg(unix)]
    pub(crate) ops_socket: Option<AdminOpsApp>,
    pub(crate) watchdog: Option<crate::background::FluxBackgroundService<AdminApp>>,
}

pub(crate) fn native_admin_services_from_config(
    config: &Config,
    server_plan: &fluxheim_server::ServerPlan,
    #[cfg(feature = "load-balancer")] load_balancer_admin_pools: Vec<
        fluxheim_server::NativeLoadBalancerAdminPool,
    >,
) -> Result<Option<NativeAdminServices>, Box<dyn Error + Send + Sync>> {
    if !config.admin.enabled {
        return Ok(None);
    }
    if server_plan
        .service(fluxheim_server::ServiceKind::AdminControlPlane)
        .is_none()
    {
        return Err("admin.enabled requires an admin service in the server plan".into());
    }

    let app = AdminApp::from_config(
        config,
        FluxProxy::from_config_with_native_load_balancers(
            config,
            #[cfg(feature = "load-balancer")]
            load_balancer_admin_pools,
        )?,
    )?;
    let watchdog = if app.self_healing_enabled {
        let Some(task) =
            server_plan.background_task(crate::background::BackgroundTaskKind::RuntimeWatchdog)
        else {
            return Err(
                "admin.self_healing.enabled requires a watchdog task in the server plan".into(),
            );
        };
        Some(crate::background::background_service_for_spec(
            task,
            app.clone(),
        ))
    } else {
        None
    };
    #[cfg(unix)]
    let ops_socket = if config.admin.ops_socket.enabled {
        Some(AdminOpsApp {
            app: app.clone(),
            require_bearer_token: config.admin.ops_socket.require_bearer_token,
        })
    } else {
        None
    };
    Ok(Some(NativeAdminServices {
        control_plane: app,
        #[cfg(unix)]
        ops_socket,
        watchdog,
    }))
}

#[cfg(unix)]
#[derive(Clone)]
pub struct AdminOpsApp {
    app: AdminApp,
    require_bearer_token: bool,
}

impl AdminApp {
    fn from_config(
        config: &Config,
        proxy: FluxProxy,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let token_secret = load_admin_token(&config.admin)?;
        let token = AdminToken::new(&token_secret, config.tls.compliance_mode().required());
        let snapshot_store = config
            .admin
            .snapshot_store
            .as_ref()
            .ok_or("admin.snapshot_store is required when admin.enabled = true")?;

        let runtime_snapshot = SnapshotStore::new(snapshot_store)
            .current_id()
            .ok()
            .flatten();

        let app = Self {
            token,
            client_certificate: AdminClientCertificatePolicy::from_config(&config.admin),
            store: SnapshotStore::new(snapshot_store),
            current_config: Arc::new(ArcSwap::from_pointee(config.clone())),
            proxy,
            health_path: config.admin.self_healing.health_path.clone(),
            health_unauthenticated: config.admin.health.unauthenticated,
            health_response: config.admin.health.response,
            self_healing_enabled: config.admin.self_healing.enabled,
            validation_window_secs: config.admin.self_healing.validation_window_secs,
            min_successful_checks: config.admin.self_healing.min_successful_checks,
            max_error_rate_per_mille: config.admin.self_healing.max_error_rate_per_mille,
            state: Arc::new(Mutex::new(SnapshotRuntimeState {
                runtime_snapshot: runtime_snapshot.clone(),
                known_good_snapshot: runtime_snapshot,
                pending_validation: None,
            })),
            auth_throttle: AdminAuthThrottle::new(config.admin.auth_throttle),
        };

        Ok(app)
    }

    fn health_response(&self) -> AdminResponse {
        match self.health_response {
            AdminHealthResponseMode::Minimal => empty_response(StatusCode::NO_CONTENT),
            AdminHealthResponseMode::Status => json_response(StatusCode::OK, br#"{"status":"ok"}"#),
        }
    }

    fn status_response(&self) -> AdminResponse {
        let current = match self.store.current_id() {
            Ok(current) => current,
            Err(error) => return internal_error_response(&error),
        };
        let snapshots = match self.store.list() {
            Ok(snapshots) => snapshots.len(),
            Err(error) => return internal_error_response(&error),
        };
        let runtime_state = self.runtime_state();
        let current_config = self.current_config.load();
        let tls = &current_config.tls;
        let tls_compliance_mode = tls.compliance_mode();
        let body = json!({
            "status": "ok",
            "snapshot_current": current,
            "snapshots": snapshots,
            "self_healing_enabled": self.self_healing_enabled,
            "tls_compliance_mode": tls_compliance_mode.label(),
            "tls_fips_required": tls.fips.required,
            "tls_iso19790_required": tls.iso19790.required,
            "runtime_snapshot": runtime_state.runtime_snapshot.as_deref(),
            "known_good_snapshot": runtime_state.known_good_snapshot.as_deref(),
            "pending_validation": pending_validation_json(runtime_state.pending_validation.as_ref()),
        });
        #[cfg(feature = "load-balancer")]
        let body = {
            let mut body = body;
            if let Some(object) = body.as_object_mut() {
                object.insert(
                    "load_balancer".to_owned(),
                    serde_json::to_value(self.proxy.load_balancer_runtime_stats())
                        .unwrap_or(Value::Null),
                );
            }
            body
        };
        #[cfg(feature = "udp-proxy")]
        let body = {
            let mut body = body;
            if let Some(object) = body.as_object_mut() {
                object.insert("udp".to_owned(), udp_status_json(&current_config));
            }
            body
        };
        json_response_value(StatusCode::OK, &body)
    }

    fn snapshots_response(&self) -> AdminResponse {
        match self.store.list() {
            Ok(snapshots) => {
                let current = self.store.current_id().ok().flatten();
                let snapshots = snapshots
                    .iter()
                    .map(|snapshot| snapshot_json(snapshot, current.as_deref()))
                    .collect::<Vec<_>>();
                json_response_value(
                    StatusCode::OK,
                    &json!({"status": "ok", "snapshots": snapshots}),
                )
            }
            Err(error) => internal_error_response(&error),
        }
    }

    fn create_snapshot_response(&self, message: Option<&str>) -> AdminResponse {
        let config = self.current_config.load_full();
        match self.store.snapshot_config(&config, message) {
            Ok(snapshot) => json_response_value(
                StatusCode::CREATED,
                &json!({
                    "status": "ok",
                    "snapshot": snapshot.id,
                    "config_path": snapshot.config_path.display().to_string(),
                }),
            ),
            Err(error @ SnapshotError::InvalidSnapshotMessage { .. }) => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    fn rollback_response(&self, target: Option<&str>, live_apply: bool) -> AdminResponse {
        if !live_apply {
            return match self.store.rollback_target(target) {
                Ok(snapshot) => json_response_value(
                    StatusCode::OK,
                    &json!({
                        "status": "ok",
                        "rollback_target": snapshot.id,
                        "config_path": snapshot.config_path.display().to_string(),
                        "live_apply": false,
                    }),
                ),
                Err(error) => error_response(StatusCode::BAD_REQUEST, &error.to_string()),
            };
        }

        let snapshot = match self.store.rollback_candidate(target) {
            Ok(snapshot) => snapshot,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
        };
        let new_config = match Config::load(Some(&snapshot.config_path)) {
            Ok(config) => config,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
        };
        let impact = match self.apply_snapshot(&snapshot, new_config, SnapshotApplyMode::Rollback) {
            Ok(impact) => impact,
            Err(response) => return response,
        };
        if let Err(error) = self.store.set_current_snapshot(&snapshot.id) {
            return internal_error_response(&error);
        }

        json_response_value(
            StatusCode::OK,
            &json!({
                "status": "ok",
                "rollback_target": snapshot.id,
                "config_path": snapshot.config_path.display().to_string(),
                "impact": impact,
                "live_apply": true,
            }),
        )
    }

    fn reload_response(&self) -> AdminResponse {
        let snapshot = match self.store.current_snapshot() {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "snapshot store has no current pointer",
                );
            }
            Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
        };

        let new_config = match Config::load(Some(&snapshot.config_path)) {
            Ok(config) => config,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
        };
        let impact = match self.apply_snapshot(&snapshot, new_config, SnapshotApplyMode::Reload) {
            Ok(impact) => impact,
            Err(response) => return response,
        };

        json_response_value(
            StatusCode::OK,
            &json!({
                "status": "ok",
                "snapshot": snapshot.id,
                "impact": impact,
                "live_apply": true,
            }),
        )
    }

    fn apply_snapshot(
        &self,
        snapshot: &ConfigSnapshot,
        new_config: Config,
        mode: SnapshotApplyMode,
    ) -> Result<String, AdminResponse> {
        let old_config = self.current_config.load_full();
        let impact = classify_reload(&old_config, &new_config);

        if !impact.is_snapshot_safe() {
            return Err(json_response_value(
                StatusCode::CONFLICT,
                &json!({
                    "status": "error",
                    "error": "process_upgrade_required",
                    "snapshot": snapshot.id,
                    "impact": impact.kind(),
                    "reasons": reload_reasons_json(impact.reasons()),
                    "live_apply": false,
                }),
            ));
        }

        if let Err(error) = self.reload_proxy_from_config(&new_config) {
            return Err(internal_error_response(&error));
        }
        self.current_config.store(Arc::new(new_config));

        let impact = impact.kind().to_owned();
        self.record_applied_snapshot(snapshot.id.clone(), impact.clone(), mode);

        Ok(impact)
    }

    fn reload_proxy_from_config(&self, new_config: &Config) -> io::Result<()> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle)
                if matches!(
                    handle.runtime_flavor(),
                    tokio::runtime::RuntimeFlavor::MultiThread
                ) =>
            {
                tokio::task::block_in_place(|| self.proxy.reload_from_config(new_config))
            }
            _ => self.proxy.reload_from_config(new_config),
        }
    }

    fn self_heal_confirm_response(&self) -> AdminResponse {
        if !self.self_healing_enabled {
            return error_response(StatusCode::BAD_REQUEST, "self-healing is disabled");
        }

        let mut state = self.lock_runtime_state();
        let Some(snapshot) = state.confirm_pending_validation() else {
            return error_response(StatusCode::BAD_REQUEST, "no pending validation");
        };

        json_response_value(
            StatusCode::OK,
            &json!({
                "status": "ok",
                "known_good_snapshot": snapshot,
                "confirmed_snapshot": snapshot,
            }),
        )
    }

    fn self_heal_fail_response(&self) -> AdminResponse {
        if !self.self_healing_enabled {
            return error_response(StatusCode::BAD_REQUEST, "self-healing is disabled");
        }

        let pending = match self.take_pending_validation() {
            Some(pending) => pending,
            None => return error_response(StatusCode::BAD_REQUEST, "no pending validation"),
        };

        self.rollback_pending_validation(&pending, "manual")
    }

    fn self_heal_report_response(&self, health: Option<&str>) -> AdminResponse {
        if !self.self_healing_enabled {
            return error_response(StatusCode::BAD_REQUEST, "self-healing is disabled");
        }

        let Some(healthy) = health.and_then(parse_health_signal) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "health signal must be ok/success/true/1 or error/fail/false/0",
            );
        };

        let outcome = self.lock_runtime_state().record_health_signal(
            healthy,
            self.min_successful_checks,
            self.max_error_rate_per_mille,
        );
        match outcome {
            SnapshotHealthSignalOutcome::NoPendingValidation => {
                error_response(StatusCode::BAD_REQUEST, "no pending validation")
            }
            SnapshotHealthSignalOutcome::Recorded { snapshot, metrics } => json_response_value(
                StatusCode::OK,
                &json!({
                    "status": "ok",
                    "action": "recorded",
                    "snapshot": snapshot,
                    "successful_checks": metrics.successful_checks,
                    "failed_checks": metrics.failed_checks,
                    "error_rate_per_mille": metrics.error_rate_per_mille(),
                }),
            ),
            SnapshotHealthSignalOutcome::Confirm { snapshot, metrics } => json_response_value(
                StatusCode::OK,
                &json!({
                    "status": "ok",
                    "action": "confirmed",
                    "known_good_snapshot": snapshot,
                    "successful_checks": metrics.successful_checks,
                    "failed_checks": metrics.failed_checks,
                    "error_rate_per_mille": metrics.error_rate_per_mille(),
                }),
            ),
            SnapshotHealthSignalOutcome::Rollback(pending) => {
                self.rollback_pending_validation(&pending, "error-rate")
            }
        }
    }

    fn enforce_self_healing_deadline(&self) -> Option<AdminResponse> {
        if !self.self_healing_enabled {
            return None;
        }

        let rollback = self
            .lock_runtime_state()
            .expired_or_unhealthy_pending(unix_secs(), self.max_error_rate_per_mille)?;

        Some(self.rollback_pending_validation(&rollback.0, rollback.1.as_str()))
    }

    fn watchdog_interval_secs(&self) -> u64 {
        self.validation_window_secs.clamp(1, 5)
    }

    fn rollback_pending_validation(
        &self,
        pending: &PendingValidation,
        reason: &str,
    ) -> AdminResponse {
        let Some(target) = pending.previous_snapshot.as_deref() else {
            return error_response(StatusCode::BAD_REQUEST, "no previous known-good snapshot");
        };
        let snapshot = match self.store.rollback_candidate(Some(target)) {
            Ok(snapshot) => snapshot,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
        };
        let new_config = match Config::load(Some(&snapshot.config_path)) {
            Ok(config) => config,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
        };
        let impact =
            match self.apply_snapshot(&snapshot, new_config, SnapshotApplyMode::SelfHealRollback) {
                Ok(impact) => impact,
                Err(response) => return response,
            };
        if let Err(error) = self.store.set_current_snapshot(&snapshot.id) {
            return internal_error_response(&error);
        }

        json_response_value(
            StatusCode::OK,
            &json!({
                "status": "ok",
                "reason": reason,
                "failed_snapshot": pending.target_snapshot,
                "rollback_target": snapshot.id,
                "impact": impact,
                "live_apply": true,
            }),
        )
    }

    fn record_applied_snapshot(&self, snapshot: String, impact: String, mode: SnapshotApplyMode) {
        self.lock_runtime_state().record_applied_snapshot(
            snapshot,
            impact,
            mode,
            self.self_healing_enabled,
            self.validation_window_secs,
            unix_secs(),
        );
    }

    fn runtime_state(&self) -> SnapshotRuntimeState {
        self.lock_runtime_state().clone()
    }

    fn take_pending_validation(&self) -> Option<PendingValidation> {
        self.lock_runtime_state().pending_validation.take()
    }

    fn lock_runtime_state(&self) -> std::sync::MutexGuard<'_, SnapshotRuntimeState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::error!(
                    target: "fluxheim::security",
                    "admin runtime state lock poisoned; aborting to avoid using inconsistent management state"
                );
                std::process::abort();
            }
        }
    }
}

#[async_trait]
impl crate::background::FluxBackgroundTask for AdminApp {
    async fn start(
        &self,
        mut shutdown: crate::background::FluxShutdown,
        mut ready: crate::background::FluxBackgroundReady,
    ) {
        ready.notify_ready();
        let interval = Duration::from_secs(self.watchdog_interval_secs());

        loop {
            if shutdown.is_shutdown() {
                break;
            }

            if shutdown.sleep_or_shutdown(interval).await {
                break;
            }
            if let Some(response) = self.enforce_self_healing_deadline() {
                if response.status.is_success() {
                    log::warn!("self-healing watchdog applied expired validation rollback");
                } else {
                    log::error!(
                        "self-healing watchdog failed expired validation rollback: status={}",
                        response.status
                    );
                }
            }
        }
    }
}

impl fluxheim_server::NativeHttp1Handler for AdminApp {
    fn handle<'a>(
        &'a self,
        request: fluxheim_server::NativeHttp1Request,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = fluxheim_server::NativeHttp1Response> + Send + 'a>,
    > {
        Box::pin(async move { self.native_http1_response(request) })
    }
}

impl AdminApp {
    fn native_http1_response(
        &self,
        request: fluxheim_server::NativeHttp1Request,
    ) -> fluxheim_server::NativeHttp1Response {
        let headers = native_admin_headers(&request.headers);
        let (path, query) = native_admin_target_parts(&request.target);
        admin_native_http1_response(self.handle_with_source(
            &request.method,
            path,
            query,
            &headers,
            request.peer_addr.map(|peer| peer.ip()),
        ))
    }
}

#[cfg(unix)]
impl fluxheim_server::NativeHttp1Handler for AdminOpsApp {
    fn handle<'a>(
        &'a self,
        request: fluxheim_server::NativeHttp1Request,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = fluxheim_server::NativeHttp1Response> + Send + 'a>,
    > {
        Box::pin(async move { self.native_http1_response(request) })
    }
}

#[cfg(unix)]
impl AdminOpsApp {
    fn native_http1_response(
        &self,
        request: fluxheim_server::NativeHttp1Request,
    ) -> fluxheim_server::NativeHttp1Response {
        let headers = native_admin_headers(&request.headers);
        let (path, query) = native_admin_target_parts(&request.target);
        admin_native_http1_response(self.app.handle_ops_socket(
            &request.method,
            path,
            query,
            Some(&headers),
            self.require_bearer_token,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arc_swap::ArcSwap;
    use http::{HeaderMap, HeaderValue, StatusCode, header};
    #[cfg(any(feature = "load-balancer", feature = "udp-proxy"))]
    use serde_json::Value;

    use super::{
        AdminApp, AdminAuthThrottle, AdminToken, MAX_ADMIN_TOKEN_FILE_BYTES,
        admin_fingerprint_list_contains, authorized, constant_time_eq, error_response,
        json_response, native_admin_target_parts, read_bounded_secret_file, read_secret_file,
    };
    #[cfg(feature = "cache")]
    use crate::config::ByteSize;
    #[cfg(any(feature = "cache", feature = "load-balancer"))]
    use crate::config::CacheConfig;
    use crate::config::{
        AdminAuthThrottleConfig, AdminClientCertificateConfig, AdminConfig, AdminHealthConfig,
        AdminHealthResponseMode, AdminSelfHealingConfig, Config, ProxyConfig, ServerConfig,
        VhostConfig, WebConfig,
    };
    use crate::native_proxy::FluxProxy;
    #[cfg(feature = "load-balancer")]
    use fluxheim_common::test_support::safe_child_path;
    use fluxheim_common::test_support::unique_temp_path;
    #[cfg(unix)]
    use fluxheim_common::test_support::{unique_group_writable_child, unique_world_writable_child};
    #[cfg(feature = "cache")]
    use fluxheim_config::config_route::RouteConfig;
    use fluxheim_snapshot::SnapshotStore;
    use fluxheim_snapshot::{PendingValidation, SnapshotRuntimeState};

    #[path = "admin_tests_support.rs"]
    mod support;
    use support::*;

    #[path = "admin_tests_auth.rs"]
    mod auth;
    #[path = "admin_tests_cache_bulk.rs"]
    mod cache_bulk;
    #[path = "admin_tests_cache_purge_basic.rs"]
    mod cache_purge_basic;
    #[path = "admin_tests_cache_purge_prefix_tag.rs"]
    mod cache_purge_prefix_tag;
    #[path = "admin_tests_cache_purge_stale_wildcard.rs"]
    mod cache_purge_stale_wildcard;
    #[path = "admin_tests_cache_status.rs"]
    mod cache_status;
    #[path = "admin_tests_core.rs"]
    mod core;
    #[path = "admin_tests_lb_status.rs"]
    mod lb_status;
    #[path = "admin_tests_lb_validation.rs"]
    mod lb_validation;
    #[path = "admin_tests_self_heal_progress.rs"]
    mod self_heal_progress;
    #[path = "admin_tests_self_heal_rollback.rs"]
    mod self_heal_rollback;
    #[path = "admin_tests_snapshot.rs"]
    mod snapshot;
    #[path = "admin_tests_status_limits.rs"]
    mod status_limits;
}

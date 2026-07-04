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
mod snapshot_runtime;

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
        #[cfg(feature = "wasm")]
        let body = {
            let mut body = body;
            if let Some(object) = body.as_object_mut() {
                object.insert("wasm".to_owned(), wasm_status_json(&current_config));
            }
            body
        };
        json_response_value(StatusCode::OK, &body)
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

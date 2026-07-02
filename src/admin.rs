use std::collections::{HashMap, VecDeque};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::{HeaderMap, StatusCode, header};
use sanitization::{SecureSanitize, ct::ConstantTimeEq};
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::config::{AdminAuthThrottleConfig, AdminConfig, AdminHealthResponseMode, Config};
use crate::native_proxy::FluxProxy;
use fluxheim_config::reload::{ReloadReason, classify_reload};
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

const MAX_ADMIN_TOKEN_BYTES: usize = 8 * 1024;
const MAX_ADMIN_TOKEN_FILE_BYTES: u64 = MAX_ADMIN_TOKEN_BYTES as u64;
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct AdminClientCertificatePolicy {
    required: bool,
    sha256_header: String,
    allow_sha256: Vec<String>,
    deny_sha256: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AdminClientCertificateDecision {
    Allowed,
    Required,
    Denied,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum AdminClientCertificateHeader {
    Missing,
    Present(String),
    Invalid,
}

#[derive(Clone)]
struct AdminToken {
    len: usize,
    digest: [u8; 32],
    mac_provider: crate::internal_crypto::AdminMacProvider,
}

impl AdminToken {
    fn new(token: &str, compliance_required: bool) -> Self {
        let mac_provider =
            crate::internal_crypto::admin_mac_provider_for_compliance_required(compliance_required);
        Self {
            len: token.len(),
            digest: digest_admin_token(token.as_bytes(), mac_provider),
            mac_provider,
        }
    }
}

impl Drop for AdminToken {
    fn drop(&mut self) {
        self.digest.secure_sanitize();
        self.len.secure_sanitize();
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AdminResponse {
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
}

#[derive(Clone)]
struct AdminAuthThrottle {
    config: AdminAuthThrottleConfig,
    state: Arc<Mutex<AdminAuthThrottleState>>,
}

#[derive(Debug, Default)]
struct AdminAuthThrottleState {
    global_failures: VecDeque<u64>,
    global_locked_until: u64,
    global_lockouts: u32,
    sources: HashMap<AuthSource, AdminAuthSourceState>,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum AuthSource {
    Ip(IpAddr),
    Unknown,
}

#[derive(Debug, Default)]
struct AdminAuthSourceState {
    failures: VecDeque<u64>,
    locked_until: u64,
    lockouts: u32,
    last_seen: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AdminAuthThrottleScope {
    Source,
    Global,
}

impl AdminAuthThrottle {
    fn new(config: AdminAuthThrottleConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(AdminAuthThrottleState::default())),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, AdminAuthThrottleState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::error!(
                    target: "fluxheim::security",
                    "admin auth throttle lock poisoned; aborting to avoid using inconsistent security state"
                );
                std::process::abort();
            }
        }
    }

    fn pre_auth_check(&self, source: Option<IpAddr>) -> Option<AdminAuthThrottleScope> {
        if !self.config.enabled {
            return None;
        }
        let now = unix_secs();
        let source = AuthSource::from(source);
        let mut state = self.lock_state();
        state.prune(now, &self.config);

        if state.global_locked_until > now {
            return Some(AdminAuthThrottleScope::Global);
        }
        if source == AuthSource::Unknown {
            return None;
        }
        state.sources.get(&source).and_then(|record| {
            (record.locked_until > now).then_some(AdminAuthThrottleScope::Source)
        })
    }

    fn record_failure(&self, source: Option<IpAddr>) -> Option<AdminAuthThrottleScope> {
        if !self.config.enabled {
            return None;
        }
        let now = unix_secs();
        let source = AuthSource::from(source);
        let mut state = self.lock_state();
        state.prune(now, &self.config);
        state.global_failures.push_back(now);
        if source == AuthSource::Unknown {
            log::warn!(
                target: "fluxheim::security",
                "admin auth failure from indeterminate source; applying global throttle only"
            );
            if state.global_failures.len() >= self.config.global_failures {
                state.global_lockouts = state.global_lockouts.saturating_add(1);
                state.global_locked_until =
                    now.saturating_add(lockout_secs(&self.config, state.global_lockouts));
                state.global_failures.clear();
                return Some(AdminAuthThrottleScope::Global);
            }
            return None;
        }
        if !state.ensure_source_capacity(&self.config, source) {
            log::warn!(
                target: "fluxheim::security",
                "admin auth throttle source table full; applying global failure accounting"
            );
            if state.global_failures.len() >= self.config.global_failures {
                state.global_lockouts = state.global_lockouts.saturating_add(1);
                state.global_locked_until =
                    now.saturating_add(lockout_secs(&self.config, state.global_lockouts));
                state.global_failures.clear();
                return Some(AdminAuthThrottleScope::Global);
            }
            return None;
        }

        let source_locked = {
            let source_record = state.sources.entry(source).or_default();
            source_record.last_seen = now;
            source_record.failures.push_back(now);
            if source_record.failures.len() >= self.config.per_source_failures {
                source_record.lockouts = source_record.lockouts.saturating_add(1);
                source_record.locked_until =
                    now.saturating_add(lockout_secs(&self.config, source_record.lockouts));
                source_record.failures.clear();
                true
            } else {
                false
            }
        };

        if state.global_failures.len() >= self.config.global_failures {
            state.global_lockouts = state.global_lockouts.saturating_add(1);
            state.global_locked_until =
                now.saturating_add(lockout_secs(&self.config, state.global_lockouts));
            state.global_failures.clear();
            return Some(AdminAuthThrottleScope::Global);
        }

        source_locked.then_some(AdminAuthThrottleScope::Source)
    }

    fn record_success(&self, source: Option<IpAddr>) {
        if !self.config.enabled {
            return;
        }
        let source = AuthSource::from(source);
        if source == AuthSource::Unknown {
            return;
        }
        let mut state = self.lock_state();
        state.sources.remove(&source);
    }
}

impl AdminAuthThrottleState {
    fn prune(&mut self, now: u64, config: &AdminAuthThrottleConfig) {
        let cutoff = now.saturating_sub(config.window_secs);
        prune_failures(&mut self.global_failures, cutoff);
        self.sources.retain(|_, record| {
            prune_failures(&mut record.failures, cutoff);
            record.locked_until > now || !record.failures.is_empty()
        });
    }

    fn ensure_source_capacity(
        &mut self,
        config: &AdminAuthThrottleConfig,
        source: AuthSource,
    ) -> bool {
        if self.sources.contains_key(&source) || self.sources.len() < config.max_sources {
            return true;
        }
        if let Some(stale_key) = self
            .sources
            .iter()
            .filter(|(_, record)| record.locked_until == 0)
            .min_by_key(|(_, record)| record.last_seen)
            .map(|(source, _)| *source)
            .or_else(|| {
                self.sources
                    .iter()
                    .min_by_key(|(_, record)| record.last_seen)
                    .map(|(source, _)| *source)
            })
        {
            self.sources.remove(&stale_key);
            log::warn!(
                target: "fluxheim::security",
                "admin auth throttle source table full; evicted stale source entry"
            );
            return true;
        }
        false
    }
}

impl From<Option<IpAddr>> for AuthSource {
    fn from(source: Option<IpAddr>) -> Self {
        source.map(Self::Ip).unwrap_or(Self::Unknown)
    }
}

impl AdminAuthThrottleScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Global => "global",
        }
    }
}

fn prune_failures(failures: &mut VecDeque<u64>, cutoff: u64) {
    while failures.front().is_some_and(|seen_at| *seen_at < cutoff) {
        failures.pop_front();
    }
}

fn lockout_secs(config: &AdminAuthThrottleConfig, lockouts: u32) -> u64 {
    let exponent = lockouts.saturating_sub(1).min(20);
    let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
    config
        .base_lockout_secs
        .saturating_mul(multiplier)
        .min(config.max_lockout_secs)
}

fn auth_source_label(source: Option<IpAddr>) -> String {
    source
        .map(|source| source.to_string())
        .unwrap_or_else(|| "unknown".to_owned())
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

    #[cfg(test)]
    fn handle(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
    ) -> AdminResponse {
        self.handle_with_source(method, path, query, headers, None)
    }

    fn handle_with_source(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        source: Option<IpAddr>,
    ) -> AdminResponse {
        if let Some(response) = self.enforce_self_healing_deadline() {
            return response;
        }

        if path.len() > MAX_ADMIN_PATH_BYTES {
            return json_response(StatusCode::URI_TOO_LONG, br#"{"error":"path_too_large"}"#);
        }

        let health_request = path == self.health_path;
        if health_request && self.health_unauthenticated {
            if method != "GET" {
                return json_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    br#"{"error":"method_not_allowed"}"#,
                );
            }
            return self.health_response();
        }

        if let Some(scope) = self.auth_throttle.pre_auth_check(source) {
            record_admin_auth_event("throttled", scope);
            log::warn!(
                target: "fluxheim::security",
                "admin auth request throttled source={} scope={}",
                auth_source_label(source),
                scope.as_str()
            );
            return json_response(
                StatusCode::TOO_MANY_REQUESTS,
                br#"{"error":"admin_auth_throttled"}"#,
            );
        }

        match self.client_certificate.allows(headers) {
            AdminClientCertificateDecision::Allowed => {}
            AdminClientCertificateDecision::Required => {
                let scope = self.auth_throttle.record_failure(source);
                record_admin_auth_event("failure", scope.unwrap_or(AdminAuthThrottleScope::Source));
                log::warn!(
                    target: "fluxheim::security",
                    "admin client certificate required source={} throttled={}",
                    auth_source_label(source),
                    scope.map(AdminAuthThrottleScope::as_str).unwrap_or("none")
                );
                if scope.is_some() {
                    record_admin_auth_event(
                        "throttled",
                        scope.unwrap_or(AdminAuthThrottleScope::Source),
                    );
                    return json_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        br#"{"error":"admin_auth_throttled"}"#,
                    );
                }
                return json_response(
                    StatusCode::FORBIDDEN,
                    br#"{"error":"admin_client_certificate_required"}"#,
                );
            }
            AdminClientCertificateDecision::Denied => {
                let scope = self.auth_throttle.record_failure(source);
                record_admin_auth_event("failure", scope.unwrap_or(AdminAuthThrottleScope::Source));
                log::warn!(
                    target: "fluxheim::security",
                    "admin client certificate denied source={} throttled={}",
                    auth_source_label(source),
                    scope.map(AdminAuthThrottleScope::as_str).unwrap_or("none")
                );
                if scope.is_some() {
                    record_admin_auth_event(
                        "throttled",
                        scope.unwrap_or(AdminAuthThrottleScope::Source),
                    );
                    return json_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        br#"{"error":"admin_auth_throttled"}"#,
                    );
                }
                return json_response(
                    StatusCode::FORBIDDEN,
                    br#"{"error":"admin_client_certificate_denied"}"#,
                );
            }
        }

        if !authorized(authorization_header(headers), &self.token) {
            let scope = self.auth_throttle.record_failure(source);
            record_admin_auth_event("failure", scope.unwrap_or(AdminAuthThrottleScope::Source));
            log::warn!(
                target: "fluxheim::security",
                "admin auth failed source={} throttled={}",
                auth_source_label(source),
                scope.map(AdminAuthThrottleScope::as_str).unwrap_or("none")
            );
            if scope.is_some() {
                record_admin_auth_event(
                    "throttled",
                    scope.unwrap_or(AdminAuthThrottleScope::Source),
                );
                return json_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    br#"{"error":"admin_auth_throttled"}"#,
                );
            }
            return json_response(StatusCode::UNAUTHORIZED, br#"{"error":"unauthorized"}"#);
        }
        self.auth_throttle.record_success(source);
        if health_request {
            if method != "GET" {
                return json_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    br#"{"error":"method_not_allowed"}"#,
                );
            }
            return self.health_response();
        }
        if query.is_some_and(|query| query.len() > MAX_ADMIN_QUERY_BYTES) {
            return json_response(StatusCode::URI_TOO_LONG, br#"{"error":"query_too_large"}"#);
        }

        match (method, path) {
            ("GET", "/_fluxheim/status") => self.status_response(),
            ("GET", "/_fluxheim/cache/status") => self.cache_status_response(),
            ("GET", "/_fluxheim/load-balancer/status") => self.load_balancer_status_response(),
            ("GET", "/_fluxheim/udp/status") => self.udp_status_response(),
            ("GET", "/_fluxheim/snapshots") => self.snapshots_response(),
            ("POST", "/_fluxheim/cache/activity/reset") => self.cache_activity_reset_response(),
            ("POST", "/_fluxheim/self-heal/confirm") => self.self_heal_confirm_response(),
            ("POST", "/_fluxheim/self-heal/fail") => self.self_heal_fail_response(),
            ("POST", "/_fluxheim/self-heal/report") => self.self_heal_report_response(
                header_value(headers, "x-fluxheim-health")
                    .or_else(|| query_param(query, "health"))
                    .or_else(|| query_param(query, "ok"))
                    .or_else(|| query_param(query, "success")),
            ),
            ("POST", "/_fluxheim/load-balancer/member-state") => self
                .load_balancer_member_state_response(
                    header_value(headers, "x-fluxheim-lb-vhost")
                        .or_else(|| query_param(query, "vhost")),
                    header_value(headers, "x-fluxheim-lb-route")
                        .or_else(|| query_param(query, "route")),
                    header_value(headers, "x-fluxheim-lb-member")
                        .or_else(|| query_param(query, "member")),
                    header_value(headers, "x-fluxheim-lb-state")
                        .or_else(|| query_param(query, "state")),
                ),
            ("POST", "/_fluxheim/load-balancer/member-weight") => self
                .load_balancer_member_weight_response(
                    header_value(headers, "x-fluxheim-lb-vhost")
                        .or_else(|| query_param(query, "vhost")),
                    header_value(headers, "x-fluxheim-lb-route")
                        .or_else(|| query_param(query, "route")),
                    header_value(headers, "x-fluxheim-lb-member")
                        .or_else(|| query_param(query, "member")),
                    header_value(headers, "x-fluxheim-lb-weight")
                        .or_else(|| query_param(query, "weight")),
                ),
            ("POST", "/_fluxheim/load-balancer/member-add") => self
                .load_balancer_member_add_response(
                    header_value(headers, "x-fluxheim-lb-vhost")
                        .or_else(|| query_param(query, "vhost")),
                    header_value(headers, "x-fluxheim-lb-route")
                        .or_else(|| query_param(query, "route")),
                    header_value(headers, "x-fluxheim-lb-member")
                        .or_else(|| query_param(query, "member")),
                    header_value(headers, "x-fluxheim-lb-weight")
                        .or_else(|| query_param(query, "weight")),
                ),
            ("POST", "/_fluxheim/load-balancer/member-remove") => self
                .load_balancer_member_remove_response(
                    header_value(headers, "x-fluxheim-lb-vhost")
                        .or_else(|| query_param(query, "vhost")),
                    header_value(headers, "x-fluxheim-lb-route")
                        .or_else(|| query_param(query, "route")),
                    header_value(headers, "x-fluxheim-lb-member")
                        .or_else(|| query_param(query, "member")),
                ),
            ("POST", "/_fluxheim/load-balancer/member-update") => self
                .load_balancer_member_update_response(
                    header_value(headers, "x-fluxheim-lb-vhost")
                        .or_else(|| query_param(query, "vhost")),
                    header_value(headers, "x-fluxheim-lb-route")
                        .or_else(|| query_param(query, "route")),
                    header_value(headers, "x-fluxheim-lb-member")
                        .or_else(|| query_param(query, "member")),
                    header_value(headers, "x-fluxheim-lb-new-member")
                        .or_else(|| header_value(headers, "x-fluxheim-lb-address"))
                        .or_else(|| query_param(query, "new_member"))
                        .or_else(|| query_param(query, "address")),
                    header_value(headers, "x-fluxheim-lb-weight")
                        .or_else(|| query_param(query, "weight")),
                ),
            ("POST", "/_fluxheim/load-balancer/persistence/clear") => self
                .load_balancer_persistence_clear_response(
                    header_value(headers, "x-fluxheim-lb-vhost")
                        .or_else(|| query_param(query, "vhost")),
                    header_value(headers, "x-fluxheim-lb-route")
                        .or_else(|| query_param(query, "route")),
                ),
            ("POST", "/_fluxheim/cache/purge") => self.cache_purge_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-host")
                    .or_else(|| query_param(query, "host")),
                header_value(headers, "x-fluxheim-cache-method")
                    .or_else(|| query_param(query, "method")),
                header_value(headers, "x-fluxheim-cache-path")
                    .or_else(|| query_param(query, "path")),
                header_value(headers, "x-fluxheim-cache-query")
                    .or_else(|| query_param(query, "url_query"))
                    .or_else(|| query_param(query, "cache_query")),
            ),
            ("POST", "/_fluxheim/cache/purge-bulk") => self.cache_purge_bulk_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-host")
                    .or_else(|| query_param(query, "host")),
                header_value(headers, "x-fluxheim-cache-method")
                    .or_else(|| query_param(query, "method")),
                cache_purge_paths(headers, query),
                header_value(headers, "x-fluxheim-cache-query")
                    .or_else(|| query_param(query, "url_query"))
                    .or_else(|| query_param(query, "cache_query")),
            ),
            ("POST", "/_fluxheim/cache/purge-index") => self.cache_purge_index_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-limit")
                    .or_else(|| query_param(query, "limit")),
                header_value(headers, "x-fluxheim-cache-batches")
                    .or_else(|| query_param(query, "batches")),
                truthy_header(headers, "x-fluxheim-cache-soft")
                    || truthy_query_param(query, "soft"),
            ),
            ("POST", "/_fluxheim/cache/purge-prefix") => self.cache_purge_prefix_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-path-prefix")
                    .or_else(|| query_param(query, "path_prefix"))
                    .or_else(|| query_param(query, "prefix")),
                header_value(headers, "x-fluxheim-cache-limit")
                    .or_else(|| query_param(query, "limit")),
                header_value(headers, "x-fluxheim-cache-batches")
                    .or_else(|| query_param(query, "batches")),
                truthy_header(headers, "x-fluxheim-cache-soft")
                    || truthy_query_param(query, "soft"),
            ),
            ("POST", "/_fluxheim/cache/purge-tag") => self.cache_purge_tag_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-tag")
                    .or_else(|| query_param(query, "cache_tag"))
                    .or_else(|| query_param(query, "tag")),
                header_value(headers, "x-fluxheim-cache-limit")
                    .or_else(|| query_param(query, "limit")),
                header_value(headers, "x-fluxheim-cache-batches")
                    .or_else(|| query_param(query, "batches")),
                truthy_header(headers, "x-fluxheim-cache-soft")
                    || truthy_query_param(query, "soft"),
            ),
            ("POST", "/_fluxheim/cache/purge-stale") => self.cache_purge_stale_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-limit")
                    .or_else(|| query_param(query, "limit")),
                header_value(headers, "x-fluxheim-cache-batches")
                    .or_else(|| query_param(query, "batches")),
                truthy_header(headers, "x-fluxheim-cache-dry-run")
                    || truthy_query_param(query, "dry_run")
                    || truthy_query_param(query, "dry-run"),
            ),
            ("POST", "/_fluxheim/cache/purge-wildcard") => self.cache_purge_wildcard_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-path-pattern")
                    .or_else(|| query_param(query, "path_pattern"))
                    .or_else(|| query_param(query, "pattern"))
                    .or_else(|| query_param(query, "wildcard")),
                header_value(headers, "x-fluxheim-cache-limit")
                    .or_else(|| query_param(query, "limit")),
                header_value(headers, "x-fluxheim-cache-batches")
                    .or_else(|| query_param(query, "batches")),
                truthy_header(headers, "x-fluxheim-cache-soft")
                    || truthy_query_param(query, "soft"),
            ),
            ("POST", "/_fluxheim/snapshot") => {
                self.create_snapshot_response(header_value(headers, "x-fluxheim-message"))
            }
            ("POST", "/_fluxheim/rollback") => self.rollback_response(
                header_value(headers, "x-fluxheim-rollback-to")
                    .or_else(|| query_param(query, "to")),
                truthy_header(headers, "x-fluxheim-live-apply")
                    || truthy_query_param(query, "live")
                    || truthy_query_param(query, "live_apply"),
            ),
            ("POST", "/_fluxheim/reload") => self.reload_response(),
            (
                _,
                "/_fluxheim/status"
                | "/_fluxheim/cache/status"
                | "/_fluxheim/load-balancer/status"
                | "/_fluxheim/udp/status"
                | "/_fluxheim/snapshots"
                | "/_fluxheim/cache/activity/reset"
                | "/_fluxheim/self-heal/confirm"
                | "/_fluxheim/self-heal/fail"
                | "/_fluxheim/self-heal/report"
                | "/_fluxheim/load-balancer/member-state"
                | "/_fluxheim/load-balancer/member-weight"
                | "/_fluxheim/load-balancer/member-add"
                | "/_fluxheim/load-balancer/member-remove"
                | "/_fluxheim/load-balancer/member-update"
                | "/_fluxheim/load-balancer/persistence/clear"
                | "/_fluxheim/cache/purge"
                | "/_fluxheim/cache/purge-bulk"
                | "/_fluxheim/cache/purge-index"
                | "/_fluxheim/cache/purge-prefix"
                | "/_fluxheim/cache/purge-tag"
                | "/_fluxheim/cache/purge-stale"
                | "/_fluxheim/cache/purge-wildcard"
                | "/_fluxheim/snapshot"
                | "/_fluxheim/rollback"
                | "/_fluxheim/reload",
            ) => json_response(
                StatusCode::METHOD_NOT_ALLOWED,
                br#"{"error":"method_not_allowed"}"#,
            ),
            ("GET" | "POST", _) => {
                json_response(StatusCode::NOT_FOUND, br#"{"error":"not_found"}"#)
            }
            _ => json_response(
                StatusCode::METHOD_NOT_ALLOWED,
                br#"{"error":"method_not_allowed"}"#,
            ),
        }
    }

    #[cfg(unix)]
    fn handle_ops_socket(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: Option<&HeaderMap>,
        require_bearer_token: bool,
    ) -> AdminResponse {
        if path.len() > MAX_ADMIN_PATH_BYTES {
            return json_response(StatusCode::URI_TOO_LONG, br#"{"error":"path_too_large"}"#);
        }
        if query.is_some_and(|query| query.len() > MAX_ADMIN_QUERY_BYTES) {
            return json_response(StatusCode::URI_TOO_LONG, br#"{"error":"query_too_large"}"#);
        }
        let known_read_only_path = matches!(
            path,
            "/_fluxheim/status"
                | "/_fluxheim/cache/status"
                | "/_fluxheim/load-balancer/status"
                | "/_fluxheim/udp/status"
                | "/_fluxheim/snapshots"
        ) || path == self.health_path;
        if method != "GET" {
            return if known_read_only_path {
                json_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    br#"{"error":"method_not_allowed"}"#,
                )
            } else {
                json_response(StatusCode::NOT_FOUND, br#"{"error":"not_found"}"#)
            };
        }
        if (require_bearer_token || path == "/_fluxheim/snapshots")
            && !headers
                .is_some_and(|headers| authorized(authorization_header(headers), &self.token))
        {
            return json_response(StatusCode::UNAUTHORIZED, br#"{"error":"unauthorized"}"#);
        }

        match path {
            "/_fluxheim/status" => self.status_response(),
            "/_fluxheim/cache/status" => self.cache_status_response(),
            "/_fluxheim/load-balancer/status" => self.load_balancer_status_response(),
            "/_fluxheim/udp/status" => self.udp_status_response(),
            "/_fluxheim/snapshots" => self.snapshots_response(),
            path if path == self.health_path => self.health_response(),
            _ => json_response(StatusCode::NOT_FOUND, br#"{"error":"not_found"}"#),
        }
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

    #[cfg(feature = "load-balancer")]
    fn load_balancer_status_response(&self) -> AdminResponse {
        json_response_value(
            StatusCode::OK,
            &json!({
                "status": "ok",
                "load_balancer": self.proxy.load_balancer_runtime_stats(),
            }),
        )
    }

    #[cfg(not(feature = "load-balancer"))]
    fn load_balancer_status_response(&self) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }

    #[cfg(feature = "udp-proxy")]
    fn udp_status_response(&self) -> AdminResponse {
        let current_config = self.current_config.load();
        json_response_value(
            StatusCode::OK,
            &json!({
                "status": "ok",
                "udp": udp_status_json(&current_config),
            }),
        )
    }

    #[cfg(not(feature = "udp-proxy"))]
    fn udp_status_response(&self) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "UDP proxy support is not compiled in",
        )
    }

    #[cfg(feature = "load-balancer")]
    fn load_balancer_member_state_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        member: Option<&str>,
        state: Option<&str>,
    ) -> AdminResponse {
        let Some(vhost) = vhost else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer vhost is required");
        };
        let Some(member) = member else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer member is required");
        };
        let Some(state) = state else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer state is required");
        };
        let Some(state) = LoadBalancerRuntimeBackendState::parse(state) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "load balancer state must be normal, drain, disable, forced_down, or manual_resume",
            );
        };
        match self
            .proxy
            .set_load_balancer_member_state(LoadBalancerMemberStateRequest {
                vhost,
                route,
                member,
                state,
            }) {
            Ok(result) => {
                let scope = if result.route.is_some() {
                    "route"
                } else {
                    "vhost"
                };
                let display_member =
                    load_balancer_display_member(result.alias.as_deref(), result.member.as_str());
                #[cfg(not(feature = "privacy-mode"))]
                log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer member state updated vhost={} route={} scope={} member={} state={} address={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.state.as_str(),
                    result.address,
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                #[cfg(feature = "privacy-mode")]
                log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer member state updated vhost={} route={} scope={} member={} state={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.state.as_str(),
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                log::info!(
                    target: "fluxheim::audit",
                    "load balancer member state updated vhost={} route={} scope={} member={} state={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.state.as_str(),
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                record_load_balancer_event(
                    &result.vhost,
                    result.route.as_deref(),
                    load_balancer_metric_member_label(
                        result.alias.as_deref(),
                        result.member.as_str(),
                    ),
                    "member_state",
                );
                let mut body = serde_json::Map::new();
                body.insert("status".to_owned(), json!("ok"));
                body.insert("vhost".to_owned(), json!(result.vhost));
                body.insert("route".to_owned(), json!(result.route));
                body.insert("scope".to_owned(), json!(scope));
                body.insert("member".to_owned(), json!(display_member));
                body.insert("state".to_owned(), json!(result.state));
                #[cfg(not(feature = "privacy-mode"))]
                body.insert("address".to_owned(), json!(result.address));
                body.insert("alias".to_owned(), json!(result.alias));
                body.insert("persistent".to_owned(), json!(result.persistent));
                json_response_value(StatusCode::OK, &Value::Object(body))
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member state rejected invalid input vhost={} route={} member={} state={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    state.as_str(),
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_state_invalid",
                );
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member state target not found vhost={} route={} member={} state={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    state.as_str(),
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_state_not_found",
                );
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "load-balancer")]
    fn load_balancer_member_weight_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        member: Option<&str>,
        weight: Option<&str>,
    ) -> AdminResponse {
        let Some(vhost) = vhost else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer vhost is required");
        };
        let Some(member) = member else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer member is required");
        };
        let Some(weight) = weight else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer weight is required");
        };
        let weight = match parse_load_balancer_runtime_weight(weight) {
            Ok(weight) => weight,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
        };
        match self
            .proxy
            .set_load_balancer_member_weight(LoadBalancerMemberWeightRequest {
                vhost,
                route,
                member,
                weight,
            }) {
            Ok(result) => {
                let scope = if result.route.is_some() {
                    "route"
                } else {
                    "vhost"
                };
                let display_member =
                    load_balancer_display_member(result.alias.as_deref(), result.member.as_str());
                #[cfg(not(feature = "privacy-mode"))]
                log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer member weight updated vhost={} route={} scope={} member={} configured_weight={} effective_weight={} runtime_weight_override={} address={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.configured_weight,
                    result.effective_weight,
                    result
                        .runtime_weight_override
                        .map(|weight| weight.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    result.address,
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                #[cfg(feature = "privacy-mode")]
                log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer member weight updated vhost={} route={} scope={} member={} configured_weight={} effective_weight={} runtime_weight_override={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.configured_weight,
                    result.effective_weight,
                    result
                        .runtime_weight_override
                        .map(|weight| weight.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                log::info!(
                    target: "fluxheim::audit",
                    "load balancer member weight updated vhost={} route={} scope={} member={} configured_weight={} effective_weight={} runtime_weight_override={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.configured_weight,
                    result.effective_weight,
                    result
                        .runtime_weight_override
                        .map(|weight| weight.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                record_load_balancer_event(
                    &result.vhost,
                    result.route.as_deref(),
                    load_balancer_metric_member_label(
                        result.alias.as_deref(),
                        result.member.as_str(),
                    ),
                    "member_weight",
                );
                let mut body = serde_json::Map::new();
                body.insert("status".to_owned(), json!("ok"));
                body.insert("vhost".to_owned(), json!(result.vhost));
                body.insert("route".to_owned(), json!(result.route));
                body.insert("scope".to_owned(), json!(scope));
                body.insert("member".to_owned(), json!(display_member));
                body.insert(
                    "configured_weight".to_owned(),
                    json!(result.configured_weight),
                );
                body.insert(
                    "effective_weight".to_owned(),
                    json!(result.effective_weight),
                );
                body.insert(
                    "runtime_weight_override".to_owned(),
                    json!(result.runtime_weight_override),
                );
                #[cfg(not(feature = "privacy-mode"))]
                body.insert("address".to_owned(), json!(result.address));
                body.insert("alias".to_owned(), json!(result.alias));
                body.insert("persistent".to_owned(), json!(result.persistent));
                json_response_value(StatusCode::OK, &Value::Object(body))
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member weight rejected invalid input vhost={} route={} member={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_weight_invalid",
                );
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member weight target not found vhost={} route={} member={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_weight_not_found",
                );
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "load-balancer")]
    fn load_balancer_member_add_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        member: Option<&str>,
        weight: Option<&str>,
    ) -> AdminResponse {
        let Some(vhost) = vhost else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer vhost is required");
        };
        let Some(member) = member else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer member is required");
        };
        let weight = match weight {
            Some(weight) => match parse_load_balancer_member_weight(weight) {
                Ok(weight) => weight,
                Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
            },
            None => 1,
        };
        let result = self
            .proxy
            .add_load_balancer_member(LoadBalancerMemberAddRequest {
                vhost,
                route,
                member,
                weight,
            });
        self.load_balancer_member_set_response(result, vhost, route, member, "member_add")
    }

    #[cfg(feature = "load-balancer")]
    fn load_balancer_member_remove_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        member: Option<&str>,
    ) -> AdminResponse {
        let Some(vhost) = vhost else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer vhost is required");
        };
        let Some(member) = member else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer member is required");
        };
        let result = self
            .proxy
            .remove_load_balancer_member(LoadBalancerMemberRemoveRequest {
                vhost,
                route,
                member,
            });
        self.load_balancer_member_set_response(result, vhost, route, member, "member_remove")
    }

    #[cfg(feature = "load-balancer")]
    fn load_balancer_member_update_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        member: Option<&str>,
        updated_member: Option<&str>,
        weight: Option<&str>,
    ) -> AdminResponse {
        let Some(vhost) = vhost else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer vhost is required");
        };
        let Some(member) = member else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer member is required");
        };
        let weight = match weight {
            Some(weight) => match parse_load_balancer_member_weight(weight) {
                Ok(weight) => Some(weight),
                Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
            },
            None => None,
        };
        let result = self
            .proxy
            .update_load_balancer_member(LoadBalancerMemberUpdateRequest {
                vhost,
                route,
                member,
                updated_member,
                weight,
            });
        self.load_balancer_member_set_response(result, vhost, route, member, "member_update")
    }

    #[cfg(feature = "load-balancer")]
    fn load_balancer_member_set_response(
        &self,
        result: io::Result<LoadBalancerMemberSetMutationResult>,
        vhost: &str,
        route: Option<&str>,
        member: &str,
        event: &'static str,
    ) -> AdminResponse {
        match result {
            Ok(result) => {
                let scope = if result.route.is_some() {
                    "route"
                } else {
                    "vhost"
                };
                let display_member =
                    load_balancer_display_member(result.alias.as_deref(), result.member.as_str());
                #[cfg(not(feature = "privacy-mode"))]
                log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer member set updated vhost={} route={} scope={} member={} operation={} configured_weight={} backend_count={} address={} previous_address={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.operation.as_str(),
                    result.configured_weight,
                    result.backend_count,
                    result.address,
                    result.previous_address.as_deref().unwrap_or(""),
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                #[cfg(feature = "privacy-mode")]
                log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer member set updated vhost={} route={} scope={} member={} operation={} configured_weight={} backend_count={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.operation.as_str(),
                    result.configured_weight,
                    result.backend_count,
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                log::info!(
                    target: "fluxheim::audit",
                    "load balancer member set updated vhost={} route={} scope={} member={} operation={} configured_weight={} backend_count={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.operation.as_str(),
                    result.configured_weight,
                    result.backend_count,
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                record_load_balancer_event(
                    &result.vhost,
                    result.route.as_deref(),
                    load_balancer_metric_member_label(
                        result.alias.as_deref(),
                        result.member.as_str(),
                    ),
                    event,
                );
                let mut body = serde_json::Map::new();
                body.insert("status".to_owned(), json!("ok"));
                body.insert("vhost".to_owned(), json!(result.vhost));
                body.insert("route".to_owned(), json!(result.route));
                body.insert("scope".to_owned(), json!(scope));
                body.insert("member".to_owned(), json!(display_member));
                body.insert("operation".to_owned(), json!(result.operation));
                body.insert(
                    "configured_weight".to_owned(),
                    json!(result.configured_weight),
                );
                body.insert("backend_count".to_owned(), json!(result.backend_count));
                #[cfg(not(feature = "privacy-mode"))]
                {
                    body.insert("address".to_owned(), json!(result.address));
                    body.insert(
                        "previous_address".to_owned(),
                        json!(result.previous_address),
                    );
                }
                body.insert("alias".to_owned(), json!(result.alias));
                body.insert("persistent".to_owned(), json!(result.persistent));
                json_response_value(StatusCode::OK, &Value::Object(body))
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member set rejected invalid input vhost={} route={} member={} event={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    event,
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_set_invalid",
                );
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member set target already exists vhost={} route={} member={} event={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    event,
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_set_conflict",
                );
                error_response(StatusCode::CONFLICT, &error.to_string())
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member set blocked by active traffic vhost={} route={} member={} event={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    event,
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_set_blocked",
                );
                error_response(StatusCode::CONFLICT, &error.to_string())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member set target not found vhost={} route={} member={} event={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    event,
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_set_not_found",
                );
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "load-balancer")]
    fn load_balancer_persistence_clear_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
    ) -> AdminResponse {
        let Some(vhost) = vhost else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer vhost is required");
        };
        match self
            .proxy
            .clear_load_balancer_persistence(LoadBalancerPersistenceClearRequest { vhost, route })
        {
            Ok(result) => {
                let scope = if result.route.is_some() {
                    "route"
                } else {
                    "vhost"
                };
                log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer persistence table cleared vhost={} route={} scope={} cleared_entries={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    result.cleared_entries,
                    result.persistent
                );
                record_load_balancer_event(
                    &result.vhost,
                    result.route.as_deref(),
                    None,
                    "persistence_clear",
                );
                json_response_value(
                    StatusCode::OK,
                    &json!({
                        "status": "ok",
                        "vhost": result.vhost,
                        "route": result.route,
                        "scope": scope,
                        "cleared_entries": result.cleared_entries,
                        "persistent": result.persistent,
                    }),
                )
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer persistence clear rejected invalid input vhost={} route={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    error
                );
                record_load_balancer_event(vhost, route, None, "persistence_clear_invalid");
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer persistence clear target not found vhost={} route={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    error
                );
                record_load_balancer_event(vhost, route, None, "persistence_clear_not_found");
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(not(feature = "load-balancer"))]
    fn load_balancer_member_weight_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _member: Option<&str>,
        _weight: Option<&str>,
    ) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }

    #[cfg(not(feature = "load-balancer"))]
    fn load_balancer_member_state_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _member: Option<&str>,
        _state: Option<&str>,
    ) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }

    #[cfg(not(feature = "load-balancer"))]
    fn load_balancer_member_add_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _member: Option<&str>,
        _weight: Option<&str>,
    ) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }

    #[cfg(not(feature = "load-balancer"))]
    fn load_balancer_member_remove_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _member: Option<&str>,
    ) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }

    #[cfg(not(feature = "load-balancer"))]
    fn load_balancer_member_update_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _member: Option<&str>,
        _updated_member: Option<&str>,
        _weight: Option<&str>,
    ) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }

    #[cfg(not(feature = "load-balancer"))]
    fn load_balancer_persistence_clear_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
    ) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }

    #[cfg(feature = "cache")]
    fn cache_status_response(&self) -> AdminResponse {
        match self.proxy.cache_runtime_stats() {
            Ok(stats) => json_response_value(
                StatusCode::OK,
                &json!({
                    "status": "ok",
                    "totals": cache_totals_json(&stats.totals),
                    "vhosts": cache_vhost_stats_json(&stats.vhosts),
                }),
            ),
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(not(feature = "cache"))]
    fn cache_status_response(&self) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(feature = "cache")]
    fn cache_activity_reset_response(&self) -> AdminResponse {
        let result = self.proxy.reset_cache_activity();
        json_response_value(
            StatusCode::OK,
            &json!({
                "status": "ok",
                "vhosts": result.vhosts,
                "enabled_vhosts": result.enabled_vhosts,
                "enabled_vhost_ratio_per_mille": ratio_per_mille(result.enabled_vhosts, result.vhosts),
                "tiered_vhosts": result.tiered_vhosts,
                "tiered_vhost_ratio_per_mille": ratio_per_mille(result.tiered_vhosts, result.vhosts),
                "configured_routes": result.configured_routes,
                "routes_total": result.routes_total,
                "cache_route_coverage_ratio_per_mille": ratio_per_mille(result.routes_total, result.configured_routes),
                "enabled_routes": result.enabled_routes,
                "enabled_route_ratio_per_mille": ratio_per_mille(result.enabled_routes, result.routes_total),
                "tiered_routes": result.tiered_routes,
                "tiered_route_ratio_per_mille": ratio_per_mille(result.tiered_routes, result.routes_total),
                "memory_tiers": result.memory_tiers,
                "disk_tiers": result.disk_tiers,
            }),
        )
    }

    #[cfg(not(feature = "cache"))]
    fn cache_activity_reset_response(&self) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
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

    #[cfg(feature = "cache")]
    fn cache_purge_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        host: Option<&str>,
        method: Option<&str>,
        path: Option<&str>,
        query: Option<&str>,
    ) -> AdminResponse {
        let host = match validated_cache_purge_host(host) {
            Ok(host) => host,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let method = match validated_cache_purge_method(method) {
            Ok(method) => method,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let path = match validated_cache_purge_path(path) {
            Ok(path) => path,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let query = match validated_cache_purge_query(query) {
            Ok(query) => query,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };

        match self
            .proxy
            .purge_image_cache(fluxheim_cache::CachePurgeRequest {
                vhost: vhost.filter(|vhost| !vhost.trim().is_empty()),
                route: route.filter(|route| !route.trim().is_empty()),
                host,
                method,
                path,
                query,
            }) {
            Ok(result) => {
                record_cache_purge_metric(
                    "exact",
                    &result.vhost,
                    result.route.as_deref(),
                    "normal",
                );
                json_response_value(
                    StatusCode::OK,
                    &json!({
                        "status": "ok",
                        "purged": result.purged(),
                        "not_purged": result.not_purged(),
                        "vhost": result.vhost,
                        "route": result.route.as_deref(),
                        "scope": cache_scope(result.route.as_deref()),
                        "host": result.host,
                        "method": result.method,
                        "path": result.path,
                        "query": result.query.as_deref(),
                        "cache_key": result.cache_key,
                        "memory_purged": result.memory_purged,
                        "memory_not_purged": result.memory_not_purged(),
                        "disk_purged": result.disk_purged,
                        "disk_not_purged": result.disk_not_purged(),
                    }),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "cache")]
    fn cache_purge_bulk_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        host: Option<&str>,
        method: Option<&str>,
        paths: Vec<&str>,
        query: Option<&str>,
    ) -> AdminResponse {
        let host = match validated_cache_purge_host(host) {
            Ok(host) => host,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let method = match validated_cache_purge_method(method) {
            Ok(method) => method,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let paths = paths
            .into_iter()
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return error_response(
                StatusCode::BAD_REQUEST,
                "at least one cache purge path is required",
            );
        }
        if paths.len() > MAX_CACHE_PURGE_BULK_PATHS {
            return error_response(
                StatusCode::BAD_REQUEST,
                "too many cache purge paths requested",
            );
        }
        for path in &paths {
            if let Err(message) = validate_cache_purge_path_value(path) {
                return error_response(StatusCode::BAD_REQUEST, message);
            }
        }
        let query = match validated_cache_purge_query(query) {
            Ok(query) => query,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };

        match self
            .proxy
            .purge_image_cache_bulk(fluxheim_cache::CacheBulkPurgeRequest {
                vhost: vhost.filter(|vhost| !vhost.trim().is_empty()),
                route: route.filter(|route| !route.trim().is_empty()),
                host,
                method,
                paths,
                query,
            }) {
            Ok(result) => {
                record_cache_purge_metric("bulk", &result.vhost, result.route(), "normal");
                json_response_value(
                    StatusCode::OK,
                    &json!({
                        "status": "ok",
                        "requested": result.requested(),
                        "purged": result.purged(),
                        "not_purged": result.not_purged(),
                        "purged_ratio_per_mille": ratio_per_mille_usize(result.purged(), result.requested()),
                        "not_purged_ratio_per_mille": ratio_per_mille_usize(result.not_purged(), result.requested()),
                        "vhost": result.vhost,
                        "route": result.route(),
                        "scope": cache_scope(result.route()),
                        "memory_purged": result.memory_purged(),
                        "memory_not_purged": result.memory_not_purged(),
                        "memory_purged_ratio_per_mille": ratio_per_mille_usize(result.memory_purged(), result.requested()),
                        "memory_not_purged_ratio_per_mille": ratio_per_mille_usize(result.memory_not_purged(), result.requested()),
                        "disk_purged": result.disk_purged(),
                        "disk_not_purged": result.disk_not_purged(),
                        "disk_purged_ratio_per_mille": ratio_per_mille_usize(result.disk_purged(), result.requested()),
                        "disk_not_purged_ratio_per_mille": ratio_per_mille_usize(result.disk_not_purged(), result.requested()),
                        "results": cache_purge_results_json(&result.results),
                    }),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "cache")]
    fn cache_purge_index_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        limit: Option<&str>,
        batches: Option<&str>,
        soft: bool,
    ) -> AdminResponse {
        let Some(vhost) = vhost.map(str::trim).filter(|vhost| !vhost.is_empty()) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "cache indexed purge vhost is required",
            );
        };
        let limit = match validated_cache_indexed_purge_limit(limit) {
            Ok(limit) => limit,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let batches = match validated_cache_indexed_purge_batches(batches) {
            Ok(batches) => batches,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let route = route.filter(|route| !route.trim().is_empty());

        match repeat_cache_indexed_purge(batches, || {
            self.proxy
                .purge_indexed_image_cache(fluxheim_cache::CacheIndexedPurgeRequest {
                    vhost,
                    route,
                    limit,
                    soft,
                })
        }) {
            Ok(result) => {
                record_cache_purge_metric(
                    "index",
                    &result.vhost,
                    result.route.as_deref(),
                    cache_indexed_purge_mode(soft),
                );
                json_response_value(
                    StatusCode::OK,
                    &cache_indexed_purge_json(&result, soft, limit, batches, None, None, None),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "cache")]
    fn cache_purge_prefix_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        path_prefix: Option<&str>,
        limit: Option<&str>,
        batches: Option<&str>,
        soft: bool,
    ) -> AdminResponse {
        let Some(vhost) = vhost.map(str::trim).filter(|vhost| !vhost.is_empty()) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "cache path-prefix purge vhost is required",
            );
        };
        let path_prefix = match validated_cache_purge_path_prefix(path_prefix) {
            Ok(path_prefix) => path_prefix,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let limit = match validated_cache_indexed_purge_limit(limit) {
            Ok(limit) => limit,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let batches = match validated_cache_indexed_purge_batches(batches) {
            Ok(batches) => batches,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let route = route.filter(|route| !route.trim().is_empty());

        match repeat_cache_indexed_purge(batches, || {
            self.proxy.purge_indexed_image_cache_path_prefix(
                fluxheim_cache::CacheIndexedPathPrefixPurgeRequest {
                    vhost,
                    route,
                    path_prefix,
                    limit,
                    soft,
                },
            )
        }) {
            Ok(result) => {
                record_cache_purge_metric(
                    "prefix",
                    &result.vhost,
                    result.route.as_deref(),
                    cache_indexed_purge_mode(soft),
                );
                json_response_value(
                    StatusCode::OK,
                    &cache_indexed_purge_json(
                        &result,
                        soft,
                        limit,
                        batches,
                        Some(("path_prefix", path_prefix)),
                        None,
                        None,
                    ),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "cache")]
    fn cache_purge_tag_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        cache_tag: Option<&str>,
        limit: Option<&str>,
        batches: Option<&str>,
        soft: bool,
    ) -> AdminResponse {
        let Some(vhost) = vhost.map(str::trim).filter(|vhost| !vhost.is_empty()) else {
            return error_response(StatusCode::BAD_REQUEST, "cache tag purge vhost is required");
        };
        let cache_tag = match validated_cache_purge_tag(cache_tag) {
            Ok(cache_tag) => cache_tag,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let limit = match validated_cache_indexed_purge_limit(limit) {
            Ok(limit) => limit,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let batches = match validated_cache_indexed_purge_batches(batches) {
            Ok(batches) => batches,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let route = route.filter(|route| !route.trim().is_empty());

        match repeat_cache_indexed_purge(batches, || {
            self.proxy
                .purge_indexed_image_cache_tag(fluxheim_cache::CacheIndexedTagPurgeRequest {
                    vhost,
                    route,
                    cache_tag,
                    limit,
                    soft,
                })
        }) {
            Ok(result) => {
                record_cache_purge_metric(
                    "tag",
                    &result.vhost,
                    result.route.as_deref(),
                    cache_indexed_purge_mode(soft),
                );
                json_response_value(
                    StatusCode::OK,
                    &cache_indexed_purge_json(
                        &result,
                        soft,
                        limit,
                        batches,
                        None,
                        Some(("cache_tag", cache_tag)),
                        None,
                    ),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "cache")]
    fn cache_purge_stale_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        limit: Option<&str>,
        batches: Option<&str>,
        dry_run: bool,
    ) -> AdminResponse {
        let Some(vhost) = vhost.map(str::trim).filter(|vhost| !vhost.is_empty()) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "cache stale purge vhost is required",
            );
        };
        let limit = match validated_cache_indexed_purge_limit(limit) {
            Ok(limit) => limit,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let batches = match validated_cache_indexed_purge_batches(batches) {
            Ok(batches) => batches,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let route = route.filter(|route| !route.trim().is_empty());

        match repeat_cache_stale_purge(batches, dry_run, || {
            self.proxy
                .purge_stale_image_cache(fluxheim_cache::CacheStalePurgeRequest {
                    vhost,
                    route,
                    limit,
                    dry_run,
                })
        }) {
            Ok(result) => {
                record_cache_purge_metric(
                    "stale",
                    &result.vhost,
                    result.route(),
                    cache_stale_purge_mode(dry_run),
                );
                let repeat_required = result.truncated()
                    && !result.increase_limit_required
                    && result.batches >= batches;
                json_response_value(
                    StatusCode::OK,
                    &json!({
                        "status": "ok",
                        "dry_run": dry_run,
                        "scanned": result.scanned(),
                        "stale": result.stale(),
                        "would_purge": stale_would_purge(dry_run, result.stale()),
                        "purged": result.purged(),
                        "not_purged": result.not_purged(),
                        "purged_ratio_per_mille": ratio_per_mille_usize(result.purged(), result.stale()),
                        "not_purged_ratio_per_mille": ratio_per_mille_usize(result.not_purged(), result.stale()),
                        "truncated": result.truncated(),
                        "repeat_required": repeat_required,
                        "limit": limit,
                        "batches": result.batches,
                        "batch_limit": batches,
                        "batches_exhausted": repeat_required,
                        "increase_limit_required": result.increase_limit_required,
                        "vhost": result.vhost,
                        "route": result.route(),
                        "scope": cache_scope(result.route()),
                        "memory_scanned": result.memory_scanned,
                        "memory_stale": result.memory_stale,
                        "memory_would_purge": stale_would_purge(dry_run, result.memory_stale),
                        "memory_purged": result.memory_purged,
                        "memory_not_purged": result.memory_stale.saturating_sub(result.memory_purged),
                        "memory_truncated": result.memory_truncated,
                        "disk_scanned": result.disk_scanned,
                        "disk_stale": result.disk_stale,
                        "disk_would_purge": stale_would_purge(dry_run, result.disk_stale),
                        "disk_purged": result.disk_purged,
                        "disk_not_purged": result.disk_stale.saturating_sub(result.disk_purged),
                        "disk_truncated": result.disk_truncated,
                    }),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "cache")]
    fn cache_purge_wildcard_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        path_pattern: Option<&str>,
        limit: Option<&str>,
        batches: Option<&str>,
        soft: bool,
    ) -> AdminResponse {
        let Some(vhost) = vhost.map(str::trim).filter(|vhost| !vhost.is_empty()) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "cache wildcard purge vhost is required",
            );
        };
        let path_pattern = match validated_cache_purge_path_pattern(path_pattern) {
            Ok(path_pattern) => path_pattern,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let limit = match validated_cache_indexed_purge_limit(limit) {
            Ok(limit) => limit,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let batches = match validated_cache_indexed_purge_batches(batches) {
            Ok(batches) => batches,
            Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
        };
        let route = route.filter(|route| !route.trim().is_empty());

        match repeat_cache_indexed_purge(batches, || {
            self.proxy.purge_indexed_image_cache_path_pattern(
                fluxheim_cache::CacheIndexedPathPatternPurgeRequest {
                    vhost,
                    route,
                    path_pattern,
                    limit,
                    soft,
                },
            )
        }) {
            Ok(result) => {
                record_cache_purge_metric(
                    "wildcard",
                    &result.vhost,
                    result.route.as_deref(),
                    cache_indexed_purge_mode(soft),
                );
                json_response_value(
                    StatusCode::OK,
                    &cache_indexed_purge_json(
                        &result,
                        soft,
                        limit,
                        batches,
                        None,
                        None,
                        Some(("path_pattern", path_pattern)),
                    ),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(not(feature = "cache"))]
    fn cache_purge_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _host: Option<&str>,
        _method: Option<&str>,
        _path: Option<&str>,
        _query: Option<&str>,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(not(feature = "cache"))]
    fn cache_purge_bulk_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _host: Option<&str>,
        _method: Option<&str>,
        _paths: Vec<&str>,
        _query: Option<&str>,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(not(feature = "cache"))]
    fn cache_purge_index_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _limit: Option<&str>,
        _batches: Option<&str>,
        _soft: bool,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(not(feature = "cache"))]
    fn cache_purge_prefix_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _path_prefix: Option<&str>,
        _limit: Option<&str>,
        _batches: Option<&str>,
        _soft: bool,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(not(feature = "cache"))]
    fn cache_purge_tag_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _cache_tag: Option<&str>,
        _limit: Option<&str>,
        _batches: Option<&str>,
        _soft: bool,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(not(feature = "cache"))]
    fn cache_purge_stale_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _limit: Option<&str>,
        _batches: Option<&str>,
        _dry_run: bool,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(not(feature = "cache"))]
    fn cache_purge_wildcard_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _path_pattern: Option<&str>,
        _limit: Option<&str>,
        _batches: Option<&str>,
        _soft: bool,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
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

fn admin_native_http1_response(response: AdminResponse) -> fluxheim_server::NativeHttp1Response {
    fluxheim_server::NativeHttp1Response::new(
        response.status.as_u16(),
        response
            .status
            .canonical_reason()
            .unwrap_or("Admin Response"),
        response.body,
    )
    .with_header(header::CONTENT_TYPE.as_str(), response.content_type)
    .with_header(header::CACHE_CONTROL.as_str(), "no-store")
}

fn native_admin_headers(headers: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let Ok(name) = http::HeaderName::try_from(name.as_str()) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::try_from(value.as_str()) else {
            continue;
        };
        map.append(name, value);
    }
    map
}

/// Return `(path, query)` from the raw HTTP request target without
/// percent-decoding. Admin routes must match encoded path strings so a future
/// normalization change cannot introduce a route-bypass gap.
fn native_admin_target_parts(target: &str) -> (&str, Option<&str>) {
    let target = match target.split_once('#') {
        Some((before_fragment, _)) => before_fragment,
        None => target,
    };
    if let Some(rest) = target.strip_prefix("http://") {
        native_admin_absolute_target_parts(rest)
    } else if let Some(rest) = target.strip_prefix("https://") {
        native_admin_absolute_target_parts(rest)
    } else {
        native_admin_origin_target_parts(target)
    }
}

fn native_admin_absolute_target_parts(target_after_scheme: &str) -> (&str, Option<&str>) {
    let path_index = target_after_scheme.find('/');
    let query_index = target_after_scheme.find('?');
    match (path_index, query_index) {
        (Some(path_index), Some(query_index)) if query_index < path_index => {
            ("/", nonempty_query(&target_after_scheme[query_index + 1..]))
        }
        (Some(path_index), _) => {
            native_admin_origin_target_parts(&target_after_scheme[path_index..])
        }
        (None, Some(query_index)) => ("/", nonempty_query(&target_after_scheme[query_index + 1..])),
        (None, None) => ("/", None),
    }
}

fn native_admin_origin_target_parts(target: &str) -> (&str, Option<&str>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    (path, (!query.is_empty()).then_some(query))
}

fn nonempty_query(query: &str) -> Option<&str> {
    (!query.is_empty()).then_some(query)
}

fn authorization_header(headers: &HeaderMap) -> Option<&str> {
    header_value(headers, header::AUTHORIZATION.as_str())
}

impl AdminClientCertificatePolicy {
    fn from_config(config: &AdminConfig) -> Self {
        Self {
            required: config.admin_client_certificate_required(),
            sha256_header: config.client_certificate.sha256_header.to_ascii_lowercase(),
            allow_sha256: normalized_sha256_fingerprints(&config.client_certificate.allow_sha256),
            deny_sha256: normalized_sha256_fingerprints(&config.client_certificate.deny_sha256),
        }
    }

    fn allows(&self, headers: &HeaderMap) -> AdminClientCertificateDecision {
        if !self.active() {
            return AdminClientCertificateDecision::Allowed;
        }

        let fingerprint = match single_sha256_header(headers, &self.sha256_header) {
            AdminClientCertificateHeader::Present(fingerprint) => fingerprint,
            AdminClientCertificateHeader::Invalid => {
                return AdminClientCertificateDecision::Denied;
            }
            AdminClientCertificateHeader::Missing
                if self.required || !self.allow_sha256.is_empty() =>
            {
                return AdminClientCertificateDecision::Required;
            }
            AdminClientCertificateHeader::Missing => {
                return AdminClientCertificateDecision::Allowed;
            }
        };

        if admin_fingerprint_list_contains(&self.deny_sha256, &fingerprint) {
            return AdminClientCertificateDecision::Denied;
        }

        if !self.allow_sha256.is_empty()
            && !admin_fingerprint_list_contains(&self.allow_sha256, &fingerprint)
        {
            return AdminClientCertificateDecision::Denied;
        }

        AdminClientCertificateDecision::Allowed
    }

    fn active(&self) -> bool {
        self.required || !self.allow_sha256.is_empty() || !self.deny_sha256.is_empty()
    }
}

fn single_sha256_header(headers: &HeaderMap, name: &str) -> AdminClientCertificateHeader {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return AdminClientCertificateHeader::Missing;
    };
    if values.next().is_some() {
        return AdminClientCertificateHeader::Invalid;
    }
    let Ok(value) = value.to_str() else {
        return AdminClientCertificateHeader::Invalid;
    };
    let value = value.trim();
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        AdminClientCertificateHeader::Present(value.to_ascii_lowercase())
    } else {
        AdminClientCertificateHeader::Invalid
    }
}

fn normalized_sha256_fingerprints(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn admin_fingerprint_list_contains(values: &[String], fingerprint: &str) -> bool {
    let fingerprint = fingerprint.as_bytes();
    let mut matched = 0u8;
    for value in values {
        matched |= value.as_bytes().ct_eq(fingerprint).unwrap_u8();
    }
    matched == 1
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn load_admin_token(
    config: &AdminConfig,
) -> Result<Zeroizing<String>, Box<dyn Error + Send + Sync>> {
    let raw = match (&config.token_env, &config.token_file) {
        (Some(env_name), None) => Zeroizing::new(
            env::var(env_name)
                .map_err(|error| format!("failed to read admin token env {env_name:?}: {error}"))?,
        ),
        (None, Some(path)) => read_secret_file(path)?,
        _ => return Err("admin token source is invalid".into()),
    };
    let token = Zeroizing::new(raw.trim().to_owned());
    if token.is_empty() {
        Err("admin token cannot be empty".into())
    } else if token.len() > MAX_ADMIN_TOKEN_BYTES {
        Err(format!("admin token cannot exceed {MAX_ADMIN_TOKEN_BYTES} bytes").into())
    } else {
        Ok(token)
    }
}

fn read_secret_file(path: &Path) -> Result<Zeroizing<String>, Box<dyn Error + Send + Sync>> {
    if secret_parent_path_contains_symlink(path).map_err(|error| {
        format!(
            "failed to inspect admin token parent path {}: {error}",
            path.display()
        )
    })? {
        return Err(format!(
            "admin token file {} must not be below a symlinked directory",
            path.display()
        )
        .into());
    }

    #[cfg(unix)]
    if fluxheim_config::fs_trust::existing_parent_has_insecure_write_permissions(path).map_err(
        |error| {
            format!(
                "failed to inspect admin token parent path {}: {error}",
                path.display()
            )
        },
    )? {
        return Err(format!(
            "admin token file {} must not be below a group- or world-writable directory",
            path.display()
        )
        .into());
    }

    let file = open_regular_secret_file(path)?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "failed to inspect admin token file {}: {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!("admin token file {} must be a regular file", path.display()).into());
    }
    if metadata.len() > MAX_ADMIN_TOKEN_FILE_BYTES {
        return Err(format!(
            "admin token file {} is too large; limit is {MAX_ADMIN_TOKEN_FILE_BYTES} bytes",
            path.display()
        )
        .into());
    }

    read_bounded_secret_file(file, path, MAX_ADMIN_TOKEN_FILE_BYTES)
}

fn read_bounded_secret_file(
    file: fs::File,
    path: &Path,
    max_bytes: u64,
) -> Result<Zeroizing<String>, Box<dyn Error + Send + Sync>> {
    let mut token = Zeroizing::new(String::new());
    let mut limited = file.take(max_bytes.saturating_add(1));
    limited.read_to_string(&mut token).map_err(|error| {
        format!(
            "failed to read admin token file {}: {error}",
            path.display()
        )
    })?;
    if token.len() as u64 > max_bytes {
        return Err(format!(
            "admin token file {} changed while reading and exceeded {max_bytes} bytes",
            path.display(),
        )
        .into());
    }
    Ok(token)
}

fn secret_parent_path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let Some(parent) = path.parent() else {
        return Ok(false);
    };
    if parent.as_os_str().is_empty() {
        return Ok(false);
    }

    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

#[cfg(unix)]
fn open_regular_secret_file(path: &Path) -> Result<fs::File, Box<dyn Error + Send + Sync>> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(rustix_to_io_error)
    .map_err(|error| {
        format!(
            "failed to open admin token file {} without following symlinks: {error}",
            path.display()
        )
    })?;
    Ok(fd.into())
}

#[cfg(unix)]
fn rustix_to_io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(not(unix))]
fn open_regular_secret_file(path: &Path) -> Result<fs::File, Box<dyn Error + Send + Sync>> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect admin token file {}: {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!("admin token file {} must be a regular file", path.display()).into());
    }

    fs::File::open(path).map_err(|error| {
        format!(
            "failed to open admin token file {}: {error}",
            path.display()
        )
        .into()
    })
}

fn authorized(header: Option<&str>, token: &AdminToken) -> bool {
    let Some(header) = header else {
        return false;
    };
    let Some(candidate) = header.trim().strip_prefix("Bearer ") else {
        return false;
    };
    let candidate = candidate.trim();
    let candidate = Zeroizing::new(candidate.as_bytes().to_vec());
    let within_limit = candidate.len() <= MAX_ADMIN_TOKEN_BYTES;
    constant_time_eq(candidate.as_slice(), token) & within_limit
}

fn constant_time_eq(candidate: &[u8], token: &AdminToken) -> bool {
    let candidate_digest = digest_admin_token(candidate, token.mac_provider);
    let candidate_len = (candidate.len() as u64).to_le_bytes();
    let token_len = (token.len as u64).to_le_bytes();
    (candidate_digest.ct_eq(&token.digest) & candidate_len.ct_eq(&token_len))
        .declassify("admin bearer-token comparison result is public")
}

fn digest_admin_token(
    token: &[u8],
    mac_provider: crate::internal_crypto::AdminMacProvider,
) -> [u8; 32] {
    crate::internal_crypto::admin_hmac_sha256_or_abort(
        mac_provider,
        "admin bearer-token",
        token_mac_key(),
        token,
    )
}

fn token_mac_key() -> &'static [u8; 32] {
    static TOKEN_MAC_KEY: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();
    TOKEN_MAC_KEY.get_or_init(|| {
        let mut key = [0_u8; 32];
        if let Err(error) = getrandom::fill(&mut key) {
            log::error!(
                "fatal: admin token MAC key generation failed; cannot continue without entropy: {error}"
            );
            std::process::abort();
        }
        Zeroizing::new(key)
    })
}

fn json_response(status: StatusCode, body: &[u8]) -> AdminResponse {
    if body.len() > MAX_ADMIN_JSON_RESPONSE_BYTES {
        return AdminResponse {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            content_type: "application/json",
            body: br#"{"status":"error","error":"admin JSON response exceeded configured safety limit"}"#
                .to_vec(),
        };
    }

    AdminResponse {
        status,
        content_type: "application/json",
        body: body.to_vec(),
    }
}

fn json_response_value(status: StatusCode, body: &impl Serialize) -> AdminResponse {
    match serde_json::to_vec(body) {
        Ok(body) => json_response(status, &body),
        Err(error) => internal_error_response(&error),
    }
}

fn empty_response(status: StatusCode) -> AdminResponse {
    AdminResponse {
        status,
        content_type: "application/octet-stream",
        body: Vec::new(),
    }
}

fn error_response(status: StatusCode, error: &str) -> AdminResponse {
    let error = bounded_admin_error_message(error);
    json_response_value(status, &json!({"status": "error", "error": error}))
}

fn internal_error_response(error: &impl std::fmt::Display) -> AdminResponse {
    log::error!("admin internal error: {error}");
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        br#"{"status":"error","error":"internal_error"}"#,
    )
}

fn bounded_admin_error_message(error: &str) -> String {
    let mut bounded: String = error.chars().take(MAX_ADMIN_ERROR_MESSAGE_CHARS).collect();
    if error.chars().count() > MAX_ADMIN_ERROR_MESSAGE_CHARS {
        bounded.push_str("...");
    }
    bounded
}

#[cfg(feature = "metrics")]
fn record_admin_auth_event(event: &str, scope: AdminAuthThrottleScope) {
    crate::metrics::record_admin_auth_event(event, scope.as_str());
}

#[cfg(not(feature = "metrics"))]
fn record_admin_auth_event(_event: &str, _scope: AdminAuthThrottleScope) {}

#[cfg(all(feature = "metrics", feature = "load-balancer"))]
fn record_load_balancer_event(vhost: &str, route: Option<&str>, member: Option<&str>, event: &str) {
    crate::metrics::record_load_balancer_event(vhost, route, member, event);
}

#[cfg(all(not(feature = "metrics"), feature = "load-balancer"))]
fn record_load_balancer_event(
    _vhost: &str,
    _route: Option<&str>,
    _member: Option<&str>,
    _event: &str,
) {
}

#[cfg(all(feature = "load-balancer", not(feature = "privacy-mode")))]
fn load_balancer_metric_member_label<'a>(
    alias: Option<&'a str>,
    member: &'a str,
) -> Option<&'a str> {
    alias.or(Some(member))
}

#[cfg(all(feature = "load-balancer", feature = "privacy-mode"))]
fn load_balancer_metric_member_label<'a>(
    alias: Option<&'a str>,
    _member: &'a str,
) -> Option<&'a str> {
    alias
}

#[cfg(all(feature = "load-balancer", not(feature = "privacy-mode")))]
fn load_balancer_display_member(alias: Option<&str>, member: &str) -> String {
    let _ = alias;
    member.to_owned()
}

#[cfg(all(feature = "load-balancer", feature = "privacy-mode"))]
fn load_balancer_display_member(alias: Option<&str>, _member: &str) -> String {
    alias.unwrap_or("redacted").to_owned()
}

fn snapshot_json(snapshot: &ConfigSnapshot, current: Option<&str>) -> Value {
    json!({
        "id": snapshot.id,
        "current": current == Some(snapshot.id.as_str()),
        "created_unix_secs": snapshot.metadata.created_unix_secs,
        "message": snapshot.metadata.message.as_deref(),
    })
}

fn pending_validation_json(pending: Option<&PendingValidation>) -> Value {
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

fn reload_reasons_json(reasons: &[ReloadReason]) -> Vec<String> {
    reasons.iter().map(ToString::to_string).collect()
}

#[cfg(feature = "udp-proxy")]
fn udp_status_json(config: &Config) -> Value {
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
fn udp_route_mode_label(mode: crate::config::UdpRouteMode) -> &'static str {
    match mode {
        crate::config::UdpRouteMode::DnsLoadBalance => "dns-load-balance",
        crate::config::UdpRouteMode::SyslogForward => "syslog-forward",
        crate::config::UdpRouteMode::QuicPassThrough => "quic-pass-through",
        crate::config::UdpRouteMode::GameProxy => "game-proxy",
    }
}

#[cfg(feature = "cache")]
fn cache_scope(route: Option<&str>) -> &'static str {
    if route.is_some() { "route" } else { "vhost" }
}

#[cfg(all(feature = "cache", feature = "metrics"))]
fn record_cache_purge_metric(operation: &str, vhost: &str, route: Option<&str>, mode: &str) {
    crate::metrics::record_cache_purge(operation, vhost, route, mode);
}

#[cfg(all(feature = "cache", not(feature = "metrics")))]
fn record_cache_purge_metric(_operation: &str, _vhost: &str, _route: Option<&str>, _mode: &str) {}

#[cfg(feature = "cache")]
fn cache_indexed_purge_mode(soft: bool) -> &'static str {
    if soft { "soft" } else { "normal" }
}

#[cfg(feature = "cache")]
fn cache_stale_purge_mode(dry_run: bool) -> &'static str {
    if dry_run { "dry_run" } else { "normal" }
}

#[cfg(feature = "cache")]
fn cache_purge_results_json(results: &[fluxheim_cache::CachePurgeResult]) -> Vec<Value> {
    results
        .iter()
        .map(|result| {
            json!({
                "purged": result.purged(),
                "not_purged": result.not_purged(),
                "route": result.route.as_deref(),
                "scope": cache_scope(result.route.as_deref()),
                "host": result.host,
                "method": result.method,
                "path": result.path,
                "query": result.query.as_deref(),
                "cache_key": result.cache_key,
                "memory_purged": result.memory_purged,
                "memory_not_purged": result.memory_not_purged(),
                "disk_purged": result.disk_purged,
                "disk_not_purged": result.disk_not_purged(),
            })
        })
        .collect()
}

#[cfg(feature = "cache")]
fn cache_totals_json(totals: &fluxheim_cache::CacheRuntimeTotals) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("vhosts".to_owned(), json!(totals.vhosts));
    object.insert("enabled_vhosts".to_owned(), json!(totals.enabled_vhosts));
    object.insert(
        "enabled_vhost_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(totals.enabled_vhosts, totals.vhosts)),
    );
    object.insert("tiered_vhosts".to_owned(), json!(totals.tiered_vhosts));
    object.insert(
        "tiered_vhost_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(totals.tiered_vhosts, totals.vhosts)),
    );
    object.insert(
        "configured_routes".to_owned(),
        json!(totals.configured_routes),
    );
    object.insert("routes_total".to_owned(), json!(totals.routes_total));
    object.insert(
        "cache_route_coverage_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.routes_total,
            totals.configured_routes
        )),
    );
    object.insert("enabled_routes".to_owned(), json!(totals.enabled_routes));
    object.insert(
        "enabled_route_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(totals.enabled_routes, totals.routes_total)),
    );
    object.insert("tiered_routes".to_owned(), json!(totals.tiered_routes));
    object.insert(
        "tiered_route_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(totals.tiered_routes, totals.routes_total)),
    );
    object.insert(
        "lock_enabled_policies".to_owned(),
        json!(totals.lock_enabled_policies),
    );
    object.insert(
        "lock_enabled_policy_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.lock_enabled_policies,
            totals.enabled_cache_policies()
        )),
    );
    object.insert(
        "origin_protection_enabled_policies".to_owned(),
        json!(totals.origin_protection_enabled_policies),
    );
    object.insert(
        "origin_protection_enabled_policy_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.origin_protection_enabled_policies,
            totals.enabled_cache_policies()
        )),
    );
    object.insert(
        "origin_protection_max_concurrent_fills".to_owned(),
        json!(totals.origin_protection_max_concurrent_fills),
    );
    object.insert(
        "peer_fill_enabled_policies".to_owned(),
        json!(totals.peer_fill_enabled_policies),
    );
    object.insert(
        "peer_fill_enabled_policy_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.peer_fill_enabled_policies,
            totals.enabled_cache_policies()
        )),
    );
    object.insert("peer_fill_peers".to_owned(), json!(totals.peer_fill_peers));
    object.insert(
        "peer_fill_max_concurrent_requests".to_owned(),
        json!(totals.peer_fill_max_concurrent_requests),
    );
    object.insert("memory_tiers".to_owned(), json!(totals.memory_tiers));
    object.insert("memory_entries".to_owned(), json!(totals.memory_entries));
    object.insert(
        "memory_weighted_size_bytes".to_owned(),
        json!(totals.memory_weighted_size_bytes),
    );
    object.insert(
        "memory_average_weighted_size_bytes".to_owned(),
        json!(average_bytes(
            totals.memory_weighted_size_bytes,
            totals.memory_entries
        )),
    );
    object.insert(
        "memory_max_size_bytes".to_owned(),
        json!(totals.memory_max_size_bytes),
    );
    object.insert(
        "memory_fill_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.memory_weighted_size_bytes,
            totals.memory_max_size_bytes
        )),
    );
    object.insert(
        "memory_purge_index_entries".to_owned(),
        json!(totals.memory_purge_index_entries),
    );
    object.insert(
        "memory_purge_index_max_entries".to_owned(),
        json!(totals.memory_purge_index_max_entries),
    );
    object.insert(
        "memory_purge_index_fill_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.memory_purge_index_entries,
            totals.memory_purge_index_max_entries
        )),
    );
    object.insert("disk_tiers".to_owned(), json!(totals.disk_tiers));
    object.insert("disk_entries".to_owned(), json!(totals.disk_entries));
    object.insert("disk_size_bytes".to_owned(), json!(totals.disk_size_bytes));
    object.insert(
        "disk_average_object_size_bytes".to_owned(),
        json!(average_bytes(totals.disk_size_bytes, totals.disk_entries)),
    );
    object.insert(
        "disk_allocated_size_bytes".to_owned(),
        json!(totals.disk_allocated_size_bytes),
    );
    object.insert(
        "disk_free_size_bytes".to_owned(),
        json!(totals.disk_free_size_bytes),
    );
    object.insert(
        "disk_free_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.disk_free_size_bytes,
            totals.disk_allocated_size_bytes
        )),
    );
    object.insert(
        "disk_free_range_count".to_owned(),
        json!(totals.disk_free_range_count),
    );
    object.insert(
        "disk_largest_free_range_bytes".to_owned(),
        json!(totals.disk_largest_free_range_bytes),
    );
    object.insert("disk_bin_files".to_owned(), json!(totals.disk_bin_files));
    object.insert(
        "disk_max_size_bytes".to_owned(),
        json!(totals.disk_max_size_bytes),
    );
    object.insert(
        "disk_fill_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.disk_size_bytes,
            totals.disk_max_size_bytes
        )),
    );
    object.insert(
        "disk_purge_index_entries".to_owned(),
        json!(totals.disk_purge_index_entries),
    );
    object.insert(
        "disk_purge_index_max_entries".to_owned(),
        json!(totals.disk_purge_index_max_entries),
    );
    object.insert(
        "disk_purge_index_fill_ratio_per_mille".to_owned(),
        json!(ratio_per_mille(
            totals.disk_purge_index_entries,
            totals.disk_purge_index_max_entries
        )),
    );
    object.insert(
        "activity".to_owned(),
        cache_activity_json(&fluxheim_cache::CacheActivityStats {
            hits: totals.hits,
            misses: totals.misses,
            stores: totals.stores,
            store_refusals: totals.store_refusals,
            evictions: totals.evictions,
            purges: totals.purges,
        }),
    );
    Value::Object(object)
}

#[cfg(feature = "cache")]
fn cache_vhost_stats_json(vhosts: &[fluxheim_cache::CacheVhostStats]) -> Vec<Value> {
    vhosts
        .iter()
        .map(|vhost| {
            json!({
                "name": vhost.name,
                "enabled": vhost.enabled,
                "tiered": vhost.tiered,
                "lock_enabled": vhost.lock_enabled,
                "lock_wait_timeout_secs": vhost.lock_wait_timeout_secs,
                "origin_protection_enabled": vhost.origin_protection_enabled,
                "origin_protection_max_concurrent_fills": vhost.origin_protection_max_concurrent_fills,
                "peer_fill_enabled": vhost.peer_fill_enabled,
                "peer_fill_peers": vhost.peer_fill_peers,
                "peer_fill_max_concurrent_requests": vhost.peer_fill_max_concurrent_requests,
                "peer_fill_fail_open": vhost.peer_fill_fail_open,
                "storage_tiers": fluxheim_cache::cache_storage_tiers(vhost.memory.is_some(), vhost.disk.is_some()),
                "configured_routes": vhost.configured_routes,
                "routes_total": vhost.routes_total,
                "cache_route_coverage_ratio_per_mille": ratio_per_mille(vhost.routes_total, vhost.configured_routes),
                "enabled_routes": vhost.enabled_routes,
                "enabled_route_ratio_per_mille": ratio_per_mille(vhost.enabled_routes, vhost.routes_total),
                "tiered_routes": vhost.tiered_routes,
                "tiered_route_ratio_per_mille": ratio_per_mille(vhost.tiered_routes, vhost.routes_total),
                "memory": memory_cache_stats_json(vhost.memory.as_ref()),
                "disk": disk_cache_stats_json(vhost.disk.as_ref()),
                "routes": cache_route_stats_json(&vhost.routes),
            })
        })
        .collect()
}

#[cfg(feature = "cache")]
fn cache_route_stats_json(routes: &[fluxheim_cache::CacheRouteStats]) -> Vec<Value> {
    routes
        .iter()
        .map(|route| {
            json!({
                "name": route.name,
                "enabled": route.enabled,
                "tiered": route.tiered,
                "lock_enabled": route.lock_enabled,
                "lock_wait_timeout_secs": route.lock_wait_timeout_secs,
                "origin_protection_enabled": route.origin_protection_enabled,
                "origin_protection_max_concurrent_fills": route.origin_protection_max_concurrent_fills,
                "peer_fill_enabled": route.peer_fill_enabled,
                "peer_fill_peers": route.peer_fill_peers,
                "peer_fill_max_concurrent_requests": route.peer_fill_max_concurrent_requests,
                "peer_fill_fail_open": route.peer_fill_fail_open,
                "storage_tiers": fluxheim_cache::cache_storage_tiers(route.memory.is_some(), route.disk.is_some()),
                "memory": memory_cache_stats_json(route.memory.as_ref()),
                "disk": disk_cache_stats_json(route.disk.as_ref()),
            })
        })
        .collect()
}

#[cfg(feature = "cache")]
fn memory_cache_stats_json(stats: Option<&fluxheim_cache::MemoryCacheStats>) -> Value {
    let Some(stats) = stats else {
        return Value::Null;
    };

    json!({
        "entries": stats.entries,
        "weighted_size_bytes": stats.weighted_size_bytes,
        "average_weighted_size_bytes": average_bytes(stats.weighted_size_bytes, stats.entries),
        "max_size_bytes": stats.max_size_bytes.as_u64(),
        "fill_ratio_per_mille": ratio_per_mille(stats.weighted_size_bytes, stats.max_size_bytes.as_u64()),
        "max_object_bytes": stats.max_object_bytes.as_u64(),
        "purge_index_entries": stats.purge_index_entries,
        "purge_index_max_entries": stats.purge_index_max_entries,
        "purge_index_fill_ratio_per_mille": ratio_per_mille(stats.purge_index_entries, stats.purge_index_max_entries),
        "activity": cache_activity_json(&stats.activity),
    })
}

#[cfg(feature = "cache")]
fn disk_cache_stats_json(stats: Option<&fluxheim_cache::DiskCacheStats>) -> Value {
    let Some(stats) = stats else {
        return Value::Null;
    };

    json!({
        "backend": stats.backend,
        "entries": stats.entries,
        "size_bytes": stats.size_bytes,
        "average_object_size_bytes": average_bytes(stats.size_bytes, stats.entries),
        "allocated_size_bytes": stats.allocated_size_bytes,
        "free_size_bytes": stats.free_size_bytes,
        "free_ratio_per_mille": ratio_per_mille(stats.free_size_bytes, stats.allocated_size_bytes),
        "free_range_count": stats.free_range_count,
        "largest_free_range_bytes": stats.largest_free_range_bytes,
        "bin_files": stats.bin_files,
        "max_size_bytes": stats.max_size_bytes.as_u64(),
        "fill_ratio_per_mille": ratio_per_mille(stats.size_bytes, stats.max_size_bytes.as_u64()),
        "max_object_bytes": stats.max_object_bytes.as_u64(),
        "purge_index_entries": stats.purge_index_entries,
        "purge_index_max_entries": stats.purge_index_max_entries,
        "purge_index_fill_ratio_per_mille": ratio_per_mille(stats.purge_index_entries, stats.purge_index_max_entries),
        "activity": cache_activity_json(&stats.activity),
    })
}

#[cfg(feature = "cache")]
fn ratio_per_mille(numerator: u64, denominator: u64) -> u64 {
    fluxheim_cache::cache_ratio_per_mille(numerator, denominator)
}

#[cfg(feature = "cache")]
fn ratio_per_mille_usize(numerator: usize, denominator: usize) -> u64 {
    fluxheim_cache::cache_ratio_per_mille_usize(numerator, denominator)
}

#[cfg(feature = "cache")]
fn stale_would_purge(dry_run: bool, stale: usize) -> usize {
    fluxheim_cache::cache_stale_would_purge(dry_run, stale)
}

#[cfg(feature = "cache")]
fn average_bytes(total_bytes: u64, entries: u64) -> u64 {
    fluxheim_cache::cache_average_bytes(total_bytes, entries)
}

#[cfg(feature = "cache")]
fn cache_activity_json(activity: &fluxheim_cache::CacheActivityStats) -> Value {
    let requests = activity.hits.saturating_add(activity.misses);
    let hit_ratio_per_mille = activity
        .hits
        .saturating_mul(1000)
        .checked_div(requests)
        .unwrap_or(0);
    let miss_ratio_per_mille = activity
        .misses
        .saturating_mul(1000)
        .checked_div(requests)
        .unwrap_or(0);
    let store_attempts = activity.stores.saturating_add(activity.store_refusals);
    let store_ratio_per_mille = activity
        .stores
        .saturating_mul(1000)
        .checked_div(store_attempts)
        .unwrap_or(0);
    let store_refusal_ratio_per_mille = activity
        .store_refusals
        .saturating_mul(1000)
        .checked_div(store_attempts)
        .unwrap_or(0);
    let eviction_ratio_per_mille = ratio_per_mille(activity.evictions, activity.stores);
    json!({
        "hits": activity.hits,
        "misses": activity.misses,
        "requests": requests,
        "hit_ratio_per_mille": hit_ratio_per_mille,
        "miss_ratio_per_mille": miss_ratio_per_mille,
        "stores": activity.stores,
        "store_refusals": activity.store_refusals,
        "store_attempts": store_attempts,
        "store_ratio_per_mille": store_ratio_per_mille,
        "store_refusal_ratio_per_mille": store_refusal_ratio_per_mille,
        "evictions": activity.evictions,
        "eviction_ratio_per_mille": eviction_ratio_per_mille,
        "purges": activity.purges,
    })
}

#[cfg(feature = "cache")]
fn cache_indexed_purge_json(
    result: &CacheIndexedPurgeBatchResult,
    soft: bool,
    limit: usize,
    batches: usize,
    path_prefix: Option<(&str, &str)>,
    cache_tag: Option<(&str, &str)>,
    path_pattern: Option<(&str, &str)>,
) -> Value {
    let mut body = json!({
        "status": "ok",
        "soft": soft,
        "matched": result.matched(),
        "purged": result.purged(),
        "not_purged": result.not_purged(),
        "purged_ratio_per_mille": ratio_per_mille_usize(result.purged(), result.matched()),
        "not_purged_ratio_per_mille": ratio_per_mille_usize(result.not_purged(), result.matched()),
        "truncated": result.truncated(),
        "repeat_required": result.truncated(),
        "limit": limit,
        "batches": result.batches,
        "batch_limit": batches,
        "batches_exhausted": result.truncated() && result.batches >= batches,
        "vhost": result.vhost,
        "route": result.route.as_deref(),
        "scope": cache_scope(result.route.as_deref()),
        "memory_matched": result.memory_matched,
        "memory_purged": result.memory_purged,
        "memory_not_purged": result.memory_not_purged(),
        "memory_purged_ratio_per_mille": ratio_per_mille_usize(result.memory_purged, result.memory_matched),
        "memory_not_purged_ratio_per_mille": ratio_per_mille_usize(result.memory_not_purged(), result.memory_matched),
        "memory_truncated": result.memory_truncated,
        "disk_matched": result.disk_matched,
        "disk_purged": result.disk_purged,
        "disk_not_purged": result.disk_not_purged(),
        "disk_purged_ratio_per_mille": ratio_per_mille_usize(result.disk_purged, result.disk_matched),
        "disk_not_purged_ratio_per_mille": ratio_per_mille_usize(result.disk_not_purged(), result.disk_matched),
        "disk_truncated": result.disk_truncated,
    });

    if let Some((key, value)) = path_prefix.or(cache_tag).or(path_pattern)
        && let Some(object) = body.as_object_mut()
    {
        object.insert(key.to_owned(), Value::String(value.to_owned()));
    }

    body
}

#[cfg(feature = "cache")]
struct CacheIndexedPurgeBatchResult {
    result: fluxheim_cache::CacheIndexedPurgeResult,
    batches: usize,
}

#[cfg(feature = "cache")]
struct CacheStalePurgeBatchResult {
    result: fluxheim_cache::CacheStalePurgeResult,
    batches: usize,
    increase_limit_required: bool,
}

#[cfg(feature = "cache")]
impl std::ops::Deref for CacheIndexedPurgeBatchResult {
    type Target = fluxheim_cache::CacheIndexedPurgeResult;

    fn deref(&self) -> &Self::Target {
        &self.result
    }
}

#[cfg(feature = "cache")]
impl std::ops::Deref for CacheStalePurgeBatchResult {
    type Target = fluxheim_cache::CacheStalePurgeResult;

    fn deref(&self) -> &Self::Target {
        &self.result
    }
}

#[cfg(feature = "cache")]
fn repeat_cache_indexed_purge(
    batches: usize,
    mut purge: impl FnMut() -> std::io::Result<fluxheim_cache::CacheIndexedPurgeResult>,
) -> std::io::Result<CacheIndexedPurgeBatchResult> {
    let mut total: Option<fluxheim_cache::CacheIndexedPurgeResult> = None;
    let mut batches_run = 0;
    for _ in 0..batches {
        let result = purge()?;
        batches_run += 1;
        let truncated = result.truncated();
        match &mut total {
            Some(total) => {
                total.memory_matched = total.memory_matched.saturating_add(result.memory_matched);
                total.memory_purged = total.memory_purged.saturating_add(result.memory_purged);
                total.disk_matched = total.disk_matched.saturating_add(result.disk_matched);
                total.disk_purged = total.disk_purged.saturating_add(result.disk_purged);
                total.memory_truncated = result.memory_truncated;
                total.disk_truncated = result.disk_truncated;
            }
            None => total = Some(result),
        }
        if !truncated {
            break;
        }
    }

    total
        .map(|result| CacheIndexedPurgeBatchResult {
            result,
            batches: batches_run,
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cache indexed purge batches must be greater than zero",
            )
        })
}

#[cfg(feature = "cache")]
fn repeat_cache_stale_purge(
    batches: usize,
    dry_run: bool,
    mut purge: impl FnMut() -> std::io::Result<fluxheim_cache::CacheStalePurgeResult>,
) -> std::io::Result<CacheStalePurgeBatchResult> {
    let mut total: Option<fluxheim_cache::CacheStalePurgeResult> = None;
    let mut batches_run = 0;
    let mut increase_limit_required = false;

    for _ in 0..batches {
        let result = purge()?;
        batches_run += 1;
        let truncated = result.truncated();
        let purged = result.purged();
        match &mut total {
            Some(total) => {
                total.memory_scanned = total.memory_scanned.saturating_add(result.memory_scanned);
                total.memory_stale = total.memory_stale.saturating_add(result.memory_stale);
                total.memory_purged = total.memory_purged.saturating_add(result.memory_purged);
                total.disk_scanned = total.disk_scanned.saturating_add(result.disk_scanned);
                total.disk_stale = total.disk_stale.saturating_add(result.disk_stale);
                total.disk_purged = total.disk_purged.saturating_add(result.disk_purged);
                total.memory_truncated = result.memory_truncated;
                total.disk_truncated = result.disk_truncated;
            }
            None => total = Some(result),
        }

        if !truncated {
            break;
        }
        if dry_run || purged == 0 {
            increase_limit_required = true;
            break;
        }
    }

    total
        .map(|result| CacheStalePurgeBatchResult {
            result,
            batches: batches_run,
            increase_limit_required,
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cache stale purge batches must be greater than zero",
            )
        })
}

fn query_param<'a>(query: Option<&'a str>, name: &str) -> Option<&'a str> {
    query_params(query, name).into_iter().next()
}

fn query_params<'a>(query: Option<&'a str>, name: &str) -> Vec<&'a str> {
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
fn parse_load_balancer_runtime_weight(value: &str) -> Result<Option<usize>, &'static str> {
    fluxheim_load_balancer::parse_load_balancer_runtime_weight(value)
}

#[cfg(feature = "load-balancer")]
fn parse_load_balancer_member_weight(value: &str) -> Result<usize, &'static str> {
    fluxheim_load_balancer::parse_load_balancer_member_weight(value)
}

fn cache_purge_paths<'a>(headers: &'a HeaderMap, query: Option<&'a str>) -> Vec<&'a str> {
    let query_paths = query_params(query, "path");
    if !query_paths.is_empty() {
        return query_paths;
    }

    header_value(headers, "x-fluxheim-cache-paths")
        .or_else(|| header_value(headers, "x-fluxheim-cache-path"))
        .map(|paths| paths.split(',').collect())
        .unwrap_or_default()
}

#[cfg(feature = "cache")]
fn validated_cache_purge_host(host: Option<&str>) -> Result<&str, &'static str> {
    let Some(host) = host.map(str::trim).filter(|host| !host.is_empty()) else {
        return Err("cache purge host is required");
    };
    if host.len() > MAX_CACHE_PURGE_HOST_BYTES
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\'))
        || host.chars().any(char::is_whitespace)
    {
        return Err("cache purge host is invalid");
    }
    Ok(host)
}

#[cfg(feature = "cache")]
fn validated_cache_purge_method(method: Option<&str>) -> Result<&str, &'static str> {
    let method = method.unwrap_or("GET").trim();
    if method.is_empty() {
        return Err("cache purge method cannot be empty");
    }
    if method.len() > MAX_CACHE_PURGE_METHOD_BYTES || !method.bytes().all(is_http_token_byte) {
        return Err("cache purge method is invalid");
    }
    Ok(method)
}

#[cfg(feature = "cache")]
fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(feature = "cache")]
fn validated_cache_purge_path(path: Option<&str>) -> Result<&str, &'static str> {
    let Some(path) = path.map(str::trim).filter(|path| !path.is_empty()) else {
        return Err("cache purge path is required and must start with /");
    };
    validate_cache_purge_path_value(path)?;
    Ok(path)
}

#[cfg(feature = "cache")]
fn validate_cache_purge_path_value(path: &str) -> Result<(), &'static str> {
    if !path.starts_with('/') {
        return Err("cache purge path is required and must start with /");
    }
    if path.len() > MAX_CACHE_PURGE_PATH_BYTES
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
    {
        return Err("cache purge path is invalid");
    }
    if path_contains_traversal_segment(path)
        || !fluxheim_common::path_safety::safe_forward_path_and_query(path)
    {
        return Err("cache purge path must not contain traversal segments");
    }
    Ok(())
}

#[cfg(feature = "cache")]
fn validated_cache_purge_path_prefix(prefix: Option<&str>) -> Result<&str, &'static str> {
    let Some(prefix) = prefix.map(str::trim).filter(|prefix| !prefix.is_empty()) else {
        return Err("cache path-prefix purge prefix is required and must start with /");
    };
    validate_cache_purge_path_value(prefix)?;
    if prefix == "/" {
        return Err("cache path-prefix purge prefix must not be /; use scope purge instead");
    }
    Ok(prefix)
}

#[cfg(feature = "cache")]
fn validated_cache_purge_path_pattern(pattern: Option<&str>) -> Result<&str, &'static str> {
    let Some(pattern) = pattern.map(str::trim).filter(|pattern| !pattern.is_empty()) else {
        return Err("cache wildcard purge pattern is required and must start with /");
    };
    validate_cache_purge_path_value(pattern)?;
    if !pattern.contains('*') {
        return Err("cache wildcard purge pattern must contain *");
    }
    if pattern
        .chars()
        .filter(|character| *character != '*')
        .collect::<String>()
        == "/"
    {
        return Err(
            "cache wildcard purge pattern must not target the whole cache; use scope purge instead",
        );
    }
    Ok(pattern)
}

#[cfg(feature = "cache")]
fn validated_cache_purge_tag(tag: Option<&str>) -> Result<&str, &'static str> {
    let Some(tag) = tag.map(str::trim).filter(|tag| !tag.is_empty()) else {
        return Err("cache tag purge tag is required");
    };
    if tag.len() > MAX_CACHE_PURGE_TAG_BYTES
        || !tag.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/' | b'=')
        })
    {
        return Err("cache tag purge tag is invalid");
    }
    Ok(tag)
}

#[cfg(feature = "cache")]
fn path_contains_traversal_segment(path: &str) -> bool {
    path.split('/').any(|segment| matches!(segment, "." | ".."))
}

#[cfg(feature = "cache")]
fn validated_cache_purge_query(query: Option<&str>) -> Result<Option<&str>, &'static str> {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return Ok(None);
    };
    if query.len() > MAX_CACHE_PURGE_QUERY_BYTES
        || query
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'#'))
    {
        return Err("cache purge query is invalid");
    }
    Ok(Some(query))
}

#[cfg(feature = "cache")]
fn validated_cache_indexed_purge_limit(limit: Option<&str>) -> Result<usize, &'static str> {
    let Some(limit) = limit.map(str::trim).filter(|limit| !limit.is_empty()) else {
        return Ok(DEFAULT_CACHE_INDEXED_PURGE_LIMIT);
    };
    let limit = limit
        .parse::<usize>()
        .map_err(|_| "cache indexed purge limit is invalid")?;
    if limit == 0 || limit > MAX_CACHE_INDEXED_PURGE_LIMIT {
        return Err("cache indexed purge limit is out of range");
    }
    Ok(limit)
}

#[cfg(feature = "cache")]
fn validated_cache_indexed_purge_batches(batches: Option<&str>) -> Result<usize, &'static str> {
    let Some(batches) = batches.map(str::trim).filter(|batches| !batches.is_empty()) else {
        return Ok(DEFAULT_CACHE_INDEXED_PURGE_BATCHES);
    };
    let batches = batches
        .parse::<usize>()
        .map_err(|_| "cache indexed purge batches is invalid")?;
    if batches == 0 || batches > MAX_CACHE_INDEXED_PURGE_BATCHES {
        return Err("cache indexed purge batches is out of range");
    }
    Ok(batches)
}

fn truthy_header(headers: &HeaderMap, name: &str) -> bool {
    header_value(headers, name).is_some_and(truthy)
}

fn truthy_query_param(query: Option<&str>, name: &str) -> bool {
    query_param(query, name).is_some_and(truthy)
}

fn truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn parse_health_signal(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "ok" | "success" | "successful" | "healthy" | "true" | "1" | "yes" | "on" => Some(true),
        "error" | "fail" | "failed" | "unhealthy" | "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn unix_secs() -> u64 {
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

    fn app() -> AdminApp {
        app_with_config(Config::default())
    }

    fn app_with_config(config: Config) -> AdminApp {
        app_with_config_and_self_healing(config, false)
    }

    fn app_with_config_and_self_healing(config: Config, self_healing_enabled: bool) -> AdminApp {
        let store = unique_temp_path("admin-snapshot-store");
        std::fs::create_dir(&store).expect("create private admin snapshot test store");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700))
                .expect("secure private admin snapshot test store");
        }
        #[cfg(feature = "load-balancer")]
        let proxy = {
            let (_, _, load_balancer_admin_pools) =
                fluxheim_server::NativeHttp1HostRouter::from_config_with_native_load_balancer_services(
                    &config,
                    fluxheim_server::DownstreamHttp1Policy::default(),
                    0,
                )
                .unwrap();
            FluxProxy::from_config_with_native_load_balancers(&config, load_balancer_admin_pools)
                .unwrap()
        };
        #[cfg(not(feature = "load-balancer"))]
        let proxy = FluxProxy::from_config(&config).unwrap();
        let auth_throttle = AdminAuthThrottle::new(config.admin.auth_throttle);
        let client_certificate = super::AdminClientCertificatePolicy::from_config(&config.admin);
        let health_unauthenticated = config.admin.health.unauthenticated;
        let health_response = config.admin.health.response;
        AdminApp {
            token: AdminToken::new("secret-token", false),
            client_certificate,
            store: SnapshotStore::new(store),
            current_config: Arc::new(ArcSwap::from_pointee(config)),
            proxy,
            health_path: "/_fluxheim/health".to_owned(),
            health_unauthenticated,
            health_response,
            self_healing_enabled,
            validation_window_secs: AdminSelfHealingConfig::default().validation_window_secs,
            min_successful_checks: AdminSelfHealingConfig::default().min_successful_checks,
            max_error_rate_per_mille: AdminSelfHealingConfig::default().max_error_rate_per_mille,
            state: Arc::new(std::sync::Mutex::new(SnapshotRuntimeState::default())),
            auth_throttle,
        }
    }

    fn native_request(
        method: &str,
        target: &str,
        headers: Vec<(String, String)>,
    ) -> fluxheim_server::NativeHttp1Request {
        fluxheim_server::NativeHttp1Request {
            method: method.to_owned(),
            peer_addr: Some("127.0.0.1:59000".parse().unwrap()),
            local_addr: Some("127.0.0.1:8080".parse().unwrap()),
            effective_client_addr: Some("127.0.0.1:59000".parse().unwrap()),
            downstream_tls: false,
            tls_identity: None,
            geo_context: None,
            target: target.to_owned(),
            version: fluxheim_protocol::Http1Version::Http11,
            headers,
            body: zeroize::Zeroizing::new(Vec::new()),
            trailers: Vec::new(),
        }
    }

    #[cfg(feature = "load-balancer")]
    fn load_balancer_admin_config() -> Config {
        Config {
            vhosts: vec![VhostConfig {
                name: "one".to_owned(),
                hosts: vec!["one.example".to_owned()],
                max_request_body_bytes: None,
                access: Default::default(),
                rate_limit: Default::default(),
                concurrency: Default::default(),
                acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
                redirect: crate::config::VhostRedirectConfig::default(),
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig {
                    upstreams: vec!["127.0.0.1:3001".to_owned(), "127.0.0.1:3002".to_owned()],
                    upstream_aliases: vec!["app-a".to_owned(), "app-b".to_owned()],
                    ..ProxyConfig::default()
                },
                cache: CacheConfig::default(),
                compression: None,
                headers: crate::config::VhostHeaderPolicyConfig::default(),
                php: crate::config::PhpConfig::default(),
                web: WebConfig::default(),
                routes: Vec::new(),
            }],
            ..Config::default()
        }
    }

    #[cfg(feature = "load-balancer")]
    fn load_balancer_persistent_admin_config() -> Config {
        let root = unique_temp_path("admin-lb-runtime-state");
        std::fs::create_dir_all(&root).unwrap();
        let mut config = load_balancer_admin_config();
        config.vhosts[0].proxy.load_balance.runtime_state_file =
            Some(safe_child_path(&root, "lb-state.json"));
        config
    }

    fn set_test_runtime_state(
        app: &AdminApp,
        runtime_snapshot: Option<String>,
        known_good_snapshot: Option<String>,
        pending_validation: Option<PendingValidation>,
    ) {
        let mut state = app.state.lock().unwrap();
        state.runtime_snapshot = runtime_snapshot;
        state.known_good_snapshot = known_good_snapshot;
        state.pending_validation = pending_validation;
    }

    #[test]
    fn status_endpoint_reports_tls_compliance_mode() {
        let config = Config {
            tls: crate::config::TlsConfig {
                iso19790: crate::config::TlsIso19790Config {
                    required: true,
                    require_disk_cache_encryption: false,
                },
                ..crate::config::TlsConfig::default()
            },
            ..Config::default()
        };
        let response =
            app_with_config(config).handle("GET", "/_fluxheim/status", None, &auth_headers());

        assert_eq!(response.status, StatusCode::OK);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(r#""tls_compliance_mode":"ISO/IEC 19790""#));
        assert!(body.contains(r#""tls_iso19790_required":true"#));
    }

    #[test]
    fn admin_auth_throttle_locks_repeated_failures_by_source() {
        let mut config = Config::default();
        config.admin.auth_throttle = AdminAuthThrottleConfig {
            enabled: true,
            window_secs: 60,
            per_source_failures: 2,
            global_failures: 100,
            base_lockout_secs: 60,
            max_lockout_secs: 60,
            max_sources: 16,
        };
        let app = app_with_config(config);
        let source = Some("192.0.2.10".parse().unwrap());
        let other_source = Some("192.0.2.11".parse().unwrap());

        let response =
            app.handle_with_source("GET", "/_fluxheim/status", None, &HeaderMap::new(), source);
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        let response =
            app.handle_with_source("GET", "/_fluxheim/status", None, &HeaderMap::new(), source);
        assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.body, br#"{"error":"admin_auth_throttled"}"#);

        let response =
            app.handle_with_source("GET", "/_fluxheim/status", None, &auth_headers(), source);
        assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);

        let response = app.handle_with_source(
            "GET",
            "/_fluxheim/status",
            None,
            &auth_headers(),
            other_source,
        );
        assert_eq!(response.status, StatusCode::OK);
    }

    #[test]
    fn admin_auth_throttle_can_lock_globally() {
        let mut config = Config::default();
        config.admin.auth_throttle = AdminAuthThrottleConfig {
            enabled: true,
            window_secs: 60,
            per_source_failures: 100,
            global_failures: 2,
            base_lockout_secs: 60,
            max_lockout_secs: 60,
            max_sources: 16,
        };
        let app = app_with_config(config);

        for source in ["192.0.2.20", "192.0.2.21"] {
            let response = app.handle_with_source(
                "GET",
                "/_fluxheim/status",
                None,
                &HeaderMap::new(),
                Some(source.parse().unwrap()),
            );
            if source == "192.0.2.20" {
                assert_eq!(response.status, StatusCode::UNAUTHORIZED);
            } else {
                assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
            }
        }

        let response = app.handle_with_source(
            "GET",
            "/_fluxheim/status",
            None,
            &auth_headers(),
            Some("192.0.2.22".parse().unwrap()),
        );
        assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn admin_auth_throttle_evicts_stale_source_when_source_table_is_full() {
        let throttle = AdminAuthThrottle::new(AdminAuthThrottleConfig {
            enabled: true,
            window_secs: 60,
            per_source_failures: 100,
            global_failures: 100,
            base_lockout_secs: 60,
            max_lockout_secs: 60,
            max_sources: 1,
        });

        assert_eq!(
            throttle.record_failure(Some("192.0.2.30".parse().unwrap())),
            None
        );
        assert_eq!(
            throttle.record_failure(Some("192.0.2.31".parse().unwrap())),
            None
        );
        assert_eq!(
            throttle.pre_auth_check(Some("192.0.2.30".parse().unwrap())),
            None
        );
        assert_eq!(
            throttle.record_failure(Some("192.0.2.31".parse().unwrap())),
            None
        );
    }

    #[test]
    fn admin_auth_throttle_does_not_source_lock_indeterminate_clients() {
        let throttle = AdminAuthThrottle::new(AdminAuthThrottleConfig {
            enabled: true,
            window_secs: 60,
            per_source_failures: 2,
            global_failures: 100,
            base_lockout_secs: 60,
            max_lockout_secs: 60,
            max_sources: 16,
        });

        assert_eq!(throttle.record_failure(None), None);
        assert_eq!(throttle.record_failure(None), None);
        assert_eq!(throttle.pre_auth_check(None), None);
    }

    #[test]
    fn admin_endpoint_rejects_oversized_query_before_parsing() {
        let query = "x=".to_owned() + &"a".repeat(super::MAX_ADMIN_QUERY_BYTES);

        let response = app().handle("GET", "/_fluxheim/status", Some(&query), &auth_headers());

        assert_eq!(response.status, StatusCode::URI_TOO_LONG);
        assert_eq!(response.body, br#"{"error":"query_too_large"}"#);
    }

    #[test]
    fn admin_endpoint_rejects_oversized_path_before_routing() {
        let path = "/".to_owned() + &"a".repeat(super::MAX_ADMIN_PATH_BYTES);

        let response = app().handle("GET", &path, None, &auth_headers());

        assert_eq!(response.status, StatusCode::URI_TOO_LONG);
        assert_eq!(response.body, br#"{"error":"path_too_large"}"#);
    }

    fn auth_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer secret-token".parse().unwrap(),
        );
        headers
    }

    #[cfg(feature = "cache")]
    fn cached_assets_route() -> RouteConfig {
        RouteConfig {
            name: "assets".to_owned(),
            path_exact: None,
            path_prefix: Some("/assets/".to_owned()),
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(ProxyConfig::default()),
            web: None,
            php: None,
            cache: Some(CacheConfig {
                enabled: true,
                memory: crate::config::CacheMemoryConfig {
                    enabled: true,
                    max_size_bytes: ByteSize::from_bytes(1024),
                },
                max_object_bytes: ByteSize::from_bytes(512),
                ..CacheConfig::default()
            }),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
        }
    }

    #[cfg(feature = "cache")]
    fn cached_tiered_route(cache_path: &std::path::Path) -> RouteConfig {
        RouteConfig {
            name: "media".to_owned(),
            path_exact: None,
            path_prefix: Some("/media/".to_owned()),
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(ProxyConfig::default()),
            web: None,
            php: None,
            cache: Some(CacheConfig {
                enabled: true,
                memory: crate::config::CacheMemoryConfig {
                    enabled: true,
                    max_size_bytes: ByteSize::from_bytes(2048),
                },
                disk: crate::config::CacheDiskConfig {
                    enabled: true,
                    path: Some(cache_path.to_path_buf()),
                    max_size_bytes: ByteSize::from_bytes(4096),
                    ..crate::config::CacheDiskConfig::default()
                },
                max_object_bytes: ByteSize::from_bytes(512),
                ..CacheConfig::default()
            }),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
        }
    }

    #[cfg(feature = "cache")]
    fn uncached_api_route() -> RouteConfig {
        RouteConfig {
            name: "api".to_owned(),
            path_exact: None,
            path_prefix: Some("/api/".to_owned()),
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: false,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            grpc: Default::default(),
            redirect: None,
            proxy: Some(ProxyConfig::default()),
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
        }
    }

    struct TestDir {
        path: std::path::PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let path = unique_temp_path(name);
            std::fs::create_dir(&path).expect("create test directory");
            Self { path }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

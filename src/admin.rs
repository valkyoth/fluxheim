use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::{HeaderMap, Response, StatusCode, header};
use pingora::apps::http_app::{HttpServer, ServeHttp};
use pingora::protocols::http::ServerSession;
use pingora::services::background::{BackgroundService, GenBackgroundService};
use pingora::services::listening::Service;

use crate::config::{AdminConfig, Config};
use crate::proxy::{FluxProxy, ProxyHealthReporter, ProxyHealthSignal};
use crate::reload::{ReloadReason, classify_reload};
use crate::snapshot::{ConfigSnapshot, SnapshotStore};

#[derive(Clone)]
pub struct AdminApp {
    token: String,
    store: SnapshotStore,
    current_config: Arc<ArcSwap<Config>>,
    proxy: FluxProxy,
    health_path: String,
    self_healing_enabled: bool,
    validation_window_secs: u64,
    min_successful_checks: usize,
    max_error_rate_per_mille: u16,
    state: Arc<Mutex<AdminRuntimeState>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AdminResponse {
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
struct AdminRuntimeState {
    runtime_snapshot: Option<String>,
    known_good_snapshot: Option<String>,
    pending_validation: Option<PendingValidation>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PendingValidation {
    target_snapshot: String,
    previous_snapshot: Option<String>,
    impact: String,
    expires_unix_secs: u64,
    successful_checks: usize,
    failed_checks: usize,
}

pub struct AdminServices {
    pub control_plane: Service<HttpServer<AdminApp>>,
    pub watchdog: Option<GenBackgroundService<AdminApp>>,
}

pub fn admin_services_from_config(
    config: &Config,
    proxy: FluxProxy,
) -> Result<Option<AdminServices>, Box<dyn Error + Send + Sync>> {
    if !config.admin.enabled {
        return Ok(None);
    }

    let app = AdminApp::from_config(config, proxy)?;
    let watchdog = if app.self_healing_enabled {
        Some(GenBackgroundService::new(
            "Fluxheim Self-Healing Watchdog".to_owned(),
            Arc::new(app.clone()),
        ))
    } else {
        None
    };
    let mut service = Service::new(
        "Fluxheim Admin Control Plane".to_owned(),
        HttpServer::new_app(app),
    );
    service.add_tcp(&config.admin.listen);
    Ok(Some(AdminServices {
        control_plane: service,
        watchdog,
    }))
}

impl AdminApp {
    fn from_config(
        config: &Config,
        proxy: FluxProxy,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let token = load_admin_token(&config.admin)?;
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
            store: SnapshotStore::new(snapshot_store),
            current_config: Arc::new(ArcSwap::from_pointee(config.clone())),
            proxy,
            health_path: config.admin.self_healing.health_path.clone(),
            self_healing_enabled: config.admin.self_healing.enabled,
            validation_window_secs: config.admin.self_healing.validation_window_secs,
            min_successful_checks: config.admin.self_healing.min_successful_checks,
            max_error_rate_per_mille: config.admin.self_healing.max_error_rate_per_mille,
            state: Arc::new(Mutex::new(AdminRuntimeState {
                runtime_snapshot: runtime_snapshot.clone(),
                known_good_snapshot: runtime_snapshot,
                pending_validation: None,
            })),
        };

        if app.self_healing_enabled {
            app.proxy.set_health_reporter(Arc::new(app.clone()));
        }

        Ok(app)
    }

    fn handle(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
    ) -> AdminResponse {
        if let Some(response) = self.enforce_self_healing_deadline() {
            return response;
        }

        if path == self.health_path {
            if method != "GET" {
                return json_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    br#"{"error":"method_not_allowed"}"#,
                );
            }
            return json_response(StatusCode::OK, br#"{"status":"ok"}"#);
        }

        if !authorized(authorization_header(headers), &self.token) {
            return json_response(StatusCode::UNAUTHORIZED, br#"{"error":"unauthorized"}"#);
        }

        match (method, path) {
            ("GET", "/_fluxheim/status") => self.status_response(),
            ("GET", "/_fluxheim/cache/status") => self.cache_status_response(),
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
            ("POST", "/_fluxheim/cache/purge") => self.cache_purge_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
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
                header_value(headers, "x-fluxheim-cache-host")
                    .or_else(|| query_param(query, "host")),
                header_value(headers, "x-fluxheim-cache-method")
                    .or_else(|| query_param(query, "method")),
                cache_purge_paths(headers, query),
                header_value(headers, "x-fluxheim-cache-query")
                    .or_else(|| query_param(query, "url_query"))
                    .or_else(|| query_param(query, "cache_query")),
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
                | "/_fluxheim/snapshots"
                | "/_fluxheim/cache/activity/reset"
                | "/_fluxheim/self-heal/confirm"
                | "/_fluxheim/self-heal/fail"
                | "/_fluxheim/self-heal/report"
                | "/_fluxheim/cache/purge"
                | "/_fluxheim/cache/purge-bulk"
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

    fn status_response(&self) -> AdminResponse {
        let current = match self.store.current_id() {
            Ok(current) => current,
            Err(error) => {
                return json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        r#"{{"status":"error","error":"{}"}}"#,
                        json_escape(&error.to_string())
                    )
                    .as_bytes(),
                );
            }
        };
        let snapshots = match self.store.list() {
            Ok(snapshots) => snapshots.len(),
            Err(error) => {
                return json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        r#"{{"status":"error","error":"{}"}}"#,
                        json_escape(&error.to_string())
                    )
                    .as_bytes(),
                );
            }
        };
        let current = current
            .map(|id| format!(r#""{}""#, json_escape(&id)))
            .unwrap_or_else(|| "null".to_owned());
        let runtime_state = self.runtime_state();
        let body = format!(
            r#"{{"status":"ok","snapshot_current":{current},"snapshots":{snapshots},"self_healing_enabled":{},"runtime_snapshot":{},"known_good_snapshot":{},"pending_validation":{}}}"#,
            self.self_healing_enabled,
            optional_json_string(runtime_state.runtime_snapshot.as_deref()),
            optional_json_string(runtime_state.known_good_snapshot.as_deref()),
            pending_validation_json(runtime_state.pending_validation.as_ref())
        );
        json_response(StatusCode::OK, body.as_bytes())
    }

    fn snapshots_response(&self) -> AdminResponse {
        match self.store.list() {
            Ok(snapshots) => {
                let current = self.store.current_id().ok().flatten();
                let mut body = String::from(r#"{"status":"ok","snapshots":["#);
                for (index, snapshot) in snapshots.iter().enumerate() {
                    if index > 0 {
                        body.push(',');
                    }
                    body.push_str(&snapshot_json(snapshot, current.as_deref()));
                }
                body.push_str("]}");
                json_response(StatusCode::OK, body.as_bytes())
            }
            Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        }
    }

    #[cfg(feature = "cache")]
    fn cache_status_response(&self) -> AdminResponse {
        match self.proxy.cache_runtime_stats() {
            Ok(stats) => {
                let body = format!(
                    r#"{{"status":"ok","totals":{},"vhosts":[{}]}}"#,
                    cache_totals_json(&stats.totals),
                    cache_vhost_stats_json(&stats.vhosts)
                );
                json_response(StatusCode::OK, body.as_bytes())
            }
            Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        }
    }

    #[cfg(not(feature = "cache"))]
    fn cache_status_response(&self) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(feature = "cache")]
    fn cache_activity_reset_response(&self) -> AdminResponse {
        let result = self.proxy.reset_cache_activity();
        let body = format!(
            r#"{{"status":"ok","memory_tiers":{},"disk_tiers":{},"tiered_vhosts":{}}}"#,
            result.memory_tiers, result.disk_tiers, result.tiered_vhosts
        );
        json_response(StatusCode::OK, body.as_bytes())
    }

    #[cfg(not(feature = "cache"))]
    fn cache_activity_reset_response(&self) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    fn create_snapshot_response(&self, message: Option<&str>) -> AdminResponse {
        let config = self.current_config.load_full();
        match self.store.snapshot_config(&config, message) {
            Ok(snapshot) => {
                let body = format!(
                    r#"{{"status":"ok","snapshot":"{}","config_path":"{}"}}"#,
                    json_escape(&snapshot.id),
                    json_escape(&snapshot.config_path.display().to_string())
                );
                json_response(StatusCode::CREATED, body.as_bytes())
            }
            Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        }
    }

    fn rollback_response(&self, target: Option<&str>, live_apply: bool) -> AdminResponse {
        if !live_apply {
            return match self.store.rollback_target(target) {
                Ok(snapshot) => {
                    let body = format!(
                        r#"{{"status":"ok","rollback_target":"{}","config_path":"{}","live_apply":false}}"#,
                        json_escape(&snapshot.id),
                        json_escape(&snapshot.config_path.display().to_string())
                    );
                    json_response(StatusCode::OK, body.as_bytes())
                }
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
        let impact = match self.apply_snapshot(&snapshot, new_config, ApplyMode::Rollback) {
            Ok(impact) => impact,
            Err(response) => return response,
        };
        if let Err(error) = self.store.set_current_snapshot(&snapshot.id) {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }

        let body = format!(
            r#"{{"status":"ok","rollback_target":"{}","config_path":"{}","impact":"{}","live_apply":true}}"#,
            json_escape(&snapshot.id),
            json_escape(&snapshot.config_path.display().to_string()),
            json_escape(&impact)
        );
        json_response(StatusCode::OK, body.as_bytes())
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
        let impact = match self.apply_snapshot(&snapshot, new_config, ApplyMode::Reload) {
            Ok(impact) => impact,
            Err(response) => return response,
        };

        let body = format!(
            r#"{{"status":"ok","snapshot":"{}","impact":"{}","live_apply":true}}"#,
            json_escape(&snapshot.id),
            json_escape(&impact)
        );
        json_response(StatusCode::OK, body.as_bytes())
    }

    #[cfg(feature = "cache")]
    fn cache_purge_response(
        &self,
        vhost: Option<&str>,
        host: Option<&str>,
        method: Option<&str>,
        path: Option<&str>,
        query: Option<&str>,
    ) -> AdminResponse {
        let Some(host) = host.filter(|host| !host.trim().is_empty()) else {
            return error_response(StatusCode::BAD_REQUEST, "cache purge host is required");
        };
        let method = method.unwrap_or("GET").trim();
        if method.is_empty() {
            return error_response(
                StatusCode::BAD_REQUEST,
                "cache purge method cannot be empty",
            );
        }
        let Some(path) = path.filter(|path| path.starts_with('/')) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "cache purge path is required and must start with /",
            );
        };

        match self
            .proxy
            .purge_image_cache(crate::proxy::CachePurgeRequest {
                vhost: vhost.filter(|vhost| !vhost.trim().is_empty()),
                host: host.trim(),
                method,
                path,
                query: query.filter(|query| !query.is_empty()),
            }) {
            Ok(result) => {
                let body = format!(
                    r#"{{"status":"ok","purged":{},"vhost":"{}","cache_key":"{}","memory_purged":{},"disk_purged":{}}}"#,
                    result.purged(),
                    json_escape(&result.vhost),
                    json_escape(&result.cache_key),
                    result.memory_purged,
                    result.disk_purged
                );
                json_response(StatusCode::OK, body.as_bytes())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        }
    }

    #[cfg(feature = "cache")]
    fn cache_purge_bulk_response(
        &self,
        vhost: Option<&str>,
        host: Option<&str>,
        method: Option<&str>,
        paths: Vec<&str>,
        query: Option<&str>,
    ) -> AdminResponse {
        let Some(host) = host.filter(|host| !host.trim().is_empty()) else {
            return error_response(StatusCode::BAD_REQUEST, "cache purge host is required");
        };
        let method = method.unwrap_or("GET").trim();
        if method.is_empty() {
            return error_response(
                StatusCode::BAD_REQUEST,
                "cache purge method cannot be empty",
            );
        }
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
        if paths.iter().any(|path| !path.starts_with('/')) {
            return error_response(
                StatusCode::BAD_REQUEST,
                "all cache purge paths must start with /",
            );
        }

        match self
            .proxy
            .purge_image_cache_bulk(crate::proxy::CacheBulkPurgeRequest {
                vhost: vhost.filter(|vhost| !vhost.trim().is_empty()),
                host: host.trim(),
                method,
                paths,
                query: query.filter(|query| !query.is_empty()),
            }) {
            Ok(result) => {
                let body = format!(
                    r#"{{"status":"ok","requested":{},"purged":{},"vhost":"{}","results":[{}]}}"#,
                    result.requested(),
                    result.purged(),
                    json_escape(&result.vhost),
                    cache_purge_results_json(&result.results)
                );
                json_response(StatusCode::OK, body.as_bytes())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        }
    }

    #[cfg(not(feature = "cache"))]
    fn cache_purge_response(
        &self,
        _vhost: Option<&str>,
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
        _host: Option<&str>,
        _method: Option<&str>,
        _paths: Vec<&str>,
        _query: Option<&str>,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    fn apply_snapshot(
        &self,
        snapshot: &ConfigSnapshot,
        new_config: Config,
        mode: ApplyMode,
    ) -> Result<String, AdminResponse> {
        let old_config = self.current_config.load_full();
        let impact = classify_reload(&old_config, &new_config);

        if !impact.is_snapshot_safe() {
            let body = format!(
                r#"{{"status":"error","error":"process_upgrade_required","snapshot":"{}","impact":"{}","reasons":[{}],"live_apply":false}}"#,
                json_escape(&snapshot.id),
                impact.kind(),
                reload_reasons_json(impact.reasons())
            );
            return Err(json_response(StatusCode::CONFLICT, body.as_bytes()));
        }

        if let Err(error) = self.proxy.reload_from_config(&new_config) {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &error.to_string(),
            ));
        }
        self.current_config.store(Arc::new(new_config));

        let impact = impact.kind().to_owned();
        self.record_applied_snapshot(snapshot.id.clone(), impact.clone(), mode);

        Ok(impact)
    }

    fn self_heal_confirm_response(&self) -> AdminResponse {
        if !self.self_healing_enabled {
            return error_response(StatusCode::BAD_REQUEST, "self-healing is disabled");
        }

        let mut state = self.lock_runtime_state();
        let Some(pending) = state.pending_validation.take() else {
            return error_response(StatusCode::BAD_REQUEST, "no pending validation");
        };
        state.known_good_snapshot = Some(pending.target_snapshot.clone());
        state.runtime_snapshot = Some(pending.target_snapshot.clone());

        let body = format!(
            r#"{{"status":"ok","known_good_snapshot":"{}","confirmed_snapshot":"{}"}}"#,
            json_escape(&pending.target_snapshot),
            json_escape(&pending.target_snapshot)
        );
        json_response(StatusCode::OK, body.as_bytes())
    }

    fn self_heal_fail_response(&self) -> AdminResponse {
        if !self.self_healing_enabled {
            return error_response(StatusCode::BAD_REQUEST, "self-healing is disabled");
        }

        let pending = match self.pending_validation() {
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

        match self.record_health_signal(healthy) {
            HealthSignalOutcome::NoPendingValidation => {
                error_response(StatusCode::BAD_REQUEST, "no pending validation")
            }
            HealthSignalOutcome::Recorded { snapshot, metrics } => {
                let body = format!(
                    r#"{{"status":"ok","action":"recorded","snapshot":"{}","successful_checks":{},"failed_checks":{},"error_rate_per_mille":{}}}"#,
                    json_escape(&snapshot),
                    metrics.successful_checks,
                    metrics.failed_checks,
                    metrics.error_rate_per_mille()
                );
                json_response(StatusCode::OK, body.as_bytes())
            }
            HealthSignalOutcome::Confirm { snapshot, metrics } => {
                let body = format!(
                    r#"{{"status":"ok","action":"confirmed","known_good_snapshot":"{}","successful_checks":{},"failed_checks":{},"error_rate_per_mille":{}}}"#,
                    json_escape(&snapshot),
                    metrics.successful_checks,
                    metrics.failed_checks,
                    metrics.error_rate_per_mille()
                );
                json_response(StatusCode::OK, body.as_bytes())
            }
            HealthSignalOutcome::Rollback(pending) => {
                self.rollback_pending_validation(&pending, "error-rate")
            }
        }
    }

    fn record_health_signal(&self, healthy: bool) -> HealthSignalOutcome {
        let mut state = self.lock_runtime_state();
        let Some(mut pending) = state.pending_validation.take() else {
            return HealthSignalOutcome::NoPendingValidation;
        };

        if healthy {
            pending.successful_checks = pending.successful_checks.saturating_add(1);
        } else {
            pending.failed_checks = pending.failed_checks.saturating_add(1);
        }

        let metrics = ValidationMetrics {
            successful_checks: pending.successful_checks,
            failed_checks: pending.failed_checks,
        };

        if metrics.failed_checks > 0
            && metrics.error_rate_per_mille() > u64::from(self.max_error_rate_per_mille)
        {
            return HealthSignalOutcome::Rollback(pending);
        }

        if metrics.successful_checks >= self.min_successful_checks {
            state.known_good_snapshot = Some(pending.target_snapshot.clone());
            state.runtime_snapshot = Some(pending.target_snapshot.clone());
            return HealthSignalOutcome::Confirm {
                snapshot: pending.target_snapshot,
                metrics,
            };
        }

        let snapshot = pending.target_snapshot.clone();
        state.pending_validation = Some(pending);
        HealthSignalOutcome::Recorded { snapshot, metrics }
    }

    fn enforce_self_healing_deadline(&self) -> Option<AdminResponse> {
        if !self.self_healing_enabled {
            return None;
        }

        let pending = self.pending_validation()?;
        let metrics = ValidationMetrics {
            successful_checks: pending.successful_checks,
            failed_checks: pending.failed_checks,
        };
        if metrics.failed_checks > 0
            && metrics.error_rate_per_mille() > u64::from(self.max_error_rate_per_mille)
        {
            return Some(self.rollback_pending_validation(&pending, "error-rate"));
        }

        if pending.expires_unix_secs > unix_secs() {
            return None;
        }

        Some(self.rollback_pending_validation(&pending, "expired"))
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
        let impact = match self.apply_snapshot(&snapshot, new_config, ApplyMode::SelfHealRollback) {
            Ok(impact) => impact,
            Err(response) => return response,
        };
        if let Err(error) = self.store.set_current_snapshot(&snapshot.id) {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }

        let body = format!(
            r#"{{"status":"ok","reason":"{}","failed_snapshot":"{}","rollback_target":"{}","impact":"{}","live_apply":true}}"#,
            json_escape(reason),
            json_escape(&pending.target_snapshot),
            json_escape(&snapshot.id),
            json_escape(&impact)
        );
        json_response(StatusCode::OK, body.as_bytes())
    }

    fn record_applied_snapshot(&self, snapshot: String, impact: String, mode: ApplyMode) {
        let mut state = self.lock_runtime_state();
        let previous = state.runtime_snapshot.clone();
        state.runtime_snapshot = Some(snapshot.clone());

        match mode {
            ApplyMode::Reload if self.self_healing_enabled => {
                state.pending_validation = Some(PendingValidation {
                    target_snapshot: snapshot,
                    previous_snapshot: previous.or_else(|| state.known_good_snapshot.clone()),
                    impact,
                    expires_unix_secs: unix_secs().saturating_add(self.validation_window_secs),
                    successful_checks: 0,
                    failed_checks: 0,
                });
            }
            ApplyMode::Reload => {
                state.known_good_snapshot = Some(snapshot);
                state.pending_validation = None;
            }
            ApplyMode::Rollback | ApplyMode::SelfHealRollback => {
                state.known_good_snapshot = Some(snapshot);
                state.pending_validation = None;
            }
        }
    }

    fn runtime_state(&self) -> AdminRuntimeState {
        self.lock_runtime_state().clone()
    }

    fn pending_validation(&self) -> Option<PendingValidation> {
        self.lock_runtime_state().pending_validation.clone()
    }

    fn lock_runtime_state(&self) -> std::sync::MutexGuard<'_, AdminRuntimeState> {
        self.state.lock().expect("admin runtime state poisoned")
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ApplyMode {
    Reload,
    Rollback,
    SelfHealRollback,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct ValidationMetrics {
    successful_checks: usize,
    failed_checks: usize,
}

impl ValidationMetrics {
    fn error_rate_per_mille(&self) -> u64 {
        let total = self.successful_checks.saturating_add(self.failed_checks);
        if total == 0 {
            return 0;
        }
        (self.failed_checks as u64).saturating_mul(1000) / (total as u64)
    }
}

impl ProxyHealthReporter for AdminApp {
    fn record_proxy_health_signal(&self, signal: ProxyHealthSignal) {
        if !self.self_healing_enabled {
            return;
        }

        match self.record_health_signal(signal.healthy()) {
            HealthSignalOutcome::NoPendingValidation => {}
            HealthSignalOutcome::Recorded { snapshot, metrics } => {
                log::debug!(
                    "proxy self-healing signal recorded: snapshot={snapshot} healthy={} successful_checks={} failed_checks={} error_rate_per_mille={}",
                    signal.healthy(),
                    metrics.successful_checks,
                    metrics.failed_checks,
                    metrics.error_rate_per_mille()
                );
            }
            HealthSignalOutcome::Confirm { snapshot, metrics } => {
                log::info!(
                    "proxy self-healing signal confirmed snapshot={snapshot} successful_checks={} failed_checks={} error_rate_per_mille={}",
                    metrics.successful_checks,
                    metrics.failed_checks,
                    metrics.error_rate_per_mille()
                );
            }
            HealthSignalOutcome::Rollback(pending) => {
                let response = self.rollback_pending_validation(&pending, "proxy-error-rate");
                if response.status.is_success() {
                    log::warn!(
                        "proxy self-healing signal rolled back failed snapshot={}",
                        pending.target_snapshot
                    );
                } else {
                    log::error!(
                        "proxy self-healing rollback failed: snapshot={} status={}",
                        pending.target_snapshot,
                        response.status.as_u16()
                    );
                }
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum HealthSignalOutcome {
    NoPendingValidation,
    Recorded {
        snapshot: String,
        metrics: ValidationMetrics,
    },
    Confirm {
        snapshot: String,
        metrics: ValidationMetrics,
    },
    Rollback(PendingValidation),
}

#[async_trait]
impl BackgroundService for AdminApp {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let interval = Duration::from_secs(self.watchdog_interval_secs());

        loop {
            if *shutdown.borrow() {
                break;
            }

            match tokio::time::timeout(interval, shutdown.changed()).await {
                Ok(Ok(())) => continue,
                Ok(Err(_closed)) => break,
                Err(_elapsed) => {
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
    }
}

#[async_trait]
impl ServeHttp for AdminApp {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let request = session.req_header();
        let response = self.handle(
            request.method.as_str(),
            request.uri.path(),
            request.uri.query(),
            &request.headers,
        );

        Response::builder()
            .status(response.status)
            .header(header::CONTENT_TYPE, response.content_type)
            .header(header::CONTENT_LENGTH, response.body.len())
            .header(header::CACHE_CONTROL, "no-store")
            .body(response.body)
            .expect("admin response builder accepts static headers")
    }
}

fn authorization_header(headers: &HeaderMap) -> Option<&str> {
    header_value(headers, header::AUTHORIZATION.as_str())
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn load_admin_token(config: &AdminConfig) -> Result<String, Box<dyn Error + Send + Sync>> {
    let raw = match (&config.token_env, &config.token_file) {
        (Some(env_name), None) => env::var(env_name)
            .map_err(|error| format!("failed to read admin token env {env_name:?}: {error}"))?,
        (None, Some(path)) => read_secret_file(path)?,
        _ => return Err("admin token source is invalid".into()),
    };
    let token = raw.trim().to_owned();
    if token.is_empty() {
        Err("admin token cannot be empty".into())
    } else {
        Ok(token)
    }
}

fn read_secret_file(path: &Path) -> Result<String, Box<dyn Error + Send + Sync>> {
    fs::read_to_string(path).map_err(|error| {
        format!(
            "failed to read admin token file {}: {error}",
            path.display()
        )
        .into()
    })
}

fn authorized(header: Option<&str>, token: &str) -> bool {
    let Some(header) = header else {
        return false;
    };
    let Some(candidate) = header.trim().strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(candidate.trim().as_bytes(), token.as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        let left = left.get(index).copied().unwrap_or(0);
        let right = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left ^ right);
    }
    diff == 0
}

fn json_response(status: StatusCode, body: &[u8]) -> AdminResponse {
    AdminResponse {
        status,
        content_type: "application/json",
        body: body.to_vec(),
    }
}

fn error_response(status: StatusCode, error: &str) -> AdminResponse {
    json_response(
        status,
        format!(r#"{{"status":"error","error":"{}"}}"#, json_escape(error)).as_bytes(),
    )
}

fn snapshot_json(snapshot: &ConfigSnapshot, current: Option<&str>) -> String {
    let message = snapshot
        .metadata
        .message
        .as_deref()
        .map(|message| format!(r#""{}""#, json_escape(message)))
        .unwrap_or_else(|| "null".to_owned());
    format!(
        r#"{{"id":"{}","current":{},"created_unix_secs":{},"message":{message}}}"#,
        json_escape(&snapshot.id),
        current == Some(snapshot.id.as_str()),
        snapshot.metadata.created_unix_secs,
    )
}

fn optional_json_string(value: Option<&str>) -> String {
    value
        .map(|value| format!(r#""{}""#, json_escape(value)))
        .unwrap_or_else(|| "null".to_owned())
}

fn pending_validation_json(pending: Option<&PendingValidation>) -> String {
    let Some(pending) = pending else {
        return "null".to_owned();
    };

    format!(
        r#"{{"target_snapshot":"{}","previous_snapshot":{},"impact":"{}","expires_unix_secs":{},"successful_checks":{},"failed_checks":{},"error_rate_per_mille":{}}}"#,
        json_escape(&pending.target_snapshot),
        optional_json_string(pending.previous_snapshot.as_deref()),
        json_escape(&pending.impact),
        pending.expires_unix_secs,
        pending.successful_checks,
        pending.failed_checks,
        ValidationMetrics {
            successful_checks: pending.successful_checks,
            failed_checks: pending.failed_checks,
        }
        .error_rate_per_mille()
    )
}

fn reload_reasons_json(reasons: &[ReloadReason]) -> String {
    let mut body = String::new();
    for (index, reason) in reasons.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push('"');
        body.push_str(&json_escape(&reason.to_string()));
        body.push('"');
    }
    body
}

#[cfg(feature = "cache")]
fn cache_purge_results_json(results: &[crate::proxy::CachePurgeResult]) -> String {
    let mut body = String::new();
    for (index, result) in results.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str(&format!(
            r#"{{"purged":{},"cache_key":"{}","memory_purged":{},"disk_purged":{}}}"#,
            result.purged(),
            json_escape(&result.cache_key),
            result.memory_purged,
            result.disk_purged
        ));
    }
    body
}

#[cfg(feature = "cache")]
fn cache_totals_json(totals: &crate::proxy::CacheRuntimeTotals) -> String {
    format!(
        r#"{{"vhosts":{},"enabled_vhosts":{},"tiered_vhosts":{},"memory_entries":{},"memory_weighted_size_bytes":{},"memory_max_size_bytes":{},"disk_entries":{},"disk_size_bytes":{},"disk_max_size_bytes":{},"activity":{}}}"#,
        totals.vhosts,
        totals.enabled_vhosts,
        totals.tiered_vhosts,
        totals.memory_entries,
        totals.memory_weighted_size_bytes,
        totals.memory_max_size_bytes,
        totals.disk_entries,
        totals.disk_size_bytes,
        totals.disk_max_size_bytes,
        cache_activity_json(&crate::cache::CacheActivityStats {
            hits: totals.hits,
            misses: totals.misses,
            stores: totals.stores,
            store_refusals: totals.store_refusals,
            purges: totals.purges,
        })
    )
}

#[cfg(feature = "cache")]
fn cache_vhost_stats_json(vhosts: &[crate::proxy::CacheVhostStats]) -> String {
    let mut body = String::new();
    for (index, vhost) in vhosts.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str(&format!(
            r#"{{"name":"{}","enabled":{},"tiered":{},"memory":{},"disk":{}}}"#,
            json_escape(&vhost.name),
            vhost.enabled,
            vhost.tiered,
            memory_cache_stats_json(vhost.memory.as_ref()),
            disk_cache_stats_json(vhost.disk.as_ref())
        ));
    }
    body
}

#[cfg(feature = "cache")]
fn memory_cache_stats_json(stats: Option<&crate::cache::MemoryCacheStats>) -> String {
    stats
        .map(|stats| {
            format!(
                r#"{{"entries":{},"weighted_size_bytes":{},"max_size_bytes":{},"max_object_bytes":{},"activity":{}}}"#,
                stats.entries,
                stats.weighted_size_bytes,
                stats.max_size_bytes.as_u64(),
                stats.max_object_bytes.as_u64(),
                cache_activity_json(&stats.activity)
            )
        })
        .unwrap_or_else(|| "null".to_owned())
}

#[cfg(feature = "cache")]
fn disk_cache_stats_json(stats: Option<&crate::cache::DiskCacheStats>) -> String {
    stats
        .map(|stats| {
            format!(
                r#"{{"entries":{},"size_bytes":{},"max_size_bytes":{},"max_object_bytes":{},"activity":{}}}"#,
                stats.entries,
                stats.size_bytes,
                stats.max_size_bytes.as_u64(),
                stats.max_object_bytes.as_u64(),
                cache_activity_json(&stats.activity)
            )
        })
        .unwrap_or_else(|| "null".to_owned())
}

#[cfg(feature = "cache")]
fn cache_activity_json(activity: &crate::cache::CacheActivityStats) -> String {
    format!(
        r#"{{"hits":{},"misses":{},"stores":{},"store_refusals":{},"purges":{}}}"#,
        activity.hits, activity.misses, activity.stores, activity.store_refusals, activity.purges
    )
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_secs()
}

fn json_escape(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use arc_swap::ArcSwap;
    use http::{HeaderMap, StatusCode, header};

    use super::{
        AdminApp, AdminRuntimeState, admin_services_from_config, authorized, constant_time_eq,
    };
    use crate::config::{
        AdminConfig, AdminSelfHealingConfig, Config, ProxyConfig, ServerConfig, VhostConfig,
        WebConfig,
    };
    #[cfg(feature = "cache")]
    use crate::config::{ByteSize, CacheConfig};
    use crate::proxy::{FluxProxy, ProxyHealthReporter, ProxyHealthSignal};
    use crate::snapshot::SnapshotStore;

    fn app() -> AdminApp {
        app_with_config(Config::default())
    }

    fn app_with_config(config: Config) -> AdminApp {
        app_with_config_and_self_healing(config, false)
    }

    fn app_with_config_and_self_healing(config: Config, self_healing_enabled: bool) -> AdminApp {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_nanos();
        let store = std::env::temp_dir().join(format!(
            "fluxheim-admin-test-{}-{nonce}-{}",
            std::process::id(),
            unique_test_sequence()
        ));
        let proxy = FluxProxy::from_config(&config).unwrap();
        AdminApp {
            token: "secret-token".to_owned(),
            store: SnapshotStore::new(store),
            current_config: Arc::new(ArcSwap::from_pointee(config)),
            proxy,
            health_path: "/_fluxheim/health".to_owned(),
            self_healing_enabled,
            validation_window_secs: AdminSelfHealingConfig::default().validation_window_secs,
            min_successful_checks: AdminSelfHealingConfig::default().min_successful_checks,
            max_error_rate_per_mille: AdminSelfHealingConfig::default().max_error_rate_per_mille,
            state: Arc::new(std::sync::Mutex::new(AdminRuntimeState::default())),
        }
    }

    #[test]
    fn health_endpoint_does_not_require_auth() {
        let response = app().handle("GET", "/_fluxheim/health", None, &HeaderMap::new());

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, br#"{"status":"ok"}"#);
    }

    #[test]
    fn status_endpoint_requires_bearer_token() {
        let response = app().handle("GET", "/_fluxheim/status", None, &HeaderMap::new());
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        let response = app().handle("GET", "/_fluxheim/status", None, &auth_headers());
        assert_eq!(response.status, StatusCode::OK);
        assert!(
            String::from_utf8(response.body)
                .unwrap()
                .contains(r#""pending_validation":null"#)
        );
    }

    #[test]
    fn snapshots_endpoint_requires_auth() {
        let response = app().handle("GET", "/_fluxheim/snapshots", None, &HeaderMap::new());
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        let response = app().handle("GET", "/_fluxheim/snapshots", None, &auth_headers());
        assert_eq!(response.status, StatusCode::OK);
        assert!(
            String::from_utf8(response.body)
                .unwrap()
                .contains(r#""snapshots":["#)
        );
    }

    #[test]
    fn snapshot_endpoint_creates_snapshot() {
        let app = app();
        let response = app.handle("POST", "/_fluxheim/snapshot", None, &auth_headers());

        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(app.store.list().unwrap().len(), 1);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_purge_endpoint_requires_auth_and_purges_by_request_identity() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let app = app_with_config(config);

        let response = app.handle(
            "POST",
            "/_fluxheim/cache/purge",
            Some("host=cached.example&path=/img/logo.png"),
            &HeaderMap::new(),
        );
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        let response = app.handle(
            "POST",
            "/_fluxheim/cache/purge",
            Some("host=cached.example&path=/img/logo.png&url_query=v=1"),
            &auth_headers(),
        );

        assert_eq!(response.status, StatusCode::OK);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(r#""purged":false"#));
        assert!(body.contains(r#""vhost":"cached""#));
        assert!(body.contains(r#""memory_purged":false"#));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_purge_endpoint_rejects_missing_identity() {
        let response = app().handle(
            "POST",
            "/_fluxheim/cache/purge",
            Some("host=example.test"),
            &auth_headers(),
        );

        assert_eq!(response.status, StatusCode::BAD_REQUEST);
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_status_endpoint_reports_vhost_cache_tiers() {
        let cache_path = std::env::temp_dir().join(format!(
            "fluxheim-admin-cache-status-{}-{}",
            std::process::id(),
            unique_test_sequence()
        ));
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    disk: crate::config::CacheDiskConfig {
                        enabled: true,
                        path: Some(cache_path.clone()),
                        max_size_bytes: ByteSize::from_bytes(4096),
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let app = app_with_config(config);

        let unauthorized = app.handle("GET", "/_fluxheim/cache/status", None, &HeaderMap::new());
        assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);

        let response = app.handle("GET", "/_fluxheim/cache/status", None, &auth_headers());

        assert_eq!(response.status, StatusCode::OK);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(r#""status":"ok""#));
        assert!(body.contains(r#""totals":{"vhosts":1"#));
        assert!(body.contains(r#""enabled_vhosts":1"#));
        assert!(body.contains(r#""tiered_vhosts":1"#));
        assert!(body.contains(r#""memory_entries":0"#));
        assert!(body.contains(r#""disk_entries":0"#));
        assert!(body.contains(r#""activity":{"hits":0,"misses":0,"stores":0"#));
        assert!(body.contains(r#""name":"cached""#));
        assert!(body.contains(r#""enabled":true"#));
        assert!(body.contains(r#""tiered":true"#));
        assert!(body.contains(r#""memory":{"entries":0"#));
        assert!(body.contains(r#""disk":{"entries":0"#));

        std::fs::remove_dir_all(cache_path).unwrap();
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_activity_reset_endpoint_requires_auth_and_reports_tiers() {
        let cache_path = std::env::temp_dir().join(format!(
            "fluxheim-admin-cache-reset-{}-{}",
            std::process::id(),
            unique_test_sequence()
        ));
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    disk: crate::config::CacheDiskConfig {
                        enabled: true,
                        path: Some(cache_path.clone()),
                        max_size_bytes: ByteSize::from_bytes(4096),
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let app = app_with_config(config);

        let unauthorized = app.handle(
            "POST",
            "/_fluxheim/cache/activity/reset",
            None,
            &HeaderMap::new(),
        );
        assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);

        let response = app.handle(
            "POST",
            "/_fluxheim/cache/activity/reset",
            None,
            &auth_headers(),
        );

        assert_eq!(response.status, StatusCode::OK);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(r#""status":"ok""#));
        assert!(body.contains(r#""memory_tiers":1"#));
        assert!(body.contains(r#""disk_tiers":1"#));
        assert!(body.contains(r#""tiered_vhosts":1"#));

        std::fs::remove_dir_all(cache_path).unwrap();
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_purge_bulk_endpoint_accepts_repeated_paths() {
        let config = Config {
            vhosts: vec![VhostConfig {
                name: "cached".to_owned(),
                hosts: vec!["cached.example".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: CacheConfig {
                    enabled: true,
                    memory: crate::config::CacheMemoryConfig {
                        enabled: true,
                        max_size_bytes: ByteSize::from_bytes(2048),
                    },
                    max_object_bytes: ByteSize::from_bytes(512),
                    ..CacheConfig::default()
                },
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let app = app_with_config(config);

        let response = app.handle(
            "POST",
            "/_fluxheim/cache/purge-bulk",
            Some("host=cached.example&path=/img/one.png&path=/img/two.png"),
            &auth_headers(),
        );

        assert_eq!(response.status, StatusCode::OK);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(r#""requested":2"#));
        assert!(body.contains(r#""purged":0"#));
        assert!(body.contains(r#""results":["#));
    }

    #[cfg(feature = "cache")]
    #[test]
    fn cache_purge_bulk_endpoint_rejects_empty_paths() {
        let response = app().handle(
            "POST",
            "/_fluxheim/cache/purge-bulk",
            Some("host=example.test"),
            &auth_headers(),
        );

        assert_eq!(response.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn admin_services_enable_watchdog_only_when_self_healing_is_enabled() {
        let dir = TestDir::new("admin-services-watchdog");
        let token_file = dir.path.join("admin-token");
        std::fs::write(&token_file, "secret-token\n").unwrap();
        let config = Config {
            admin: AdminConfig {
                enabled: true,
                token_file: Some(token_file),
                snapshot_store: Some(dir.path.join("snapshots")),
                self_healing: AdminSelfHealingConfig {
                    enabled: true,
                    ..AdminSelfHealingConfig::default()
                },
                ..AdminConfig::default()
            },
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();

        let services = admin_services_from_config(&config, proxy).unwrap().unwrap();

        assert!(services.watchdog.is_some());
    }

    #[test]
    fn admin_from_config_installs_proxy_health_reporter_when_self_healing_is_enabled() {
        let dir = TestDir::new("admin-proxy-health-reporter");
        let token_file = dir.path.join("admin-token");
        std::fs::write(&token_file, "secret-token\n").unwrap();
        let config = Config {
            admin: AdminConfig {
                enabled: true,
                token_file: Some(token_file),
                snapshot_store: Some(dir.path.join("snapshots")),
                self_healing: AdminSelfHealingConfig {
                    enabled: true,
                    ..AdminSelfHealingConfig::default()
                },
                ..AdminConfig::default()
            },
            ..Config::default()
        };
        let proxy = FluxProxy::from_config(&config).unwrap();

        let app = AdminApp::from_config(&config, proxy).unwrap();

        assert!(app.proxy.has_health_reporter());
    }

    #[test]
    fn watchdog_interval_is_bounded() {
        let app = app_with_config_and_self_healing(Config::default(), true);

        assert_eq!(app.watchdog_interval_secs(), 5);
    }

    #[test]
    fn rollback_endpoint_moves_pointer_without_live_apply() {
        let app = app();
        let first = app
            .store
            .snapshot_config(&Config::default(), Some("first"))
            .unwrap();
        let second = app
            .store
            .snapshot_config(&Config::default(), Some("second"))
            .unwrap();
        assert_eq!(app.store.current_id().unwrap(), Some(second.id));

        let response = app.handle("POST", "/_fluxheim/rollback", None, &auth_headers());

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(app.store.current_id().unwrap(), Some(first.id));
        assert!(
            String::from_utf8(response.body)
                .unwrap()
                .contains(r#""live_apply":false"#)
        );
    }

    #[test]
    fn rollback_endpoint_can_live_apply_snapshot_safe_target() {
        let live_config = Config {
            vhosts: vec![VhostConfig {
                name: "live".to_owned(),
                hosts: vec!["live.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let app = app_with_config(live_config.clone());
        let rollback_config = Config {
            vhosts: vec![VhostConfig {
                name: "rollback".to_owned(),
                hosts: vec!["rollback.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let rollback = app
            .store
            .snapshot_config(&rollback_config, Some("rollback"))
            .unwrap();
        let live = app
            .store
            .snapshot_config(&live_config, Some("live"))
            .unwrap();
        assert_eq!(app.store.current_id().unwrap(), Some(live.id));

        let response = app.handle(
            "POST",
            "/_fluxheim/rollback",
            Some("live=true"),
            &auth_headers(),
        );

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(app.store.current_id().unwrap(), Some(rollback.id.clone()));
        assert_eq!(app.proxy.route_host(Some("rollback.test")), "rollback");
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(r#""live_apply":true"#));
        assert!(body.contains(r#""impact":"snapshot""#));
    }

    #[test]
    fn live_rollback_rejects_process_upgrade_target_without_moving_pointer() {
        let app = app();
        let process_upgrade_config = Config {
            server: ServerConfig {
                listen: vec!["127.0.0.1:19081".to_owned()],
                ..ServerConfig::default()
            },
            ..Config::default()
        };
        let process_upgrade = app
            .store
            .snapshot_config(&process_upgrade_config, Some("process upgrade"))
            .unwrap();
        let current = app
            .store
            .snapshot_config(&Config::default(), Some("current"))
            .unwrap();
        assert_eq!(app.store.current_id().unwrap(), Some(current.id.clone()));

        let response = app.handle(
            "POST",
            "/_fluxheim/rollback",
            Some("live=true"),
            &auth_headers(),
        );

        assert_eq!(response.status, StatusCode::CONFLICT);
        assert_eq!(app.store.current_id().unwrap(), Some(current.id));
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(&process_upgrade.id));
        assert!(body.contains("listener-changed"));
    }

    #[test]
    fn reload_endpoint_requires_current_snapshot() {
        let response = app().handle("POST", "/_fluxheim/reload", None, &auth_headers());

        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(
            String::from_utf8(response.body)
                .unwrap()
                .contains("current pointer")
        );
    }

    #[test]
    fn reload_endpoint_applies_snapshot_safe_config() {
        let app = app();
        let new_config = Config {
            vhosts: vec![VhostConfig {
                name: "example".to_owned(),
                hosts: vec!["example.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let snapshot = app
            .store
            .snapshot_config(&new_config, Some("add example vhost"))
            .unwrap();

        let response = app.handle("POST", "/_fluxheim/reload", None, &auth_headers());

        assert_eq!(response.status, StatusCode::OK);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(r#""live_apply":true"#));
        assert!(body.contains(&snapshot.id));
        assert_eq!(app.proxy.route_host(Some("example.test")), "example");
        assert_eq!(app.current_config.load().vhosts[0].name, "example");
    }

    #[test]
    fn self_healing_reload_enters_pending_validation() {
        let app = app_with_config_and_self_healing(Config::default(), true);
        let baseline = app
            .store
            .snapshot_config(&Config::default(), Some("baseline"))
            .unwrap();
        app.state.lock().unwrap().runtime_snapshot = Some(baseline.id.clone());
        app.state.lock().unwrap().known_good_snapshot = Some(baseline.id.clone());

        let new_config = Config {
            vhosts: vec![VhostConfig {
                name: "candidate".to_owned(),
                hosts: vec!["candidate.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let candidate = app
            .store
            .snapshot_config(&new_config, Some("candidate"))
            .unwrap();

        let response = app.handle("POST", "/_fluxheim/reload", None, &auth_headers());

        assert_eq!(response.status, StatusCode::OK);
        let state = app.runtime_state();
        let pending = state.pending_validation.unwrap();
        assert_eq!(state.runtime_snapshot, Some(candidate.id.clone()));
        assert_eq!(state.known_good_snapshot, Some(baseline.id.clone()));
        assert_eq!(pending.target_snapshot, candidate.id);
        assert_eq!(pending.previous_snapshot, Some(baseline.id));
    }

    #[test]
    fn self_healing_confirm_marks_pending_snapshot_known_good() {
        let app = app_with_config_and_self_healing(Config::default(), true);
        let snapshot = app
            .store
            .snapshot_config(&Config::default(), Some("candidate"))
            .unwrap();
        app.state.lock().unwrap().pending_validation = Some(super::PendingValidation {
            target_snapshot: snapshot.id.clone(),
            previous_snapshot: None,
            impact: "noop".to_owned(),
            expires_unix_secs: super::unix_secs().saturating_add(30),
            successful_checks: 0,
            failed_checks: 0,
        });

        let response = app.handle(
            "POST",
            "/_fluxheim/self-heal/confirm",
            None,
            &auth_headers(),
        );

        assert_eq!(response.status, StatusCode::OK);
        let state = app.runtime_state();
        assert_eq!(state.pending_validation, None);
        assert_eq!(state.known_good_snapshot, Some(snapshot.id));
    }

    #[test]
    fn self_healing_report_confirms_after_enough_successes() {
        let mut app = app_with_config_and_self_healing(Config::default(), true);
        app.min_successful_checks = 2;
        let snapshot = app
            .store
            .snapshot_config(&Config::default(), Some("candidate"))
            .unwrap();
        app.state.lock().unwrap().pending_validation = Some(super::PendingValidation {
            target_snapshot: snapshot.id.clone(),
            previous_snapshot: None,
            impact: "noop".to_owned(),
            expires_unix_secs: super::unix_secs().saturating_add(30),
            successful_checks: 0,
            failed_checks: 0,
        });

        let response = app.handle(
            "POST",
            "/_fluxheim/self-heal/report",
            Some("health=ok"),
            &auth_headers(),
        );
        assert_eq!(response.status, StatusCode::OK);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(r#""action":"recorded""#));
        assert_eq!(
            app.runtime_state()
                .pending_validation
                .as_ref()
                .unwrap()
                .successful_checks,
            1
        );

        let response = app.handle(
            "POST",
            "/_fluxheim/self-heal/report",
            Some("success=true"),
            &auth_headers(),
        );

        assert_eq!(response.status, StatusCode::OK);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(r#""action":"confirmed""#));
        let state = app.runtime_state();
        assert_eq!(state.pending_validation, None);
        assert_eq!(state.known_good_snapshot, Some(snapshot.id));
    }

    #[test]
    fn self_healing_report_rolls_back_when_error_rate_exceeds_threshold() {
        let baseline_config = Config {
            vhosts: vec![VhostConfig {
                name: "baseline".to_owned(),
                hosts: vec!["baseline.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let app = app_with_config_and_self_healing(baseline_config.clone(), true);
        let baseline = app
            .store
            .snapshot_config(&baseline_config, Some("baseline"))
            .unwrap();
        let candidate_config = Config {
            vhosts: vec![VhostConfig {
                name: "candidate".to_owned(),
                hosts: vec!["candidate.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let candidate = app
            .store
            .snapshot_config(&candidate_config, Some("candidate"))
            .unwrap();
        app.state.lock().unwrap().runtime_snapshot = Some(candidate.id.clone());
        app.state.lock().unwrap().known_good_snapshot = Some(baseline.id.clone());
        app.state.lock().unwrap().pending_validation = Some(super::PendingValidation {
            target_snapshot: candidate.id.clone(),
            previous_snapshot: Some(baseline.id.clone()),
            impact: "snapshot".to_owned(),
            expires_unix_secs: super::unix_secs().saturating_add(30),
            successful_checks: 0,
            failed_checks: 0,
        });
        app.proxy.reload_from_config(&candidate_config).unwrap();

        let response = app.handle(
            "POST",
            "/_fluxheim/self-heal/report",
            Some("health=error"),
            &auth_headers(),
        );

        assert_eq!(response.status, StatusCode::OK);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(r#""reason":"error-rate""#));
        assert_eq!(app.store.current_id().unwrap(), Some(baseline.id.clone()));
        assert_eq!(app.proxy.route_host(Some("baseline.test")), "baseline");
        let state = app.runtime_state();
        assert_eq!(state.pending_validation, None);
        assert_eq!(state.known_good_snapshot, Some(baseline.id));
    }

    #[test]
    fn proxy_health_signal_confirms_pending_snapshot() {
        let mut app = app_with_config_and_self_healing(Config::default(), true);
        app.min_successful_checks = 2;
        let snapshot = app
            .store
            .snapshot_config(&Config::default(), Some("candidate"))
            .unwrap();
        app.state.lock().unwrap().pending_validation = Some(super::PendingValidation {
            target_snapshot: snapshot.id.clone(),
            previous_snapshot: None,
            impact: "noop".to_owned(),
            expires_unix_secs: super::unix_secs().saturating_add(30),
            successful_checks: 1,
            failed_checks: 0,
        });

        ProxyHealthReporter::record_proxy_health_signal(&app, ProxyHealthSignal::Success);

        let state = app.runtime_state();
        assert_eq!(state.pending_validation, None);
        assert_eq!(state.known_good_snapshot, Some(snapshot.id));
    }

    #[test]
    fn proxy_health_signal_rolls_back_when_error_rate_exceeds_threshold() {
        let baseline_config = Config {
            vhosts: vec![VhostConfig {
                name: "baseline".to_owned(),
                hosts: vec!["baseline.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let app = app_with_config_and_self_healing(baseline_config.clone(), true);
        let baseline = app
            .store
            .snapshot_config(&baseline_config, Some("baseline"))
            .unwrap();
        let candidate_config = Config {
            vhosts: vec![VhostConfig {
                name: "candidate".to_owned(),
                hosts: vec!["candidate.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let candidate = app
            .store
            .snapshot_config(&candidate_config, Some("candidate"))
            .unwrap();
        app.state.lock().unwrap().runtime_snapshot = Some(candidate.id.clone());
        app.state.lock().unwrap().known_good_snapshot = Some(baseline.id.clone());
        app.state.lock().unwrap().pending_validation = Some(super::PendingValidation {
            target_snapshot: candidate.id.clone(),
            previous_snapshot: Some(baseline.id.clone()),
            impact: "snapshot".to_owned(),
            expires_unix_secs: super::unix_secs().saturating_add(30),
            successful_checks: 0,
            failed_checks: 0,
        });
        app.proxy.reload_from_config(&candidate_config).unwrap();

        ProxyHealthReporter::record_proxy_health_signal(&app, ProxyHealthSignal::Failure);

        assert_eq!(app.store.current_id().unwrap(), Some(baseline.id.clone()));
        assert_eq!(app.proxy.route_host(Some("baseline.test")), "baseline");
        let state = app.runtime_state();
        assert_eq!(state.pending_validation, None);
        assert_eq!(state.known_good_snapshot, Some(baseline.id));
    }

    #[test]
    fn watchdog_guard_rolls_back_persisted_error_rate() {
        let baseline_config = Config {
            vhosts: vec![VhostConfig {
                name: "baseline".to_owned(),
                hosts: vec!["baseline.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let app = app_with_config_and_self_healing(baseline_config.clone(), true);
        let baseline = app
            .store
            .snapshot_config(&baseline_config, Some("baseline"))
            .unwrap();
        let candidate_config = Config {
            vhosts: vec![VhostConfig {
                name: "candidate".to_owned(),
                hosts: vec!["candidate.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let candidate = app
            .store
            .snapshot_config(&candidate_config, Some("candidate"))
            .unwrap();
        app.state.lock().unwrap().runtime_snapshot = Some(candidate.id.clone());
        app.state.lock().unwrap().known_good_snapshot = Some(baseline.id.clone());
        app.state.lock().unwrap().pending_validation = Some(super::PendingValidation {
            target_snapshot: candidate.id.clone(),
            previous_snapshot: Some(baseline.id.clone()),
            impact: "snapshot".to_owned(),
            expires_unix_secs: super::unix_secs().saturating_add(30),
            successful_checks: 0,
            failed_checks: 1,
        });
        app.proxy.reload_from_config(&candidate_config).unwrap();

        let response = app.handle("GET", "/_fluxheim/status", None, &auth_headers());

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(app.store.current_id().unwrap(), Some(baseline.id.clone()));
        assert_eq!(app.proxy.route_host(Some("baseline.test")), "baseline");
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(r#""reason":"error-rate""#));
        assert_eq!(app.runtime_state().known_good_snapshot, Some(baseline.id));
    }

    #[test]
    fn self_healing_fail_rolls_back_to_previous_snapshot() {
        let baseline_config = Config {
            vhosts: vec![VhostConfig {
                name: "baseline".to_owned(),
                hosts: vec!["baseline.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let app = app_with_config_and_self_healing(baseline_config.clone(), true);
        let baseline = app
            .store
            .snapshot_config(&baseline_config, Some("baseline"))
            .unwrap();
        let candidate_config = Config {
            vhosts: vec![VhostConfig {
                name: "candidate".to_owned(),
                hosts: vec!["candidate.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let candidate = app
            .store
            .snapshot_config(&candidate_config, Some("candidate"))
            .unwrap();
        app.state.lock().unwrap().runtime_snapshot = Some(candidate.id.clone());
        app.state.lock().unwrap().known_good_snapshot = Some(baseline.id.clone());
        app.state.lock().unwrap().pending_validation = Some(super::PendingValidation {
            target_snapshot: candidate.id.clone(),
            previous_snapshot: Some(baseline.id.clone()),
            impact: "snapshot".to_owned(),
            expires_unix_secs: 1,
            successful_checks: 0,
            failed_checks: 0,
        });
        app.proxy.reload_from_config(&candidate_config).unwrap();

        let response = app.handle("POST", "/_fluxheim/self-heal/fail", None, &auth_headers());

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(app.store.current_id().unwrap(), Some(baseline.id.clone()));
        assert_eq!(app.proxy.route_host(Some("baseline.test")), "baseline");
        let state = app.runtime_state();
        assert_eq!(state.pending_validation, None);
        assert_eq!(state.known_good_snapshot, Some(baseline.id));
    }

    #[test]
    fn expired_self_healing_validation_rolls_back_fail_closed() {
        let baseline_config = Config {
            vhosts: vec![VhostConfig {
                name: "baseline".to_owned(),
                hosts: vec!["baseline.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let app = app_with_config_and_self_healing(baseline_config.clone(), true);
        let baseline = app
            .store
            .snapshot_config(&baseline_config, Some("baseline"))
            .unwrap();
        let candidate_config = Config {
            vhosts: vec![VhostConfig {
                name: "candidate".to_owned(),
                hosts: vec!["candidate.test".to_owned()],
                tls: crate::config::VhostTlsConfig::default(),
                proxy: ProxyConfig::default(),
                cache: crate::config::CacheConfig::default(),
                web: WebConfig::default(),
            }],
            ..Config::default()
        };
        let candidate = app
            .store
            .snapshot_config(&candidate_config, Some("candidate"))
            .unwrap();
        app.state.lock().unwrap().runtime_snapshot = Some(candidate.id.clone());
        app.state.lock().unwrap().known_good_snapshot = Some(baseline.id.clone());
        app.state.lock().unwrap().pending_validation = Some(super::PendingValidation {
            target_snapshot: candidate.id.clone(),
            previous_snapshot: Some(baseline.id.clone()),
            impact: "snapshot".to_owned(),
            expires_unix_secs: 0,
            successful_checks: 0,
            failed_checks: 0,
        });
        app.proxy.reload_from_config(&candidate_config).unwrap();

        let response = app.handle("GET", "/_fluxheim/status", None, &auth_headers());

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(app.store.current_id().unwrap(), Some(baseline.id.clone()));
        assert_eq!(app.proxy.route_host(Some("baseline.test")), "baseline");
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(r#""reason":"expired""#));
        assert!(body.contains(&candidate.id));
        let state = app.runtime_state();
        assert_eq!(state.pending_validation, None);
        assert_eq!(state.known_good_snapshot, Some(baseline.id));
    }

    #[test]
    fn reload_endpoint_rejects_process_upgrade_config() {
        let app = app();
        let new_config = Config {
            server: ServerConfig {
                listen: vec!["127.0.0.1:19081".to_owned()],
                ..ServerConfig::default()
            },
            ..Config::default()
        };
        app.store
            .snapshot_config(&new_config, Some("change listener"))
            .unwrap();

        let response = app.handle("POST", "/_fluxheim/reload", None, &auth_headers());

        assert_eq!(response.status, StatusCode::CONFLICT);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains(r#""error":"process_upgrade_required""#));
        assert!(body.contains("listener-changed"));
    }

    #[test]
    fn rejects_unknown_paths_and_methods() {
        assert_eq!(
            app()
                .handle("GET", "/missing", None, &auth_headers())
                .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            app()
                .handle("POST", "/_fluxheim/status", None, &auth_headers())
                .status,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    #[test]
    fn bearer_token_comparison_checks_full_string() {
        assert!(authorized(Some("Bearer secret-token"), "secret-token"));
        assert!(!authorized(Some("Bearer secret"), "secret-token"));
        assert!(!constant_time_eq(b"secret", b"secret-token"));
    }

    fn auth_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer secret-token".parse().unwrap(),
        );
        headers
    }

    fn unique_test_sequence() -> u64 {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    }

    struct TestDir {
        path: std::path::PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "fluxheim-{name}-{nonce}-{}",
                unique_test_sequence()
            ));
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

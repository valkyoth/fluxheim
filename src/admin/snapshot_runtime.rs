use super::*;

impl AdminApp {
    pub(super) fn snapshots_response(&self) -> AdminResponse {
        match self.store.list_entries() {
            Ok(snapshots) => {
                let current = self.store.current_id().ok().flatten();
                let snapshots = snapshots
                    .iter()
                    .map(|entry| snapshot_entry_json(entry, current.as_deref()))
                    .collect::<Vec<_>>();
                json_response_value(
                    StatusCode::OK,
                    &json!({"status": "ok", "snapshots": snapshots}),
                )
            }
            Err(error) => internal_error_response(&error),
        }
    }

    pub(super) fn create_snapshot_response(&self, message: Option<&str>) -> AdminResponse {
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

    pub(super) fn rollback_response(
        &self,
        target: Option<&str>,
        live_apply: bool,
    ) -> AdminResponse {
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

    pub(super) fn reload_response(&self) -> AdminResponse {
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

    pub(super) fn apply_snapshot(
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
        if mode != SnapshotApplyMode::SelfHealRollback {
            self.record_applied_snapshot(snapshot.id.clone(), impact.clone(), mode)
                .map_err(|error| internal_error_response(&error))?;
        }

        Ok(impact)
    }

    pub(super) fn reload_proxy_from_config(&self, new_config: &Config) -> io::Result<()> {
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

    pub(super) fn self_heal_confirm_response(&self) -> AdminResponse {
        if !self.self_healing_enabled {
            return error_response(StatusCode::BAD_REQUEST, "self-healing is disabled");
        }

        let mut state = self.lock_runtime_state();
        let Some(snapshot) = state.confirm_pending_validation() else {
            return error_response(StatusCode::BAD_REQUEST, "no pending validation");
        };
        drop(state);
        self.set_validation_deadline(None);
        if let Err(error) = self.persist_runtime_state() {
            return internal_error_response(&error);
        }

        json_response_value(
            StatusCode::OK,
            &json!({
                "status": "ok",
                "known_good_snapshot": snapshot,
                "confirmed_snapshot": snapshot,
            }),
        )
    }

    pub(super) fn self_heal_fail_response(&self) -> AdminResponse {
        if !self.self_healing_enabled {
            return error_response(StatusCode::BAD_REQUEST, "self-healing is disabled");
        }

        let pending = match self.pending_validation() {
            Some(pending) => pending,
            None => return error_response(StatusCode::BAD_REQUEST, "no pending validation"),
        };

        self.rollback_pending_validation(&pending, "manual")
    }

    pub(super) fn self_heal_report_response(&self, health: Option<&str>) -> AdminResponse {
        if !self.self_healing_enabled {
            return error_response(StatusCode::BAD_REQUEST, "self-healing is disabled");
        }

        let Some(healthy) = health.and_then(parse_health_signal) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "health signal must be ok/success/true/1 or error/fail/false/0",
            );
        };

        let outcome = {
            self.lock_runtime_state().record_health_signal(
                healthy,
                self.min_successful_checks,
                self.max_error_rate_per_mille,
            )
        };
        if matches!(outcome, SnapshotHealthSignalOutcome::Confirm { .. }) {
            self.set_validation_deadline(None);
        }
        if let Err(error) = self.persist_runtime_state() {
            return internal_error_response(&error);
        }
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

    pub(super) fn enforce_self_healing_deadline(&self) -> Option<AdminResponse> {
        if !self.self_healing_enabled {
            return None;
        }

        let expired = self.validation_expired();
        let rollback = self
            .lock_runtime_state()
            .rollback_required(expired, self.max_error_rate_per_mille)?;

        Some(self.rollback_pending_validation(&rollback.0, rollback.1.as_str()))
    }

    pub(super) fn watchdog_interval_secs(&self) -> u64 {
        self.validation_window_secs.clamp(1, 5)
    }

    pub(super) fn rollback_pending_validation(
        &self,
        pending: &PendingValidation,
        reason: &str,
    ) -> AdminResponse {
        let Some(target) = pending.previous_snapshot.as_deref() else {
            self.record_failed_rollback(pending);
            return error_response(StatusCode::BAD_REQUEST, "no previous known-good snapshot");
        };
        let snapshot = match self.store.rollback_candidate(Some(target)) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.record_failed_rollback(pending);
                return error_response(StatusCode::BAD_REQUEST, &error.to_string());
            }
        };
        let new_config = match Config::load(Some(&snapshot.config_path)) {
            Ok(config) => config,
            Err(error) => {
                self.record_failed_rollback(pending);
                return error_response(StatusCode::BAD_REQUEST, &error.to_string());
            }
        };
        let impact =
            match self.apply_snapshot(&snapshot, new_config, SnapshotApplyMode::SelfHealRollback) {
                Ok(impact) => impact,
                Err(response) => {
                    self.record_failed_rollback(pending);
                    return response;
                }
            };
        if let Err(error) = self.store.set_current_snapshot(&snapshot.id) {
            self.record_failed_rollback(pending);
            return internal_error_response(&error);
        }
        self.lock_runtime_state()
            .complete_rollback(snapshot.id.clone());
        self.set_validation_deadline(None);
        if let Err(error) = self.persist_runtime_state() {
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

    pub(super) fn record_applied_snapshot(
        &self,
        snapshot: String,
        impact: String,
        mode: SnapshotApplyMode,
    ) -> Result<(), SnapshotError> {
        self.lock_runtime_state().record_applied_snapshot(
            snapshot,
            impact,
            mode,
            self.self_healing_enabled,
            self.validation_window_secs,
            unix_secs(),
        );
        let pending = self.lock_runtime_state().pending_validation.is_some();
        self.set_validation_deadline(
            pending.then(|| {
                std::time::Instant::now() + Duration::from_secs(self.validation_window_secs)
            }),
        );
        self.persist_runtime_state()
    }

    pub(super) fn runtime_state(&self) -> SnapshotRuntimeState {
        self.lock_runtime_state().clone()
    }

    pub(super) fn pending_validation(&self) -> Option<PendingValidation> {
        self.lock_runtime_state().pending_validation.clone()
    }

    pub(super) fn persist_runtime_state(&self) -> Result<(), SnapshotError> {
        self.store.save_runtime_state(&self.runtime_state())
    }

    fn record_failed_rollback(&self, pending: &PendingValidation) {
        self.lock_runtime_state().rollback_failed(pending.clone());
        if let Err(error) = self.persist_runtime_state() {
            log::error!(
                target: "fluxheim::security",
                "failed to persist retryable snapshot rollback state: {error}"
            );
        }
    }

    fn validation_expired(&self) -> bool {
        let deadline = self.lock_validation_deadline();
        match *deadline {
            Some(deadline) => std::time::Instant::now() >= deadline,
            None => self
                .lock_runtime_state()
                .pending_validation
                .as_ref()
                .is_some_and(|pending| pending.expires_unix_secs <= unix_secs()),
        }
    }

    fn set_validation_deadline(&self, deadline: Option<std::time::Instant>) {
        *self.lock_validation_deadline() = deadline;
    }

    fn lock_validation_deadline(&self) -> std::sync::MutexGuard<'_, Option<std::time::Instant>> {
        match self.validation_deadline.lock() {
            Ok(guard) => guard,
            Err(_) => {
                log::error!(
                    target: "fluxheim::security",
                    "admin validation deadline lock poisoned; aborting to avoid inconsistent self-healing state"
                );
                std::process::abort();
            }
        }
    }

    pub(super) fn lock_runtime_state(&self) -> std::sync::MutexGuard<'_, SnapshotRuntimeState> {
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

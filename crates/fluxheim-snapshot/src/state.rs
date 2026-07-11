use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRuntimeState {
    pub runtime_snapshot: Option<String>,
    pub known_good_snapshot: Option<String>,
    pub pending_validation: Option<PendingValidation>,
}

impl SnapshotRuntimeState {
    pub fn record_applied_snapshot(
        &mut self,
        snapshot: String,
        impact: String,
        mode: SnapshotApplyMode,
        self_healing_enabled: bool,
        validation_window_secs: u64,
        now_unix_secs: u64,
    ) {
        let previous = self.runtime_snapshot.clone();
        self.runtime_snapshot = Some(snapshot.clone());

        match mode {
            SnapshotApplyMode::Reload if self_healing_enabled => {
                self.pending_validation = Some(PendingValidation {
                    target_snapshot: snapshot,
                    previous_snapshot: previous.or_else(|| self.known_good_snapshot.clone()),
                    impact,
                    expires_unix_secs: now_unix_secs.saturating_add(validation_window_secs),
                    successful_checks: 0,
                    failed_checks: 0,
                    rollback_attempts: 0,
                    last_rollback_failure: None,
                });
            }
            SnapshotApplyMode::Reload => {
                self.known_good_snapshot = Some(snapshot);
                self.pending_validation = None;
            }
            SnapshotApplyMode::Rollback | SnapshotApplyMode::SelfHealRollback => {
                self.known_good_snapshot = Some(snapshot);
                self.pending_validation = None;
            }
        }
    }

    pub fn confirm_pending_validation(&mut self) -> Option<String> {
        let pending = self.pending_validation.take()?;
        self.known_good_snapshot = Some(pending.target_snapshot.clone());
        self.runtime_snapshot = Some(pending.target_snapshot.clone());
        Some(pending.target_snapshot)
    }

    pub fn record_health_signal(
        &mut self,
        healthy: bool,
        min_successful_checks: usize,
        max_error_rate_per_mille: u16,
    ) -> SnapshotHealthSignalOutcome {
        let Some(pending) = self.pending_validation.as_mut() else {
            return SnapshotHealthSignalOutcome::NoPendingValidation;
        };

        if healthy {
            pending.successful_checks = pending.successful_checks.saturating_add(1);
        } else {
            pending.failed_checks = pending.failed_checks.saturating_add(1);
        }

        let metrics = pending.metrics();

        if metrics.failed_checks > 0
            && metrics.error_rate_per_mille() > u64::from(max_error_rate_per_mille)
        {
            return SnapshotHealthSignalOutcome::Rollback(pending.clone());
        }

        if metrics.successful_checks >= min_successful_checks {
            let snapshot = pending.target_snapshot.clone();
            self.known_good_snapshot = Some(snapshot.clone());
            self.runtime_snapshot = Some(snapshot.clone());
            self.pending_validation = None;
            return SnapshotHealthSignalOutcome::Confirm { snapshot, metrics };
        }

        let snapshot = pending.target_snapshot.clone();
        SnapshotHealthSignalOutcome::Recorded { snapshot, metrics }
    }

    pub fn expired_or_unhealthy_pending(
        &mut self,
        now_unix_secs: u64,
        max_error_rate_per_mille: u16,
    ) -> Option<(PendingValidation, SnapshotRollbackReason)> {
        let expired = self
            .pending_validation
            .as_ref()
            .is_some_and(|pending| pending.expires_unix_secs <= now_unix_secs);
        self.rollback_required(expired, max_error_rate_per_mille)
    }

    pub fn rollback_required(
        &self,
        expired: bool,
        max_error_rate_per_mille: u16,
    ) -> Option<(PendingValidation, SnapshotRollbackReason)> {
        let pending = self.pending_validation.as_ref()?;
        let metrics = pending.metrics();
        let reason = if metrics.failed_checks > 0
            && metrics.error_rate_per_mille() > u64::from(max_error_rate_per_mille)
        {
            SnapshotRollbackReason::ErrorRate
        } else if expired {
            SnapshotRollbackReason::Expired
        } else {
            return None;
        };
        Some((pending.clone(), reason))
    }

    pub fn complete_rollback(&mut self, restored_snapshot: String) {
        self.runtime_snapshot = Some(restored_snapshot.clone());
        self.known_good_snapshot = Some(restored_snapshot);
        self.pending_validation = None;
    }

    pub fn rollback_failed(&mut self, mut pending: PendingValidation) {
        pending.rollback_attempts = pending.rollback_attempts.saturating_add(1);
        pending.last_rollback_failure = Some("rollback application did not complete".to_owned());
        self.pending_validation = Some(pending);
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SnapshotApplyMode {
    Reload,
    Rollback,
    SelfHealRollback,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingValidation {
    pub target_snapshot: String,
    pub previous_snapshot: Option<String>,
    pub impact: String,
    pub expires_unix_secs: u64,
    pub successful_checks: usize,
    pub failed_checks: usize,
    #[serde(default)]
    pub rollback_attempts: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rollback_failure: Option<String>,
}

impl PendingValidation {
    pub fn metrics(&self) -> ValidationMetrics {
        ValidationMetrics {
            successful_checks: self.successful_checks,
            failed_checks: self.failed_checks,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ValidationMetrics {
    pub successful_checks: usize,
    pub failed_checks: usize,
}

impl ValidationMetrics {
    pub fn error_rate_per_mille(&self) -> u64 {
        let total = self.successful_checks.saturating_add(self.failed_checks);
        if total == 0 {
            return 0;
        }
        (self.failed_checks as u64).saturating_mul(1000) / (total as u64)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SnapshotHealthSignalOutcome {
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SnapshotRollbackReason {
    ErrorRate,
    Expired,
}

impl SnapshotRollbackReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ErrorRate => "error-rate",
            Self::Expired => "expired",
        }
    }
}

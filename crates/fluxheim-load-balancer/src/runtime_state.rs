use std::io;
use std::path::Path;

use super::state_file::{load_runtime_state_file, write_runtime_state_file};
use super::{
    LoadBalancerRuntimeStateRestore, LoadBalancerRuntimeStateSnapshot, UpstreamLoadBalancer,
};

const LOAD_BALANCER_RUNTIME_STATE_VERSION: u16 = 1;

impl UpstreamLoadBalancer {
    pub fn runtime_state_persistent(&self) -> bool {
        self.runtime_state_file.is_some()
    }

    pub fn runtime_state_snapshot(&self) -> LoadBalancerRuntimeStateSnapshot {
        let live_keys = self.live_backend_keys();
        LoadBalancerRuntimeStateSnapshot {
            version: LOAD_BALANCER_RUNTIME_STATE_VERSION,
            runtime_overrides: self.backend_policy.runtime_snapshot(),
            persistence: self
                .persistence
                .as_ref()
                .map(|persistence| persistence.snapshot(&live_keys)),
        }
    }

    pub fn restore_runtime_state_snapshot(
        &self,
        snapshot: &LoadBalancerRuntimeStateSnapshot,
    ) -> io::Result<LoadBalancerRuntimeStateRestore> {
        if snapshot.version != LOAD_BALANCER_RUNTIME_STATE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported load balancer runtime state version",
            ));
        }
        let prepared_policy = self
            .backend_policy
            .prepare_runtime_snapshot(&snapshot.runtime_overrides)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let live_keys = self.live_backend_keys();
        let prepared_persistence = if let (Some(persistence), Some(snapshot)) =
            (&self.persistence, &snapshot.persistence)
        {
            Some(
                persistence
                    .prepare_snapshot(snapshot, &live_keys)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            )
        } else {
            None
        };
        let persistence_entries = prepared_persistence
            .as_ref()
            .map_or(0, |snapshot| snapshot.restored_entries());
        self.backend_policy.commit_runtime_snapshot(prepared_policy);
        if let (Some(persistence), Some(snapshot)) = (&self.persistence, prepared_persistence) {
            persistence.commit_snapshot(snapshot);
        }
        Ok(LoadBalancerRuntimeStateRestore {
            persistence_entries,
        })
    }

    pub(super) fn load_runtime_state_if_configured(&self) {
        let Some(path) = &self.runtime_state_file else {
            return;
        };
        match load_runtime_state_file(path) {
            Ok(Some(snapshot)) => match self.restore_runtime_state_snapshot(&snapshot) {
                Ok(restored) => log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer runtime state restored path={} persistence_entries={}",
                    path.display(),
                    restored.persistence_entries
                ),
                Err(error) => log::warn!(
                    target: "fluxheim::security",
                    "load balancer runtime state ignored path={} error={}",
                    path.display(),
                    error
                ),
            },
            Ok(None) => {}
            Err(error) => log::warn!(
                target: "fluxheim::security",
                "load balancer runtime state could not be read path={} error={}",
                path.display(),
                error
            ),
        }
    }

    pub(super) fn save_runtime_state_if_configured(&self, reason: &str) {
        let Some(path) = &self.runtime_state_file else {
            return;
        };
        let _guard = self
            .runtime_state_save_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let snapshot = self.runtime_state_snapshot();
        write_runtime_state_snapshot(path, &snapshot, reason);
    }

    pub(super) fn save_runtime_state_if_configured_in_background(&self, reason: &'static str) {
        if self.runtime_state_file.is_none() {
            return;
        }
        let balancer = self.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || {
                balancer.save_runtime_state_if_configured(reason);
            });
        } else {
            self.save_runtime_state_if_configured(reason);
        }
    }
}

fn write_runtime_state_snapshot(
    path: &Path,
    snapshot: &LoadBalancerRuntimeStateSnapshot,
    reason: &str,
) {
    match write_runtime_state_file(path, snapshot) {
        Ok(()) => log::debug!(
            target: "fluxheim::load_balancer",
            "load balancer runtime state saved path={} reason={}",
            path.display(),
            reason
        ),
        Err(error) => log::warn!(
            target: "fluxheim::security",
            "load balancer runtime state save failed path={} reason={} error={}",
            path.display(),
            reason,
            error
        ),
    }
}

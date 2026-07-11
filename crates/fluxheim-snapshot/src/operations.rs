use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::time::Duration;

use serde::Serialize;

use crate::prune_boundary::PruneBoundary;
use crate::store::{
    MAX_SNAPSHOT_STORE_ENTRIES, SnapshotEntryStatus, SnapshotError, SnapshotIntegrityStatus,
    SnapshotStore,
};
use crate::store_fs::{
    path_exists_without_following_symlinks, require_private_regular_file, sync_directory,
};
use crate::store_support::unix_duration;

const MAX_DOCTOR_ISSUES: usize = 4096;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SnapshotPruneOptions {
    pub keep: Option<usize>,
    pub older_than: Option<Duration>,
    pub protected_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize)]
pub struct SnapshotPruneReport {
    pub deleted: Vec<String>,
    pub retained: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct SnapshotDiff {
    pub old: String,
    pub new: String,
    pub changed_top_level_fields: Vec<String>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize)]
pub struct SnapshotDoctorReport {
    pub healthy: bool,
    pub checked_snapshots: usize,
    pub authenticated_snapshots: usize,
    pub unverified_snapshots: usize,
    pub issues: Vec<String>,
}

impl SnapshotStore {
    pub fn verify(&self, id: &str) -> Result<SnapshotIntegrityStatus, SnapshotError> {
        Ok(self.snapshot(id)?.integrity)
    }

    pub fn diff(&self, old: &str, new: &str) -> Result<SnapshotDiff, SnapshotError> {
        let (old, old_bytes) = self.load_snapshot_config_bytes(old)?;
        let (new, new_bytes) = self.load_snapshot_config_bytes(new)?;
        let old_value = read_snapshot_toml(&old_bytes)?;
        let new_value = read_snapshot_toml(&new_bytes)?;
        let old_table = old_value.as_table().ok_or_else(invalid_snapshot_toml)?;
        let new_table = new_value.as_table().ok_or_else(invalid_snapshot_toml)?;
        let fields = old_table
            .keys()
            .chain(new_table.keys())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|field| old_table.get(*field) != new_table.get(*field))
            .cloned()
            .collect();
        Ok(SnapshotDiff {
            old: old.id,
            new: new.id,
            changed_top_level_fields: fields,
        })
    }

    pub fn doctor(&self) -> Result<SnapshotDoctorReport, SnapshotError> {
        let entries = self.list_entries()?;
        let mut report = SnapshotDoctorReport {
            healthy: true,
            checked_snapshots: entries.len(),
            ..SnapshotDoctorReport::default()
        };
        if !self.root().exists() {
            return Ok(report);
        }
        let current = match self.current_id() {
            Ok(current) => current,
            Err(_) => {
                push_issue(&mut report, "current pointer failed validation".to_owned());
                None
            }
        };
        let ids = entries
            .iter()
            .map(|entry| entry.id.clone())
            .collect::<BTreeSet<_>>();
        let prune_boundaries = match self.load_prune_boundaries() {
            Ok(boundaries) => boundaries,
            Err(_) => {
                push_issue(
                    &mut report,
                    "snapshot pruning boundary state failed validation".to_owned(),
                );
                BTreeSet::new()
            }
        };
        if let Some(current) = current.as_deref()
            && !ids.contains(current)
        {
            push_issue(
                &mut report,
                "current pointer does not reference a snapshot".to_owned(),
            );
        }
        let mut generations = BTreeMap::<u64, String>::new();
        for entry in entries {
            match entry.status {
                SnapshotEntryStatus::Healthy => report.authenticated_snapshots += 1,
                SnapshotEntryStatus::Unverified => report.unverified_snapshots += 1,
                SnapshotEntryStatus::Corrupt => {
                    push_issue(&mut report, format!("snapshot {} is corrupt", entry.id));
                }
            }
            let Some(snapshot) = entry.snapshot else {
                continue;
            };
            if snapshot.metadata.generation != 0
                && let Some(previous) =
                    generations.insert(snapshot.metadata.generation, snapshot.id.clone())
            {
                push_issue(
                    &mut report,
                    format!(
                        "snapshots {previous} and {} share a generation",
                        snapshot.id
                    ),
                );
            }
            if let Some(parent) = snapshot.metadata.parent_id.as_deref()
                && !ids.contains(parent)
                && !prune_boundaries.contains(&PruneBoundary {
                    child_id: snapshot.id.clone(),
                    removed_parent_id: parent.to_owned(),
                })
            {
                push_issue(
                    &mut report,
                    format!("snapshot {} has a missing parent", snapshot.id),
                );
            }
        }
        for directory in [self.root().to_path_buf(), self.configs_dir()] {
            for entry in fs::read_dir(directory).map_err(SnapshotError::Io)? {
                let name = entry.map_err(SnapshotError::Io)?.file_name();
                if name.to_string_lossy().contains(".tmp-") {
                    push_issue(
                        &mut report,
                        "snapshot store contains a stale temporary file".to_owned(),
                    );
                }
            }
        }
        if report.checked_snapshots > MAX_SNAPSHOT_STORE_ENTRIES {
            push_issue(
                &mut report,
                "snapshot store exceeds its capacity".to_owned(),
            );
        }
        for path in [
            self.root().join(".snapshot.lock"),
            self.current_path(),
            self.runtime_state_path(),
            self.generation_path(),
            self.prune_boundary_path(),
        ] {
            if path_exists_without_following_symlinks(&path).unwrap_or(true)
                && require_private_regular_file(&path).is_err()
            {
                push_issue(
                    &mut report,
                    "snapshot store contains unsafe state-file permissions".to_owned(),
                );
            }
        }
        if self
            .integrity
            .as_deref()
            .is_some_and(|key| require_private_regular_file(key.source_path()).is_err())
        {
            push_issue(
                &mut report,
                "snapshot integrity key permissions are unsafe".to_owned(),
            );
        }
        if self.verify_generation_state().is_err() {
            push_issue(
                &mut report,
                "snapshot generation state failed validation".to_owned(),
            );
        }
        report.healthy = report.issues.is_empty();
        Ok(report)
    }

    pub fn prune(
        &self,
        options: &SnapshotPruneOptions,
    ) -> Result<SnapshotPruneReport, SnapshotError> {
        if options.keep.is_none() && options.older_than.is_none() {
            return Err(SnapshotError::InvalidPrunePolicy);
        }
        self.with_store_lock(|| self.prune_locked(options))
    }

    fn prune_locked(
        &self,
        options: &SnapshotPruneOptions,
    ) -> Result<SnapshotPruneReport, SnapshotError> {
        let mut snapshots = self.list()?;
        snapshots.sort_by_key(|snapshot| {
            (
                snapshot.metadata.generation,
                snapshot.metadata.created_unix_secs,
            )
        });
        let mut protected = options
            .protected_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if let Some(current) = self.current_id()? {
            protected.insert(current);
        }
        if let Some(state) = self.load_runtime_state()? {
            protected.extend(state.runtime_snapshot);
            protected.extend(state.known_good_snapshot);
            if let Some(pending) = state.pending_validation {
                protected.insert(pending.target_snapshot);
                protected.extend(pending.previous_snapshot);
            }
        }
        for id in protected.clone() {
            if let Ok(snapshot) = self.snapshot(&id)
                && let Some(parent) = snapshot.metadata.parent_id
            {
                protected.insert(parent);
            }
        }
        let now = unix_duration()?.as_secs();
        let keep_from = snapshots.len().saturating_sub(options.keep.unwrap_or(0));
        let mut deleted = Vec::new();
        let mut delete_ids = BTreeSet::new();
        for (index, snapshot) in snapshots.iter().enumerate() {
            let outside_keep = options.keep.is_some_and(|_| index < keep_from);
            let old = options.older_than.is_some_and(|age| {
                now.saturating_sub(snapshot.metadata.created_unix_secs) >= age.as_secs()
            });
            if !protected.contains(&snapshot.id) && (outside_keep || old) {
                delete_ids.insert(snapshot.id.clone());
            }
        }
        let retained_ids = snapshots
            .iter()
            .filter(|snapshot| !delete_ids.contains(&snapshot.id))
            .map(|snapshot| snapshot.id.clone())
            .collect::<BTreeSet<_>>();
        let mut boundaries = self.load_prune_boundaries()?;
        boundaries.retain(|boundary| retained_ids.contains(&boundary.child_id));
        for snapshot in &snapshots {
            if retained_ids.contains(&snapshot.id)
                && let Some(parent) = snapshot.metadata.parent_id.as_ref()
                && delete_ids.contains(parent)
            {
                boundaries.insert(PruneBoundary {
                    child_id: snapshot.id.clone(),
                    removed_parent_id: parent.clone(),
                });
            }
        }
        self.save_prune_boundaries(&boundaries)?;
        for snapshot in &snapshots {
            if delete_ids.contains(&snapshot.id) {
                remove_if_present(&snapshot.config_path)?;
                remove_if_present(&snapshot.metadata_path)?;
                remove_if_present(&self.integrity_path(&snapshot.id))?;
                deleted.push(snapshot.id.clone());
            }
        }
        sync_directory(&self.configs_dir())?;
        Ok(SnapshotPruneReport {
            retained: snapshots.len().saturating_sub(deleted.len()),
            deleted,
        })
    }
}

fn read_snapshot_toml(bytes: &[u8]) -> Result<toml::Value, SnapshotError> {
    let raw = std::str::from_utf8(bytes).map_err(|error| {
        SnapshotError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    })?;
    toml::from_str(raw).map_err(SnapshotError::Decode)
}

fn invalid_snapshot_toml() -> SnapshotError {
    SnapshotError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "snapshot config root is not a TOML table",
    ))
}

fn remove_if_present(path: &std::path::Path) -> Result<(), SnapshotError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SnapshotError::Io(error)),
    }
}

fn push_issue(report: &mut SnapshotDoctorReport, issue: String) {
    if report.issues.len() < MAX_DOCTOR_ISSUES {
        report.issues.push(issue);
    }
}

use fluxheim_common::test_support::{safe_child_path, unique_temp_path};
use fluxheim_config::{Config, ProxyConfig};
use std::sync::{Arc, Barrier};

use crate::store::MAX_SNAPSHOT_STORE_ENTRIES;
use crate::store_fs::write_atomically_new;
use crate::{
    PendingValidation, SnapshotApplyMode, SnapshotEntryStatus, SnapshotError,
    SnapshotIntegrityStatus, SnapshotPruneOptions, SnapshotRuntimeState, SnapshotStore,
};

#[derive(Debug)]
struct TestCryptoProvider;

impl crate::SnapshotCryptoProvider for TestCryptoProvider {
    fn label(&self) -> &'static str {
        "test-ring"
    }

    fn compliance_capable(&self) -> bool {
        false
    }

    fn sha256(&self, chunks: &[&[u8]]) -> Result<[u8; 32], String> {
        let mut context = ring::digest::Context::new(&ring::digest::SHA256);
        for chunk in chunks {
            context.update(chunk);
        }
        let mut output = [0_u8; 32];
        output.copy_from_slice(context.finish().as_ref());
        Ok(output)
    }

    fn hmac_sha256(&self, key: &[u8], chunks: &[&[u8]]) -> Result<[u8; 32], String> {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
        let mut context = ring::hmac::Context::with_key(&key);
        for chunk in chunks {
            context.update(chunk);
        }
        let mut output = [0_u8; 32];
        output.copy_from_slice(context.sign().as_ref());
        Ok(output)
    }
}

#[test]
fn concurrent_snapshot_creation_cannot_exceed_capacity() {
    let dir = TestDir::new("snapshot-concurrent-capacity");
    let configs = dir.child("configs");
    std::fs::create_dir(&configs).unwrap();
    for index in 0..MAX_SNAPSHOT_STORE_ENTRIES - 1 {
        std::fs::write(
            safe_child_path(&configs, &format!("legacy-{index:04}.toml")),
            b"",
        )
        .unwrap();
    }
    let store = Arc::new(SnapshotStore::new(dir.path()));
    let barrier = Arc::new(Barrier::new(3));
    let handles = (0..2)
        .map(|_| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store.snapshot_config(&Config::default(), None)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    assert_eq!(
        store.list_entries().unwrap().len(),
        MAX_SNAPSHOT_STORE_ENTRIES
    );
}

#[test]
fn snapshots_record_explicit_parent_and_generation() {
    let dir = TestDir::new("snapshot-parent-generation");
    let store = SnapshotStore::new(dir.path());
    let first = store
        .snapshot_config(&Config::default(), Some("first"))
        .unwrap();
    let second = store
        .snapshot_config(&Config::default(), Some("second"))
        .unwrap();

    assert_eq!(first.metadata.parent_id, None);
    assert_eq!(first.metadata.generation, 1);
    assert_eq!(
        second.metadata.parent_id.as_deref(),
        Some(first.id.as_str())
    );
    assert_eq!(second.metadata.generation, 2);
    assert_eq!(
        store.rollback_candidate(None).unwrap().snapshot.id,
        first.id
    );
}

#[test]
fn authenticated_snapshot_rejects_modified_config() {
    let dir = TestDir::new("snapshot-integrity");
    let key = dir.child("snapshot.key");
    std::fs::write(&key, [7u8; 32]).unwrap();
    set_private_test_file(&key);
    let store = SnapshotStore::with_integrity_key_file(
        dir.child("store"),
        &key,
        Arc::new(TestCryptoProvider),
    )
    .unwrap();
    let snapshot = store.snapshot_config(&Config::default(), None).unwrap();

    assert_eq!(
        store.verify(&snapshot.id).unwrap(),
        SnapshotIntegrityStatus::Authenticated
    );
    assert_eq!(store.list_entries().unwrap().len(), 1);
    assert!(store.doctor().unwrap().healthy);
    let state = SnapshotRuntimeState {
        runtime_snapshot: Some(snapshot.id.clone()),
        known_good_snapshot: Some(snapshot.id.clone()),
        pending_validation: None,
    };
    store.save_runtime_state(&state).unwrap();
    assert_eq!(store.load_runtime_state().unwrap(), Some(state));
    let recovery_path = store.root().join("self-healing.toml");
    let recovery = std::fs::read_to_string(&recovery_path).unwrap();
    std::fs::write(
        &recovery_path,
        recovery.replace(&snapshot.id, "tampered-snapshot"),
    )
    .unwrap();
    assert!(matches!(
        store.load_runtime_state(),
        Err(SnapshotError::RuntimeStateIntegrityFailed)
    ));
    std::fs::write(
        &snapshot.config_path,
        "[server]\nlisten = [\"127.0.0.1:1\"]\n",
    )
    .unwrap();
    assert!(matches!(
        store.verify(&snapshot.id),
        Err(SnapshotError::IntegrityVerificationFailed { .. })
    ));
}

#[cfg(unix)]
#[test]
fn rejects_world_readable_integrity_key_and_key_inside_store() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TestDir::new("snapshot-private-key");
    let key = dir.child("snapshot.key");
    std::fs::write(&key, [9u8; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        SnapshotStore::with_integrity_key_file(
            dir.child("store"),
            &key,
            Arc::new(TestCryptoProvider)
        ),
        Err(SnapshotError::UnsafeIntegrityKey { .. })
    ));

    let store_root = dir.child("inside-store");
    std::fs::create_dir(&store_root).unwrap();
    let inside_key = safe_child_path(&store_root, "snapshot.key");
    std::fs::write(&inside_key, [9u8; 32]).unwrap();
    set_private_test_file(&inside_key);
    assert!(matches!(
        SnapshotStore::with_integrity_key_file(
            &store_root,
            &inside_key,
            Arc::new(TestCryptoProvider)
        ),
        Err(SnapshotError::UnsafeIntegrityKey { .. })
    ));
}

#[cfg(unix)]
#[test]
fn doctor_rejects_world_readable_snapshot_state() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TestDir::new("snapshot-doctor-private");
    let store = SnapshotStore::new(dir.path());
    let snapshot = store.snapshot_config(&Config::default(), None).unwrap();
    std::fs::set_permissions(
        &snapshot.config_path,
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    let entries = store.list_entries().unwrap();
    assert_eq!(entries[0].status, SnapshotEntryStatus::Corrupt);
    assert!(!store.doctor().unwrap().healthy);
}

#[test]
fn verified_rollback_config_is_not_reopened_after_verification() {
    let dir = TestDir::new("snapshot-verified-bytes");
    let store = SnapshotStore::new(dir.path());
    let first = store.snapshot_config(&Config::default(), None).unwrap();
    store.snapshot_config(&Config::default(), None).unwrap();

    let verified = store.rollback_candidate(None).unwrap();
    std::fs::write(
        &first.config_path,
        "[server]\nlisten = [\"127.0.0.1:65535\"]\n",
    )
    .unwrap();

    assert_eq!(
        toml::to_string(&verified.config).unwrap(),
        toml::to_string(&Config::default()).unwrap()
    );
}

#[test]
fn published_snapshot_survives_current_pointer_failure() {
    let dir = TestDir::new("snapshot-current-failure");
    let store = SnapshotStore::new(dir.path());
    SnapshotStore::fail_next_current_update();

    let error = store.snapshot_config(&Config::default(), None).unwrap_err();
    let id = match error {
        SnapshotError::SnapshotPublishedButCurrentUpdateFailed { id } => id,
        other => panic!("unexpected snapshot error: {other}"),
    };

    assert!(store.snapshot(&id).is_ok());
    assert_eq!(store.current_id().unwrap(), None);
}

#[test]
fn generation_high_water_survives_pruning_latest_snapshot() {
    let dir = TestDir::new("snapshot-generation-high-water");
    let store = SnapshotStore::new(dir.path());
    let _first = store.snapshot_config(&Config::default(), None).unwrap();
    let second = store.snapshot_config(&Config::default(), None).unwrap();
    let third = store.snapshot_config(&Config::default(), None).unwrap();
    store.set_current_snapshot(&second.id).unwrap();
    let report = store
        .prune(&SnapshotPruneOptions {
            keep: Some(0),
            older_than: None,
            protected_ids: Vec::new(),
        })
        .unwrap();
    assert!(report.deleted.contains(&third.id));

    let replacement = store.snapshot_config(&Config::default(), None).unwrap();
    assert_eq!(replacement.metadata.generation, 4);
}

#[test]
fn invalid_snapshot_filename_is_escaped_in_reports() {
    let dir = TestDir::new("snapshot-safe-label");
    let store = SnapshotStore::new(dir.path());
    store.snapshot_config(&Config::default(), None).unwrap();
    let malicious = store.root().join("configs").join("forged\n\u{1b}[31m.toml");
    std::fs::write(&malicious, b"").unwrap();
    set_private_test_file(&malicious);

    let entries = store.list_entries().unwrap();
    let invalid = entries
        .iter()
        .find(|entry| entry.id.contains("forged"))
        .unwrap();
    assert!(!invalid.id.contains('\n'));
    assert!(!invalid.id.contains('\u{1b}'));
    let doctor = store.doctor().unwrap();
    assert!(
        doctor
            .issues
            .iter()
            .all(|issue| { !issue.contains('\n') && !issue.contains('\u{1b}') })
    );
}

#[test]
fn resilient_listing_and_doctor_report_corrupt_entries() {
    let dir = TestDir::new("snapshot-doctor-corrupt");
    let store = SnapshotStore::new(dir.path());
    let snapshot = store.snapshot_config(&Config::default(), None).unwrap();
    std::fs::write(&snapshot.metadata_path, "not valid metadata").unwrap();

    let entries = store.list_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].status, SnapshotEntryStatus::Corrupt);
    let report = store.doctor().unwrap();
    assert!(!report.healthy);
    assert_eq!(report.checked_snapshots, 1);
    assert!(report.issues.iter().any(|issue| issue.contains("corrupt")));
}

#[test]
fn snapshot_diff_reports_changed_top_level_fields() {
    let dir = TestDir::new("snapshot-diff");
    let store = SnapshotStore::new(dir.path());
    let first = store.snapshot_config(&Config::default(), None).unwrap();
    let changed = Config {
        proxy: ProxyConfig {
            upstream: Some("127.0.0.1:9000".to_owned()),
            ..ProxyConfig::default()
        },
        ..Config::default()
    };
    let second = store.snapshot_config(&changed, None).unwrap();

    let diff = store.diff(&first.id, &second.id).unwrap();
    assert!(diff.changed_top_level_fields.contains(&"proxy".to_owned()));
}

#[test]
fn prune_keeps_current_and_its_parent() {
    let dir = TestDir::new("snapshot-prune-protected");
    let store = SnapshotStore::new(dir.path());
    let first = store
        .snapshot_config(&Config::default(), Some("first"))
        .unwrap();
    let second = store
        .snapshot_config(&Config::default(), Some("second"))
        .unwrap();
    let third = store
        .snapshot_config(&Config::default(), Some("third"))
        .unwrap();

    let report = store
        .prune(&SnapshotPruneOptions {
            keep: Some(0),
            older_than: None,
            protected_ids: Vec::new(),
        })
        .unwrap();

    assert_eq!(report.deleted, vec![first.id]);
    assert!(store.snapshot(&second.id).is_ok());
    assert!(store.snapshot(&third.id).is_ok());
    assert!(store.doctor().unwrap().healthy);
}

#[test]
fn self_healing_state_persists_pending_and_failed_rollback() {
    let dir = TestDir::new("snapshot-persisted-recovery");
    let store = SnapshotStore::new(dir.path());
    let first = store.snapshot_config(&Config::default(), None).unwrap();
    let second = store.snapshot_config(&Config::default(), None).unwrap();
    let pending = PendingValidation {
        target_snapshot: second.id.clone(),
        previous_snapshot: Some(first.id.clone()),
        impact: "snapshot".to_owned(),
        expires_unix_secs: 100,
        successful_checks: 0,
        failed_checks: 1,
        rollback_attempts: 0,
        last_rollback_failure: None,
    };
    let mut state = SnapshotRuntimeState {
        runtime_snapshot: Some(second.id),
        known_good_snapshot: Some(first.id),
        pending_validation: Some(pending.clone()),
    };
    state.rollback_failed(pending);
    store.save_runtime_state(&state).unwrap();

    let restored = store.load_runtime_state().unwrap().unwrap();
    let restored_pending = restored.pending_validation.unwrap();
    assert_eq!(restored_pending.rollback_attempts, 1);
    assert!(restored_pending.last_rollback_failure.is_some());
}

#[test]
fn failed_create_new_atomic_write_removes_temporary_file() {
    let dir = TestDir::new("snapshot-temp-cleanup");
    let destination = dir.child("existing");
    std::fs::write(&destination, b"old").unwrap();

    assert!(write_atomically_new(&destination, b"new").is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), b"old");
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")
    }));
}

#[test]
fn runtime_rollback_state_is_only_cleared_after_completion() {
    let pending = PendingValidation {
        target_snapshot: "candidate".to_owned(),
        previous_snapshot: Some("known".to_owned()),
        impact: "snapshot".to_owned(),
        expires_unix_secs: 10,
        successful_checks: 0,
        failed_checks: 1,
        rollback_attempts: 0,
        last_rollback_failure: None,
    };
    let mut state = SnapshotRuntimeState {
        runtime_snapshot: Some("candidate".to_owned()),
        known_good_snapshot: Some("known".to_owned()),
        pending_validation: Some(pending.clone()),
    };

    assert!(matches!(
        state.record_health_signal(false, 2, 0),
        crate::SnapshotHealthSignalOutcome::Rollback(_)
    ));
    assert!(state.pending_validation.is_some());
    state.rollback_failed(pending);
    assert_eq!(
        state.pending_validation.as_ref().unwrap().rollback_attempts,
        1
    );
    state.complete_rollback("known".to_owned());
    assert!(state.pending_validation.is_none());
}

#[test]
fn runtime_state_reload_initializes_rollback_tracking() {
    let mut state = SnapshotRuntimeState::default();
    state.record_applied_snapshot(
        "candidate".to_owned(),
        "snapshot".to_owned(),
        SnapshotApplyMode::Reload,
        true,
        30,
        10,
    );
    let pending = state.pending_validation.unwrap();
    assert_eq!(pending.rollback_attempts, 0);
    assert_eq!(pending.last_rollback_failure, None);
}

struct TestDir {
    path: std::path::PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let path = unique_temp_path(name);
        std::fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn child(&self, name: &str) -> std::path::PathBuf {
        safe_child_path(&self.path, name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn set_private_test_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
}

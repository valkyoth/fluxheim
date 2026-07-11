use super::{MAX_SNAPSHOT_STORE_ENTRIES, SnapshotError, SnapshotStore};
use crate::metadata::{MAX_SNAPSHOT_ID_BYTES, MAX_SNAPSHOT_MESSAGE_BYTES};
use crate::store_fs::{SNAPSHOT_DIR_MODE, SNAPSHOT_FILE_MODE};
use crate::{
    PendingValidation, SnapshotApplyMode, SnapshotHealthSignalOutcome, SnapshotRollbackReason,
    SnapshotRuntimeState, ValidationMetrics,
};

mod tests {
    use super::{
        PendingValidation, SnapshotApplyMode, SnapshotError, SnapshotHealthSignalOutcome,
        SnapshotRollbackReason, SnapshotRuntimeState, SnapshotStore, ValidationMetrics,
    };
    use fluxheim_common::test_support::{safe_child_path, safe_relative_path, unique_temp_path};
    use fluxheim_config::{Config, ProxyConfig};

    #[test]
    fn runtime_state_records_reload_pending_validation() {
        let mut state = SnapshotRuntimeState {
            runtime_snapshot: Some("old".to_owned()),
            known_good_snapshot: Some("known".to_owned()),
            pending_validation: None,
        };

        state.record_applied_snapshot(
            "candidate".to_owned(),
            "snapshot".to_owned(),
            SnapshotApplyMode::Reload,
            true,
            30,
            100,
        );

        assert_eq!(state.runtime_snapshot.as_deref(), Some("candidate"));
        assert_eq!(state.known_good_snapshot.as_deref(), Some("known"));
        assert_eq!(
            state.pending_validation,
            Some(PendingValidation {
                target_snapshot: "candidate".to_owned(),
                previous_snapshot: Some("old".to_owned()),
                impact: "snapshot".to_owned(),
                expires_unix_secs: 130,
                successful_checks: 0,
                failed_checks: 0,
                rollback_attempts: 0,
                last_rollback_failure: None,
            })
        );
    }

    #[test]
    fn runtime_state_confirms_pending_after_enough_successes() {
        let mut state = SnapshotRuntimeState {
            runtime_snapshot: Some("candidate".to_owned()),
            known_good_snapshot: Some("old".to_owned()),
            pending_validation: Some(PendingValidation {
                target_snapshot: "candidate".to_owned(),
                previous_snapshot: Some("old".to_owned()),
                impact: "snapshot".to_owned(),
                expires_unix_secs: 130,
                successful_checks: 1,
                failed_checks: 0,
                rollback_attempts: 0,
                last_rollback_failure: None,
            }),
        };

        let outcome = state.record_health_signal(true, 2, 500);

        assert_eq!(
            outcome,
            SnapshotHealthSignalOutcome::Confirm {
                snapshot: "candidate".to_owned(),
                metrics: ValidationMetrics {
                    successful_checks: 2,
                    failed_checks: 0,
                },
            }
        );
        assert!(state.pending_validation.is_none());
        assert_eq!(state.known_good_snapshot.as_deref(), Some("candidate"));
    }

    #[test]
    fn runtime_state_rolls_back_when_error_rate_exceeds_threshold() {
        let mut state = SnapshotRuntimeState {
            runtime_snapshot: Some("candidate".to_owned()),
            known_good_snapshot: Some("old".to_owned()),
            pending_validation: Some(PendingValidation {
                target_snapshot: "candidate".to_owned(),
                previous_snapshot: Some("old".to_owned()),
                impact: "snapshot".to_owned(),
                expires_unix_secs: 130,
                successful_checks: 1,
                failed_checks: 0,
                rollback_attempts: 0,
                last_rollback_failure: None,
            }),
        };

        let outcome = state.record_health_signal(false, 2, 400);

        assert!(matches!(
            outcome,
            SnapshotHealthSignalOutcome::Rollback(PendingValidation {
                failed_checks: 1,
                ..
            })
        ));
        assert!(state.pending_validation.is_some());
    }

    #[test]
    fn runtime_state_detects_expired_pending_validation() {
        let mut state = SnapshotRuntimeState {
            runtime_snapshot: Some("candidate".to_owned()),
            known_good_snapshot: Some("old".to_owned()),
            pending_validation: Some(PendingValidation {
                target_snapshot: "candidate".to_owned(),
                previous_snapshot: Some("old".to_owned()),
                impact: "snapshot".to_owned(),
                expires_unix_secs: 130,
                successful_checks: 1,
                failed_checks: 0,
                rollback_attempts: 0,
                last_rollback_failure: None,
            }),
        };

        let rollback = state.expired_or_unhealthy_pending(130, 400);

        assert!(matches!(
            rollback,
            Some((_, SnapshotRollbackReason::Expired))
        ));
        assert!(state.pending_validation.is_some());
    }

    #[test]
    fn snapshots_validated_config_and_sets_current() {
        let dir = TestDir::new("snapshot-current");
        let store = SnapshotStore::new(dir.path());
        let snapshot = store
            .snapshot_config(&Config::default(), Some("initial config"))
            .unwrap();

        assert!(snapshot.config_path.is_file());
        assert!(snapshot.metadata_path.is_file());
        assert_eq!(store.current_id().unwrap(), Some(snapshot.id.clone()));
        assert_eq!(
            store.list().unwrap()[0].metadata.message.as_deref(),
            Some("initial config")
        );
        assert!(snapshot.config_path.starts_with(store.root()));
    }

    #[cfg(unix)]
    #[test]
    fn snapshots_are_written_with_private_modes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new("snapshot-private-modes");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let store = SnapshotStore::new(dir.path());
        let snapshot = store
            .snapshot_config(&Config::default(), Some("initial config"))
            .unwrap();

        let root_mode = std::fs::metadata(store.root())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let configs_mode = std::fs::metadata(store.root().join("configs"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let config_name = format!("{}.toml", snapshot.id);
        let metadata_name = format!("{}.meta.toml", snapshot.id);
        let (config_mode, metadata_mode) =
            snapshot_file_modes_by_name(&store, &config_name, &metadata_name);
        let current_mode = std::fs::metadata(store.root().join("current"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let lock_mode = std::fs::metadata(store.root().join(".snapshot.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(root_mode, super::SNAPSHOT_DIR_MODE);
        assert_eq!(configs_mode, super::SNAPSHOT_DIR_MODE);
        assert_eq!(config_mode, super::SNAPSHOT_FILE_MODE);
        assert_eq!(metadata_mode, super::SNAPSHOT_FILE_MODE);
        assert_eq!(current_mode, super::SNAPSHOT_FILE_MODE);
        assert_eq!(lock_mode, super::SNAPSHOT_FILE_MODE);
    }

    #[cfg(unix)]
    fn snapshot_file_modes_by_name(
        store: &SnapshotStore,
        config_name: &str,
        metadata_name: &str,
    ) -> (u32, u32) {
        use std::os::unix::fs::PermissionsExt;

        let mut config_mode = None;
        let mut metadata_mode = None;
        for entry in std::fs::read_dir(store.root().join("configs")).unwrap() {
            let entry = entry.unwrap();
            let mode = entry.metadata().unwrap().permissions().mode() & 0o777;
            if entry.file_name() == config_name {
                config_mode = Some(mode);
            } else if entry.file_name() == metadata_name {
                metadata_mode = Some(mode);
            }
        }

        (
            config_mode.expect("snapshot config file mode"),
            metadata_mode.expect("snapshot metadata file mode"),
        )
    }

    #[test]
    fn rejects_oversized_snapshot_message() {
        let dir = TestDir::new("snapshot-message-oversized");
        let store = SnapshotStore::new(dir.path());

        let error = store
            .snapshot_config(
                &Config::default(),
                Some(&"a".repeat(super::MAX_SNAPSHOT_MESSAGE_BYTES + 1)),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            SnapshotError::InvalidSnapshotMessage { .. }
        ));
        assert_eq!(store.list().unwrap().len(), 0);
    }

    #[test]
    fn rejects_snapshot_message_with_control_character() {
        let dir = TestDir::new("snapshot-message-control");
        let store = SnapshotStore::new(dir.path());

        let error = store
            .snapshot_config(&Config::default(), Some("line one\nline two"))
            .unwrap_err();

        assert!(matches!(
            error,
            SnapshotError::InvalidSnapshotMessage { .. }
        ));
    }

    #[test]
    fn rejects_snapshot_store_with_too_many_entries() {
        let dir = TestDir::new("snapshot-too-many-entries");
        let store = SnapshotStore::new(dir.path());
        let configs = dir.child("configs");
        std::fs::create_dir(&configs).unwrap();
        for index in 0..=super::MAX_SNAPSHOT_STORE_ENTRIES {
            std::fs::write(safe_child_path(&configs, &format!("s{index:04}.toml")), b"").unwrap();
        }

        let entries = store.list_entries().unwrap();

        assert_eq!(entries.len(), super::MAX_SNAPSHOT_STORE_ENTRIES + 1);
        assert_eq!(
            entries.last().unwrap().status,
            crate::SnapshotEntryStatus::Corrupt
        );
    }

    #[test]
    fn snapshot_config_rejects_full_snapshot_store_before_writing() {
        let dir = TestDir::new("snapshot-capacity-before-write");
        let store = SnapshotStore::new(dir.path());
        let configs = dir.child("configs");
        std::fs::create_dir(&configs).unwrap();
        for index in 0..super::MAX_SNAPSHOT_STORE_ENTRIES {
            std::fs::write(safe_child_path(&configs, &format!("s{index:04}.toml")), b"").unwrap();
        }

        let error = store
            .snapshot_config(&Config::default(), Some("should not write"))
            .unwrap_err();

        assert!(
            matches!(error, SnapshotError::Io(error) if error.kind() == std::io::ErrorKind::StorageFull)
        );
        let created_configs = std::fs::read_dir(&configs)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .ok()
                    .and_then(|entry| {
                        entry
                            .path()
                            .extension()
                            .and_then(|value| value.to_str())
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some("toml")
            })
            .count();
        assert_eq!(created_configs, super::MAX_SNAPSHOT_STORE_ENTRIES);
        assert!(store.current_id().unwrap().is_none());
    }

    #[test]
    fn current_snapshot_loads_current_pointer() {
        let dir = TestDir::new("snapshot-current-load");
        let store = SnapshotStore::new(dir.path());
        assert!(store.current_snapshot().unwrap().is_none());

        let snapshot = store
            .snapshot_config(&Config::default(), Some("first"))
            .unwrap();

        assert_eq!(store.current_snapshot().unwrap().unwrap().id, snapshot.id);
    }

    #[test]
    fn rollback_without_target_selects_previous_snapshot() {
        let dir = TestDir::new("snapshot-rollback");
        let store = SnapshotStore::new(dir.path());
        let first = store
            .snapshot_config(&Config::default(), Some("first"))
            .unwrap();
        let second_config = Config {
            proxy: ProxyConfig {
                upstream: Some("127.0.0.1:4000".to_owned()),
                ..ProxyConfig::default()
            },
            ..Config::default()
        };
        let second = store
            .snapshot_config(&second_config, Some("second"))
            .unwrap();
        assert_eq!(store.current_id().unwrap(), Some(second.id));

        let rollback = store.rollback_target(None).unwrap();

        assert_eq!(rollback.id, first.id);
        assert_eq!(store.current_id().unwrap(), Some(first.id));
    }

    #[test]
    fn rollback_candidate_does_not_move_current_pointer() {
        let dir = TestDir::new("snapshot-rollback-candidate");
        let store = SnapshotStore::new(dir.path());
        let first = store
            .snapshot_config(&Config::default(), Some("first"))
            .unwrap();
        let second = store
            .snapshot_config(&Config::default(), Some("second"))
            .unwrap();

        let candidate = store.rollback_candidate(None).unwrap();

        assert_eq!(candidate.snapshot.id, first.id);
        assert_eq!(store.current_id().unwrap(), Some(second.id));
    }

    #[test]
    fn rollback_rejects_invalid_snapshot_id() {
        let dir = TestDir::new("snapshot-invalid-id");
        let store = SnapshotStore::new(dir.path());

        let error = store.rollback_target(Some("../bad")).unwrap_err();

        assert!(matches!(error, SnapshotError::InvalidSnapshotId { .. }));
    }

    #[test]
    fn rollback_rejects_oversized_snapshot_id_without_reflecting_it() {
        let dir = TestDir::new("snapshot-oversized-id");
        let store = SnapshotStore::new(dir.path());
        let id = "a".repeat(super::MAX_SNAPSHOT_ID_BYTES + 1);

        let error = store.rollback_target(Some(&id)).unwrap_err();
        let message = error.to_string();

        assert!(matches!(error, SnapshotError::InvalidSnapshotId { .. }));
        assert!(message.contains("129 bytes"));
        assert!(message.contains("expected 1..=128"));
        assert!(!message.contains(&id));
    }

    #[test]
    fn invalid_snapshot_id_diagnostic_does_not_reflect_controls() {
        let dir = TestDir::new("snapshot-control-id");
        let store = SnapshotStore::new(dir.path());
        let id = "forged\nsecurity-log";

        let message = store.rollback_target(Some(id)).unwrap_err().to_string();

        assert!(!message.contains(id));
        assert!(!message.contains('\n'));
        assert!(message.contains("invalid snapshot id"));
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

        fn path(&self) -> &std::path::Path {
            &self.path
        }

        fn child(&self, name: &str) -> std::path::PathBuf {
            safe_relative_path(&self.path, name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

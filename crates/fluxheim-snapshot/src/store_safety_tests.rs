use super::{SnapshotError, SnapshotStore};
use crate::store_fs::MAX_CURRENT_SNAPSHOT_POINTER_BYTES;
#[cfg(any(unix, windows))]
use crate::store_fs::open_private_lock_file;
#[cfg(unix)]
use crate::store_fs::write_atomically;

mod tests {
    #[cfg(any(unix, windows))]
    use super::open_private_lock_file;
    #[cfg(unix)]
    use super::write_atomically;
    use super::{SnapshotError, SnapshotStore};
    use fluxheim_common::test_support::unique_temp_path;
    #[cfg(unix)]
    use fluxheim_common::test_support::{
        safe_child_path, safe_relative_path, unique_group_writable_child,
        unique_world_writable_child,
    };
    use fluxheim_config::Config;

    #[test]
    fn rejects_snapshot_store_root_with_parent_traversal() {
        let store = SnapshotStore::new("../fluxheim-snapshots");

        let error = store.list().unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeStoreRoot { .. }));
    }

    #[cfg(windows)]
    #[test]
    fn accepts_canonical_windows_test_store_path() {
        let root = unique_temp_path("snapshot-canonical-windows-root");
        std::fs::create_dir(&root).unwrap();
        let store = SnapshotStore::new(&root);

        store
            .snapshot_config(&Config::default(), Some("initial"))
            .unwrap();

        assert_eq!(store.list().unwrap().len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_snapshot_store_root() {
        let target = TestDir::new("snapshot-root-target");
        let root = unique_temp_path("snapshot-root-symlink");
        std::os::unix::fs::symlink(target.path(), &root).unwrap();
        let store = SnapshotStore::new(&root);

        let error = store.list().unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeStoreRoot { .. }));
        let _ = std::fs::remove_file(root);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_snapshot_store_root_below_symlinked_directory() {
        let dir = TestDir::new("snapshot-root-parent-symlink");
        let real_parent = dir.child("real-parent");
        let linked_parent = dir.child("linked-parent");
        std::fs::create_dir(&real_parent).unwrap();
        std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();
        let store = SnapshotStore::new(linked_parent.join("snapshots"));

        let error = store
            .snapshot_config(&Config::default(), Some("initial"))
            .unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeStoreRoot { .. }));
        assert!(!real_parent.join("snapshots").exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_lock_open_rejects_symlinked_parent_component() {
        let dir = TestDir::new("snapshot-lock-parent-symlink");
        let real_parent = dir.child("real-parent");
        let linked_parent = dir.child("linked-parent");
        std::fs::create_dir(&real_parent).unwrap();
        std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();

        let error = open_private_lock_file(&linked_parent.join(".snapshot.lock")).unwrap_err();
        assert!(matches!(
            error,
            SnapshotError::UnsafeSnapshotPath { .. } | SnapshotError::Io(_)
        ));
        assert!(!real_parent.join(".snapshot.lock").exists());
    }

    #[cfg(windows)]
    #[test]
    fn private_lock_open_rejects_junctioned_parent_component() {
        let dir = TestDir::new("snapshot-lock-parent-junction");
        let real_parent = dir.path().join("real-parent");
        let junction = dir.path().join("junction");
        std::fs::create_dir(&real_parent).unwrap();
        let command = format!(
            "mklink /J \"{}\" \"{}\"",
            junction.display(),
            real_parent.display()
        );
        let status = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", &command])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "failed to create test directory junction");

        let error = open_private_lock_file(&junction.join(".snapshot.lock")).unwrap_err();
        std::fs::remove_dir(&junction).unwrap();

        assert!(matches!(
            error,
            SnapshotError::UnsafeSnapshotPath { .. } | SnapshotError::Io(_)
        ));
        assert!(!real_parent.join(".snapshot.lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_snapshot_store_root_below_world_writable_directory() {
        let root = unique_world_writable_child("snapshot-root-world-writable", "snapshots");
        let store = SnapshotStore::new(&root);

        let error = store
            .snapshot_config(&Config::default(), Some("initial"))
            .unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeStoreRoot { .. }));
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_snapshot_store_root_below_group_writable_directory() {
        let root = unique_group_writable_child("snapshot-root-group-writable", "snapshots");
        let store = SnapshotStore::new(&root);

        let error = store
            .snapshot_config(&Config::default(), Some("initial"))
            .unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeStoreRoot { .. }));
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_current_pointer() {
        let dir = TestDir::new("snapshot-current-symlink");
        let store = SnapshotStore::new(dir.path());
        let snapshot = store
            .snapshot_config(&Config::default(), Some("initial"))
            .unwrap();

        let outside = dir.child("outside-current");
        std::fs::write(&outside, format!("{}\n", snapshot.id)).unwrap();
        std::fs::remove_file(store.current_path()).unwrap();
        std::os::unix::fs::symlink(&outside, store.current_path()).unwrap();

        let error = store.current_id().unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeSnapshotPath { .. }));
    }

    #[test]
    fn rejects_oversized_current_pointer() {
        let dir = TestDir::new("snapshot-current-oversized");
        let store = SnapshotStore::new(dir.path());
        store
            .snapshot_config(&Config::default(), Some("initial"))
            .unwrap();
        std::fs::write(
            store.current_path(),
            vec![b'a'; (super::MAX_CURRENT_SNAPSHOT_POINTER_BYTES + 1) as usize],
        )
        .unwrap();

        let error = store.current_id().unwrap_err();

        assert!(
            matches!(error, SnapshotError::Io(error) if error.kind() == std::io::ErrorKind::InvalidData)
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_snapshot_config() {
        let dir = TestDir::new("snapshot-config-symlink");
        let store = SnapshotStore::new(dir.path());
        let snapshot_id = "symlinked_config";
        let configs_dir = dir.child("configs");
        std::fs::create_dir(&configs_dir).unwrap();
        set_private_test_directory(&configs_dir);
        let outside = dir.child("outside.toml");
        std::fs::write(
            &outside,
            toml::to_string_pretty(&Config::default()).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            &outside,
            safe_child_path(&configs_dir, "symlinked_config.toml"),
        )
        .unwrap();

        let error = store.rollback_candidate(Some(snapshot_id)).unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeSnapshotPath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_snapshot_metadata() {
        let dir = TestDir::new("snapshot-metadata-symlink");
        let store = SnapshotStore::new(dir.path());
        let snapshot_id = "symlinked_metadata";
        let configs_dir = dir.child("configs");
        std::fs::create_dir(&configs_dir).unwrap();
        set_private_test_directory(&configs_dir);
        std::fs::write(
            safe_child_path(&configs_dir, "symlinked_metadata.toml"),
            toml::to_string_pretty(&Config::default()).unwrap(),
        )
        .unwrap();
        let outside = dir.child("outside.meta.toml");
        std::fs::write(
            &outside,
            format!(
                "id = \"{}\"\ncreated_unix_secs = 1\nmessage = \"outside\"\n",
                snapshot_id
            ),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            &outside,
            safe_child_path(&configs_dir, "symlinked_metadata.meta.toml"),
        )
        .unwrap();

        let entries = store.list_entries().unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, crate::SnapshotEntryStatus::Corrupt);
        assert!(entries[0].snapshot.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_configs_directory() {
        let dir = TestDir::new("snapshot-configs-dir-symlink");
        let outside = TestDir::new("snapshot-configs-outside");
        let configs_dir = dir.child("configs");
        std::os::unix::fs::symlink(outside.path(), &configs_dir).unwrap();
        let store = SnapshotStore::new(dir.path());

        let error = store.list().unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeSnapshotPath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_atomic_write_below_symlinked_parent() {
        let dir = TestDir::new("snapshot-write-parent-symlink");
        let outside = TestDir::new("snapshot-write-parent-outside");
        let symlinked_parent = dir.child("linked-parent");
        std::os::unix::fs::symlink(outside.path(), &symlinked_parent).unwrap();

        let error = write_atomically(&symlinked_parent.join("current"), b"snapshot\n").unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeSnapshotPath { .. }));
        let _ = std::fs::remove_file(symlinked_parent);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_atomic_write_to_symlinked_destination() {
        let dir = TestDir::new("snapshot-write-destination-symlink");
        let outside = dir.child("outside-current");
        let destination = dir.child("current");
        std::fs::write(&outside, "old\n").unwrap();
        std::os::unix::fs::symlink(&outside, &destination).unwrap();

        let error = write_atomically(&destination, b"new\n").unwrap_err();

        assert!(matches!(error, SnapshotError::UnsafeSnapshotPath { .. }));
        assert_eq!(std::fs::read_to_string(outside).unwrap(), "old\n");
    }

    struct TestDir {
        path: std::path::PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let path = unique_temp_path(name);
            std::fs::create_dir(&path).expect("create test directory");
            set_private_test_directory(&path);
            Self { path }
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }

        #[cfg(unix)]
        fn child(&self, name: &str) -> std::path::PathBuf {
            safe_relative_path(&self.path, name)
        }
    }

    fn set_private_test_directory(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

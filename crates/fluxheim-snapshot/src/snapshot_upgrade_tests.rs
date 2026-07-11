use std::path::{Path, PathBuf};
use std::sync::Arc;

use fluxheim_common::test_support::{safe_child_path, unique_temp_path};
use fluxheim_config::Config;

use crate::{SnapshotCryptoProvider, SnapshotStore};

#[derive(Debug)]
struct TestCryptoProvider;

impl SnapshotCryptoProvider for TestCryptoProvider {
    fn label(&self) -> &'static str {
        "snapshot-upgrade-test"
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
fn pre_generation_authenticated_store_bootstraps_and_migrates() {
    let dir = TestDir::new("snapshot-pre-generation-bootstrap");
    let store = authenticated_store(&dir);
    let first = store
        .snapshot_config(&Config::default(), Some("first"))
        .unwrap();
    let second = store
        .snapshot_config(&Config::default(), Some("second"))
        .unwrap();
    for id in [&first.id, &second.id] {
        rewrite_manifest_as_v1(&store, id);
    }
    std::fs::remove_file(store.root().join("generation.toml")).unwrap();

    assert_eq!(store.current_snapshot().unwrap().unwrap().id, second.id);
    assert!(store.doctor().unwrap().healthy);
    assert!(!manifest_raw(&store, &first.id).contains("generation_hmac_sha256"));

    let third = store
        .snapshot_config(&Config::default(), Some("third"))
        .unwrap();

    assert_eq!(third.metadata.generation, 3);
    assert!(store.root().join("generation.toml").is_file());
    assert!(store.doctor().unwrap().healthy);
    for id in [&first.id, &second.id, &third.id] {
        assert!(manifest_raw(&store, id).contains("generation_hmac_sha256"));
        assert_eq!(
            store.verify(id).unwrap(),
            crate::SnapshotIntegrityStatus::Authenticated
        );
    }
}

#[test]
fn authenticated_counter_allows_interrupted_legacy_migration_to_resume() {
    let dir = TestDir::new("snapshot-legacy-migration-resume");
    let store = authenticated_store(&dir);
    let first = store
        .snapshot_config(&Config::default(), Some("first"))
        .unwrap();
    let second = store
        .snapshot_config(&Config::default(), Some("second"))
        .unwrap();
    rewrite_manifest_as_v1(&store, &first.id);

    let third = store
        .snapshot_config(&Config::default(), Some("third"))
        .unwrap();

    assert_eq!(third.metadata.generation, 3);
    assert!(store.doctor().unwrap().healthy);
    for id in [&first.id, &second.id, &third.id] {
        assert!(manifest_raw(&store, id).contains("generation_hmac_sha256"));
    }
}

fn rewrite_manifest_as_v1(store: &SnapshotStore, id: &str) {
    let path = integrity_path(store, id);
    let mut manifest: toml::Table =
        toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    manifest.remove("generation");
    manifest.remove("generation_hmac_sha256");
    std::fs::write(path, toml::to_string_pretty(&manifest).unwrap()).unwrap();
}

fn manifest_raw(store: &SnapshotStore, id: &str) -> String {
    std::fs::read_to_string(integrity_path(store, id)).unwrap()
}

fn integrity_path(store: &SnapshotStore, id: &str) -> PathBuf {
    store
        .root()
        .join("configs")
        .join(format!("{id}.integrity.toml"))
}

fn authenticated_store(dir: &TestDir) -> SnapshotStore {
    let key = dir.child("snapshot.key");
    std::fs::write(&key, [17_u8; 32]).unwrap();
    set_private_file(&key);
    SnapshotStore::with_integrity_key_file(dir.child("store"), &key, Arc::new(TestCryptoProvider))
        .unwrap()
}

fn set_private_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
}

struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let path = unique_temp_path(name);
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn child(&self, name: &str) -> PathBuf {
        safe_child_path(&self.0, name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

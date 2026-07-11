use std::sync::Arc;

use fluxheim_common::test_support::{safe_child_path, unique_temp_path};
use fluxheim_config::Config;

use crate::{SnapshotCryptoProvider, SnapshotError, SnapshotPruneOptions, SnapshotStore};

#[derive(Debug)]
struct TestCryptoProvider;

impl SnapshotCryptoProvider for TestCryptoProvider {
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

#[cfg(unix)]
#[test]
fn doctor_rechecks_integrity_key_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TestDir::new("snapshot-doctor-key-mode");
    let (store, key) = authenticated_store(&dir);
    store.snapshot_config(&Config::default(), None).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

    let report = store.doctor().unwrap();
    assert!(!report.healthy);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("integrity key permissions"))
    );
}

#[test]
fn authenticated_generation_state_rejects_tampering() {
    let dir = TestDir::new("snapshot-generation-auth");
    let (store, _key) = authenticated_store(&dir);
    store.snapshot_config(&Config::default(), None).unwrap();
    let path = safe_child_path(store.root(), "generation.toml");
    let raw = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, raw.replace("generation = 1", "generation = 9")).unwrap();

    assert!(matches!(
        store.snapshot_config(&Config::default(), None),
        Err(SnapshotError::GenerationStateInvalid)
    ));
    assert!(!store.doctor().unwrap().healthy);
}

#[test]
fn authenticated_prune_boundary_rejects_tampering() {
    let dir = TestDir::new("snapshot-prune-auth");
    let (store, _key) = authenticated_store(&dir);
    store.snapshot_config(&Config::default(), None).unwrap();
    store.snapshot_config(&Config::default(), None).unwrap();
    store.snapshot_config(&Config::default(), None).unwrap();
    store
        .prune(&SnapshotPruneOptions {
            keep: Some(0),
            older_than: None,
            protected_ids: Vec::new(),
        })
        .unwrap();
    let path = safe_child_path(store.root(), "prune-boundaries.toml");
    let mut raw = std::fs::read_to_string(&path).unwrap().into_bytes();
    let marker = b"hmac_sha256 = \"";
    let offset = raw
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap()
        + marker.len();
    raw[offset] = if raw[offset] == b'0' { b'1' } else { b'0' };
    std::fs::write(&path, raw).unwrap();

    assert!(!store.doctor().unwrap().healthy);
}

fn authenticated_store(dir: &TestDir) -> (SnapshotStore, std::path::PathBuf) {
    let key = dir.child("snapshot.key");
    std::fs::write(&key, [11u8; 32]).unwrap();
    set_private_file(&key);
    let store = SnapshotStore::with_integrity_key_file(
        dir.child("store"),
        &key,
        Arc::new(TestCryptoProvider),
    )
    .unwrap();
    (store, key)
}

fn set_private_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
}

struct TestDir(std::path::PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let path = unique_temp_path(name);
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn child(&self, name: &str) -> std::path::PathBuf {
        safe_child_path(&self.0, name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

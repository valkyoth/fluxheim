use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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

#[derive(Debug)]
struct FailingCryptoProvider {
    fail_label: &'static [u8],
}

#[derive(Debug, Default)]
struct CryptoCallCounts {
    sha256: AtomicUsize,
    snapshot_hmac: AtomicUsize,
    generation_witness_hmac: AtomicUsize,
}

#[derive(Debug)]
struct CountingCryptoProvider {
    counts: Arc<CryptoCallCounts>,
}

impl SnapshotCryptoProvider for CountingCryptoProvider {
    fn label(&self) -> &'static str {
        "counting-test-provider"
    }

    fn compliance_capable(&self) -> bool {
        false
    }

    fn sha256(&self, chunks: &[&[u8]]) -> Result<[u8; 32], String> {
        self.counts.sha256.fetch_add(1, Ordering::Relaxed);
        TestCryptoProvider.sha256(chunks)
    }

    fn hmac_sha256(&self, key: &[u8], chunks: &[&[u8]]) -> Result<[u8; 32], String> {
        match chunks.first().copied() {
            Some(b"fluxheim-snapshot-v1\0") => {
                self.counts.snapshot_hmac.fetch_add(1, Ordering::Relaxed);
            }
            Some(b"fluxheim-snapshot-generation-witness-v1\0") => {
                self.counts
                    .generation_witness_hmac
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        TestCryptoProvider.hmac_sha256(key, chunks)
    }
}

impl SnapshotCryptoProvider for FailingCryptoProvider {
    fn label(&self) -> &'static str {
        "failing-test-provider"
    }

    fn compliance_capable(&self) -> bool {
        false
    }

    fn sha256(&self, chunks: &[&[u8]]) -> Result<[u8; 32], String> {
        TestCryptoProvider.sha256(chunks)
    }

    fn hmac_sha256(&self, key: &[u8], chunks: &[&[u8]]) -> Result<[u8; 32], String> {
        if chunks
            .first()
            .is_some_and(|label| *label == self.fail_label)
        {
            return Err("injected cryptographic provider failure".to_owned());
        }
        TestCryptoProvider.hmac_sha256(key, chunks)
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

#[test]
fn snapshot_generation_provider_failure_is_returned_without_abort() {
    let dir = TestDir::new("snapshot-provider-generation-failure");
    let store = store_with_provider(
        &dir,
        Arc::new(FailingCryptoProvider {
            fail_label: b"fluxheim-snapshot-generation-v1\0",
        }),
    );

    assert!(matches!(
        store.snapshot_config(&Config::default(), None),
        Err(SnapshotError::CryptoProvider(_))
    ));
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn snapshot_manifest_provider_failure_is_returned_without_abort() {
    let dir = TestDir::new("snapshot-provider-manifest-failure");
    let store = store_with_provider(
        &dir,
        Arc::new(FailingCryptoProvider {
            fail_label: b"fluxheim-snapshot-v1\0",
        }),
    );

    assert!(matches!(
        store.snapshot_config(&Config::default(), None),
        Err(SnapshotError::CryptoProvider(_))
    ));
    assert!(store.list().unwrap().is_empty());
    assert!(store.current_id().unwrap().is_none());
}

#[test]
fn generation_witness_provider_failure_is_returned_without_abort() {
    let dir = TestDir::new("snapshot-provider-witness-failure");
    let store = store_with_provider(
        &dir,
        Arc::new(FailingCryptoProvider {
            fail_label: b"fluxheim-snapshot-generation-witness-v1\0",
        }),
    );

    assert!(matches!(
        store.snapshot_config(&Config::default(), None),
        Err(SnapshotError::CryptoProvider(_))
    ));
    assert!(store.list().unwrap().is_empty());
}

#[test]
fn recovery_provider_failure_is_returned_without_abort() {
    let dir = TestDir::new("snapshot-provider-recovery-failure");
    let store = store_with_provider(
        &dir,
        Arc::new(FailingCryptoProvider {
            fail_label: b"fluxheim-snapshot-recovery-v1\0",
        }),
    );
    store.snapshot_config(&Config::default(), None).unwrap();

    assert!(matches!(
        store.save_runtime_state(&crate::SnapshotRuntimeState::default()),
        Err(SnapshotError::CryptoProvider(_))
    ));
    assert!(!store.root().join("self-healing.toml").exists());
}

#[test]
fn prune_provider_failure_preserves_snapshots_without_abort() {
    let dir = TestDir::new("snapshot-provider-prune-failure");
    let store = store_with_provider(
        &dir,
        Arc::new(FailingCryptoProvider {
            fail_label: b"fluxheim-snapshot-prune-boundary-v1\0",
        }),
    );
    store.snapshot_config(&Config::default(), None).unwrap();
    store.snapshot_config(&Config::default(), None).unwrap();
    store.snapshot_config(&Config::default(), None).unwrap();

    assert!(matches!(
        store.prune(&SnapshotPruneOptions {
            keep: Some(0),
            older_than: None,
            protected_ids: Vec::new(),
        }),
        Err(SnapshotError::CryptoProvider(_))
    ));
    assert_eq!(store.list().unwrap().len(), 3);
}

#[test]
fn generation_state_replay_and_removal_fail_before_publication() {
    let dir = TestDir::new("snapshot-generation-replay");
    let (store, _key) = authenticated_store(&dir);
    store.snapshot_config(&Config::default(), None).unwrap();
    let generation_path = safe_child_path(store.root(), "generation.toml");
    let generation_one = std::fs::read(&generation_path).unwrap();
    store.snapshot_config(&Config::default(), None).unwrap();

    std::fs::write(&generation_path, &generation_one).unwrap();
    assert!(matches!(
        store.snapshot_config(&Config::default(), None),
        Err(SnapshotError::GenerationStateInvalid)
    ));
    assert_eq!(store.list().unwrap().len(), 2);
    assert!(!store.doctor().unwrap().healthy);

    std::fs::remove_file(&generation_path).unwrap();
    assert!(matches!(
        store.snapshot_config(&Config::default(), None),
        Err(SnapshotError::GenerationStateInvalid)
    ));
    assert_eq!(store.list().unwrap().len(), 2);
}

#[test]
fn generation_verification_scans_only_small_authenticated_witnesses() {
    let dir = TestDir::new("snapshot-generation-witness-scan");
    let counts = Arc::new(CryptoCallCounts::default());
    let store = store_with_provider(
        &dir,
        Arc::new(CountingCryptoProvider {
            counts: Arc::clone(&counts),
        }),
    );
    store.snapshot_config(&Config::default(), None).unwrap();
    store.snapshot_config(&Config::default(), None).unwrap();
    let sha_before = counts.sha256.load(Ordering::Relaxed);
    let snapshot_hmac_before = counts.snapshot_hmac.load(Ordering::Relaxed);
    let witness_before = counts.generation_witness_hmac.load(Ordering::Relaxed);

    store.verify_generation_state().unwrap();

    assert_eq!(counts.sha256.load(Ordering::Relaxed), sha_before);
    assert_eq!(
        counts.snapshot_hmac.load(Ordering::Relaxed),
        snapshot_hmac_before
    );
    assert_eq!(
        counts.generation_witness_hmac.load(Ordering::Relaxed) - witness_before,
        2
    );
}

#[test]
fn tampered_generation_witness_blocks_snapshot_before_publication() {
    let dir = TestDir::new("snapshot-generation-witness-tamper");
    let (store, _key) = authenticated_store(&dir);
    let first = store.snapshot_config(&Config::default(), None).unwrap();
    store.snapshot_config(&Config::default(), None).unwrap();
    let integrity_path = store
        .root()
        .join("configs")
        .join(format!("{}.integrity.toml", first.id));
    let raw = std::fs::read_to_string(&integrity_path).unwrap();
    std::fs::write(
        &integrity_path,
        raw.replace("generation = 1", "generation = 9"),
    )
    .unwrap();

    assert!(matches!(
        store.snapshot_config(&Config::default(), None),
        Err(SnapshotError::GenerationStateInvalid)
    ));
    let configs = std::fs::read_dir(store.root().join("configs"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .file_stem()
                .and_then(|stem| stem.to_str())
                .is_some_and(|stem| !stem.ends_with(".meta") && !stem.ends_with(".integrity"))
        })
        .count();
    assert_eq!(configs, 2);
}

#[test]
fn unverified_generation_scan_rejects_oversized_metadata() {
    let dir = TestDir::new("snapshot-generation-metadata-limit");
    let store = SnapshotStore::new(dir.child("store"));
    let snapshot = store.snapshot_config(&Config::default(), None).unwrap();
    std::fs::write(&snapshot.metadata_path, vec![b'a'; 16 * 1024 + 1]).unwrap();

    assert!(store.snapshot_config(&Config::default(), None).is_err());
    assert_eq!(store.list_entries().unwrap().len(), 1);
}

#[test]
fn prior_manifest_format_loads_and_migrates_on_locked_creation() {
    let dir = TestDir::new("snapshot-manifest-v1-upgrade");
    let (store, _key) = authenticated_store(&dir);
    let first = store
        .snapshot_config(&Config::default(), Some("first"))
        .unwrap();
    let second = store
        .snapshot_config(&Config::default(), Some("second"))
        .unwrap();
    for id in [&first.id, &second.id] {
        rewrite_manifest_as_v1(&store, id);
    }

    assert_eq!(store.current_snapshot().unwrap().unwrap().id, second.id);
    assert_eq!(
        store.rollback_candidate(None).unwrap().snapshot.id,
        first.id
    );
    assert!(store.doctor().unwrap().healthy);
    assert!(!manifest_raw(&store, &first.id).contains("generation_hmac_sha256"));

    let third = store
        .snapshot_config(&Config::default(), Some("third"))
        .unwrap();

    assert_eq!(third.metadata.generation, 3);
    for id in [&first.id, &second.id, &third.id] {
        let raw = manifest_raw(&store, id);
        assert!(raw.contains("generation_hmac_sha256"));
        assert_eq!(
            store.verify(id).unwrap(),
            crate::SnapshotIntegrityStatus::Authenticated
        );
    }
}

fn rewrite_manifest_as_v1(store: &SnapshotStore, id: &str) {
    let path = store
        .root()
        .join("configs")
        .join(format!("{id}.integrity.toml"));
    let mut manifest: toml::Table =
        toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    manifest.remove("generation");
    manifest.remove("generation_hmac_sha256");
    std::fs::write(path, toml::to_string_pretty(&manifest).unwrap()).unwrap();
}

fn manifest_raw(store: &SnapshotStore, id: &str) -> String {
    std::fs::read_to_string(
        store
            .root()
            .join("configs")
            .join(format!("{id}.integrity.toml")),
    )
    .unwrap()
}

fn authenticated_store(dir: &TestDir) -> (SnapshotStore, std::path::PathBuf) {
    let store = store_with_provider(dir, Arc::new(TestCryptoProvider));
    (store, dir.child("snapshot.key"))
}

fn store_with_provider(dir: &TestDir, provider: Arc<dyn SnapshotCryptoProvider>) -> SnapshotStore {
    let key = dir.child("snapshot.key");
    std::fs::write(&key, [11u8; 32]).unwrap();
    set_private_file(&key);
    SnapshotStore::with_integrity_key_file(dir.child("store"), &key, provider).unwrap()
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

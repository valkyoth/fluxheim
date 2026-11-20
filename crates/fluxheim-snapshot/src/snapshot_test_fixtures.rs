use crate::integrity::{SnapshotIntegrityManifest, SnapshotIntegrityManifestV1};
use crate::{ConfigSnapshot, SnapshotStore};
use fluxheim_config::Config;

/// Generate the legacy witness from the same fixture inputs as the snapshot,
/// without reading or deserializing the current on-disk manifest.
pub(super) fn install_default_config_v1_manifest(store: &SnapshotStore, snapshot: &ConfigSnapshot) {
    let config = toml::to_string_pretty(&Config::default()).unwrap();
    let metadata = toml::to_string_pretty(&snapshot.metadata).unwrap();
    let key = store.integrity.as_ref().unwrap();
    let SnapshotIntegrityManifest::V2(current) = key
        .manifest(
            &snapshot.id,
            config.as_bytes(),
            metadata.as_bytes(),
            snapshot.metadata.generation,
        )
        .unwrap()
    else {
        panic!("expected a current generation witness");
    };
    let legacy = SnapshotIntegrityManifestV1 {
        algorithm: current.algorithm,
        key_id: current.key_id,
        config_sha256: current.config_sha256,
        metadata_hmac_sha256: current.metadata_hmac_sha256,
    };
    crate::store_fs::write_atomically(
        &store.integrity_path(&snapshot.id),
        toml::to_string_pretty(&legacy).unwrap().as_bytes(),
    )
    .unwrap();
}

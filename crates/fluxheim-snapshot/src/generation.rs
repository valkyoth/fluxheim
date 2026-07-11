use std::fs;

use serde::{Deserialize, Serialize};

use crate::integrity::{
    GENERATION_MAC_LABEL, MAX_INTEGRITY_MANIFEST_BYTES, SnapshotIntegrityKey,
    SnapshotIntegrityManifest,
};
use crate::metadata::{
    MAX_SNAPSHOT_METADATA_BYTES, SnapshotMetadata, validate_snapshot_id, validate_snapshot_metadata,
};
use crate::store::{SnapshotError, SnapshotStore};
use crate::store_fs::{
    read_optional_regular_file_to_string_with_limit, read_regular_file_to_string_with_limit,
    regular_snapshot_file_exists, write_atomically,
};

const MAX_GENERATION_STATE_BYTES: usize = 4096;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationState {
    generation: u64,
    key_id: Option<String>,
    hmac_sha256: Option<String>,
}

impl SnapshotStore {
    pub(crate) fn allocate_generation_unlocked(&self) -> Result<u64, SnapshotError> {
        let observed_max = self.observed_max_generation(true)?;
        let current = match read_optional_regular_file_to_string_with_limit(
            &self.generation_path(),
            MAX_GENERATION_STATE_BYTES as u64,
        )? {
            Some(raw) => self.decode_generation_state(&raw)?,
            None if observed_max == 0 => 0,
            None => return Err(SnapshotError::GenerationStateInvalid),
        };
        if current < observed_max {
            return Err(SnapshotError::GenerationStateInvalid);
        }
        let next = current
            .checked_add(1)
            .ok_or(SnapshotError::GenerationExhausted)?;
        let raw = self.encode_generation_state(next)?;
        if raw.len() > MAX_GENERATION_STATE_BYTES {
            return Err(SnapshotError::GenerationStateInvalid);
        }
        write_atomically(&self.generation_path(), raw.as_bytes())?;
        Ok(next)
    }

    pub(crate) fn verify_generation_state(&self) -> Result<(), SnapshotError> {
        let observed_max = self.observed_max_generation(false)?;
        let Some(raw) = read_optional_regular_file_to_string_with_limit(
            &self.generation_path(),
            MAX_GENERATION_STATE_BYTES as u64,
        )?
        else {
            return if observed_max == 0 {
                Ok(())
            } else {
                Err(SnapshotError::GenerationStateInvalid)
            };
        };
        let persisted = self.decode_generation_state(&raw)?;
        if persisted < observed_max {
            return Err(SnapshotError::GenerationStateInvalid);
        }
        Ok(())
    }

    fn encode_generation_state(&self, generation: u64) -> Result<String, SnapshotError> {
        let payload = generation.to_be_bytes();
        let (key_id, hmac_sha256) = match self.integrity.as_deref() {
            Some(key) => (
                Some(key.key_id().to_owned()),
                Some(key.sign_state(GENERATION_MAC_LABEL, &payload)?),
            ),
            None => (None, None),
        };
        toml::to_string(&GenerationState {
            generation,
            key_id,
            hmac_sha256,
        })
        .map_err(SnapshotError::Encode)
    }

    fn decode_generation_state(&self, raw: &str) -> Result<u64, SnapshotError> {
        if raw.len() > MAX_GENERATION_STATE_BYTES {
            return Err(SnapshotError::GenerationStateInvalid);
        }
        let state: GenerationState =
            toml::from_str(raw).map_err(|_| SnapshotError::GenerationStateInvalid)?;
        match self.integrity.as_deref() {
            Some(key) => {
                let signature = state
                    .hmac_sha256
                    .as_deref()
                    .and_then(crate::integrity::decode_hex_32)
                    .ok_or(SnapshotError::GenerationStateInvalid)?;
                if state.key_id.as_deref() != Some(key.key_id())
                    || !key.verify_state(
                        GENERATION_MAC_LABEL,
                        &state.generation.to_be_bytes(),
                        &signature,
                    )
                {
                    return Err(SnapshotError::GenerationStateInvalid);
                }
            }
            None if state.key_id.is_some() || state.hmac_sha256.is_some() => {
                return Err(SnapshotError::GenerationStateInvalid);
            }
            None => {}
        }
        Ok(state.generation)
    }

    pub(crate) fn generation_path(&self) -> std::path::PathBuf {
        self.root().join("generation.toml")
    }

    fn observed_max_generation(&self, migrate_legacy: bool) -> Result<u64, SnapshotError> {
        if !self.safe_existing_configs_dir()? {
            return Ok(0);
        }
        if let Some(key) = self.integrity.as_deref() {
            return self.observed_authenticated_generation(key, migrate_legacy);
        }
        self.observed_unverified_generation()
    }

    fn observed_authenticated_generation(
        &self,
        key: &SnapshotIntegrityKey,
        migrate_legacy: bool,
    ) -> Result<u64, SnapshotError> {
        let mut maximum = 0;
        for entry in fs::read_dir(self.configs_dir()).map_err(SnapshotError::Io)? {
            let path = entry.map_err(SnapshotError::Io)?.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|stem| stem.to_str()) else {
                return Err(SnapshotError::GenerationStateInvalid);
            };
            if id.ends_with(".meta") || id.ends_with(".integrity") {
                continue;
            }
            validate_snapshot_id(id).map_err(|_| SnapshotError::GenerationStateInvalid)?;
            if !regular_snapshot_file_exists(&path)? {
                return Err(SnapshotError::GenerationStateInvalid);
            }
            let raw = read_regular_file_to_string_with_limit(
                &self.integrity_path(id),
                MAX_INTEGRITY_MANIFEST_BYTES,
            )?;
            let manifest: SnapshotIntegrityManifest =
                toml::from_str(&raw).map_err(|_| SnapshotError::GenerationStateInvalid)?;
            let generation = match &manifest {
                SnapshotIntegrityManifest::V2(witness) => {
                    key.verify_generation_witness(id, witness)
                }
                SnapshotIntegrityManifest::V1(_) => {
                    self.verify_legacy_generation(id, key, &manifest, migrate_legacy)
                }
            }
            .map_err(generation_scan_error)?;
            maximum = maximum.max(generation);
        }
        Ok(maximum)
    }

    fn verify_legacy_generation(
        &self,
        id: &str,
        key: &SnapshotIntegrityKey,
        manifest: &SnapshotIntegrityManifest,
        migrate: bool,
    ) -> Result<u64, SnapshotError> {
        let config = read_regular_file_to_string_with_limit(
            &self.config_path(id),
            crate::store_fs::MAX_SNAPSHOT_FILE_BYTES,
        )?;
        let metadata_raw = read_regular_file_to_string_with_limit(
            &self.metadata_path(id),
            MAX_SNAPSHOT_METADATA_BYTES,
        )?;
        let metadata: SnapshotMetadata =
            toml::from_str(&metadata_raw).map_err(SnapshotError::Decode)?;
        validate_snapshot_metadata(&metadata, id)?;
        key.verify(
            id,
            config.as_bytes(),
            metadata_raw.as_bytes(),
            metadata.generation,
            manifest,
        )?;
        if migrate {
            let witness = key.manifest(
                id,
                config.as_bytes(),
                metadata_raw.as_bytes(),
                metadata.generation,
            )?;
            let raw = toml::to_string_pretty(&witness).map_err(SnapshotError::Encode)?;
            if raw.len() as u64 > MAX_INTEGRITY_MANIFEST_BYTES {
                return Err(SnapshotError::GenerationStateInvalid);
            }
            write_atomically(&self.integrity_path(id), raw.as_bytes())?;
        }
        Ok(metadata.generation)
    }

    fn observed_unverified_generation(&self) -> Result<u64, SnapshotError> {
        let mut maximum = 0;
        for entry in fs::read_dir(self.configs_dir()).map_err(SnapshotError::Io)? {
            let path = entry.map_err(SnapshotError::Io)?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                return Err(SnapshotError::GenerationStateInvalid);
            };
            let Some(id) = name.strip_suffix(".meta.toml") else {
                continue;
            };
            validate_snapshot_id(id).map_err(|_| SnapshotError::GenerationStateInvalid)?;
            let raw = read_regular_file_to_string_with_limit(&path, MAX_SNAPSHOT_METADATA_BYTES)?;
            let metadata: SnapshotMetadata =
                toml::from_str(&raw).map_err(|_| SnapshotError::GenerationStateInvalid)?;
            validate_snapshot_metadata(&metadata, id)
                .map_err(|_| SnapshotError::GenerationStateInvalid)?;
            maximum = maximum.max(metadata.generation);
        }
        Ok(maximum)
    }
}

fn generation_scan_error(error: SnapshotError) -> SnapshotError {
    match error {
        SnapshotError::CryptoProvider(_) => error,
        _ => SnapshotError::GenerationStateInvalid,
    }
}

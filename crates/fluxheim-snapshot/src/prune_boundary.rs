use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::integrity::PRUNE_BOUNDARY_MAC_LABEL;
use crate::store::{SnapshotError, SnapshotStore};
use crate::store_fs::{read_optional_regular_file_to_string_with_limit, write_atomically};

const MAX_PRUNE_BOUNDARY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PruneBoundary {
    pub child_id: String,
    pub removed_parent_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedPruneBoundaries {
    records_toml: String,
    key_id: Option<String>,
    hmac_sha256: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PruneBoundaryRecords {
    records: Vec<PruneBoundary>,
}

impl SnapshotStore {
    pub(crate) fn load_prune_boundaries(&self) -> Result<BTreeSet<PruneBoundary>, SnapshotError> {
        let Some(raw) = read_optional_regular_file_to_string_with_limit(
            &self.prune_boundary_path(),
            MAX_PRUNE_BOUNDARY_BYTES as u64,
        )?
        else {
            return Ok(BTreeSet::new());
        };
        if raw.len() > MAX_PRUNE_BOUNDARY_BYTES {
            return Err(SnapshotError::PruneBoundaryInvalid);
        }
        let persisted: PersistedPruneBoundaries =
            toml::from_str(&raw).map_err(|_| SnapshotError::PruneBoundaryInvalid)?;
        match self.integrity.as_deref() {
            Some(key) => {
                let signature = persisted
                    .hmac_sha256
                    .as_deref()
                    .and_then(crate::integrity::decode_hex_32)
                    .ok_or(SnapshotError::PruneBoundaryInvalid)?;
                if persisted.key_id.as_deref() != Some(key.key_id())
                    || !key.verify_state(
                        PRUNE_BOUNDARY_MAC_LABEL,
                        persisted.records_toml.as_bytes(),
                        &signature,
                    )
                {
                    return Err(SnapshotError::PruneBoundaryInvalid);
                }
            }
            None if persisted.key_id.is_some() || persisted.hmac_sha256.is_some() => {
                return Err(SnapshotError::PruneBoundaryInvalid);
            }
            None => {}
        }
        let records: PruneBoundaryRecords = toml::from_str(&persisted.records_toml)
            .map_err(|_| SnapshotError::PruneBoundaryInvalid)?;
        for record in &records.records {
            crate::metadata::validate_snapshot_id(&record.child_id)?;
            crate::metadata::validate_snapshot_id(&record.removed_parent_id)?;
        }
        Ok(records.records.into_iter().collect())
    }

    pub(crate) fn save_prune_boundaries(
        &self,
        records: &BTreeSet<PruneBoundary>,
    ) -> Result<(), SnapshotError> {
        let records_toml = toml::to_string(&PruneBoundaryRecords {
            records: records.iter().cloned().collect(),
        })
        .map_err(SnapshotError::Encode)?;
        let (key_id, hmac_sha256) = match self.integrity.as_deref() {
            Some(key) => (
                Some(key.key_id().to_owned()),
                Some(key.sign_state(PRUNE_BOUNDARY_MAC_LABEL, records_toml.as_bytes())?),
            ),
            None => (None, None),
        };
        let raw = toml::to_string(&PersistedPruneBoundaries {
            records_toml,
            key_id,
            hmac_sha256,
        })
        .map_err(SnapshotError::Encode)?;
        if raw.len() > MAX_PRUNE_BOUNDARY_BYTES {
            return Err(SnapshotError::PruneBoundaryInvalid);
        }
        write_atomically(&self.prune_boundary_path(), raw.as_bytes())
    }

    pub(crate) fn prune_boundary_path(&self) -> std::path::PathBuf {
        self.root().join("prune-boundaries.toml")
    }
}

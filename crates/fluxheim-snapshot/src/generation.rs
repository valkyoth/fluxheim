use serde::{Deserialize, Serialize};

use crate::integrity::GENERATION_MAC_LABEL;
use crate::store::{SnapshotError, SnapshotStore};
use crate::store_fs::{read_optional_regular_file_to_string_with_limit, write_atomically};

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
        let observed_max = self.observed_max_generation()?;
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
        let observed_max = self.observed_max_generation()?;
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

    fn observed_max_generation(&self) -> Result<u64, SnapshotError> {
        Ok(self
            .list()?
            .into_iter()
            .map(|snapshot| snapshot.metadata.generation)
            .max()
            .unwrap_or(0))
    }
}

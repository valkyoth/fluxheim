use crate::metadata::validate_snapshot_id;
use crate::state::SnapshotRuntimeState;
use crate::store::{SnapshotError, SnapshotStore};
use crate::store_fs::{read_optional_regular_file_to_string_with_limit, write_atomically};
use serde::{Deserialize, Serialize};

pub(crate) const MAX_RUNTIME_STATE_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_RUNTIME_DIAGNOSTIC_BYTES: usize = 4096;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedRuntimeState {
    state_toml: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hmac_sha256: Option<String>,
}

impl SnapshotStore {
    pub fn load_runtime_state(&self) -> Result<Option<SnapshotRuntimeState>, SnapshotError> {
        self.validate_for_recovery()?;
        let Some(raw) = read_optional_regular_file_to_string_with_limit(
            &self.runtime_state_path(),
            MAX_RUNTIME_STATE_BYTES,
        )?
        else {
            return Ok(None);
        };
        let persisted: PersistedRuntimeState =
            toml::from_str(&raw).map_err(SnapshotError::Decode)?;
        require_runtime_state_size(&persisted.state_toml)?;
        match self.integrity.as_deref() {
            Some(key)
                if persisted.key_id.as_deref() == Some(key.key_id())
                    && persisted.hmac_sha256.as_deref().is_some_and(|signature| {
                        key.verify_recovery(persisted.state_toml.as_bytes(), signature)
                    }) => {}
            Some(_) => return Err(SnapshotError::RuntimeStateIntegrityFailed),
            None if persisted.key_id.is_none() && persisted.hmac_sha256.is_none() => {}
            None => return Err(SnapshotError::RuntimeStateIntegrityFailed),
        }
        let state: SnapshotRuntimeState =
            toml::from_str(&persisted.state_toml).map_err(SnapshotError::Decode)?;
        validate_runtime_state(&state)?;
        Ok(Some(state))
    }

    pub fn save_runtime_state(&self, state: &SnapshotRuntimeState) -> Result<(), SnapshotError> {
        validate_runtime_state(state)?;
        let state_toml = toml::to_string_pretty(state).map_err(SnapshotError::Encode)?;
        require_runtime_state_size(&state_toml)?;
        let persisted = match self.integrity.as_deref() {
            Some(key) => PersistedRuntimeState {
                hmac_sha256: Some(key.sign_recovery(state_toml.as_bytes())?),
                key_id: Some(key.key_id().to_owned()),
                state_toml,
            },
            None => PersistedRuntimeState {
                state_toml,
                key_id: None,
                hmac_sha256: None,
            },
        };
        let raw = toml::to_string_pretty(&persisted).map_err(SnapshotError::Encode)?;
        require_runtime_state_size(&raw)?;
        self.with_store_lock(|| write_atomically(&self.runtime_state_path(), raw.as_bytes()))
    }

    pub(crate) fn runtime_state_path(&self) -> std::path::PathBuf {
        self.root().join("self-healing.toml")
    }

    fn validate_for_recovery(&self) -> Result<(), SnapshotError> {
        self.current_id().map(|_| ())
    }
}

fn validate_runtime_state(state: &SnapshotRuntimeState) -> Result<(), SnapshotError> {
    for id in [
        state.runtime_snapshot.as_deref(),
        state.known_good_snapshot.as_deref(),
        state
            .pending_validation
            .as_ref()
            .map(|pending| pending.target_snapshot.as_str()),
        state
            .pending_validation
            .as_ref()
            .and_then(|pending| pending.previous_snapshot.as_deref()),
    ]
    .into_iter()
    .flatten()
    {
        validate_snapshot_id(id)?;
    }
    if let Some(pending) = state.pending_validation.as_ref() {
        validate_runtime_diagnostic(&pending.impact)?;
        if let Some(failure) = pending.last_rollback_failure.as_deref() {
            validate_runtime_diagnostic(failure)?;
        }
    }
    Ok(())
}

fn validate_runtime_diagnostic(value: &str) -> Result<(), SnapshotError> {
    if value.len() > MAX_RUNTIME_DIAGNOSTIC_BYTES || value.chars().any(char::is_control) {
        return Err(SnapshotError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "snapshot recovery diagnostic is invalid or exceeds its configured limit",
        )));
    }
    Ok(())
}

fn require_runtime_state_size(raw: &str) -> Result<(), SnapshotError> {
    let length = u64::try_from(raw.len()).map_err(|_| {
        SnapshotError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "serialized snapshot recovery state length overflowed",
        ))
    })?;
    if length > MAX_RUNTIME_STATE_BYTES {
        return Err(SnapshotError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("serialized snapshot recovery state exceeds {MAX_RUNTIME_STATE_BYTES} bytes"),
        )));
    }
    Ok(())
}

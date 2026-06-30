use serde::{Deserialize, Serialize};

use crate::store::SnapshotError;

pub const MAX_SNAPSHOT_ID_BYTES: usize = 128;
pub const MAX_SNAPSHOT_MESSAGE_BYTES: usize = 4096;

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotMetadata {
    pub id: String,
    pub created_unix_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub(crate) fn snapshot_message(message: Option<&str>) -> Result<Option<String>, SnapshotError> {
    match message {
        Some(message) => valid_snapshot_message(message),
        None => Ok(None),
    }
}

pub(crate) fn valid_snapshot_message(message: &str) -> Result<Option<String>, SnapshotError> {
    let message = message.trim();
    if message.is_empty() {
        Ok(None)
    } else if message.len() > MAX_SNAPSHOT_MESSAGE_BYTES || message.chars().any(char::is_control) {
        Err(SnapshotError::InvalidSnapshotMessage {
            max_bytes: MAX_SNAPSHOT_MESSAGE_BYTES,
        })
    } else {
        Ok(Some(message.to_owned()))
    }
}

pub(crate) fn validate_snapshot_metadata(
    metadata: &SnapshotMetadata,
    expected_id: &str,
) -> Result<(), SnapshotError> {
    validate_snapshot_id(&metadata.id)?;
    if metadata.id != expected_id {
        return Err(SnapshotError::InvalidSnapshotId {
            id: metadata.id.clone(),
        });
    }
    if let Some(message) = metadata.message.as_deref() {
        valid_snapshot_message(message)?;
    }
    Ok(())
}

pub(crate) fn validate_snapshot_id(id: &str) -> Result<(), SnapshotError> {
    if id.is_empty()
        || id.len() > MAX_SNAPSHOT_ID_BYTES
        || id
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
    {
        return Err(SnapshotError::InvalidSnapshotId { id: id.to_owned() });
    }

    Ok(())
}

use std::fs::File;
use std::io::{self, Read as _};
use std::path::Path;

use ring::{digest, hmac};
use sanitization::SecretVec;
use serde::{Deserialize, Serialize};

use crate::store::SnapshotError;

pub(crate) const MAX_INTEGRITY_KEY_BYTES: u64 = 4096;
const MIN_INTEGRITY_KEY_BYTES: usize = 32;
const SNAPSHOT_MAC_LABEL: &[u8] = b"fluxheim-snapshot-v1\0";
const RECOVERY_MAC_LABEL: &[u8] = b"fluxheim-snapshot-recovery-v1\0";

#[derive(Debug)]
pub(crate) struct SnapshotIntegrityKey {
    secret: SecretVec,
    key_id: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotIntegrityManifest {
    pub algorithm: String,
    pub key_id: String,
    pub config_sha256: String,
    pub metadata_hmac_sha256: String,
}

impl SnapshotIntegrityKey {
    pub(crate) fn load(path: &Path) -> Result<Self, SnapshotError> {
        if fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(path)
            .unwrap_or(true)
        {
            return Err(SnapshotError::UnsafeIntegrityKey {
                path: path.to_path_buf(),
            });
        }
        let mut file = open_secret_file(path)?;
        let metadata = file.metadata().map_err(SnapshotError::Io)?;
        if !metadata.is_file() || metadata.len() > MAX_INTEGRITY_KEY_BYTES {
            return Err(SnapshotError::InvalidIntegrityKey);
        }
        let admitted =
            usize::try_from(metadata.len()).map_err(|_| SnapshotError::InvalidIntegrityKey)?;
        let mut secret = SecretVec::from_fn(admitted, |_| 0);
        secret
            .with_secret_mut(|bytes| file.read_exact(bytes))
            .map_err(SnapshotError::Io)?;
        let mut growth_probe = [0u8; 1];
        let grew = file.read(&mut growth_probe).map_err(SnapshotError::Io)? != 0;
        sanitization::sanitize_bytes(&mut growth_probe);
        if grew || secret.with_secret(|bytes| bytes.len()) < MIN_INTEGRITY_KEY_BYTES {
            return Err(SnapshotError::InvalidIntegrityKey);
        }
        let key_id =
            secret.with_secret(|bytes| hex(digest::digest(&digest::SHA256, bytes).as_ref()));
        Ok(Self { secret, key_id })
    }

    pub(crate) fn manifest(
        &self,
        id: &str,
        config: &[u8],
        metadata: &[u8],
    ) -> SnapshotIntegrityManifest {
        SnapshotIntegrityManifest {
            algorithm: "hmac-sha256".to_owned(),
            key_id: self.key_id.clone(),
            config_sha256: hex(digest::digest(&digest::SHA256, config).as_ref()),
            metadata_hmac_sha256: hex(self.sign(id, config, metadata).as_ref()),
        }
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn sign_recovery(&self, state: &[u8]) -> String {
        self.secret.with_secret(|secret| {
            let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
            let mut context = hmac::Context::with_key(&key);
            context.update(RECOVERY_MAC_LABEL);
            context.update(&(state.len() as u64).to_be_bytes());
            context.update(state);
            hex(context.sign().as_ref())
        })
    }

    pub(crate) fn verify_recovery(&self, state: &[u8], signature: &str) -> bool {
        let Some(signature) = decode_hex_32(signature) else {
            return false;
        };
        self.secret.with_secret(|secret| {
            let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
            let mut input = Vec::with_capacity(RECOVERY_MAC_LABEL.len() + state.len() + 8);
            input.extend_from_slice(RECOVERY_MAC_LABEL);
            input.extend_from_slice(&(state.len() as u64).to_be_bytes());
            input.extend_from_slice(state);
            hmac::verify(&key, &input, &signature).is_ok()
        })
    }

    pub(crate) fn verify(
        &self,
        id: &str,
        config: &[u8],
        metadata: &[u8],
        manifest: &SnapshotIntegrityManifest,
    ) -> Result<(), SnapshotError> {
        if manifest.algorithm != "hmac-sha256" || manifest.key_id != self.key_id {
            return Err(SnapshotError::IntegrityVerificationFailed { id: id.to_owned() });
        }
        let config_digest = hex(digest::digest(&digest::SHA256, config).as_ref());
        if config_digest != manifest.config_sha256 {
            return Err(SnapshotError::IntegrityVerificationFailed { id: id.to_owned() });
        }
        let expected = decode_hex_32(&manifest.metadata_hmac_sha256)
            .ok_or_else(|| SnapshotError::IntegrityVerificationFailed { id: id.to_owned() })?;
        self.secret
            .with_secret(|secret| {
                hmac::verify(
                    &hmac::Key::new(hmac::HMAC_SHA256, secret),
                    &mac_input(id, config, metadata),
                    &expected,
                )
            })
            .map_err(|_| SnapshotError::IntegrityVerificationFailed { id: id.to_owned() })
    }

    fn sign(&self, id: &str, config: &[u8], metadata: &[u8]) -> hmac::Tag {
        self.secret.with_secret(|secret| {
            hmac::sign(
                &hmac::Key::new(hmac::HMAC_SHA256, secret),
                &mac_input(id, config, metadata),
            )
        })
    }
}

fn mac_input(id: &str, config: &[u8], metadata: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(
        SNAPSHOT_MAC_LABEL.len() + id.len() + config.len() + metadata.len() + 24,
    );
    input.extend_from_slice(SNAPSHOT_MAC_LABEL);
    append_field(&mut input, id.as_bytes());
    append_field(&mut input, config);
    append_field(&mut input, metadata);
    input
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = hex_nibble(pair[0])?.checked_mul(16)? | hex_nibble(pair[1])?;
    }
    Some(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(unix)]
fn open_secret_file(path: &Path) -> Result<File, SnapshotError> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| SnapshotError::Io(io::Error::from_raw_os_error(error.raw_os_error())))?;
    Ok(fd.into())
}

#[cfg(not(unix))]
fn open_secret_file(path: &Path) -> Result<File, SnapshotError> {
    File::open(path).map_err(SnapshotError::Io)
}

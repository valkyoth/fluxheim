use std::fs::File;
use std::io::{self, Read as _};
use std::path::Path;
use std::sync::Arc;

use sanitization::{SecretVec, ct::ConstantTimeEq as _};
use serde::{Deserialize, Serialize};

use crate::store::SnapshotError;
use crate::store_fs::require_private_regular_file;

pub(crate) const MAX_INTEGRITY_KEY_BYTES: u64 = 4096;
const MIN_INTEGRITY_KEY_BYTES: usize = 32;
const SNAPSHOT_MAC_LABEL: &[u8] = b"fluxheim-snapshot-v1\0";
const GENERATION_WITNESS_MAC_LABEL: &[u8] = b"fluxheim-snapshot-generation-witness-v1\0";
const RECOVERY_MAC_LABEL: &[u8] = b"fluxheim-snapshot-recovery-v1\0";
pub(crate) const GENERATION_MAC_LABEL: &[u8] = b"fluxheim-snapshot-generation-v1\0";
pub(crate) const PRUNE_BOUNDARY_MAC_LABEL: &[u8] = b"fluxheim-snapshot-prune-boundary-v1\0";
pub(crate) const MAX_INTEGRITY_MANIFEST_BYTES: u64 = 4096;

pub trait SnapshotCryptoProvider: std::fmt::Debug + Send + Sync {
    fn label(&self) -> &'static str;
    fn compliance_capable(&self) -> bool;
    fn sha256(&self, chunks: &[&[u8]]) -> Result<[u8; 32], String>;
    fn hmac_sha256(&self, key: &[u8], chunks: &[&[u8]]) -> Result<[u8; 32], String>;
}

#[derive(Debug)]
pub(crate) struct SnapshotIntegrityKey {
    secret: SecretVec,
    key_id: String,
    provider: Arc<dyn SnapshotCryptoProvider>,
    source_path: std::path::PathBuf,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum SnapshotIntegrityManifest {
    V2(SnapshotIntegrityManifestV2),
    V1(SnapshotIntegrityManifestV1),
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotIntegrityManifestV1 {
    pub algorithm: String,
    pub key_id: String,
    pub config_sha256: String,
    pub metadata_hmac_sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotIntegrityManifestV2 {
    pub algorithm: String,
    pub key_id: String,
    pub config_sha256: String,
    pub metadata_hmac_sha256: String,
    pub generation: u64,
    pub generation_hmac_sha256: String,
}

impl SnapshotIntegrityKey {
    pub(crate) fn load(
        path: &Path,
        provider: Arc<dyn SnapshotCryptoProvider>,
    ) -> Result<Self, SnapshotError> {
        if fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(path)
            .unwrap_or(true)
        {
            return Err(SnapshotError::UnsafeIntegrityKey {
                path: path.to_path_buf(),
            });
        }
        let mut file = open_secret_file(path)?;
        require_private_regular_file(path).map_err(|_| SnapshotError::UnsafeIntegrityKey {
            path: path.to_path_buf(),
        })?;
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
        let key_id = secret
            .with_secret(|bytes| provider.sha256(&[bytes]))
            .map_err(SnapshotError::CryptoProvider)
            .map(|digest| hex(&digest))?;
        Ok(Self {
            secret,
            key_id,
            provider,
            source_path: path.to_path_buf(),
        })
    }

    pub(crate) fn manifest(
        &self,
        id: &str,
        config: &[u8],
        metadata: &[u8],
        generation: u64,
    ) -> Result<SnapshotIntegrityManifest, SnapshotError> {
        let config_digest = self
            .provider
            .sha256(&[config])
            .map_err(SnapshotError::CryptoProvider)?;
        let signature = self.sign_result(id, config, metadata)?;
        let generation_signature = self.sign_generation_witness(id, generation)?;
        Ok(SnapshotIntegrityManifest::V2(SnapshotIntegrityManifestV2 {
            algorithm: "hmac-sha256".to_owned(),
            key_id: self.key_id.clone(),
            config_sha256: hex(&config_digest),
            metadata_hmac_sha256: hex(&signature),
            generation,
            generation_hmac_sha256: hex(&generation_signature),
        }))
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn source_path(&self) -> &Path {
        &self.source_path
    }

    pub(crate) fn sign_recovery(&self, state: &[u8]) -> Result<String, SnapshotError> {
        self.sign_state(RECOVERY_MAC_LABEL, state)
    }

    pub(crate) fn verify_recovery(&self, state: &[u8], signature: &str) -> bool {
        let Some(signature) = decode_hex_32(signature) else {
            return false;
        };
        self.verify_state(RECOVERY_MAC_LABEL, state, &signature)
    }

    pub(crate) fn sign_state(&self, label: &[u8], state: &[u8]) -> Result<String, SnapshotError> {
        let length = u64::try_from(state.len())
            .map_err(|_| SnapshotError::CryptoProvider("state length overflow".to_owned()))?
            .to_be_bytes();
        self.secret
            .with_secret(|secret| {
                self.provider
                    .hmac_sha256(secret, &[label, &length, state])
                    .map(|digest| hex(&digest))
            })
            .map_err(SnapshotError::CryptoProvider)
    }

    pub(crate) fn verify_state(&self, label: &[u8], state: &[u8], signature: &[u8; 32]) -> bool {
        let length = (state.len() as u64).to_be_bytes();
        self.secret.with_secret(|secret| {
            self.provider
                .hmac_sha256(secret, &[label, &length, state])
                .is_ok_and(|digest| {
                    digest
                        .ct_eq(signature)
                        .declassify("snapshot state signature result is public")
                })
        })
    }

    pub(crate) fn verify(
        &self,
        id: &str,
        config: &[u8],
        metadata: &[u8],
        generation: u64,
        manifest: &SnapshotIntegrityManifest,
    ) -> Result<(), SnapshotError> {
        let common = manifest.common();
        if common.algorithm != "hmac-sha256" || common.key_id != self.key_id {
            return Err(SnapshotError::IntegrityVerificationFailed { id: id.to_owned() });
        }
        let config_digest = self
            .provider
            .sha256(&[config])
            .map_err(SnapshotError::CryptoProvider)
            .map(|digest| hex(&digest))?;
        if config_digest != common.config_sha256 {
            return Err(SnapshotError::IntegrityVerificationFailed { id: id.to_owned() });
        }
        if let SnapshotIntegrityManifest::V2(witness) = manifest {
            if witness.generation != generation {
                return Err(SnapshotError::IntegrityVerificationFailed { id: id.to_owned() });
            }
            self.verify_generation_witness(id, witness)?;
        }
        let expected = decode_hex_32(common.metadata_hmac_sha256)
            .ok_or_else(|| SnapshotError::IntegrityVerificationFailed { id: id.to_owned() })?;
        if self
            .sign_result(id, config, metadata)?
            .ct_eq(&expected)
            .declassify("snapshot integrity signature result is public")
        {
            Ok(())
        } else {
            Err(SnapshotError::IntegrityVerificationFailed { id: id.to_owned() })
        }
    }

    pub(crate) fn verify_generation_witness(
        &self,
        id: &str,
        manifest: &SnapshotIntegrityManifestV2,
    ) -> Result<u64, SnapshotError> {
        crate::metadata::validate_snapshot_id(id)?;
        if manifest.algorithm != "hmac-sha256" || manifest.key_id != self.key_id {
            return Err(SnapshotError::IntegrityVerificationFailed { id: id.to_owned() });
        }
        let expected = decode_hex_32(&manifest.generation_hmac_sha256)
            .ok_or_else(|| SnapshotError::IntegrityVerificationFailed { id: id.to_owned() })?;
        if self
            .sign_generation_witness(id, manifest.generation)?
            .ct_eq(&expected)
            .declassify("snapshot generation witness result is public")
        {
            Ok(manifest.generation)
        } else {
            Err(SnapshotError::IntegrityVerificationFailed { id: id.to_owned() })
        }
    }

    fn sign_generation_witness(
        &self,
        id: &str,
        generation: u64,
    ) -> Result<[u8; 32], SnapshotError> {
        let id_length = encoded_length(id.len())?;
        self.secret
            .with_secret(|secret| {
                self.provider.hmac_sha256(
                    secret,
                    &[
                        GENERATION_WITNESS_MAC_LABEL,
                        &id_length,
                        id.as_bytes(),
                        &generation.to_be_bytes(),
                    ],
                )
            })
            .map_err(SnapshotError::CryptoProvider)
    }

    fn sign_result(
        &self,
        id: &str,
        config: &[u8],
        metadata: &[u8],
    ) -> Result<[u8; 32], SnapshotError> {
        let id_length = encoded_length(id.len())?;
        let config_length = encoded_length(config.len())?;
        let metadata_length = encoded_length(metadata.len())?;
        self.secret
            .with_secret(|secret| {
                self.provider.hmac_sha256(
                    secret,
                    &[
                        SNAPSHOT_MAC_LABEL,
                        &id_length,
                        id.as_bytes(),
                        &config_length,
                        config,
                        &metadata_length,
                        metadata,
                    ],
                )
            })
            .map_err(SnapshotError::CryptoProvider)
    }
}

impl SnapshotIntegrityManifest {
    fn common(&self) -> SnapshotIntegrityManifestCommon<'_> {
        match self {
            Self::V2(manifest) => SnapshotIntegrityManifestCommon {
                algorithm: &manifest.algorithm,
                key_id: &manifest.key_id,
                config_sha256: &manifest.config_sha256,
                metadata_hmac_sha256: &manifest.metadata_hmac_sha256,
            },
            Self::V1(manifest) => SnapshotIntegrityManifestCommon {
                algorithm: &manifest.algorithm,
                key_id: &manifest.key_id,
                config_sha256: &manifest.config_sha256,
                metadata_hmac_sha256: &manifest.metadata_hmac_sha256,
            },
        }
    }
}

struct SnapshotIntegrityManifestCommon<'a> {
    algorithm: &'a str,
    key_id: &'a str,
    config_sha256: &'a str,
    metadata_hmac_sha256: &'a str,
}

fn encoded_length(length: usize) -> Result<[u8; 8], SnapshotError> {
    u64::try_from(length)
        .map(u64::to_be_bytes)
        .map_err(|_| SnapshotError::CryptoProvider("field length overflow".to_owned()))
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

pub(crate) fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
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

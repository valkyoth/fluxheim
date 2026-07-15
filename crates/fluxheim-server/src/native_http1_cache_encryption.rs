use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fluxheim_config::{CacheDiskEncryptionConfig, CacheDiskEncryptionProvider};
use fs2::FileExt as _;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use sanitization::SecretBytes;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::native_http1_cache_disk_path::NativeSafeDiskCachePath;

#[cfg(feature = "openbao-cache-encryption")]
#[path = "native_http1_cache_openbao.rs"]
mod native_http1_cache_openbao;

#[cfg(feature = "openbao-cache-encryption")]
use native_http1_cache_openbao::{
    native_openbao_transit_provider, openbao_transit_decrypt, openbao_transit_encrypt,
};

pub(super) const NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1: &[u8] = b"FLUXHEIM-CACHE-ENC-v1\n";
pub(super) const NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V2: &[u8] = b"FLUXHEIM-CACHE-ENC-v2\n";
const NATIVE_DISK_CACHE_GCM_RANDOM_NONCE_INVOCATION_LIMIT: u64 = 1_u64 << 32;
const NATIVE_DISK_CACHE_GCM_RANDOM_NONCE_WARNING_AT: u64 =
    NATIVE_DISK_CACHE_GCM_RANDOM_NONCE_INVOCATION_LIMIT - 1_000_000;

#[derive(Debug)]
pub(super) struct NativeDiskCacheEncryption {
    key_id: Arc<str>,
    provider: NativeDiskCacheEncryptionProvider,
    local_nonce_counter_path: Option<PathBuf>,
}

#[derive(Debug)]
enum NativeDiskCacheEncryptionProvider {
    Local {
        key: Arc<LessSafeKey>,
    },
    #[cfg(feature = "openbao-cache-encryption")]
    OpenBaoTransit {
        address: Arc<str>,
        mount: Arc<str>,
        key_name: Arc<str>,
        token: sanitization::SecretString,
    },
    #[cfg(not(feature = "openbao-cache-encryption"))]
    OpenBaoTransitDisabled,
}

impl NativeDiskCacheEncryption {
    pub(super) fn from_config(
        config: &CacheDiskEncryptionConfig,
        cache_root: &Path,
    ) -> std::io::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        let key_id = Arc::from(config.key_id.as_deref().unwrap_or("local"));
        let (provider, local_nonce_counter_path) = match config.provider {
            CacheDiskEncryptionProvider::Local => {
                let key_bytes = match (&config.key_file, config.key_credential.as_deref()) {
                    (Some(path), None) => read_native_cache_encryption_key_file(path)?,
                    (None, Some(credential)) => {
                        let path = native_cache_encryption_credential_path(credential);
                        read_native_cache_encryption_key_file(&path)?
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "native disk cache encryption requires exactly one local key source",
                        ));
                    }
                };
                let counter_identity: [u8; 32] =
                    key_bytes.expose_secret(|key_bytes| Sha256::digest(key_bytes).into());
                let unbound = key_bytes
                    .expose_secret(|key_bytes| UnboundKey::new(&AES_256_GCM, key_bytes))
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "invalid native disk cache encryption key",
                        )
                    })?;
                (
                    NativeDiskCacheEncryptionProvider::Local {
                        key: Arc::new(LessSafeKey::new(unbound)),
                    },
                    Some(native_cache_nonce_counter_path(
                        cache_root,
                        &counter_identity,
                    )),
                )
            }
            CacheDiskEncryptionProvider::OpenbaoTransit => {
                (native_openbao_transit_provider(config)?, None)
            }
        };
        Ok(Some(Self {
            key_id,
            provider,
            local_nonce_counter_path,
        }))
    }

    pub(super) fn encrypt(
        &self,
        _combined_key: &str,
        plaintext: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let aad = native_cache_encryption_aad_v2(&self.key_id);
        let (nonce, ciphertext) = match &self.provider {
            NativeDiskCacheEncryptionProvider::Local { key } => {
                self.reserve_local_nonce_invocation(
                    NATIVE_DISK_CACHE_GCM_RANDOM_NONCE_INVOCATION_LIMIT,
                )?;
                let mut nonce = [0_u8; 12];
                getrandom::fill(&mut nonce).map_err(|error| {
                    std::io::Error::other(format!(
                        "generate native cache encryption nonce: {error}"
                    ))
                })?;
                let mut ciphertext = plaintext.to_vec();
                key.seal_in_place_append_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(aad),
                    &mut ciphertext,
                )
                .map_err(|_| std::io::Error::other("encrypt native cache object"))?;
                (nonce.to_vec(), ciphertext)
            }
            #[cfg(feature = "openbao-cache-encryption")]
            NativeDiskCacheEncryptionProvider::OpenBaoTransit {
                address,
                mount,
                key_name,
                token,
            } => {
                let ciphertext = token
                    .try_with_secret(|token| {
                        openbao_transit_encrypt(address, mount, key_name, token, plaintext, &aad)
                    })
                    .map_err(|error| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
                    })??;
                (Vec::new(), ciphertext.into_bytes())
            }
            #[cfg(not(feature = "openbao-cache-encryption"))]
            NativeDiskCacheEncryptionProvider::OpenBaoTransitDisabled => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "native disk cache OpenBao Transit encryption is not enabled in this build",
                ));
            }
        };

        let mut encoded = Vec::with_capacity(
            NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V2.len()
                + 128
                + self.key_id.len()
                + nonce.len()
                + ciphertext.len(),
        );
        encoded.write_all(NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V2)?;
        writeln!(encoded, "{}", self.key_id.len())?;
        writeln!(encoded, "{}", nonce.len())?;
        writeln!(encoded, "{}", ciphertext.len())?;
        encoded.write_all(self.key_id.as_bytes())?;
        encoded.write_all(&nonce)?;
        encoded.write_all(&ciphertext)?;
        Ok(encoded)
    }

    fn reserve_local_nonce_invocation(&self, limit: u64) -> std::io::Result<()> {
        let path = self.local_nonce_counter_path.as_ref().ok_or_else(|| {
            std::io::Error::other("local cache encryption nonce counter is unavailable")
        })?;
        let lock_path = path.with_extension("counter.lock");
        let lock_file =
            NativeSafeDiskCachePath::from_path(lock_path).open_or_create_read_write_file()?;
        lock_file.lock_exclusive()?;
        let count = read_native_cache_nonce_counter(path)?;
        if count >= limit {
            return Err(std::io::Error::other(
                "native local disk-cache encryption key reached its AES-GCM invocation limit; rotate the key",
            ));
        }
        let count = count.checked_add(1).ok_or_else(|| {
            std::io::Error::other("native cache encryption nonce counter overflow")
        })?;
        write_native_cache_nonce_counter(path, count)?;
        if count == NATIVE_DISK_CACHE_GCM_RANDOM_NONCE_WARNING_AT {
            log::warn!(
                target: "fluxheim::security",
                "native local disk-cache encryption key_id={} is approaching the AES-GCM random-nonce invocation limit; rotate the local cache encryption key",
                self.key_id
            );
        }
        Ok(())
    }

    pub(super) fn decrypt(&self, bytes: &[u8]) -> std::io::Result<Zeroizing<Vec<u8>>> {
        if bytes.get(..NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V2.len())
            == Some(NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V2)
        {
            return self.decrypt_v2(bytes);
        }
        if bytes.get(..NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1.len())
            == Some(NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1)
        {
            return self.decrypt_v1(bytes);
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unencrypted cache object found while native disk encryption is enabled",
        ))
    }

    fn decrypt_v2(&self, bytes: &[u8]) -> std::io::Result<Zeroizing<Vec<u8>>> {
        let mut offset = NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V2.len();
        let key_id_len = native_encrypted_disk_len(bytes, &mut offset)?;
        let nonce_len = native_encrypted_disk_len(bytes, &mut offset)?;
        let ciphertext_len = native_encrypted_disk_len(bytes, &mut offset)?;
        let total_len = offset
            .checked_add(key_id_len)
            .and_then(|value| value.checked_add(nonce_len))
            .and_then(|value| value.checked_add(ciphertext_len))
            .ok_or_else(encrypted_size_overflow)?;
        if total_len != bytes.len() {
            return Err(encrypted_length_mismatch());
        }
        let key_id_end = offset + key_id_len;
        let nonce_end = key_id_end + nonce_len;
        let key_id = native_cache_utf8(&bytes[offset..key_id_end], "encryption key id")?;
        self.validate_key_id(&key_id)?;
        self.decrypt_payload(
            nonce_len,
            &bytes[key_id_end..nonce_end],
            &bytes[nonce_end..],
            native_cache_encryption_aad_v2(&self.key_id),
        )
    }

    fn decrypt_v1(&self, bytes: &[u8]) -> std::io::Result<Zeroizing<Vec<u8>>> {
        let mut offset = NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1.len();
        let key_id_len = native_encrypted_disk_len(bytes, &mut offset)?;
        let combined_key_len = native_encrypted_disk_len(bytes, &mut offset)?;
        let nonce_len = native_encrypted_disk_len(bytes, &mut offset)?;
        let ciphertext_len = native_encrypted_disk_len(bytes, &mut offset)?;
        let total_len = offset
            .checked_add(key_id_len)
            .and_then(|value| value.checked_add(combined_key_len))
            .and_then(|value| value.checked_add(nonce_len))
            .and_then(|value| value.checked_add(ciphertext_len))
            .ok_or_else(encrypted_size_overflow)?;
        if total_len != bytes.len() {
            return Err(encrypted_length_mismatch());
        }

        let key_id_end = offset + key_id_len;
        let combined_key_end = key_id_end + combined_key_len;
        let nonce_end = combined_key_end + nonce_len;
        let key_id = native_cache_utf8(&bytes[offset..key_id_end], "encryption key id")?;
        self.validate_key_id(&key_id)?;
        let combined_key = native_cache_utf8(&bytes[key_id_end..combined_key_end], "combined key")?;
        self.decrypt_payload(
            nonce_len,
            &bytes[combined_key_end..nonce_end],
            &bytes[nonce_end..],
            native_cache_encryption_aad_v1(&self.key_id, &combined_key),
        )
    }

    fn validate_key_id(&self, key_id: &str) -> std::io::Result<()> {
        if key_id == self.key_id.as_ref() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encrypted native cache object key id does not match configured key",
            ))
        }
    }

    fn decrypt_payload(
        &self,
        nonce_len: usize,
        nonce_bytes: &[u8],
        ciphertext_bytes: &[u8],
        aad: Vec<u8>,
    ) -> std::io::Result<Zeroizing<Vec<u8>>> {
        match &self.provider {
            NativeDiskCacheEncryptionProvider::Local { key } => {
                if nonce_len != 12 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid encrypted native cache object nonce length",
                    ));
                }
                let mut nonce = [0_u8; 12];
                nonce.copy_from_slice(nonce_bytes);
                let mut plaintext = ciphertext_bytes.to_vec();
                key.open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(aad),
                    &mut plaintext,
                )
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "decrypt native cache object",
                    )
                })?;
                let plaintext_len = plaintext
                    .len()
                    .checked_sub(AES_256_GCM.tag_len())
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "short encrypted native cache object",
                        )
                    })?;
                plaintext.truncate(plaintext_len);
                Ok(Zeroizing::new(plaintext))
            }
            #[cfg(feature = "openbao-cache-encryption")]
            NativeDiskCacheEncryptionProvider::OpenBaoTransit {
                address,
                mount,
                key_name,
                token,
            } => {
                if nonce_len != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid OpenBao encrypted native cache object nonce length",
                    ));
                }
                let ciphertext = native_cache_utf8(ciphertext_bytes, "openbao ciphertext")?;
                token
                    .try_with_secret(|token| {
                        openbao_transit_decrypt(address, mount, key_name, token, &ciphertext, &aad)
                    })
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?
            }
            #[cfg(not(feature = "openbao-cache-encryption"))]
            NativeDiskCacheEncryptionProvider::OpenBaoTransitDisabled => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "native disk cache OpenBao Transit encryption is not enabled in this build",
            )),
        }
    }
}

fn read_native_cache_nonce_counter(path: &Path) -> std::io::Result<u64> {
    let mut file = match NativeSafeDiskCachePath::from_path(path.to_path_buf()).open_existing_file()
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() > 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native cache encryption nonce counter is oversized",
        ));
    }
    let mut encoded = String::new();
    file.read_to_string(&mut encoded)?;
    if encoded.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native cache encryption nonce counter is empty",
        ));
    }
    encoded.trim().parse::<u64>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native cache encryption nonce counter is invalid",
        )
    })
}

fn write_native_cache_nonce_counter(path: &Path, count: u64) -> std::io::Result<()> {
    let destination = NativeSafeDiskCachePath::from_path(path.to_path_buf());
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "native cache encryption nonce counter has no parent",
        )
    })?;
    let mut last_collision = None;
    for _ in 0..4 {
        let mut random = [0_u8; 12];
        getrandom::fill(&mut random).map_err(|error| {
            std::io::Error::other(format!("cache nonce counter temp random: {error}"))
        })?;
        let mut suffix = String::with_capacity(random.len() * 2);
        for byte in random {
            use std::fmt::Write as _;
            let _ = write!(suffix, "{byte:02x}");
        }
        let temporary = NativeSafeDiskCachePath::from_path(
            parent.join(format!(".fluxheim-gcm-counter-{suffix}.tmp")),
        );
        let result = (|| {
            let mut file = temporary.create_new_file()?;
            writeln!(file, "{count}")?;
            file.sync_all()?;
            destination.rename_from(&temporary)?;
            destination.sync_parent_dir()
        })();
        match result {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = temporary.remove_file();
                last_collision = Some(error);
            }
            Err(error) => {
                let _ = temporary.remove_file();
                return Err(error);
            }
        }
    }
    Err(last_collision.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "native cache encryption nonce counter temp collision",
        )
    }))
}

#[cfg(not(feature = "openbao-cache-encryption"))]
fn native_openbao_transit_provider(
    _config: &CacheDiskEncryptionConfig,
) -> std::io::Result<NativeDiskCacheEncryptionProvider> {
    Ok(NativeDiskCacheEncryptionProvider::OpenBaoTransitDisabled)
}

fn native_encrypted_disk_len(bytes: &[u8], offset: &mut usize) -> std::io::Result<usize> {
    let relative_newline = bytes
        .get(*offset..)
        .and_then(|tail| tail.iter().position(|byte| *byte == b'\n'))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encrypted native cache object length line is truncated",
            )
        })?;
    let end = (*offset).checked_add(relative_newline).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted native cache object length offset overflow",
        )
    })?;
    let line = std::str::from_utf8(&bytes[*offset..end]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted native cache object length is not UTF-8",
        )
    })?;
    *offset = end.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted native cache object length offset overflow",
        )
    })?;
    line.parse::<usize>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "encrypted native cache object length is invalid",
        )
    })
}

fn native_cache_encryption_aad_v1(key_id: &str, combined_key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + key_id.len() + combined_key.len());
    aad.extend_from_slice(b"fluxheim-cache-disk-v1\0");
    aad.extend_from_slice(key_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(combined_key.as_bytes());
    aad
}

fn native_cache_encryption_aad_v2(key_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + key_id.len());
    aad.extend_from_slice(b"fluxheim-cache-disk-v2\0");
    aad.extend_from_slice(key_id.as_bytes());
    aad
}

fn encrypted_size_overflow() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "encrypted native cache object size overflow",
    )
}

fn encrypted_length_mismatch() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "encrypted native cache object length mismatch",
    )
}

fn native_cache_nonce_counter_path(cache_root: &Path, key_identity: &[u8; 32]) -> PathBuf {
    let mut suffix = String::with_capacity(32);
    for byte in &key_identity[..16] {
        use std::fmt::Write as _;
        let _ = write!(suffix, "{byte:02x}");
    }
    cache_root.join(format!(".fluxheim-gcm-{suffix}.counter"))
}

fn native_cache_encryption_credential_path(credential_name: &str) -> PathBuf {
    std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/secrets"))
        .join(credential_name)
}

fn read_native_cache_encryption_key_file(path: &Path) -> std::io::Result<SecretBytes<32>> {
    let contents = read_native_cache_encryption_secret_file(path)?;
    parse_native_cache_encryption_hex_key(contents.trim())
}

fn read_native_cache_encryption_secret_file(path: &Path) -> std::io::Result<Zeroizing<String>> {
    let mut file = NativeSafeDiskCachePath::from_path(path.to_path_buf()).open_existing_file()?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native cache disk encryption secret must be a small regular file",
        ));
    }
    let mut contents = Zeroizing::new(String::new());
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

fn parse_native_cache_encryption_hex_key(value: &str) -> std::io::Result<SecretBytes<32>> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native cache disk encryption key must be 64 hex characters",
        ));
    }
    SecretBytes::try_from_fn(|index| {
        let offset = index.saturating_mul(2);
        let high = native_hex_value(value.as_bytes()[offset])?;
        let low = native_hex_value(value.as_bytes()[offset + 1])?;
        Ok((high << 4) | low)
    })
}

fn native_hex_value(byte: u8) -> std::io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid hex digit",
        )),
    }
}

fn native_cache_utf8(bytes: &[u8], field: &str) -> std::io::Result<String> {
    std::str::from_utf8(bytes)
        .map(ToOwned::to_owned)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("encrypted native cache object {field} is not UTF-8"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_encryption(root: &Path) -> NativeDiskCacheEncryption {
        let key_bytes = [7_u8; 32];
        let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
        let key_identity: [u8; 32] = Sha256::digest(key_bytes).into();
        let key_id: Arc<str> = Arc::from("test-key");
        NativeDiskCacheEncryption {
            local_nonce_counter_path: Some(native_cache_nonce_counter_path(root, &key_identity)),
            key_id,
            provider: NativeDiskCacheEncryptionProvider::Local {
                key: Arc::new(LessSafeKey::new(unbound)),
            },
        }
    }

    #[test]
    fn v2_envelope_hides_combined_key_and_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let encryption = local_encryption(directory.path());
        let combined_key = "private.example/account?id=42";
        let plaintext = format!("object metadata {combined_key}");

        let encrypted = encryption
            .encrypt(combined_key, plaintext.as_bytes())
            .unwrap();

        assert!(encrypted.starts_with(NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V2));
        assert!(
            !encrypted
                .windows(combined_key.len())
                .any(|window| { window == combined_key.as_bytes() })
        );
        assert_eq!(
            encryption.decrypt(&encrypted).unwrap().as_slice(),
            plaintext.as_bytes()
        );
    }

    #[test]
    fn local_nonce_limit_is_persistent_and_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let first = local_encryption(directory.path());
        first.reserve_local_nonce_invocation(2).unwrap();
        drop(first);

        let second = local_encryption(directory.path());
        second.reserve_local_nonce_invocation(2).unwrap();
        assert!(second.reserve_local_nonce_invocation(2).is_err());
    }

    #[test]
    fn damaged_nonce_counter_fails_closed_instead_of_resetting() {
        let directory = tempfile::tempdir().unwrap();
        let encryption = local_encryption(directory.path());
        NativeSafeDiskCachePath::from_path(
            encryption
                .local_nonce_counter_path
                .as_ref()
                .unwrap()
                .clone(),
        )
        .create_new_file()
        .unwrap();

        assert!(encryption.reserve_local_nonce_invocation(10).is_err());
    }

    #[test]
    fn v1_envelope_remains_readable_during_migration() {
        let directory = tempfile::tempdir().unwrap();
        let encryption = local_encryption(directory.path());
        let NativeDiskCacheEncryptionProvider::Local { key } = &encryption.provider else {
            unreachable!();
        };
        let combined_key = "legacy.example/object";
        let plaintext = b"legacy encrypted object";
        let nonce = [9_u8; 12];
        let mut ciphertext = plaintext.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(native_cache_encryption_aad_v1(
                &encryption.key_id,
                combined_key,
            )),
            &mut ciphertext,
        )
        .unwrap();
        let mut encoded = Vec::new();
        encoded
            .write_all(NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1)
            .unwrap();
        writeln!(encoded, "{}", encryption.key_id.len()).unwrap();
        writeln!(encoded, "{}", combined_key.len()).unwrap();
        writeln!(encoded, "{}", nonce.len()).unwrap();
        writeln!(encoded, "{}", ciphertext.len()).unwrap();
        encoded.write_all(encryption.key_id.as_bytes()).unwrap();
        encoded.write_all(combined_key.as_bytes()).unwrap();
        encoded.write_all(&nonce).unwrap();
        encoded.write_all(&ciphertext).unwrap();

        assert_eq!(encryption.decrypt(&encoded).unwrap().as_slice(), plaintext);
    }
}

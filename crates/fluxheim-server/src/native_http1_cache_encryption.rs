use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fluxheim_config::{CacheDiskEncryptionConfig, CacheDiskEncryptionProvider};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
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
const NATIVE_DISK_CACHE_GCM_RANDOM_NONCE_INVOCATION_LIMIT: u64 = 1_u64 << 32;
const NATIVE_DISK_CACHE_GCM_RANDOM_NONCE_WARNING_AT: u64 =
    NATIVE_DISK_CACHE_GCM_RANDOM_NONCE_INVOCATION_LIMIT - 1_000_000;

#[derive(Debug)]
pub(super) struct NativeDiskCacheEncryption {
    key_id: Arc<str>,
    provider: NativeDiskCacheEncryptionProvider,
    local_nonce_invocations: AtomicU64,
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
    pub(super) fn from_config(config: &CacheDiskEncryptionConfig) -> std::io::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        let key_id = Arc::from(config.key_id.as_deref().unwrap_or("local"));
        let provider = match config.provider {
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
                let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid native disk cache encryption key",
                    )
                })?;
                NativeDiskCacheEncryptionProvider::Local {
                    key: Arc::new(LessSafeKey::new(unbound)),
                }
            }
            CacheDiskEncryptionProvider::OpenbaoTransit => native_openbao_transit_provider(config)?,
        };
        Ok(Some(Self {
            key_id,
            provider,
            local_nonce_invocations: AtomicU64::new(0),
        }))
    }

    pub(super) fn encrypt(&self, combined_key: &str, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        let aad = native_cache_encryption_aad(&self.key_id, combined_key);
        let (nonce, ciphertext) = match &self.provider {
            NativeDiskCacheEncryptionProvider::Local { key } => {
                self.record_local_nonce_invocation();
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
            NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1.len()
                + 128
                + self.key_id.len()
                + combined_key.len()
                + nonce.len()
                + ciphertext.len(),
        );
        encoded.write_all(NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1)?;
        writeln!(encoded, "{}", self.key_id.len())?;
        writeln!(encoded, "{}", combined_key.len())?;
        writeln!(encoded, "{}", nonce.len())?;
        writeln!(encoded, "{}", ciphertext.len())?;
        encoded.write_all(self.key_id.as_bytes())?;
        encoded.write_all(combined_key.as_bytes())?;
        encoded.write_all(&nonce)?;
        encoded.write_all(&ciphertext)?;
        Ok(encoded)
    }

    fn record_local_nonce_invocation(&self) {
        let count = self
            .local_nonce_invocations
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if count == NATIVE_DISK_CACHE_GCM_RANDOM_NONCE_WARNING_AT {
            log::warn!(
                target: "fluxheim::security",
                "native local disk-cache encryption key_id={} is approaching the AES-GCM random-nonce invocation limit; rotate the local cache encryption key",
                self.key_id
            );
        } else if count == NATIVE_DISK_CACHE_GCM_RANDOM_NONCE_INVOCATION_LIMIT {
            log::error!(
                target: "fluxheim::security",
                "native local disk-cache encryption key_id={} reached the AES-GCM random-nonce invocation limit; rotate the local cache encryption key immediately",
                self.key_id
            );
        }
    }

    pub(super) fn decrypt(&self, bytes: &[u8]) -> std::io::Result<Zeroizing<Vec<u8>>> {
        if bytes.get(..NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1.len())
            != Some(NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unencrypted cache object found while native disk encryption is enabled",
            ));
        }

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
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "encrypted native cache object size overflow",
                )
            })?;
        if total_len != bytes.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encrypted native cache object length mismatch",
            ));
        }

        let key_id_end = offset + key_id_len;
        let combined_key_end = key_id_end + combined_key_len;
        let nonce_end = combined_key_end + nonce_len;
        let key_id = native_cache_utf8(&bytes[offset..key_id_end], "encryption key id")?;
        if key_id != self.key_id.as_ref() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encrypted native cache object key id does not match configured key",
            ));
        }
        let combined_key = native_cache_utf8(&bytes[key_id_end..combined_key_end], "combined key")?;
        let aad = native_cache_encryption_aad(&self.key_id, &combined_key);
        match &self.provider {
            NativeDiskCacheEncryptionProvider::Local { key } => {
                if nonce_len != 12 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid encrypted native cache object nonce length",
                    ));
                }
                let mut nonce = [0_u8; 12];
                nonce.copy_from_slice(&bytes[combined_key_end..nonce_end]);
                let mut plaintext = bytes[nonce_end..].to_vec();
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
                let ciphertext = native_cache_utf8(&bytes[nonce_end..], "openbao ciphertext")?;
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

fn native_cache_encryption_aad(key_id: &str, combined_key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + key_id.len() + combined_key.len());
    aad.extend_from_slice(b"fluxheim-cache-disk-v1\0");
    aad.extend_from_slice(key_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(combined_key.as_bytes());
    aad
}

fn native_cache_encryption_credential_path(credential_name: &str) -> PathBuf {
    std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/secrets"))
        .join(credential_name)
}

fn read_native_cache_encryption_key_file(path: &Path) -> std::io::Result<[u8; 32]> {
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

fn parse_native_cache_encryption_hex_key(value: &str) -> std::io::Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native cache disk encryption key must be 64 hex characters",
        ));
    }
    let mut key = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = native_hex_value(chunk[0])?;
        let low = native_hex_value(chunk[1])?;
        key[index] = (high << 4) | low;
    }
    Ok(key)
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

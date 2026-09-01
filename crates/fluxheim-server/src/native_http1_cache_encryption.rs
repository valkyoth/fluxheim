use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fluxheim_config::{CacheDiskEncryptionConfig, CacheDiskEncryptionProvider};
use fs2::FileExt as _;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::{hkdf, hmac};
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
const NATIVE_CACHE_ROOT_ID_FILE: &str = ".fluxheim-encryption-root-v1";
const NATIVE_CACHE_ROOT_ID_LOCK_FILE: &str = ".fluxheim-encryption-root-v1.lock";
const NATIVE_CACHE_ACTIVE_KEY_FILE: &str = ".fluxheim-encryption-key-v1";
const NATIVE_CACHE_ACTIVE_KEY_LOCK_FILE: &str = ".fluxheim-encryption-key-v1.lock";
const NATIVE_CACHE_MIGRATION_PENDING_FILE: &str = ".fluxheim-encryption-migration-v1.pending";
#[cfg(feature = "openbao-cache-encryption")]
const NATIVE_CACHE_OPENBAO_INDEX_KEY_FILE: &str = ".fluxheim-index-key-v1.transit";
const NATIVE_CACHE_ROOT_ID_BYTES: usize = 32;
const NATIVE_CACHE_DATA_KEY_INFO: &[u8] = b"fluxheim/cache/aes-gcm/root/v1";
const NATIVE_CACHE_INDEX_KEY_INFO: &[u8] = b"fluxheim/cache/index-hmac/root/v1";

struct NativeCacheHkdfKeyLength;

impl hkdf::KeyType for NativeCacheHkdfKeyLength {
    fn len(&self) -> usize {
        32
    }
}

#[derive(Debug)]
pub(super) struct NativeDiskCacheEncryption {
    key_id: Arc<str>,
    provider: NativeDiskCacheEncryptionProvider,
    local_nonce_counter_path: Option<PathBuf>,
    index_key: Arc<SecretBytes<32>>,
    root_migration_required: bool,
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
        let (root_id, mut root_migration_required) =
            load_or_create_native_cache_root_id(cache_root)?;
        let (provider, local_nonce_counter_path, index_key) = match config.provider {
            CacheDiskEncryptionProvider::Local => {
                let master_key = match (&config.key_file, config.key_credential.as_deref()) {
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
                let data_key = master_key.expose_secret(|master_key| {
                    derive_native_cache_root_key(master_key, &root_id, NATIVE_CACHE_DATA_KEY_INFO)
                })?;
                let index_key = master_key.expose_secret(|master_key| {
                    derive_native_cache_root_key(master_key, &root_id, NATIVE_CACHE_INDEX_KEY_INFO)
                })?;
                let counter_identity: [u8; 32] =
                    data_key.expose_secret(|data_key| Sha256::digest(data_key).into());
                let unbound = data_key
                    .expose_secret(|key_bytes| UnboundKey::new(&AES_256_GCM, key_bytes))
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "invalid native disk cache encryption key",
                        )
                    })?;
                let counter_path = native_cache_nonce_counter_path(cache_root, &counter_identity);
                root_migration_required |= initialize_native_cache_local_key(
                    cache_root,
                    &counter_identity,
                    &counter_path,
                    root_migration_required,
                )?;
                (
                    NativeDiskCacheEncryptionProvider::Local {
                        key: Arc::new(LessSafeKey::new(unbound)),
                    },
                    Some(counter_path),
                    Arc::new(index_key),
                )
            }
            CacheDiskEncryptionProvider::OpenbaoTransit => {
                let provider = native_openbao_transit_provider(config)?;
                let index_key = native_openbao_index_key(
                    &provider,
                    cache_root,
                    &root_id,
                    root_migration_required,
                )?;
                (provider, None, Arc::new(index_key))
            }
        };
        Ok(Some(Self {
            key_id,
            provider,
            local_nonce_counter_path,
            index_key,
            root_migration_required,
        }))
    }

    pub(super) const fn root_migration_required(&self) -> bool {
        self.root_migration_required
    }

    pub(super) fn complete_root_migration(&self, cache_root: &Path) -> std::io::Result<()> {
        let pending = NativeSafeDiskCachePath::from_path(
            cache_root.join(NATIVE_CACHE_MIGRATION_PENDING_FILE),
        );
        match pending.remove_file() {
            Ok(()) => pending.sync_parent_dir(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(super) fn index_key(&self) -> Arc<SecretBytes<32>> {
        Arc::clone(&self.index_key)
    }

    pub(super) fn confidential_index_identity(&self, combined_key: &str) -> String {
        native_cache_confidential_index_identity(&self.index_key, combined_key)
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
        let count = read_native_cache_nonce_counter(path)?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "native cache encryption nonce counter disappeared; rotate the cache key",
            )
        })?;
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
                "native local disk-cache encryption is approaching the AES-GCM random-nonce invocation limit; rotate the local cache encryption key"
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "legacy encrypted native cache object must be purged during v2 migration",
            ));
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

#[cfg(feature = "openbao-cache-encryption")]
fn native_openbao_index_key(
    provider: &NativeDiskCacheEncryptionProvider,
    cache_root: &Path,
    root_id: &[u8; NATIVE_CACHE_ROOT_ID_BYTES],
    root_migration_required: bool,
) -> std::io::Result<SecretBytes<32>> {
    load_or_create_openbao_index_key(provider, cache_root, root_id, root_migration_required)
}

#[cfg(not(feature = "openbao-cache-encryption"))]
fn native_openbao_index_key(
    _provider: &NativeDiskCacheEncryptionProvider,
    _cache_root: &Path,
    _root_id: &[u8; NATIVE_CACHE_ROOT_ID_BYTES],
    _root_migration_required: bool,
) -> std::io::Result<SecretBytes<32>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "native disk cache OpenBao Transit encryption is not enabled in this build",
    ))
}

fn derive_native_cache_root_key(
    master_key: &[u8],
    root_id: &[u8; NATIVE_CACHE_ROOT_ID_BYTES],
    info: &'static [u8],
) -> std::io::Result<SecretBytes<32>> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, root_id);
    let prk = salt.extract(master_key);
    let info = [info];
    let okm = prk
        .expand(&info, NativeCacheHkdfKeyLength)
        .map_err(|_| std::io::Error::other("derive native cache root key"))?;
    let mut derived = [0_u8; 32];
    okm.fill(&mut derived)
        .map_err(|_| std::io::Error::other("fill native cache root key"))?;
    Ok(SecretBytes::from_array(derived))
}

pub(super) fn native_cache_confidential_index_identity(
    index_key: &SecretBytes<32>,
    combined_key: &str,
) -> String {
    index_key.expose_secret(|index_key| {
        let key = hmac::Key::new(hmac::HMAC_SHA256, index_key);
        let tag = hmac::sign(&key, combined_key.as_bytes());
        let mut encoded = String::with_capacity(tag.as_ref().len() * 2);
        for byte in tag.as_ref() {
            use std::fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    })
}

#[cfg(feature = "openbao-cache-encryption")]
fn load_or_create_openbao_index_key(
    provider: &NativeDiskCacheEncryptionProvider,
    cache_root: &Path,
    root_id: &[u8; NATIVE_CACHE_ROOT_ID_BYTES],
    root_migration_required: bool,
) -> std::io::Result<SecretBytes<32>> {
    let NativeDiskCacheEncryptionProvider::OpenBaoTransit {
        address,
        mount,
        key_name,
        token,
    } = provider
    else {
        return Err(std::io::Error::other(
            "OpenBao index key requires the Transit provider",
        ));
    };
    let path = cache_root.join(NATIVE_CACHE_OPENBAO_INDEX_KEY_FILE);
    let mut aad = b"fluxheim/cache/index-key/openbao/v1\0".to_vec();
    aad.extend_from_slice(root_id);
    match read_native_cache_state_bounded(&path, 64 * 1024)? {
        Some(ciphertext) => {
            let ciphertext = std::str::from_utf8(&ciphertext).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "OpenBao cache index-key state is not UTF-8",
                )
            })?;
            let plaintext = token
                .try_with_secret(|token| {
                    openbao_transit_decrypt(address, mount, key_name, token, ciphertext, &aad)
                })
                .map_err(std::io::Error::other)??;
            let mut index_key = SecretBytes::zeroed();
            index_key.copy_from_slice(&plaintext).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "OpenBao cache index key has invalid length",
                )
            })?;
            Ok(index_key)
        }
        None if root_migration_required => {
            let mut random = [0_u8; 32];
            getrandom::fill(&mut random).map_err(|error| {
                std::io::Error::other(format!("generate OpenBao cache index key: {error}"))
            })?;
            let index_key = SecretBytes::from_array(random);
            let ciphertext = index_key
                .expose_secret(|index_key| {
                    token.try_with_secret(|token| {
                        openbao_transit_encrypt(address, mount, key_name, token, index_key, &aad)
                    })
                })
                .map_err(std::io::Error::other)??;
            write_native_cache_state_atomically(
                &path,
                ciphertext.as_bytes(),
                ".fluxheim-index-key",
            )?;
            Ok(index_key)
        }
        None => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "OpenBao cache index-key state is missing from an established root",
        )),
    }
}

#[cfg(feature = "openbao-cache-encryption")]
fn read_native_cache_state_bounded(
    path: &Path,
    max_bytes: u64,
) -> std::io::Result<Option<Vec<u8>>> {
    let file = match NativeSafeDiskCachePath::from_path(path.to_path_buf()).open_existing_file() {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native cache encryption state is oversized",
        ));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native cache encryption state is oversized",
        ));
    }
    Ok(Some(bytes))
}

fn load_or_create_native_cache_root_id(
    cache_root: &Path,
) -> std::io::Result<([u8; NATIVE_CACHE_ROOT_ID_BYTES], bool)> {
    let path = cache_root.join(NATIVE_CACHE_ROOT_ID_FILE);
    let lock = NativeSafeDiskCachePath::from_path(cache_root.join(NATIVE_CACHE_ROOT_ID_LOCK_FILE))
        .open_or_create_read_write_file()?;
    lock.lock_exclusive()?;
    match NativeSafeDiskCachePath::from_path(path.clone()).open_existing_file() {
        Ok(mut file) => {
            if file.metadata()?.len() != NATIVE_CACHE_ROOT_ID_BYTES as u64 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "native cache encryption root identity has invalid length",
                ));
            }
            let mut root_id = [0_u8; NATIVE_CACHE_ROOT_ID_BYTES];
            file.read_exact(&mut root_id)?;
            Ok((root_id, native_cache_migration_is_pending(cache_root)?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            mark_native_cache_migration_pending(cache_root)?;
            let mut root_id = [0_u8; NATIVE_CACHE_ROOT_ID_BYTES];
            getrandom::fill(&mut root_id).map_err(|error| {
                std::io::Error::other(format!("generate native cache root identity: {error}"))
            })?;
            write_native_cache_state_atomically(&path, &root_id, ".fluxheim-encryption-root")?;
            Ok((root_id, true))
        }
        Err(error) => Err(error),
    }
}

fn initialize_native_cache_local_key(
    cache_root: &Path,
    key_identity: &[u8; 32],
    path: &Path,
    root_migration_required: bool,
) -> std::io::Result<bool> {
    let marker_path = cache_root.join(NATIVE_CACHE_ACTIVE_KEY_FILE);
    let marker_lock =
        NativeSafeDiskCachePath::from_path(cache_root.join(NATIVE_CACHE_ACTIVE_KEY_LOCK_FILE))
            .open_or_create_read_write_file()?;
    marker_lock.lock_exclusive()?;
    let active_identity = read_native_cache_fixed_state::<32>(&marker_path)?;
    let key_changed = match active_identity {
        Some(active_identity) => active_identity != *key_identity,
        None if root_migration_required => true,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "native cache encryption active-key marker is missing from an established root",
            ));
        }
    };
    if key_changed {
        mark_native_cache_migration_pending(cache_root)?;
    }
    let lock_path = path.with_extension("counter.lock");
    let lock_file =
        NativeSafeDiskCachePath::from_path(lock_path).open_or_create_read_write_file()?;
    lock_file.lock_exclusive()?;
    match read_native_cache_nonce_counter(path)? {
        Some(_) => {}
        None if key_changed => write_native_cache_nonce_counter(path, 0)?,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "native cache encryption nonce counter is missing from an established root; rotate the cache key",
            ));
        }
    }
    if key_changed {
        write_native_cache_state_atomically(
            &marker_path,
            key_identity,
            ".fluxheim-encryption-key",
        )?;
    }
    Ok(key_changed)
}

fn native_cache_migration_is_pending(cache_root: &Path) -> std::io::Result<bool> {
    let path = cache_root.join(NATIVE_CACHE_MIGRATION_PENDING_FILE);
    match NativeSafeDiskCachePath::from_path(path).open_existing_file() {
        Ok(file) => {
            if !file.metadata()?.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "native cache encryption migration marker is not a regular file",
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn mark_native_cache_migration_pending(cache_root: &Path) -> std::io::Result<()> {
    let path = cache_root.join(NATIVE_CACHE_MIGRATION_PENDING_FILE);
    if native_cache_migration_is_pending(cache_root)? {
        return Ok(());
    }
    write_native_cache_state_atomically(&path, b"pending\n", ".fluxheim-encryption-migration")
}

fn read_native_cache_fixed_state<const N: usize>(path: &Path) -> std::io::Result<Option<[u8; N]>> {
    let mut file = match NativeSafeDiskCachePath::from_path(path.to_path_buf()).open_existing_file()
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() != N as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native cache encryption state has invalid length",
        ));
    }
    let mut state = [0_u8; N];
    file.read_exact(&mut state)?;
    Ok(Some(state))
}

fn read_native_cache_nonce_counter(path: &Path) -> std::io::Result<Option<u64>> {
    let mut file = match NativeSafeDiskCachePath::from_path(path.to_path_buf()).open_existing_file()
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
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
    encoded.trim().parse::<u64>().map(Some).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "native cache encryption nonce counter is invalid",
        )
    })
}

fn write_native_cache_nonce_counter(path: &Path, count: u64) -> std::io::Result<()> {
    write_native_cache_state_atomically(
        path,
        format!("{count}\n").as_bytes(),
        ".fluxheim-gcm-counter",
    )
}

fn write_native_cache_state_atomically(
    path: &Path,
    bytes: &[u8],
    temporary_prefix: &str,
) -> std::io::Result<()> {
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
            parent.join(format!("{temporary_prefix}-{suffix}.tmp")),
        );
        let result = (|| {
            let mut file = temporary.create_new_file()?;
            file.write_all(bytes)?;
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
    #[cfg(windows)]
    let mut file = fluxheim_config::fs_trust::open_confidential_file(path)?;
    #[cfg(not(windows))]
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

    fn local_config(key_file: PathBuf) -> CacheDiskEncryptionConfig {
        CacheDiskEncryptionConfig {
            enabled: true,
            key_id: Some("test-key".to_owned()),
            key_file: Some(key_file),
            ..Default::default()
        }
    }

    fn write_test_key(path: &Path, byte: u8) {
        let mut encoded = String::with_capacity(64);
        for _ in 0..32 {
            use std::fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        #[cfg(windows)]
        {
            use std::io::Write as _;

            let mut file =
                fluxheim_config::fs_trust::open_or_create_confidential_file(path).unwrap();
            file.set_len(0).unwrap();
            file.write_all(encoded.as_bytes()).unwrap();
            file.sync_all().unwrap();
        }
        #[cfg(not(windows))]
        std::fs::write(path, encoded).unwrap();
    }

    fn local_encryption(root: &Path) -> NativeDiskCacheEncryption {
        let key_bytes = [7_u8; 32];
        let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
        let key_identity: [u8; 32] = Sha256::digest(key_bytes).into();
        let key_id: Arc<str> = Arc::from("test-key");
        let counter_path = native_cache_nonce_counter_path(root, &key_identity);
        if read_native_cache_nonce_counter(&counter_path)
            .unwrap()
            .is_none()
        {
            write_native_cache_nonce_counter(&counter_path, 0).unwrap();
        }
        NativeDiskCacheEncryption {
            local_nonce_counter_path: Some(counter_path),
            key_id,
            provider: NativeDiskCacheEncryptionProvider::Local {
                key: Arc::new(LessSafeKey::new(unbound)),
            },
            index_key: Arc::new(SecretBytes::from_array([8_u8; 32])),
            root_migration_required: false,
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
        .open_or_create_read_write_file()
        .and_then(|file| file.set_len(0))
        .unwrap();

        assert!(encryption.reserve_local_nonce_invocation(10).is_err());
    }

    #[test]
    fn v1_envelope_is_rejected_after_root_migration() {
        let directory = tempfile::tempdir().unwrap();
        let encryption = local_encryption(directory.path());
        assert!(
            encryption
                .decrypt(NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1)
                .is_err()
        );
    }

    #[test]
    fn root_key_derivation_separates_data_and_index_keys() {
        let root_id = [3_u8; NATIVE_CACHE_ROOT_ID_BYTES];
        let data = derive_native_cache_root_key(&[7_u8; 32], &root_id, NATIVE_CACHE_DATA_KEY_INFO)
            .unwrap();
        let index =
            derive_native_cache_root_key(&[7_u8; 32], &root_id, NATIVE_CACHE_INDEX_KEY_INFO)
                .unwrap();

        let equal = data.expose_secret(|data| index.expose_secret(|index| data == index));
        assert!(!equal);
    }

    #[test]
    fn confidential_index_identity_is_not_an_unkeyed_cache_key_digest() {
        let directory = tempfile::tempdir().unwrap();
        let encryption = local_encryption(directory.path());
        let combined_key = "private.example/account?token=guessable";
        let digest = Sha256::digest(combined_key.as_bytes());
        let mut unkeyed = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(unkeyed, "{byte:02x}");
        }

        assert_ne!(
            encryption.confidential_index_identity(combined_key),
            unkeyed
        );
    }

    #[test]
    fn identical_master_keys_are_cryptographically_separated_by_cache_root() {
        let directory = tempfile::tempdir().unwrap();
        let key_file = directory.path().join("cache.key");
        let first_root = directory.path().join("first");
        let second_root = directory.path().join("second");
        std::fs::create_dir_all(&first_root).unwrap();
        std::fs::create_dir_all(&second_root).unwrap();
        write_test_key(&key_file, 0x42);
        let config = local_config(key_file);

        let first = NativeDiskCacheEncryption::from_config(&config, &first_root)
            .unwrap()
            .unwrap();
        let second = NativeDiskCacheEncryption::from_config(&config, &second_root)
            .unwrap()
            .unwrap();
        let combined_key = "private.example/account?id=42";
        let ciphertext = first.encrypt(combined_key, b"root-bound").unwrap();

        assert!(first.root_migration_required());
        assert!(second.root_migration_required());
        assert_ne!(
            first.confidential_index_identity(combined_key),
            second.confidential_index_identity(combined_key)
        );
        assert!(second.decrypt(&ciphertext).is_err());

        let interrupted = NativeDiskCacheEncryption::from_config(&config, &first_root)
            .unwrap()
            .unwrap();
        assert!(interrupted.root_migration_required());
        first.complete_root_migration(&first_root).unwrap();
        let restarted = NativeDiskCacheEncryption::from_config(&config, &first_root)
            .unwrap()
            .unwrap();
        assert!(!restarted.root_migration_required());
        assert_eq!(
            restarted.decrypt(&ciphertext).unwrap().as_slice(),
            b"root-bound"
        );
    }

    #[test]
    fn established_root_rejects_missing_nonce_counter() {
        let directory = tempfile::tempdir().unwrap();
        let key_file = directory.path().join("cache.key");
        let cache_root = directory.path().join("cache");
        std::fs::create_dir_all(&cache_root).unwrap();
        write_test_key(&key_file, 0x31);
        let config = local_config(key_file);
        let encryption = NativeDiskCacheEncryption::from_config(&config, &cache_root)
            .unwrap()
            .unwrap();
        let counter = encryption.local_nonce_counter_path.clone().unwrap();
        std::fs::remove_file(counter).unwrap();

        let error = NativeDiskCacheEncryption::from_config(&config, &cache_root).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(error.to_string().contains("nonce counter is missing"));
    }

    #[test]
    fn local_key_rotation_derives_new_root_key_and_requests_cache_migration() {
        let directory = tempfile::tempdir().unwrap();
        let key_file = directory.path().join("cache.key");
        let cache_root = directory.path().join("cache");
        std::fs::create_dir_all(&cache_root).unwrap();
        write_test_key(&key_file, 0x19);
        let config = local_config(key_file.clone());
        let first = NativeDiskCacheEncryption::from_config(&config, &cache_root)
            .unwrap()
            .unwrap();
        first.complete_root_migration(&cache_root).unwrap();
        let ciphertext = first.encrypt("cache-key", b"old key").unwrap();

        write_test_key(&key_file, 0x20);
        let rotated = NativeDiskCacheEncryption::from_config(&config, &cache_root)
            .unwrap()
            .unwrap();

        assert!(rotated.root_migration_required());
        assert!(rotated.decrypt(&ciphertext).is_err());
        assert_ne!(
            first.confidential_index_identity("cache-key"),
            rotated.confidential_index_identity("cache-key")
        );
    }
}

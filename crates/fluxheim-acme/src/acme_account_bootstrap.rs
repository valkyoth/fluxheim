use super::*;
use crate::acme_account_state::ACCOUNT_BOOTSTRAP_PENDING_FILE;
use rustls::pki_types::PrivatePkcs8KeyDer;
use sanitization::SecretVec;
use sanitization::ct::ConstantTimeEq as _;
use sha2::{Digest as _, Sha256};

const ACCOUNT_BOOTSTRAP_MAGIC: &[u8] = b"FLUXHEIM-ACME-ACCOUNT-KEY-V1\0";
const ACCOUNT_BOOTSTRAP_ISSUER_HASH_BYTES: usize = 32;
const MAX_ACCOUNT_BOOTSTRAP_BYTES: u64 = 4096;

pub(crate) enum AccountBootstrap {
    Existing(instant_acme::AccountCredentials),
    Pending(PendingAccountBootstrap),
}

pub(crate) struct PendingAccountBootstrap {
    directory: PathBuf,
    credentials_path: AcmeAccountCredentialsPath,
    pending_path: PathBuf,
    key_der: SecretVec,
    initial_key: Option<instant_acme::Key>,
    recovered: bool,
    _lock: AcmeMutationLock,
}

#[cfg(test)]
pub(crate) fn begin_account_bootstrap(
    storage: &Path,
    issuer_name: &str,
    issuer_directory: &str,
) -> Result<AccountBootstrap, AcmeAccountStoreError> {
    let credentials_path = account_credentials_path(storage, issuer_name);
    let directory = credentials_path
        .path
        .parent()
        .ok_or_else(|| AcmeAccountStoreError::UnsafePath {
            path: credentials_path.path.clone(),
            message: "credentials path has no parent directory".to_owned(),
        })?
        .to_path_buf();
    ensure_safe_account_directory(&directory)?;
    let mutation_lock = AcmeMutationLock::acquire(&directory)
        .map_err(|error| account_store_io_error(&directory.join(".fluxheim-acme.lock"), error))?;
    begin_account_bootstrap_locked(
        credentials_path,
        &directory,
        issuer_directory,
        mutation_lock,
    )
}

pub(crate) fn try_begin_account_bootstrap(
    storage: &Path,
    issuer_name: &str,
    issuer_directory: &str,
) -> Result<AccountStoreAttempt<AccountBootstrap>, AcmeAccountStoreError> {
    let credentials_path = account_credentials_path(storage, issuer_name);
    let directory = credentials_path
        .path
        .parent()
        .ok_or_else(|| AcmeAccountStoreError::UnsafePath {
            path: credentials_path.path.clone(),
            message: "credentials path has no parent directory".to_owned(),
        })?
        .to_path_buf();
    ensure_safe_account_directory(&directory)?;
    let Some(mutation_lock) = AcmeMutationLock::try_acquire(&directory)
        .map_err(|error| account_store_io_error(&directory.join(".fluxheim-acme.lock"), error))?
    else {
        return Ok(AccountStoreAttempt::Contended);
    };
    begin_account_bootstrap_locked(
        credentials_path,
        &directory,
        issuer_directory,
        mutation_lock,
    )
    .map(AccountStoreAttempt::Acquired)
}

fn begin_account_bootstrap_locked(
    credentials_path: AcmeAccountCredentialsPath,
    directory: &Path,
    issuer_directory: &str,
    mutation_lock: AcmeMutationLock,
) -> Result<AccountBootstrap, AcmeAccountStoreError> {
    let pending_path = directory.join(ACCOUNT_BOOTSTRAP_PENDING_FILE);
    let credentials = load_account_credentials_locked(&credentials_path.path, directory, true)?;
    let pending = read_pending_key(&pending_path, issuer_directory)?;

    if let Some(credentials) = credentials {
        if let Some(pending) = pending {
            let matches = pending.with_secret(|pending| {
                credentials.with_private_key(|key| {
                    pending
                        .ct_eq(key)
                        .declassify("ACME bootstrap key recovery result is public")
                })
            });
            if !matches {
                return Err(AcmeAccountStoreError::UnsafePath {
                    path: pending_path,
                    message: "pending bootstrap key does not match active account credentials"
                        .to_owned(),
                });
            }
            sanitize_and_remove_pending_key(directory, &pending_path)?;
        }
        return Ok(AccountBootstrap::Existing(credentials));
    }

    let (key_der, initial_key, recovered) = match pending {
        Some(key_der) => (key_der, None, true),
        None => {
            let (key, generated) = instant_acme::Key::generate_secret_pkcs8().map_err(|error| {
                AcmeAccountStoreError::UnsafePath {
                    path: pending_path.clone(),
                    message: format!("failed to generate pending account key: {error}"),
                }
            })?;
            let key_der = generated;
            write_pending_key(directory, &pending_path, issuer_directory, &key_der)?;
            (key_der, Some(key), false)
        }
    };

    Ok(AccountBootstrap::Pending(PendingAccountBootstrap {
        directory: directory.to_path_buf(),
        credentials_path,
        pending_path,
        key_der,
        initial_key,
        recovered,
        _lock: mutation_lock,
    }))
}

impl PendingAccountBootstrap {
    pub(crate) fn recovered(&self) -> bool {
        self.recovered
    }

    pub(crate) fn key_pair(
        &mut self,
    ) -> Result<(instant_acme::Key, SecretVec), AcmeAccountStoreError> {
        self.key_der.with_secret(|key_der| {
            let key = if let Some(key) = self.initial_key.take() {
                key
            } else {
                instant_acme::Key::from_pkcs8_der(PrivatePkcs8KeyDer::from(key_der)).map_err(
                    |_| AcmeAccountStoreError::UnsafePath {
                        path: self.pending_path.clone(),
                        message: "pending account key is not valid PKCS#8 P-256 material"
                            .to_owned(),
                    },
                )?
            };
            Ok((key, SecretVec::from_slice(key_der)))
        })
    }

    pub(crate) fn existing_key_pair(
        &mut self,
    ) -> Result<(instant_acme::Key, SecretVec), AcmeAccountStoreError> {
        self.key_pair()
    }

    pub(crate) fn promote(
        self,
        credentials: &instant_acme::AccountCredentials,
    ) -> Result<(), AcmeAccountStoreError> {
        let matches = self.key_der.with_secret(|pending| {
            credentials.with_private_key(|key| {
                pending
                    .ct_eq(key)
                    .declassify("ACME bootstrap credential key match result is public")
            })
        });
        if !matches {
            return Err(AcmeAccountStoreError::UnsafePath {
                path: self.credentials_path.path.clone(),
                message: "remote account credentials do not contain the pending key".to_owned(),
            });
        }
        store_account_credentials_locked(&self.credentials_path, &self.directory, credentials)?;
        sanitize_and_remove_pending_key(&self.directory, &self.pending_path)
    }

    #[cfg(test)]
    pub(crate) fn key_digest(&self) -> [u8; 32] {
        self.key_der.with_secret(|key| Sha256::digest(key).into())
    }

    #[cfg(test)]
    pub(crate) fn persist_credentials_before_cleanup(
        &self,
        credentials: &instant_acme::AccountCredentials,
    ) -> Result<(), AcmeAccountStoreError> {
        store_account_credentials_locked(&self.credentials_path, &self.directory, credentials)
            .map(drop)
    }
}

fn write_pending_key(
    directory: &Path,
    pending_path: &Path,
    issuer_directory: &str,
    key_der: &SecretVec,
) -> Result<(), AcmeAccountStoreError> {
    ensure_safe_account_destination(pending_path)?;
    let transaction =
        unique_transaction_id().map_err(|error| account_store_io_error(directory, error))?;
    let temporary = directory.join(format!(".credentials.bootstrap.{transaction}.tmp"));
    let issuer_hash = Sha256::digest(issuer_directory.as_bytes());
    let mut record = SecretVec::from_fn(
        ACCOUNT_BOOTSTRAP_MAGIC.len() + ACCOUNT_BOOTSTRAP_ISSUER_HASH_BYTES + key_der.len(),
        |_| 0,
    );
    record.with_secret_mut(|record| {
        let hash_start = ACCOUNT_BOOTSTRAP_MAGIC.len();
        let key_start = hash_start + ACCOUNT_BOOTSTRAP_ISSUER_HASH_BYTES;
        record[..hash_start].copy_from_slice(ACCOUNT_BOOTSTRAP_MAGIC);
        record[hash_start..key_start].copy_from_slice(&issuer_hash);
        key_der.with_secret(|key| record[key_start..].copy_from_slice(key));
    });
    let result = (|| {
        record.with_secret(|record| write_account_credentials_file(&temporary, record))?;
        fs::rename(&temporary, pending_path)
            .map_err(|error| account_store_io_error(pending_path, error))?;
        sync_account_directory(directory)
    })();
    if result.is_err()
        && let Err(error) = sanitize_and_remove_pending_key(directory, &temporary)
    {
        log::error!(
            target: "fluxheim::security",
            "failed to sanitize pending ACME account-key temporary file: {error}"
        );
    }
    result
}

fn read_pending_key(
    pending_path: &Path,
    issuer_directory: &str,
) -> Result<Option<SecretVec>, AcmeAccountStoreError> {
    let metadata = match fs::symlink_metadata(pending_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(account_store_io_error(pending_path, error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AcmeAccountStoreError::UnsafePath {
            path: pending_path.to_path_buf(),
            message: "pending account key is not a regular file".to_owned(),
        });
    }
    let header_len = ACCOUNT_BOOTSTRAP_MAGIC.len() + ACCOUNT_BOOTSTRAP_ISSUER_HASH_BYTES;
    if metadata.len() <= header_len as u64 || metadata.len() > MAX_ACCOUNT_BOOTSTRAP_BYTES {
        return Err(AcmeAccountStoreError::Oversized {
            path: pending_path.to_path_buf(),
            max_bytes: MAX_ACCOUNT_BOOTSTRAP_BYTES,
        });
    }
    let admitted =
        usize::try_from(metadata.len()).map_err(|_| AcmeAccountStoreError::Oversized {
            path: pending_path.to_path_buf(),
            max_bytes: MAX_ACCOUNT_BOOTSTRAP_BYTES,
        })?;
    let mut file = open_regular_account_credentials_file(pending_path)
        .map_err(|error| account_store_io_error(pending_path, error))?;
    let mut record = SecretVec::from_fn(admitted, |_| 0);
    record
        .with_secret_mut(|record| file.read_exact(record))
        .map_err(|error| account_store_io_error(pending_path, error))?;
    let mut growth_probe = [0_u8; 1];
    let grew = file
        .read(&mut growth_probe)
        .map_err(|error| account_store_io_error(pending_path, error))?
        != 0;
    sanitization::SecureSanitize::secure_sanitize(&mut growth_probe);
    if grew {
        return Err(AcmeAccountStoreError::Oversized {
            path: pending_path.to_path_buf(),
            max_bytes: MAX_ACCOUNT_BOOTSTRAP_BYTES,
        });
    }

    record
        .with_secret(|record| {
            let hash_start = ACCOUNT_BOOTSTRAP_MAGIC.len();
            let key_start = hash_start + ACCOUNT_BOOTSTRAP_ISSUER_HASH_BYTES;
            if record[..hash_start] != *ACCOUNT_BOOTSTRAP_MAGIC {
                return Err(AcmeAccountStoreError::UnsafePath {
                    path: pending_path.to_path_buf(),
                    message: "pending account key has an invalid format".to_owned(),
                });
            }
            let expected_hash = Sha256::digest(issuer_directory.as_bytes());
            let issuer_matches = record[hash_start..key_start]
                .ct_eq(&expected_hash)
                .declassify("ACME bootstrap issuer binding result is public");
            if !issuer_matches {
                return Err(AcmeAccountStoreError::UnsafePath {
                    path: pending_path.to_path_buf(),
                    message: "pending account key belongs to a different issuer directory"
                        .to_owned(),
                });
            }
            Ok(SecretVec::from_slice(&record[key_start..]))
        })
        .map(Some)
}

fn sanitize_and_remove_pending_key(
    directory: &Path,
    path: &Path,
) -> Result<(), AcmeAccountStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(account_store_io_error(path, error)),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_ACCOUNT_BOOTSTRAP_BYTES
    {
        return Err(AcmeAccountStoreError::UnsafePath {
            path: path.to_path_buf(),
            message: "pending account key cannot be safely sanitized".to_owned(),
        });
    }
    let mut options = fs::OpenOptions::new();
    options.write(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(super::UNIX_O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|error| account_store_io_error(path, error))?;
    let zeros = [0_u8; 512];
    let mut remaining = metadata.len();
    while remaining != 0 {
        let length = usize::try_from(remaining.min(zeros.len() as u64)).map_err(|_| {
            AcmeAccountStoreError::Oversized {
                path: path.to_path_buf(),
                max_bytes: MAX_ACCOUNT_BOOTSTRAP_BYTES,
            }
        })?;
        file.write_all(&zeros[..length])
            .map_err(|error| account_store_io_error(path, error))?;
        remaining -= length as u64;
    }
    file.sync_all()
        .map_err(|error| account_store_io_error(path, error))?;
    file.set_len(0)
        .map_err(|error| account_store_io_error(path, error))?;
    file.sync_all()
        .map_err(|error| account_store_io_error(path, error))?;
    drop(file);
    fs::remove_file(path).map_err(|error| account_store_io_error(path, error))?;
    sync_account_directory(directory)
}

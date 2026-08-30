use std::fs;
use std::io;
use std::io::Read;
use std::path::Path;

#[cfg(feature = "acme-client")]
use std::path::PathBuf;

use sanitization::SecretVec;

#[cfg(feature = "acme-client")]
#[path = "acme_account_bootstrap.rs"]
mod bootstrap;
#[path = "acme_account_store_fs.rs"]
mod fs_ops;
#[cfg(all(feature = "acme-client", test))]
pub(crate) use bootstrap::begin_account_bootstrap;
#[cfg(feature = "acme-client")]
pub(crate) use bootstrap::{
    AccountBootstrap, PendingAccountBootstrap, try_begin_account_bootstrap,
};
#[cfg(not(unix))]
use fs_ops::reject_existing_symlink_in_account_path;
use fs_ops::{
    account_store_io_error, open_regular_account_credentials_file, sync_account_directory,
    write_account_credentials_file,
};

#[cfg(target_os = "linux")]
use super::UNIX_O_NOFOLLOW;
use super::{
    AcmeAccountCredentialsPath, AcmeAccountStoreError, AcmeMutationLock,
    MAX_ACCOUNT_CREDENTIALS_BYTES, managed_certificate_segment, reject_pending_account_bootstrap,
    reject_pending_account_deactivation, reject_pending_account_mutation, unique_transaction_id,
};

const ACME_ACCOUNT_DIR: &str = "accounts";
const ACME_ACCOUNT_CREDENTIALS_FILE: &str = "credentials.json";

#[cfg(feature = "acme-client")]
pub(crate) enum AccountStoreAttempt<T> {
    Acquired(T),
    Contended,
}

#[cfg(feature = "acme-client")]
pub(crate) struct AccountDeactivationTransaction {
    directory: PathBuf,
    active: PathBuf,
    pending: PathBuf,
    _lock: AcmeMutationLock,
}

pub fn account_credentials_path(storage: &Path, issuer_name: &str) -> AcmeAccountCredentialsPath {
    AcmeAccountCredentialsPath {
        path: storage
            .join(ACME_ACCOUNT_DIR)
            .join(managed_certificate_segment(issuer_name))
            .join(ACME_ACCOUNT_CREDENTIALS_FILE),
    }
}

/// Loads persisted ACME account credentials.
///
/// # Blocking
///
/// Waits indefinitely for the issuer lifecycle lock. Async code should use
/// `load_account_credentials_async` instead.
pub fn load_account_credentials(
    storage: &Path,
    issuer_name: &str,
) -> Result<Option<instant_acme::AccountCredentials>, AcmeAccountStoreError> {
    let path = account_credentials_path(storage, issuer_name).path;
    let directory = path
        .parent()
        .ok_or_else(|| AcmeAccountStoreError::UnsafePath {
            path: path.clone(),
            message: "credentials path has no parent directory".to_owned(),
        })?;
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(AcmeAccountStoreError::UnsafePath {
                path: directory.to_path_buf(),
                message: "account directory is not a real directory".to_owned(),
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(account_store_io_error(directory, error)),
    }
    let _lock = AcmeMutationLock::acquire(directory)
        .map_err(|error| account_store_io_error(&directory.join(".fluxheim-acme.lock"), error))?;
    load_account_credentials_locked(&path, directory, false)
}

#[cfg(feature = "acme-client")]
pub(crate) fn try_load_account_credentials(
    storage: &Path,
    issuer_name: &str,
) -> Result<AccountStoreAttempt<Option<instant_acme::AccountCredentials>>, AcmeAccountStoreError> {
    let path = account_credentials_path(storage, issuer_name).path;
    let directory = path
        .parent()
        .ok_or_else(|| AcmeAccountStoreError::UnsafePath {
            path: path.clone(),
            message: "credentials path has no parent directory".to_owned(),
        })?;
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(AcmeAccountStoreError::UnsafePath {
                path: directory.to_path_buf(),
                message: "account directory is not a real directory".to_owned(),
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(AccountStoreAttempt::Acquired(None));
        }
        Err(error) => return Err(account_store_io_error(directory, error)),
    }
    let Some(_lock) = AcmeMutationLock::try_acquire(directory)
        .map_err(|error| account_store_io_error(&directory.join(".fluxheim-acme.lock"), error))?
    else {
        return Ok(AccountStoreAttempt::Contended);
    };
    load_account_credentials_locked(&path, directory, false).map(AccountStoreAttempt::Acquired)
}

fn load_account_credentials_locked(
    path: &Path,
    directory: &Path,
    allow_bootstrap_recovery: bool,
) -> Result<Option<instant_acme::AccountCredentials>, AcmeAccountStoreError> {
    reject_pending_account_deactivation(directory)?;
    if !allow_bootstrap_recovery {
        reject_pending_account_bootstrap(directory)?;
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(account_store_io_error(path, error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AcmeAccountStoreError::UnsafePath {
            path: path.to_path_buf(),
            message: "credentials path is not a real file".to_owned(),
        });
    }
    if metadata.len() > MAX_ACCOUNT_CREDENTIALS_BYTES {
        return Err(AcmeAccountStoreError::Oversized {
            path: path.to_path_buf(),
            max_bytes: MAX_ACCOUNT_CREDENTIALS_BYTES,
        });
    }

    let mut file = open_regular_account_credentials_file(path)
        .map_err(|error| account_store_io_error(path, error))?;
    let admitted =
        usize::try_from(metadata.len()).map_err(|_| AcmeAccountStoreError::Oversized {
            path: path.to_path_buf(),
            max_bytes: MAX_ACCOUNT_CREDENTIALS_BYTES,
        })?;
    let mut contents = SecretVec::from_fn(admitted, |_| 0);
    contents
        .with_secret_mut(|contents| file.read_exact(contents))
        .map_err(|error| account_store_io_error(path, error))?;
    let mut growth_probe = [0_u8; 1];
    let grew = file
        .read(&mut growth_probe)
        .map_err(|error| account_store_io_error(path, error))?
        != 0;
    sanitization::SecureSanitize::secure_sanitize(&mut growth_probe);
    if grew {
        return Err(AcmeAccountStoreError::Oversized {
            path: path.to_path_buf(),
            max_bytes: MAX_ACCOUNT_CREDENTIALS_BYTES,
        });
    }

    contents
        .with_secret(|contents| serde_json::from_slice(contents))
        .map(Some)
        .map_err(|error| AcmeAccountStoreError::Deserialize {
            path: path.to_path_buf(),
            message: error.to_string(),
        })
}

#[cfg(all(feature = "acme-client", test))]
pub(crate) fn begin_account_deactivation(
    storage: &Path,
    issuer_name: &str,
) -> Result<AccountDeactivationTransaction, AcmeAccountStoreError> {
    let active = account_credentials_path(storage, issuer_name).path;
    let directory = active
        .parent()
        .ok_or_else(|| AcmeAccountStoreError::UnsafePath {
            path: active.clone(),
            message: "credentials path has no parent directory".to_owned(),
        })?
        .to_path_buf();
    ensure_safe_account_directory(&directory)?;
    let lock = AcmeMutationLock::acquire(&directory)
        .map_err(|error| account_store_io_error(&directory.join(".fluxheim-acme.lock"), error))?;
    begin_account_deactivation_locked(active, &directory, lock)
}

#[cfg(feature = "acme-client")]
pub(crate) fn try_begin_account_deactivation(
    storage: &Path,
    issuer_name: &str,
) -> Result<AccountStoreAttempt<AccountDeactivationTransaction>, AcmeAccountStoreError> {
    let active = account_credentials_path(storage, issuer_name).path;
    let directory = active
        .parent()
        .ok_or_else(|| AcmeAccountStoreError::UnsafePath {
            path: active.clone(),
            message: "credentials path has no parent directory".to_owned(),
        })?
        .to_path_buf();
    ensure_safe_account_directory(&directory)?;
    let Some(lock) = AcmeMutationLock::try_acquire(&directory)
        .map_err(|error| account_store_io_error(&directory.join(".fluxheim-acme.lock"), error))?
    else {
        return Ok(AccountStoreAttempt::Contended);
    };
    begin_account_deactivation_locked(active, &directory, lock).map(AccountStoreAttempt::Acquired)
}

#[cfg(feature = "acme-client")]
fn begin_account_deactivation_locked(
    active: PathBuf,
    directory: &Path,
    lock: AcmeMutationLock,
) -> Result<AccountDeactivationTransaction, AcmeAccountStoreError> {
    ensure_safe_account_destination(&active)?;
    let pending = directory.join(super::acme_account_state::ACCOUNT_DEACTIVATION_PENDING_FILE);
    match fs::symlink_metadata(&pending) {
        Ok(_) => {
            return Err(AcmeAccountStoreError::UnsafePath {
                path: pending,
                message: "account deactivation transaction already exists".to_owned(),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(account_store_io_error(&pending, error)),
    }
    fs::rename(&active, &pending).map_err(|error| account_store_io_error(&active, error))?;
    sync_account_directory(directory)?;
    Ok(AccountDeactivationTransaction {
        directory: directory.to_path_buf(),
        active,
        pending,
        _lock: lock,
    })
}

#[cfg(feature = "acme-client")]
impl AccountDeactivationTransaction {
    #[cfg(test)]
    pub(crate) fn abandon(self) {}

    pub(crate) fn rollback(self) -> Result<(), AcmeAccountStoreError> {
        fs::rename(&self.pending, &self.active)
            .map_err(|error| account_store_io_error(&self.active, error))?;
        sync_account_directory(&self.directory)
    }

    pub(crate) fn complete(self) -> Result<(), AcmeAccountStoreError> {
        fs::remove_file(&self.pending)
            .map_err(|error| account_store_io_error(&self.pending, error))?;
        sync_account_directory(&self.directory)
    }
}

/// Persists ACME account credentials atomically.
///
/// # Blocking
///
/// Waits indefinitely for the issuer lifecycle lock. Async code should use
/// `store_account_credentials_async` instead.
pub fn store_account_credentials(
    storage: &Path,
    issuer_name: &str,
    credentials: &instant_acme::AccountCredentials,
) -> Result<AcmeAccountCredentialsPath, AcmeAccountStoreError> {
    let credentials_path = account_credentials_path(storage, issuer_name);
    let directory =
        credentials_path
            .path
            .parent()
            .ok_or_else(|| AcmeAccountStoreError::UnsafePath {
                path: credentials_path.path.clone(),
                message: "credentials path has no parent directory".to_owned(),
            })?;
    ensure_safe_account_directory(directory)?;
    let _mutation_lock = AcmeMutationLock::acquire(directory)
        .map_err(|error| account_store_io_error(&directory.join(".fluxheim-acme.lock"), error))?;
    reject_pending_account_mutation(directory)?;
    store_account_credentials_locked(&credentials_path, directory, credentials)
}

pub(crate) fn store_account_credentials_locked(
    credentials_path: &AcmeAccountCredentialsPath,
    directory: &Path,
    credentials: &instant_acme::AccountCredentials,
) -> Result<AcmeAccountCredentialsPath, AcmeAccountStoreError> {
    ensure_safe_account_destination(&credentials_path.path)?;

    let contents = SecretVec::from_vec(serde_json::to_vec(credentials).map_err(|error| {
        AcmeAccountStoreError::Serialize {
            message: error.to_string(),
        }
    })?);
    if contents.len() as u64 > MAX_ACCOUNT_CREDENTIALS_BYTES {
        return Err(AcmeAccountStoreError::Oversized {
            path: credentials_path.path.clone(),
            max_bytes: MAX_ACCOUNT_CREDENTIALS_BYTES,
        });
    }

    let transaction =
        unique_transaction_id().map_err(|error| account_store_io_error(directory, error))?;
    let tmp_path = directory.join(format!(".credentials.{transaction}.tmp"));
    let result = (|| {
        contents.with_secret(|contents| write_account_credentials_file(&tmp_path, contents))?;
        fs::rename(&tmp_path, &credentials_path.path)
            .map_err(|error| account_store_io_error(&credentials_path.path, error))?;
        sync_account_directory(directory)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    result?;
    Ok(credentials_path.clone())
}

/// Removes persisted ACME account credentials.
///
/// # Blocking
///
/// Waits indefinitely for the issuer lifecycle lock. Async code should use
/// `remove_account_credentials_async` instead.
pub fn remove_account_credentials(
    storage: &Path,
    issuer_name: &str,
) -> Result<bool, AcmeAccountStoreError> {
    let credentials_path = account_credentials_path(storage, issuer_name);
    let directory =
        credentials_path
            .path
            .parent()
            .ok_or_else(|| AcmeAccountStoreError::UnsafePath {
                path: credentials_path.path.clone(),
                message: "credentials path has no parent directory".to_owned(),
            })?;
    ensure_safe_account_directory(directory)?;
    let _mutation_lock = AcmeMutationLock::acquire(directory)
        .map_err(|error| account_store_io_error(&directory.join(".fluxheim-acme.lock"), error))?;
    reject_pending_account_mutation(directory)?;
    ensure_safe_account_destination(&credentials_path.path)?;
    match fs::remove_file(&credentials_path.path) {
        Ok(()) => {
            sync_account_directory(directory)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(account_store_io_error(&credentials_path.path, error)),
    }
}

pub(crate) fn ensure_safe_account_directory(directory: &Path) -> Result<(), AcmeAccountStoreError> {
    #[cfg(unix)]
    {
        crate::acme_directory::create_private_directory_all(directory)
            .map_err(|error| account_store_io_error(directory, error))?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        reject_existing_symlink_in_account_path(directory)?;
        #[cfg(windows)]
        if directory.exists()
            && fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(
                directory,
            )
            .map_err(|error| account_store_io_error(directory, error))?
        {
            return Err(AcmeAccountStoreError::UnsafePath {
                path: directory.to_path_buf(),
                message: "existing account directory has an untrusted ACL".to_owned(),
            });
        }
        fs::create_dir_all(directory).map_err(|error| account_store_io_error(directory, error))?;
        reject_existing_symlink_in_account_path(directory)?;
        let metadata = fs::symlink_metadata(directory)
            .map_err(|error| account_store_io_error(directory, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AcmeAccountStoreError::UnsafePath {
                path: directory.to_path_buf(),
                message: "path is not a real directory".to_owned(),
            });
        }

        #[cfg(windows)]
        fluxheim_config::fs_trust::harden_private_directory(directory)
            .map_err(|error| account_store_io_error(directory, error))?;

        Ok(())
    }
}

pub(crate) fn ensure_safe_account_destination(path: &Path) -> Result<(), AcmeAccountStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(AcmeAccountStoreError::UnsafePath {
                path: path.to_path_buf(),
                message: "credentials path is not a real file".to_owned(),
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(account_store_io_error(path, error)),
    }
}

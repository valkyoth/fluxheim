use super::backup::{cleanup_backup, restore_backup};
use super::fs_ops::{
    CertificateDirectoryFd, ManagedCertificateOwner, rename_certificate_file, sync_directory,
    write_new_file,
};
use super::*;
use serde::{Deserialize, Serialize};

const INSTALL_JOURNAL_FILE: &str = ".install.transaction";
const MAX_INSTALL_JOURNAL_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum CertificateInstallPhase {
    Prepared,
    Publishing,
    Published,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CertificateInstallJournal {
    transaction: String,
    cert_existed: bool,
    key_existed: bool,
    phase: CertificateInstallPhase,
}

pub(super) fn begin_certificate_install(
    directory: &Path,
    transaction: &str,
    cert_existed: bool,
    key_existed: bool,
    owner: ManagedCertificateOwner,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    write_journal(
        directory,
        &CertificateInstallJournal {
            transaction: transaction.to_owned(),
            cert_existed,
            key_existed,
            phase: CertificateInstallPhase::Prepared,
        },
        owner,
        directory_fd,
    )
}

pub(super) fn update_certificate_install_phase(
    directory: &Path,
    transaction: &str,
    cert_existed: bool,
    key_existed: bool,
    phase: CertificateInstallPhase,
    owner: ManagedCertificateOwner,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    write_journal(
        directory,
        &CertificateInstallJournal {
            transaction: transaction.to_owned(),
            cert_existed,
            key_existed,
            phase,
        },
        owner,
        directory_fd,
    )
}

pub(super) fn complete_certificate_install(
    directory: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    cleanup_backup(
        directory,
        &directory.join(INSTALL_JOURNAL_FILE),
        directory_fd,
    )?;
    sync_directory(directory, directory_fd)
}

pub(super) fn recover_interrupted_install(
    directory: &Path,
    paths: &AcmeCertificatePaths,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    let journal_path = directory.join(INSTALL_JOURNAL_FILE);
    let Some(journal) = read_journal(&journal_path)? else {
        return Ok(());
    };
    validate_transaction_id(&journal.transaction, &journal_path)?;
    let cert_tmp = directory.join(format!(".fullchain.{}.tmp", journal.transaction));
    let key_tmp = directory.join(format!(".privkey.{}.tmp", journal.transaction));
    let cert_backup = directory.join(".fullchain.pem.previous");
    let key_backup = directory.join(".privkey.pem.previous");

    match journal.phase {
        CertificateInstallPhase::Prepared => {
            cleanup_backup(directory, &cert_backup, directory_fd)?;
            cleanup_backup(directory, &key_backup, directory_fd)?;
        }
        CertificateInstallPhase::Publishing => {
            restore_original(
                directory,
                &cert_backup,
                &paths.cert_path,
                journal.cert_existed,
                directory_fd,
            )?;
            restore_original(
                directory,
                &key_backup,
                &paths.key_path,
                journal.key_existed,
                directory_fd,
            )?;
        }
        CertificateInstallPhase::Published => {
            cleanup_backup(directory, &cert_backup, directory_fd)?;
            cleanup_backup(directory, &key_backup, directory_fd)?;
        }
    }
    cleanup_backup(directory, &cert_tmp, directory_fd)?;
    cleanup_backup(directory, &key_tmp, directory_fd)?;
    cleanup_backup(directory, &journal_path, directory_fd)?;
    sync_directory(directory, directory_fd)
}

fn restore_original(
    directory: &Path,
    backup: &Path,
    destination: &Path,
    existed: bool,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    if existed {
        require_regular_backup(backup)?;
        restore_backup(directory, backup, destination, directory_fd).map_err(|error| {
            AcmeCertificateInstallError::Io {
                path: destination.to_path_buf(),
                error,
            }
        })
    } else {
        cleanup_backup(directory, destination, directory_fd)
    }
}

fn require_regular_backup(path: &Path) -> Result<(), AcmeCertificateInstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| AcmeCertificateInstallError::Io {
        path: path.to_path_buf(),
        error,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: "ACME transaction backup is not a regular file".to_owned(),
        });
    }
    Ok(())
}

fn write_journal(
    directory: &Path,
    journal: &CertificateInstallJournal,
    owner: ManagedCertificateOwner,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    validate_transaction_id(&journal.transaction, directory)?;
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| AcmeCertificateInstallError::Transaction(error.to_string()))?;
    if bytes.len() as u64 > MAX_INSTALL_JOURNAL_BYTES {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: directory.join(INSTALL_JOURNAL_FILE),
            message: "ACME install journal is too large".to_owned(),
        });
    }
    let temporary = directory.join(format!(".install.{}.journal.tmp", journal.transaction));
    let journal_path = directory.join(INSTALL_JOURNAL_FILE);
    cleanup_backup(directory, &temporary, directory_fd)?;
    write_new_file(directory, &temporary, &bytes, 0o600, owner, directory_fd)?;
    rename_certificate_file(directory, &temporary, &journal_path, directory_fd)?;
    sync_directory(directory, directory_fd)
}

fn read_journal(
    path: &Path,
) -> Result<Option<CertificateInstallJournal>, AcmeCertificateInstallError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(AcmeCertificateInstallError::Io {
                path: path.to_path_buf(),
                error,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: "ACME install journal is not a regular file".to_owned(),
        });
    }
    let file = match open_journal_no_follow(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(AcmeCertificateInstallError::Io {
                path: path.to_path_buf(),
                error,
            });
        }
    };
    let mut bytes = Vec::new();
    file.take(MAX_INSTALL_JOURNAL_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        })?;
    if bytes.len() as u64 > MAX_INSTALL_JOURNAL_BYTES {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: "ACME install journal is too large".to_owned(),
        });
    }
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: format!("ACME install journal is invalid: {error}"),
        }
    })
}

fn open_journal_no_follow(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(super::super::UNIX_O_NOFOLLOW);
    }
    options.open(path)
}

fn validate_transaction_id(
    transaction: &str,
    path: &Path,
) -> Result<(), AcmeCertificateInstallError> {
    if transaction.len() == 32 && transaction.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: "ACME install journal transaction ID is invalid".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::backup::backup_existing_file;
    use super::super::fs_ops::{
        ensure_safe_directory, managed_certificate_ownership, open_safe_certificate_directory,
    };
    use super::*;

    #[test]
    fn publishing_recovery_restores_the_complete_previous_pair() {
        let storage = fluxheim_common::test_support::unique_temp_path("acme-install-recovery");
        let paths = managed_certificate_paths(&storage, "example");
        let directory = paths.cert_path.parent().unwrap().to_path_buf();
        let ownership = managed_certificate_ownership(&storage).unwrap();
        let owner = ownership.file_owner();
        ensure_safe_directory(&directory, &ownership).unwrap();
        fs::write(&paths.cert_path, b"old certificate").unwrap();
        fs::write(&paths.key_path, b"old key").unwrap();
        #[cfg(unix)]
        let directory_fd = open_safe_certificate_directory(&directory).unwrap();
        #[cfg(unix)]
        let directory_fd = Some(&directory_fd);
        #[cfg(not(unix))]
        let directory_fd = None;
        let cert_backup = directory.join(".fullchain.pem.previous");
        let key_backup = directory.join(".privkey.pem.previous");
        assert!(
            backup_existing_file(&directory, &paths.cert_path, &cert_backup, directory_fd).unwrap()
        );
        assert!(
            backup_existing_file(&directory, &paths.key_path, &key_backup, directory_fd).unwrap()
        );
        let transaction = "0123456789abcdef0123456789abcdef";
        update_certificate_install_phase(
            &directory,
            transaction,
            true,
            true,
            CertificateInstallPhase::Publishing,
            owner,
            directory_fd,
        )
        .unwrap();
        let replacement = directory.join("replacement.tmp");
        fs::write(&replacement, b"new certificate").unwrap();
        fs::rename(replacement, &paths.cert_path).unwrap();

        recover_interrupted_install(&directory, &paths, directory_fd).unwrap();

        assert_eq!(fs::read(&paths.cert_path).unwrap(), b"old certificate");
        assert_eq!(fs::read(&paths.key_path).unwrap(), b"old key");
        assert!(!directory.join(INSTALL_JOURNAL_FILE).exists());
    }
}

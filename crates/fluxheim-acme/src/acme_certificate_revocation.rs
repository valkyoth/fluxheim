use super::backup::cleanup_backup;
#[cfg(all(feature = "acme-client", unix))]
use super::fs_ops::open_safe_certificate_directory;
use super::fs_ops::{CertificateDirectoryFd, rename_certificate_file, sync_directory};
#[cfg(feature = "acme-client")]
use super::fs_ops::{
    ManagedCertificateOwner, certificate_directory, managed_certificate_owner, write_new_file,
};
#[cfg(feature = "acme-client")]
use super::revocation_fs::read_bounded_regular_file;
use super::revocation_fs::{
    certificate_file_exists_regular, ensure_certificate_slot_absent, ensure_existing_regular_file,
    revocation_file_names_valid,
};
use super::*;
use serde::{Deserialize, Serialize};

#[cfg(all(test, feature = "acme-client"))]
#[path = "acme_certificate_revocation_test_support.rs"]
mod test_support;
#[cfg(all(test, feature = "acme-client"))]
pub(crate) use test_support::simulate_prepared_revocation_crash;
const REVOCATION_JOURNAL_FILE: &str = ".revocation.transaction";
const MAX_REVOCATION_JOURNAL_BYTES: u64 = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum RevocationPhase {
    Prepared,
    PairQuarantined,
    RemotePending,
    RemoteConfirmed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RevocationJournal {
    transaction: String,
    certificate_name: String,
    private_key_name: String,
    phase: RevocationPhase,
}

#[cfg(feature = "acme-client")]
pub(crate) struct ManagedCertificateQuarantine {
    paths: AcmeCertificatePaths,
    directory: PathBuf,
    journal: RevocationJournal,
    _mutation_lock: AcmeMutationLock,
    #[cfg(unix)]
    directory_fd: CertificateDirectoryFd,
    active: bool,
}

#[cfg(feature = "acme-client")]
pub(crate) fn begin_managed_certificate_quarantine(
    paths: &AcmeCertificatePaths,
) -> Result<ManagedCertificateQuarantine, AcmeCertificateInstallError> {
    let directory = certificate_directory(paths)?;
    let owner = managed_certificate_owner(&directory)?;
    let mutation_lock =
        AcmeMutationLock::acquire(&directory).map_err(|error| AcmeCertificateInstallError::Io {
            path: directory.join(".fluxheim-acme.lock"),
            error,
        })?;
    #[cfg(unix)]
    let directory_fd = open_safe_certificate_directory(&directory)?;
    #[cfg(unix)]
    let directory_fd_ref = Some(&directory_fd);
    #[cfg(not(unix))]
    let directory_fd_ref: Option<&CertificateDirectoryFd> = None;
    recover_interrupted_revocation(&directory, paths, directory_fd_ref)?;
    ensure_existing_regular_file(&directory, &paths.cert_path, directory_fd_ref)?;
    ensure_existing_regular_file(&directory, &paths.key_path, directory_fd_ref)?;

    let transaction = unique_transaction_id().map_err(|error| AcmeCertificateInstallError::Io {
        path: directory.clone(),
        error,
    })?;
    let mut journal = RevocationJournal {
        certificate_name: format!(".revoked-{transaction}-fullchain.pem"),
        private_key_name: format!(".revoked-{transaction}-privkey.pem"),
        transaction,
        phase: RevocationPhase::Prepared,
    };
    write_revocation_journal(&directory, &journal, owner, directory_fd_ref)?;
    let certificate = directory.join(&journal.certificate_name);
    let private_key = directory.join(&journal.private_key_name);
    rename_certificate_file(&directory, &paths.cert_path, &certificate, directory_fd_ref)?;
    if let Err(error) =
        rename_certificate_file(&directory, &paths.key_path, &private_key, directory_fd_ref)
    {
        if rename_certificate_file(&directory, &certificate, &paths.cert_path, directory_fd_ref)
            .is_ok()
        {
            let _ = clear_revocation_journal(&directory, directory_fd_ref);
        }
        return Err(error);
    }
    sync_directory(&directory, directory_fd_ref)?;
    journal.phase = RevocationPhase::PairQuarantined;
    write_revocation_journal(&directory, &journal, owner, directory_fd_ref)?;

    Ok(ManagedCertificateQuarantine {
        paths: paths.clone(),
        directory,
        journal,
        _mutation_lock: mutation_lock,
        #[cfg(unix)]
        directory_fd,
        active: true,
    })
}

#[cfg(feature = "acme-client")]
impl ManagedCertificateQuarantine {
    pub(crate) fn read_quarantined_certificate(
        &self,
    ) -> Result<Vec<u8>, AcmeCertificateInstallError> {
        read_bounded_regular_file(
            &self.directory,
            &self.directory.join(&self.journal.certificate_name),
            self.directory_fd(),
            MAX_CERTIFICATE_CHAIN_BYTES,
        )
    }

    pub(crate) fn mark_remote_pending(&mut self) -> Result<(), AcmeCertificateInstallError> {
        self.update_phase(RevocationPhase::RemotePending)
    }

    pub(crate) fn mark_remote_confirmed(&mut self) -> Result<(), AcmeCertificateInstallError> {
        self.update_phase(RevocationPhase::RemoteConfirmed)
    }

    pub(crate) fn complete(mut self) -> Result<(PathBuf, PathBuf), AcmeCertificateInstallError> {
        if self.journal.phase != RevocationPhase::RemoteConfirmed {
            return Err(AcmeCertificateInstallError::Transaction(
                "ACME revocation cannot complete before remote confirmation".to_owned(),
            ));
        }
        clear_revocation_journal(&self.directory, self.directory_fd())?;
        self.active = false;
        Ok(self.quarantine_paths())
    }

    #[cfg(test)]
    pub(crate) fn rollback(mut self) -> Result<(), AcmeCertificateInstallError> {
        if !matches!(
            self.journal.phase,
            RevocationPhase::Prepared | RevocationPhase::PairQuarantined
        ) {
            return Err(AcmeCertificateInstallError::Transaction(
                "ACME revocation cannot automatically restore after remote contact".to_owned(),
            ));
        }
        restore_quarantined_pair(
            &self.directory,
            &self.paths,
            &self.journal,
            self.directory_fd(),
        )?;
        clear_revocation_journal(&self.directory, self.directory_fd())?;
        self.active = false;
        Ok(())
    }

    fn update_phase(&mut self, phase: RevocationPhase) -> Result<(), AcmeCertificateInstallError> {
        let mut updated = self.journal.clone();
        updated.phase = phase;
        write_revocation_journal(
            &self.directory,
            &updated,
            managed_certificate_owner(&self.directory)?,
            self.directory_fd(),
        )?;
        self.journal = updated;
        Ok(())
    }

    pub(crate) fn quarantine_paths(&self) -> (PathBuf, PathBuf) {
        (
            self.directory.join(&self.journal.certificate_name),
            self.directory.join(&self.journal.private_key_name),
        )
    }

    #[cfg(test)]
    pub(crate) fn abandon(mut self) -> (PathBuf, PathBuf) {
        self.active = false;
        self.quarantine_paths()
    }

    #[cfg(unix)]
    fn directory_fd(&self) -> Option<&CertificateDirectoryFd> {
        Some(&self.directory_fd)
    }

    #[cfg(not(unix))]
    fn directory_fd(&self) -> Option<&CertificateDirectoryFd> {
        None
    }
}

#[cfg(feature = "acme-client")]
impl Drop for ManagedCertificateQuarantine {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if matches!(
            self.journal.phase,
            RevocationPhase::Prepared | RevocationPhase::PairQuarantined
        ) {
            if let Err(error) = restore_quarantined_pair(
                &self.directory,
                &self.paths,
                &self.journal,
                self.directory_fd(),
            )
            .and_then(|()| clear_revocation_journal(&self.directory, self.directory_fd()))
            {
                log::error!(
                    target: "fluxheim::security",
                    "failed to restore pre-remote ACME revocation transaction at {}: {error}",
                    self.directory.display()
                );
            }
        } else {
            log::error!(
                target: "fluxheim::security",
                "ACME revocation outcome is pending or confirmed at {}; certificate remains quarantined",
                self.directory.display()
            );
        }
    }
}

pub(super) fn recover_interrupted_revocation(
    directory: &Path,
    paths: &AcmeCertificatePaths,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    let Some(journal) = read_revocation_journal(directory, directory_fd)? else {
        return Ok(());
    };
    validate_revocation_journal(directory, &journal)?;
    match journal.phase {
        RevocationPhase::Prepared | RevocationPhase::PairQuarantined => {
            restore_quarantined_pair(directory, paths, &journal, directory_fd)?;
            clear_revocation_journal(directory, directory_fd)
        }
        RevocationPhase::RemotePending => {
            ensure_quarantined_pair(directory, paths, &journal, directory_fd)?;
            Err(AcmeCertificateInstallError::UnsafePath {
                path: directory.join(REVOCATION_JOURNAL_FILE),
                message: format!(
                    "ACME revocation outcome is ambiguous; certificate remains quarantined as {} and {}; operator resolution is required",
                    journal.certificate_name, journal.private_key_name
                ),
            })
        }
        RevocationPhase::RemoteConfirmed => {
            ensure_quarantined_pair(directory, paths, &journal, directory_fd)?;
            log::error!(
                target: "fluxheim::security",
                "recovered confirmed ACME revocation; replacement certificate is required"
            );
            clear_revocation_journal(directory, directory_fd)
        }
    }
}

fn ensure_quarantined_pair(
    directory: &Path,
    paths: &AcmeCertificatePaths,
    journal: &RevocationJournal,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    ensure_certificate_slot_absent(directory, &paths.cert_path, directory_fd)?;
    ensure_certificate_slot_absent(directory, &paths.key_path, directory_fd)?;
    ensure_existing_regular_file(
        directory,
        &directory.join(&journal.certificate_name),
        directory_fd,
    )?;
    ensure_existing_regular_file(
        directory,
        &directory.join(&journal.private_key_name),
        directory_fd,
    )
}

fn restore_quarantined_pair(
    directory: &Path,
    paths: &AcmeCertificatePaths,
    journal: &RevocationJournal,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    restore_quarantined_file(
        directory,
        &directory.join(&journal.certificate_name),
        &paths.cert_path,
        directory_fd,
    )?;
    restore_quarantined_file(
        directory,
        &directory.join(&journal.private_key_name),
        &paths.key_path,
        directory_fd,
    )?;
    ensure_existing_regular_file(directory, &paths.cert_path, directory_fd)?;
    ensure_existing_regular_file(directory, &paths.key_path, directory_fd)?;
    sync_directory(directory, directory_fd)
}

fn restore_quarantined_file(
    directory: &Path,
    quarantine: &Path,
    active: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    let active_exists = certificate_file_exists_regular(directory, active, directory_fd)?;
    let quarantine_exists = certificate_file_exists_regular(directory, quarantine, directory_fd)?;
    match (active_exists, quarantine_exists) {
        (true, false) => Ok(()),
        (false, true) => {
            ensure_certificate_slot_absent(directory, active, directory_fd)?;
            rename_certificate_file(directory, quarantine, active, directory_fd)
        }
        (true, true) => Err(AcmeCertificateInstallError::UnsafePath {
            path: active.to_path_buf(),
            message: "both active and quarantined ACME certificate files exist".to_owned(),
        }),
        (false, false) => Err(AcmeCertificateInstallError::UnsafePath {
            path: active.to_path_buf(),
            message: "both active and quarantined ACME certificate files are missing".to_owned(),
        }),
    }
}

#[cfg(feature = "acme-client")]
fn write_revocation_journal(
    directory: &Path,
    journal: &RevocationJournal,
    owner: ManagedCertificateOwner,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    validate_revocation_journal(directory, journal)?;
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| AcmeCertificateInstallError::Transaction(error.to_string()))?;
    if bytes.len() as u64 > MAX_REVOCATION_JOURNAL_BYTES {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: directory.join(REVOCATION_JOURNAL_FILE),
            message: "ACME revocation journal is too large".to_owned(),
        });
    }
    let temporary = directory.join(format!(".revocation.{}.tmp", journal.transaction));
    let journal_path = directory.join(REVOCATION_JOURNAL_FILE);
    cleanup_backup(directory, &temporary, directory_fd)?;
    write_new_file(directory, &temporary, &bytes, 0o600, owner, directory_fd)?;
    rename_certificate_file(directory, &temporary, &journal_path, directory_fd)?;
    sync_directory(directory, directory_fd)
}

fn read_revocation_journal(
    directory: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<Option<RevocationJournal>, AcmeCertificateInstallError> {
    #[cfg(not(unix))]
    let _ = directory_fd;
    let path = directory.join(REVOCATION_JOURNAL_FILE);
    #[cfg(unix)]
    let file = {
        let directory_fd = directory_fd.ok_or_else(|| AcmeCertificateInstallError::UnsafePath {
            path: directory.to_path_buf(),
            message: "managed certificate directory fd is unavailable".to_owned(),
        })?;
        match rustix::fs::openat(
            directory_fd,
            REVOCATION_JOURNAL_FILE,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(file) => Some(fs::File::from(file)),
            Err(error) if error == rustix::io::Errno::NOENT => None,
            Err(error) => {
                return Err(AcmeCertificateInstallError::Io {
                    path,
                    error: error.into(),
                });
            }
        }
    };
    #[cfg(not(unix))]
    let file = match fs::symlink_metadata(&path) {
        Ok(metadata)
            if super::fs_ops::certificate_metadata_is_link(&metadata) || !metadata.is_file() =>
        {
            return Err(AcmeCertificateInstallError::UnsafePath {
                path,
                message: "ACME revocation journal is not a regular file".to_owned(),
            });
        }
        Ok(_) => match fs::OpenOptions::new().read(true).open(&path) {
            Ok(file) => Some(file),
            Err(error) => return Err(AcmeCertificateInstallError::Io { path, error }),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(AcmeCertificateInstallError::Io { path, error }),
    };
    let Some(file) = file else {
        return Ok(None);
    };
    let metadata = file
        .metadata()
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.clone(),
            error,
        })?;
    if !metadata.is_file() || metadata.len() > MAX_REVOCATION_JOURNAL_BYTES {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path,
            message: "ACME revocation journal is not a bounded regular file".to_owned(),
        });
    }
    let mut bytes = Vec::new();
    file.take(MAX_REVOCATION_JOURNAL_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.clone(),
            error,
        })?;
    if bytes.len() as u64 > MAX_REVOCATION_JOURNAL_BYTES {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path,
            message: "ACME revocation journal exceeds its byte limit".to_owned(),
        });
    }
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        AcmeCertificateInstallError::UnsafePath {
            path,
            message: format!("ACME revocation journal is invalid: {error}"),
        }
    })
}

fn clear_revocation_journal(
    directory: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    cleanup_backup(
        directory,
        &directory.join(REVOCATION_JOURNAL_FILE),
        directory_fd,
    )?;
    sync_directory(directory, directory_fd)
}

fn validate_revocation_journal(
    directory: &Path,
    journal: &RevocationJournal,
) -> Result<(), AcmeCertificateInstallError> {
    if revocation_file_names_valid(
        &journal.transaction,
        &journal.certificate_name,
        &journal.private_key_name,
    ) {
        Ok(())
    } else {
        Err(AcmeCertificateInstallError::UnsafePath {
            path: directory.join(REVOCATION_JOURNAL_FILE),
            message: "ACME revocation journal contains invalid file names".to_owned(),
        })
    }
}

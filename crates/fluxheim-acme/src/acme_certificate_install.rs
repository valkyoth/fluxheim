use super::*;

#[path = "acme_certificate_install_backup.rs"]
mod backup;
#[path = "acme_certificate_install_fs.rs"]
pub(crate) mod fs_ops;
#[path = "acme_certificate_install_recovery.rs"]
mod recovery;

use backup::{backup_existing_file, cleanup_backup};
#[cfg(any(not(unix), feature = "acme-client"))]
use fs_ops::CertificateDirectoryFd;
pub(crate) use fs_ops::{
    ManagedCertificateOwner, managed_certificate_owner, reject_existing_symlink_in_path,
};
use fs_ops::{
    certificate_directory, ensure_safe_destination, ensure_safe_directory,
    open_safe_certificate_directory, rename_certificate_file, write_new_file,
};
#[cfg(feature = "acme-client")]
use fs_ops::{ensure_certificate_slot_absent, ensure_existing_regular_file, sync_directory};
use recovery::{
    CertificateInstallPhase, begin_certificate_install, complete_certificate_install,
    recover_interrupted_install, update_certificate_install_phase,
};

pub fn install_managed_certificate(
    storage: &Path,
    vhost_name: &str,
    fullchain_pem: &[u8],
    private_key_pem: &[u8],
    expected_domains: &[String],
) -> Result<AcmeCertificatePaths, AcmeCertificateInstallError> {
    validate_issued_material(fullchain_pem, private_key_pem, expected_domains)?;

    let paths = managed_certificate_paths(storage, vhost_name);
    let owner = managed_certificate_owner(storage)?;
    install_certificate_files(&paths, fullchain_pem, private_key_pem, owner)?;
    Ok(paths)
}

pub fn recover_managed_certificate_transaction(
    storage: &Path,
    vhost_name: &str,
) -> Result<(), AcmeCertificateInstallError> {
    let paths = managed_certificate_paths(storage, vhost_name);
    let owner = managed_certificate_owner(storage)?;
    let directory = certificate_directory(&paths)?;
    ensure_safe_directory(&directory, owner)?;
    let _mutation_lock =
        AcmeMutationLock::acquire(&directory).map_err(|error| AcmeCertificateInstallError::Io {
            path: directory.join(".fluxheim-acme.lock"),
            error,
        })?;
    #[cfg(unix)]
    let directory_fd = open_safe_certificate_directory(&directory)?;
    #[cfg(unix)]
    let directory_fd = Some(&directory_fd);
    #[cfg(not(unix))]
    let directory_fd: Option<&CertificateDirectoryFd> = None;
    recover_interrupted_install(&directory, &paths, directory_fd)
}

#[cfg(feature = "acme-client")]
pub(crate) struct ManagedCertificateQuarantine {
    paths: AcmeCertificatePaths,
    directory: PathBuf,
    quarantined_certificate: PathBuf,
    quarantined_private_key: PathBuf,
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
    ensure_existing_regular_file(&directory, &paths.cert_path, directory_fd_ref)?;
    ensure_existing_regular_file(&directory, &paths.key_path, directory_fd_ref)?;
    let transaction = unique_transaction_id().map_err(|error| AcmeCertificateInstallError::Io {
        path: directory.clone(),
        error,
    })?;
    let quarantined_certificate = directory.join(format!(".revoked-{transaction}-fullchain.pem"));
    let quarantined_private_key = directory.join(format!(".revoked-{transaction}-privkey.pem"));
    rename_certificate_file(
        &directory,
        &paths.cert_path,
        &quarantined_certificate,
        directory_fd_ref,
    )?;
    if let Err(error) = rename_certificate_file(
        &directory,
        &paths.key_path,
        &quarantined_private_key,
        directory_fd_ref,
    ) {
        if let Err(rollback) = rename_certificate_file(
            &directory,
            &quarantined_certificate,
            &paths.cert_path,
            directory_fd_ref,
        ) {
            log::error!(
                target: "fluxheim::security",
                "ACME revocation quarantine rollback failed at {}: {rollback}",
                paths.cert_path.display()
            );
        }
        return Err(error);
    }
    sync_directory(&directory, directory_fd_ref)?;
    Ok(ManagedCertificateQuarantine {
        paths: paths.clone(),
        directory,
        quarantined_certificate,
        quarantined_private_key,
        _mutation_lock: mutation_lock,
        #[cfg(unix)]
        directory_fd,
        active: true,
    })
}

#[cfg(feature = "acme-client")]
impl ManagedCertificateQuarantine {
    pub(crate) fn complete(mut self) -> (PathBuf, PathBuf) {
        self.active = false;
        (
            self.quarantined_certificate.clone(),
            self.quarantined_private_key.clone(),
        )
    }

    pub(crate) fn rollback(mut self) -> Result<(), AcmeCertificateInstallError> {
        self.restore()?;
        self.active = false;
        Ok(())
    }

    fn restore(&mut self) -> Result<(), AcmeCertificateInstallError> {
        let directory_fd = self.directory_fd();
        ensure_certificate_slot_absent(&self.directory, &self.paths.cert_path, directory_fd)?;
        ensure_certificate_slot_absent(&self.directory, &self.paths.key_path, directory_fd)?;
        rename_certificate_file(
            &self.directory,
            &self.quarantined_certificate,
            &self.paths.cert_path,
            directory_fd,
        )?;
        if let Err(error) = rename_certificate_file(
            &self.directory,
            &self.quarantined_private_key,
            &self.paths.key_path,
            directory_fd,
        ) {
            let _ = rename_certificate_file(
                &self.directory,
                &self.paths.cert_path,
                &self.quarantined_certificate,
                directory_fd,
            );
            return Err(error);
        }
        sync_directory(&self.directory, directory_fd)
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
        if self.active
            && let Err(error) = self.restore()
        {
            log::error!(
                target: "fluxheim::security",
                "failed to restore ACME certificate quarantine at {}: {error}",
                self.directory.display()
            );
        }
    }
}

pub(super) fn install_certificate_files(
    paths: &AcmeCertificatePaths,
    fullchain_pem: &[u8],
    private_key_pem: &[u8],
    owner: ManagedCertificateOwner,
) -> Result<(), AcmeCertificateInstallError> {
    let directory = certificate_directory(paths)?;
    ensure_safe_directory(&directory, owner)?;
    let _mutation_lock =
        AcmeMutationLock::acquire(&directory).map_err(|error| AcmeCertificateInstallError::Io {
            path: directory.join(".fluxheim-acme.lock"),
            error,
        })?;
    #[cfg(unix)]
    let directory_fd = open_safe_certificate_directory(&directory)?;
    #[cfg(unix)]
    let directory_fd = Some(&directory_fd);
    #[cfg(not(unix))]
    let directory_fd: Option<&CertificateDirectoryFd> = None;
    recover_interrupted_install(&directory, paths, directory_fd)?;

    let transaction = unique_transaction_id().map_err(|error| AcmeCertificateInstallError::Io {
        path: directory.clone(),
        error,
    })?;
    let cert_tmp = directory.join(format!(".fullchain.{transaction}.tmp"));
    let key_tmp = directory.join(format!(".privkey.{transaction}.tmp"));
    let cert_backup = directory.join(".fullchain.pem.previous");
    let key_backup = directory.join(".privkey.pem.previous");
    let mut journal_started = false;

    let result = (|| {
        write_new_file(
            &directory,
            &cert_tmp,
            fullchain_pem,
            0o644,
            owner,
            directory_fd,
        )?;
        write_new_file(
            &directory,
            &key_tmp,
            private_key_pem,
            0o600,
            owner,
            directory_fd,
        )?;
        ensure_safe_destination(&paths.cert_path)?;
        ensure_safe_destination(&paths.key_path)?;
        begin_certificate_install(&directory, &transaction, false, false, owner, directory_fd)?;
        journal_started = true;
        let cert_backed_up =
            backup_existing_file(&directory, &paths.cert_path, &cert_backup, directory_fd)?;
        let key_backed_up =
            backup_existing_file(&directory, &paths.key_path, &key_backup, directory_fd)?;
        update_certificate_install_phase(
            &directory,
            &transaction,
            cert_backed_up,
            key_backed_up,
            CertificateInstallPhase::Publishing,
            owner,
            directory_fd,
        )?;
        rename_certificate_file(&directory, &cert_tmp, &paths.cert_path, directory_fd)?;
        rename_certificate_file(&directory, &key_tmp, &paths.key_path, directory_fd)?;
        update_certificate_install_phase(
            &directory,
            &transaction,
            cert_backed_up,
            key_backed_up,
            CertificateInstallPhase::Published,
            owner,
            directory_fd,
        )?;
        cleanup_backup(&directory, &cert_backup, directory_fd)?;
        cleanup_backup(&directory, &key_backup, directory_fd)?;
        complete_certificate_install(&directory, directory_fd)?;
        Ok(())
    })();

    if result.is_err() {
        let recovery = if journal_started {
            recover_interrupted_install(&directory, paths, directory_fd)
        } else {
            cleanup_backup(&directory, &cert_tmp, directory_fd)
                .and_then(|()| cleanup_backup(&directory, &key_tmp, directory_fd))
        };
        if let Err(error) = recovery {
            log_acme_certificate_recovery_error(
                "recovering interrupted certificate transaction",
                &directory,
                &error,
            );
        }
    }

    result
}

fn log_acme_certificate_recovery_error(action: &str, path: &Path, error: &dyn fmt::Display) {
    log::error!(
        target: "fluxheim::security",
        "ACME certificate install recovery failed while {action} at {}: {error}",
        path.display()
    );
}

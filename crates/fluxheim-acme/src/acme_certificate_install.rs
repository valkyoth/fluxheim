use super::*;

#[path = "acme_certificate_install_backup.rs"]
mod backup;
#[path = "acme_certificate_install_fs.rs"]
pub(crate) mod fs_ops;
#[path = "acme_certificate_install_recovery.rs"]
mod recovery;
#[path = "acme_certificate_revocation.rs"]
mod revocation;
#[path = "acme_certificate_revocation_fs.rs"]
mod revocation_fs;

use backup::{backup_existing_file, cleanup_backup};
#[cfg(not(unix))]
use fs_ops::CertificateDirectoryFd;
#[cfg(not(unix))]
pub(crate) use fs_ops::reject_existing_symlink_in_path;
use fs_ops::{
    ManagedCertificateOwnership, certificate_directory, ensure_safe_destination,
    ensure_safe_directory, managed_certificate_ownership, open_safe_certificate_directory,
    rename_certificate_file, write_new_file,
};
use recovery::{
    CertificateInstallPhase, begin_certificate_install, complete_certificate_install,
    recover_interrupted_install, update_certificate_install_phase,
};
#[cfg(feature = "acme-client")]
pub(crate) use revocation::begin_managed_certificate_quarantine;
use revocation::recover_interrupted_revocation;
#[cfg(all(feature = "acme-client", test))]
pub(crate) use revocation::simulate_prepared_revocation_crash;
#[cfg(all(feature = "acme-client", test))]
pub(crate) use revocation_fs::revocation_file_names_valid;

pub fn install_managed_certificate(
    storage: &Path,
    vhost_name: &str,
    fullchain_pem: &[u8],
    private_key_pem: &[u8],
    expected_domains: &[String],
) -> Result<AcmeCertificatePaths, AcmeCertificateInstallError> {
    validate_issued_material(fullchain_pem, private_key_pem, expected_domains)?;

    let paths = managed_certificate_paths(storage, vhost_name);
    let ownership = managed_certificate_ownership(storage)?;
    install_certificate_files(&paths, fullchain_pem, private_key_pem, ownership)?;
    Ok(paths)
}

pub fn recover_managed_certificate_transaction(
    storage: &Path,
    vhost_name: &str,
) -> Result<(), AcmeCertificateInstallError> {
    let paths = managed_certificate_paths(storage, vhost_name);
    let ownership = managed_certificate_ownership(storage)?;
    let directory = certificate_directory(&paths)?;
    ensure_safe_directory(&directory, &ownership)?;
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
    recover_interrupted_revocation(&directory, &paths, directory_fd)?;
    recover_interrupted_install(&directory, &paths, directory_fd)
}

pub(super) fn install_certificate_files(
    paths: &AcmeCertificatePaths,
    fullchain_pem: &[u8],
    private_key_pem: &[u8],
    ownership: ManagedCertificateOwnership,
) -> Result<(), AcmeCertificateInstallError> {
    let directory = certificate_directory(paths)?;
    ensure_safe_directory(&directory, &ownership)?;
    let owner = ownership.file_owner();
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
    recover_interrupted_revocation(&directory, paths, directory_fd)?;
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

fn log_acme_certificate_recovery_error(_action: &str, _path: &Path, _error: &dyn fmt::Display) {
    log::error!(
        target: "fluxheim::security",
        "ACME certificate install recovery failed; operator intervention may be required"
    );
}

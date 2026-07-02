use super::*;

#[path = "acme_certificate_install_backup.rs"]
mod backup;
#[path = "acme_certificate_install_fs.rs"]
pub(crate) mod fs_ops;

use backup::{backup_existing_file, cleanup_backup, restore_backup};
#[cfg(not(unix))]
use fs_ops::CertificateDirectoryFd;
pub(crate) use fs_ops::{
    ManagedCertificateOwner, managed_certificate_owner, reject_existing_symlink_in_path,
};
use fs_ops::{
    certificate_directory, ensure_safe_destination, ensure_safe_directory,
    open_safe_certificate_directory, rename_certificate_file, sync_directory, write_new_file,
};

pub fn install_managed_certificate(
    storage: &Path,
    vhost_name: &str,
    fullchain_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<AcmeCertificatePaths, AcmeCertificateInstallError> {
    validate_certificate_pem(fullchain_pem)?;
    validate_private_key_pem(private_key_pem)?;

    let paths = managed_certificate_paths(storage, vhost_name);
    let owner = managed_certificate_owner(storage)?;
    install_certificate_files(&paths, fullchain_pem, private_key_pem, owner)?;
    Ok(paths)
}

pub(super) fn install_certificate_files(
    paths: &AcmeCertificatePaths,
    fullchain_pem: &[u8],
    private_key_pem: &[u8],
    owner: ManagedCertificateOwner,
) -> Result<(), AcmeCertificateInstallError> {
    let directory = certificate_directory(paths)?;
    ensure_safe_directory(&directory, owner)?;
    #[cfg(unix)]
    let directory_fd = open_safe_certificate_directory(&directory)?;
    #[cfg(unix)]
    let directory_fd = Some(&directory_fd);
    #[cfg(not(unix))]
    let directory_fd: Option<&CertificateDirectoryFd> = None;

    let cert_tmp = directory.join(".fullchain.pem.tmp");
    let key_tmp = directory.join(".privkey.pem.tmp");
    let cert_backup = directory.join(".fullchain.pem.previous");
    let key_backup = directory.join(".privkey.pem.previous");
    let mut cert_backed_up = false;
    let mut key_backed_up = false;

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
        cert_backed_up =
            backup_existing_file(&directory, &paths.cert_path, &cert_backup, directory_fd)?;
        key_backed_up =
            backup_existing_file(&directory, &paths.key_path, &key_backup, directory_fd)?;
        rename_certificate_file(&directory, &cert_tmp, &paths.cert_path, directory_fd)?;
        if let Err(error) =
            rename_certificate_file(&directory, &key_tmp, &paths.key_path, directory_fd)
        {
            if cert_backed_up
                && let Err(restore_error) =
                    restore_backup(&directory, &cert_backup, &paths.cert_path, directory_fd)
            {
                log_acme_certificate_recovery_error(
                    "restoring previous certificate after private-key install failure",
                    &paths.cert_path,
                    &restore_error,
                );
            }
            return Err(error);
        }
        cleanup_backup(&directory, &cert_backup, directory_fd)?;
        cleanup_backup(&directory, &key_backup, directory_fd)?;
        sync_directory(&directory, directory_fd)?;
        Ok(())
    })();

    if result.is_err() {
        if let Err(error) = cleanup_backup(&directory, &cert_tmp, directory_fd) {
            log_acme_certificate_recovery_error(
                "removing temporary certificate file",
                &cert_tmp,
                &error,
            );
        }
        if let Err(error) = cleanup_backup(&directory, &key_tmp, directory_fd) {
            log_acme_certificate_recovery_error(
                "removing temporary private-key file",
                &key_tmp,
                &error,
            );
        }
        if cert_backed_up
            && let Err(error) =
                restore_backup(&directory, &cert_backup, &paths.cert_path, directory_fd)
        {
            log_acme_certificate_recovery_error(
                "restoring previous certificate",
                &paths.cert_path,
                &error,
            );
        }
        if key_backed_up
            && let Err(error) =
                restore_backup(&directory, &key_backup, &paths.key_path, directory_fd)
        {
            log_acme_certificate_recovery_error(
                "restoring previous private key",
                &paths.key_path,
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

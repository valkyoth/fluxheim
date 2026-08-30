use super::*;

pub(crate) fn simulate_prepared_revocation_crash(
    paths: &AcmeCertificatePaths,
) -> Result<PathBuf, AcmeCertificateInstallError> {
    let directory = certificate_directory(paths)?;
    let owner = managed_certificate_owner(&directory)?;
    let _lock =
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
    let transaction = unique_transaction_id().map_err(|error| AcmeCertificateInstallError::Io {
        path: directory.clone(),
        error,
    })?;
    let journal = RevocationJournal {
        certificate_name: format!(".revoked-{transaction}-fullchain.pem"),
        private_key_name: format!(".revoked-{transaction}-privkey.pem"),
        transaction,
        phase: RevocationPhase::Prepared,
    };
    write_revocation_journal(&directory, &journal, owner, directory_fd)?;
    let quarantine = directory.join(&journal.certificate_name);
    rename_certificate_file(&directory, &paths.cert_path, &quarantine, directory_fd)?;
    sync_directory(&directory, directory_fd)?;
    Ok(quarantine)
}

use super::super::backup::backup_existing_file;
#[cfg(unix)]
use super::super::fs_ops::open_safe_certificate_directory;
use super::super::fs_ops::{ensure_safe_directory, managed_certificate_ownership};
use super::*;

#[test]
fn interrupted_publishing_recovery_cannot_resume_after_consuming_a_backup() {
    // Exercise the crash boundary after one or both actual restore operations,
    // before the unchanged Publishing journal is cleared. No CA is contacted.
    for restored_key in [false, true] {
        let storage = fluxheim_common::test_support::unique_temp_path("acme-recovery-retry");
        let paths = managed_certificate_paths(&storage, "example");
        let directory = paths.cert_path.parent().unwrap().to_path_buf();
        let ownership = managed_certificate_ownership(&storage).unwrap();
        let owner = ownership.file_owner();
        ensure_safe_directory(&directory, &ownership).unwrap();
        #[cfg(unix)]
        let directory_fd = open_safe_certificate_directory(&directory).unwrap();
        #[cfg(unix)]
        let directory_fd = Some(&directory_fd);
        #[cfg(not(unix))]
        let directory_fd = None;

        fs::write(&paths.cert_path, b"old certificate").unwrap();
        fs::write(&paths.key_path, b"old key").unwrap();
        let cert_backup = directory.join(".fullchain.pem.previous");
        let key_backup = directory.join(".privkey.pem.previous");
        assert!(
            backup_existing_file(&directory, &paths.cert_path, &cert_backup, directory_fd).unwrap()
        );
        assert!(
            backup_existing_file(&directory, &paths.key_path, &key_backup, directory_fd).unwrap()
        );
        update_certificate_install_phase(
            &directory,
            "0123456789abcdef0123456789abcdef",
            true,
            true,
            CertificateInstallPhase::Publishing,
            owner,
            directory_fd,
        )
        .unwrap();
        // Unlink active names before writing: backup hard links must retain old bytes.
        fs::remove_file(&paths.cert_path).unwrap();
        fs::remove_file(&paths.key_path).unwrap();
        fs::write(&paths.cert_path, b"new certificate").unwrap();
        fs::write(&paths.key_path, b"new key").unwrap();
        restore_original(
            &directory,
            &cert_backup,
            &paths.cert_path,
            true,
            directory_fd,
        )
        .unwrap();
        if restored_key {
            restore_original(&directory, &key_backup, &paths.key_path, true, directory_fd).unwrap();
        }

        // documented contract: recovery consumes the backup, but its journal does not
        // record that progress. Retrying now fails even with recoverable bytes.
        let error = recover_interrupted_install(&directory, &paths, directory_fd).unwrap_err();
        assert!(
            matches!(error, AcmeCertificateInstallError::Io { path, error }
            if path == cert_backup && error.kind() == io::ErrorKind::NotFound)
        );
        assert_eq!(fs::read(&paths.cert_path).unwrap(), b"old certificate");
        assert_eq!(
            fs::read(&paths.key_path).unwrap(),
            if restored_key { b"old key" } else { b"new key" }
        );
        assert!(directory.join(INSTALL_JOURNAL_FILE).exists());
        if !restored_key {
            assert_eq!(fs::read(&key_backup).unwrap(), b"old key");
        }
        fs::remove_dir_all(storage).unwrap();
    }
}

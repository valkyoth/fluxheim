use super::super::backup::backup_existing_file;
#[cfg(unix)]
use super::super::fs_ops::open_safe_certificate_directory;
use super::super::fs_ops::{ensure_safe_directory, managed_certificate_ownership};
use super::*;

#[test]
fn restart_after_each_install_step_selects_only_a_complete_generation() {
    let domains = vec!["site.example".into()];
    let pair = || {
        let p = rcgen::generate_simple_self_signed(domains.clone()).unwrap();
        (p.cert.pem(), p.signing_key.serialize_pem())
    };
    let old = pair();
    let new = pair();
    let txn = "0123456789abcdef0123456789abcdef";
    for existed in [false, true] {
        for stop in 0..=13 {
            let storage = fluxheim_common::test_support::unique_temp_path("acme-install-steps");
            let paths = managed_certificate_paths(&storage, "example");
            let dir = paths.cert_path.parent().unwrap();
            let ownership = managed_certificate_ownership(&storage).unwrap();
            ensure_safe_directory(dir, &ownership).unwrap();
            let owner = ownership.file_owner();
            #[cfg(unix)]
            let fd = open_safe_certificate_directory(dir).unwrap();
            #[cfg(unix)]
            let fd = Some(&fd);
            #[cfg(not(unix))]
            let fd = None;
            let ct = dir.join(format!(".fullchain.{txn}.tmp"));
            let kt = dir.join(format!(".privkey.{txn}.tmp"));
            let cb = dir.join(".fullchain.pem.previous");
            let kb = dir.join(".privkey.pem.previous");
            if existed {
                fs::write(&paths.cert_path, &old.0).unwrap();
                fs::write(&paths.key_path, &old.1).unwrap();
            }
            for step in 1..=stop {
                match step {
                    1 => begin_certificate_install(dir, txn, false, false, owner, fd).unwrap(),
                    2 => write_new_file(dir, &ct, new.0.as_bytes(), 0o644, owner, fd).unwrap(),
                    3 => write_new_file(dir, &kt, new.1.as_bytes(), 0o600, owner, fd).unwrap(),
                    4 => assert_eq!(
                        backup_existing_file(dir, &paths.cert_path, &cb, fd).unwrap(),
                        existed
                    ),
                    5 => assert_eq!(
                        backup_existing_file(dir, &paths.key_path, &kb, fd).unwrap(),
                        existed
                    ),
                    6 | 10 => sync_directory(dir, fd).unwrap(),
                    7 => update_certificate_install_phase(
                        dir,
                        txn,
                        existed,
                        existed,
                        CertificateInstallPhase::Publishing,
                        owner,
                        fd,
                    )
                    .unwrap(),
                    8 => rename_certificate_file(dir, &ct, &paths.cert_path, fd).unwrap(),
                    9 => rename_certificate_file(dir, &kt, &paths.key_path, fd).unwrap(),
                    11 => update_certificate_install_phase(
                        dir,
                        txn,
                        existed,
                        existed,
                        CertificateInstallPhase::Published,
                        owner,
                        fd,
                    )
                    .unwrap(),
                    12 => cleanup_backup(dir, &cb, fd).unwrap(),
                    _ => cleanup_backup(dir, &kb, fd).unwrap(),
                }
            }
            for _ in 0..2 {
                recover_managed_certificate_transaction(&storage, "example").unwrap();
                if stop >= 11 || existed {
                    let expected = if stop >= 11 { &new } else { &old };
                    let cert = fs::read(&paths.cert_path).unwrap();
                    let key = fs::read(&paths.key_path).unwrap();
                    validate_issued_material(&cert, &key, &domains).unwrap();
                    assert_eq!(cert, expected.0.as_bytes());
                    assert_eq!(key, expected.1.as_bytes());
                } else {
                    assert!(!paths.cert_path.exists() && !paths.key_path.exists());
                }
            }
            fs::remove_dir_all(storage).unwrap();
        }
    }
}

#[test]
fn recovery_checks_both_identities_before_modifying_either_active_file() {
    for phase in [
        CertificateInstallPhase::Publishing,
        CertificateInstallPhase::Published,
        CertificateInstallPhase::RolledBack,
    ] {
        for missing in [true, false] {
            let storage =
                fluxheim_common::test_support::unique_temp_path("acme-recovery-integrity");
            let paths = managed_certificate_paths(&storage, "example");
            let dir = paths.cert_path.parent().unwrap();
            let ownership = managed_certificate_ownership(&storage).unwrap();
            ensure_safe_directory(dir, &ownership).unwrap();
            #[cfg(unix)]
            let fd = open_safe_certificate_directory(dir).unwrap();
            #[cfg(unix)]
            let directory_fd = Some(&fd);
            #[cfg(not(unix))]
            let directory_fd = None;
            let owner = ownership.file_owner();
            let previous = dir.join(".privkey.pem.previous");
            fs::write(dir.join(".fullchain.pem.previous"), b"certificate backup").unwrap();
            fs::write(&previous, b"key backup").unwrap();
            fs::write(&paths.cert_path, b"active certificate").unwrap();
            fs::write(&paths.key_path, b"active key").unwrap();
            update_certificate_install_phase(
                dir,
                "0123456789abcdef0123456789abcdef",
                true,
                true,
                phase,
                owner,
                directory_fd,
            )
            .unwrap();
            let target = if phase == CertificateInstallPhase::Publishing {
                &previous
            } else {
                &paths.key_path
            };
            if missing {
                fs::remove_file(target).unwrap();
            } else {
                fs::write(target, b"replaced").unwrap();
            }
            for _ in 0..2 {
                assert!(recover_interrupted_install(dir, &paths, owner, directory_fd).is_err());
                assert_eq!(fs::read(&paths.cert_path).unwrap(), b"active certificate");
                assert!(dir.join(INSTALL_JOURNAL_FILE).is_file());
                assert!(dir.join(".fullchain.pem.previous").is_file());
            }
            fs::remove_dir_all(storage).unwrap();
        }
    }
}

#[test]
fn publishing_recovery_replays_both_restores_without_consuming_backups() {
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

        let old = rcgen::generate_simple_self_signed(vec!["site.example".into()]).unwrap();
        let new = rcgen::generate_simple_self_signed(vec!["site.example".into()]).unwrap();
        let old_cert = old.cert.pem();
        let old_key = old.signing_key.serialize_pem();
        fs::write(&paths.cert_path, &old_cert).unwrap();
        fs::write(&paths.key_path, &old_key).unwrap();
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
        fs::write(&paths.cert_path, new.cert.pem()).unwrap();
        fs::write(&paths.key_path, new.signing_key.serialize_pem()).unwrap();
        restore_original(
            &directory,
            &cert_backup,
            &directory.join(".fullchain.0123456789abcdef0123456789abcdef.tmp"),
            &paths.cert_path,
            true,
            directory_fd,
        )
        .unwrap();
        if restored_key {
            restore_original(
                &directory,
                &key_backup,
                &directory.join(".privkey.0123456789abcdef0123456789abcdef.tmp"),
                &paths.key_path,
                true,
                directory_fd,
            )
            .unwrap();
        }

        for _ in 0..2 {
            recover_interrupted_install(&directory, &paths, owner, directory_fd).unwrap();
            let cert = fs::read(&paths.cert_path).unwrap();
            let key = fs::read(&paths.key_path).unwrap();
            assert_eq!(cert, old_cert.as_bytes());
            assert_eq!(key, old_key.as_bytes());
            validate_issued_material(&cert, &key, &["site.example".into()]).unwrap();
        }
        assert!(!directory.join(INSTALL_JOURNAL_FILE).exists());
        fs::remove_dir_all(storage).unwrap();
    }
}

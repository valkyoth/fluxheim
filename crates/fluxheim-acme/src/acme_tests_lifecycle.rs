use super::*;

#[cfg(feature = "acme-client")]
#[test]
fn tls_alpn_install_and_cleanup_never_leave_a_partial_pair() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-tls-alpn-race");
    let store = AcmeTlsAlpn01ChallengeStore::new(&storage);
    let (certificate, key) = tls_alpn_01_certificate("example.test", &[42_u8; 32]).unwrap();
    let key = std::sync::Arc::new(key);

    for _ in 0..32 {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let install_store = store.clone();
        let install_barrier = barrier.clone();
        let certificate = certificate.clone();
        let key = key.clone();
        let installer = std::thread::spawn(move || {
            install_barrier.wait();
            key.with_secret(|private_key| {
                install_store.install_challenge_certificate(
                    "example.test",
                    &certificate,
                    private_key,
                )
            })
        });
        let cleanup_store = store.clone();
        let cleanup_barrier = barrier.clone();
        let cleaner = std::thread::spawn(move || {
            cleanup_barrier.wait();
            cleanup_store.remove_challenge_certificate("example.test")
        });
        barrier.wait();
        installer.join().unwrap().unwrap();
        cleaner.join().unwrap().unwrap();

        let paths = store.certificate_paths_for_sni("example.test").unwrap();
        assert_eq!(paths.cert_path.exists(), paths.key_path.exists());
    }
}

#[cfg(feature = "acme-client")]
#[test]
fn revocation_quarantine_rollback_restores_the_complete_pair() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-revoke-rollback");
    let paths = install_managed_certificate(
        &storage,
        "example",
        test_certificate_pem(),
        test_private_key_pem(),
        &["example.test".to_owned()],
    )
    .unwrap();

    let quarantine = crate::begin_managed_certificate_quarantine(&paths).unwrap();
    assert!(!paths.cert_path.exists());
    assert!(!paths.key_path.exists());
    quarantine.rollback().unwrap();

    assert_eq!(
        std::fs::read(paths.cert_path).unwrap(),
        test_certificate_pem()
    );
    assert_eq!(
        std::fs::read(paths.key_path).unwrap(),
        test_private_key_pem()
    );
}

#[cfg(feature = "acme-client")]
#[test]
fn dropped_revocation_quarantine_restores_the_complete_pair() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-revoke-drop");
    let paths = install_managed_certificate(
        &storage,
        "example",
        test_certificate_pem(),
        test_private_key_pem(),
        &["example.test".to_owned()],
    )
    .unwrap();

    drop(crate::begin_managed_certificate_quarantine(&paths).unwrap());

    assert_eq!(
        std::fs::read(paths.cert_path).unwrap(),
        test_certificate_pem()
    );
    assert_eq!(
        std::fs::read(paths.key_path).unwrap(),
        test_private_key_pem()
    );
}

#[cfg(feature = "acme-client")]
#[test]
fn revocation_reads_quarantined_identity_while_renewal_waits() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-revoke-renew-race");
    let (certificate_a, key_a) = issued_material_for(&["example.test"]);
    let paths = install_managed_certificate(
        &storage,
        "example",
        certificate_a.as_bytes(),
        key_a.as_bytes(),
        &["example.test".to_owned()],
    )
    .unwrap();
    let quarantine = crate::begin_managed_certificate_quarantine(&paths).unwrap();

    assert_eq!(
        quarantine.read_quarantined_certificate().unwrap(),
        certificate_a.as_bytes()
    );

    let (certificate_b, key_b) = issued_material_for(&["example.test"]);
    let (attempting_tx, attempting_rx) = std::sync::mpsc::channel();
    let (completed_tx, completed_rx) = std::sync::mpsc::channel();
    let renewal_storage = storage.clone();
    let renewal = std::thread::spawn(move || {
        attempting_tx.send(()).unwrap();
        completed_tx
            .send(install_managed_certificate(
                &renewal_storage,
                "example",
                certificate_b.as_bytes(),
                key_b.as_bytes(),
                &["example.test".to_owned()],
            ))
            .unwrap();
    });

    attempting_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert!(
        completed_rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err()
    );
    quarantine.rollback().unwrap();
    completed_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap()
        .unwrap();
    renewal.join().unwrap();
}

fn installed_revocation_test_pair(label: &str) -> (std::path::PathBuf, AcmeCertificatePaths) {
    let storage = fluxheim_common::test_support::unique_temp_path(label);
    let paths = install_managed_certificate(
        &storage,
        "example",
        test_certificate_pem(),
        test_private_key_pem(),
        &["example.test".to_owned()],
    )
    .unwrap();
    (storage, paths)
}

#[test]
fn revocation_journal_rejects_unbound_or_unsafe_file_names() {
    let transaction = "0123456789abcdef0123456789abcdef";
    assert!(
        crate::acme_certificate_install::revocation_file_names_valid(
            transaction,
            ".revoked-0123456789abcdef0123456789abcdef-fullchain.pem",
            ".revoked-0123456789abcdef0123456789abcdef-privkey.pem",
        )
    );
    assert!(
        !crate::acme_certificate_install::revocation_file_names_valid(
            transaction,
            "../../outside.pem",
            ".revoked-0123456789abcdef0123456789abcdef-privkey.pem",
        )
    );
    assert!(
        !crate::acme_certificate_install::revocation_file_names_valid(
            "not-a-transaction",
            ".revoked-not-a-transaction-fullchain.pem",
            ".revoked-not-a-transaction-privkey.pem",
        )
    );
}

#[test]
fn prepared_revocation_crash_restores_partial_pair() {
    let (storage, paths) = installed_revocation_test_pair("acme-revoke-prepared-crash");
    let quarantine =
        crate::acme_certificate_install::simulate_prepared_revocation_crash(&paths).unwrap();
    assert!(!paths.cert_path.exists());
    assert!(paths.key_path.exists());

    recover_managed_certificate_transaction(&storage, "example").unwrap();

    assert!(paths.cert_path.exists());
    assert!(paths.key_path.exists());
    assert!(!quarantine.exists());
}

#[test]
fn pair_quarantined_crash_restores_pair_before_remote_contact() {
    let (storage, paths) = installed_revocation_test_pair("acme-revoke-pair-crash");
    let quarantine = crate::begin_managed_certificate_quarantine(&paths).unwrap();
    let (certificate, private_key) = quarantine.abandon();

    recover_managed_certificate_transaction(&storage, "example").unwrap();

    assert!(paths.cert_path.exists());
    assert!(paths.key_path.exists());
    assert!(!certificate.exists());
    assert!(!private_key.exists());
}

#[test]
fn remote_pending_crash_remains_fail_closed() {
    let (storage, paths) = installed_revocation_test_pair("acme-revoke-pending-crash");
    let mut quarantine = crate::begin_managed_certificate_quarantine(&paths).unwrap();
    quarantine.mark_remote_pending().unwrap();
    let (certificate, private_key) = quarantine.abandon();

    let error = recover_managed_certificate_transaction(&storage, "example").unwrap_err();

    assert!(error.to_string().contains("outcome is ambiguous"));
    assert!(!paths.cert_path.exists());
    assert!(!paths.key_path.exists());
    assert!(certificate.exists());
    assert!(private_key.exists());

    assert!(
        install_managed_certificate(
            &storage,
            "example",
            test_certificate_pem(),
            test_private_key_pem(),
            &["example.test".to_owned()],
        )
        .is_err()
    );
}

#[test]
fn remote_confirmed_crash_keeps_quarantine_and_allows_replacement() {
    let (storage, paths) = installed_revocation_test_pair("acme-revoke-confirmed-crash");
    let mut quarantine = crate::begin_managed_certificate_quarantine(&paths).unwrap();
    quarantine.mark_remote_pending().unwrap();
    quarantine.mark_remote_confirmed().unwrap();
    let (certificate, private_key) = quarantine.abandon();

    recover_managed_certificate_transaction(&storage, "example").unwrap();

    assert!(!paths.cert_path.exists());
    assert!(!paths.key_path.exists());
    assert!(certificate.exists());
    assert!(private_key.exists());

    install_managed_certificate(
        &storage,
        "example",
        test_certificate_pem(),
        test_private_key_pem(),
        &["example.test".to_owned()],
    )
    .unwrap();
    assert!(paths.cert_path.exists());
    assert!(paths.key_path.exists());
    assert!(certificate.exists());
    assert!(private_key.exists());
}

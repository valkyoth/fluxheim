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

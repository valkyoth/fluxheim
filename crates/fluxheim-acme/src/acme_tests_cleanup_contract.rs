use super::*;

#[cfg(unix)]
#[test]
fn http_cleanup_error_currently_skips_later_published_tokens() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-cleanup-http");
    let store = AcmeHttp01ChallengeStore::new(&storage, "example");
    store
        .install_key_authorization("first", "first.thumbprint")
        .unwrap();
    store
        .install_key_authorization("second", "second.thumbprint")
        .unwrap();
    let first = store.root.join("first");
    std::fs::remove_file(&first).unwrap();
    std::os::unix::fs::symlink(store.root.join("missing"), &first).unwrap();

    // Characterize documented contract: failure must stay visible, but should not
    // prevent an independent valid token from being cleaned up.
    let error =
        crate::cleanup_http_01_challenges(&store, &["first".to_owned(), "second".to_owned()])
            .unwrap_err();
    assert!(matches!(error, AcmeRenewalError::Challenge { token, .. } if token == "first"));
    assert_eq!(
        store.load_key_authorization("second").unwrap().as_deref(),
        Some("second.thumbprint")
    );
    std::fs::remove_dir_all(storage).unwrap();
}

#[test]
fn tls_cleanup_error_currently_skips_later_published_domains() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-cleanup-alpn");
    let store = AcmeTlsAlpn01ChallengeStore::new(&storage);
    for domain in ["first.example.test", "second.example.test"] {
        let (certificate, key) = tls_alpn_01_certificate(domain, &[42; 32]).unwrap();
        key.with_secret(|key| store.install_challenge_certificate(domain, &certificate, key))
            .unwrap();
    }
    let first = store
        .certificate_paths_for_sni("first.example.test")
        .unwrap();
    let second = store
        .certificate_paths_for_sni("second.example.test")
        .unwrap();
    std::fs::remove_file(&first.cert_path).unwrap();
    std::fs::create_dir(&first.cert_path).unwrap();
    let error = crate::cleanup_tls_alpn_01_challenges(
        &store,
        &[
            "first.example.test".to_owned(),
            "second.example.test".to_owned(),
        ],
    )
    .unwrap_err();
    assert!(
        matches!(error, AcmeRenewalError::Challenge { token, .. } if token == "first.example.test")
    );
    assert!(second.cert_path.is_file() && second.key_path.is_file());
    std::fs::remove_dir_all(storage).unwrap();
}

#[test]
fn tls_cleanup_failure_can_leave_a_partial_challenge_pair() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-cleanup-partial");
    let store = AcmeTlsAlpn01ChallengeStore::new(&storage);
    let (certificate, key) = tls_alpn_01_certificate("example.test", &[42; 32]).unwrap();
    let paths = key
        .with_secret(|key| store.install_challenge_certificate("example.test", &certificate, key))
        .unwrap();
    std::fs::remove_file(&paths.key_path).unwrap();
    std::fs::create_dir(&paths.key_path).unwrap();

    assert!(store.remove_challenge_certificate("example.test").is_err());
    assert!(!paths.cert_path.exists());
    assert!(paths.key_path.is_dir());
    std::fs::remove_dir_all(storage).unwrap();
}

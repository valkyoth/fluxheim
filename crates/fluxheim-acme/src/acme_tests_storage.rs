use super::*;

#[cfg(feature = "acme-client")]
#[test]
fn tls_alpn_01_challenge_store_writes_and_removes_safe_files() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-tls-alpn-store");
    let store = super::AcmeTlsAlpn01ChallengeStore::new(&storage);
    let digest = [42_u8; 32];
    let (cert_pem, key_pem) = super::tls_alpn_01_certificate("Example.TEST", &digest).unwrap();

    let paths = key_pem
        .with_secret(|private_key| {
            store.install_challenge_certificate("Example.TEST", &cert_pem, private_key)
        })
        .unwrap();

    assert!(paths.cert_path.starts_with(&storage));
    assert!(paths.key_path.starts_with(&storage));
    assert!(paths.cert_path.is_file());
    assert!(paths.key_path.is_file());
    assert_eq!(
        store.certificate_paths_for_sni("example.test").unwrap(),
        paths
    );

    assert!(store.remove_challenge_certificate("example.test").unwrap());
    assert!(!paths.cert_path.exists());
    assert!(!paths.key_path.exists());
}

#[test]
fn account_credentials_store_round_trips_secure_file() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-store");
    let credentials = test_account_credentials();

    let path = store_account_credentials(&storage, "letsencrypt", &credentials).unwrap();
    let loaded = load_account_credentials(&storage, "letsencrypt")
        .unwrap()
        .unwrap();

    assert_eq!(
        loaded.private_key().secret_pkcs8_der(),
        credentials.private_key().secret_pkcs8_der()
    );
    assert_eq!(
        serde_json::to_value(&loaded).unwrap(),
        serde_json::to_value(&credentials).unwrap()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(path.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn account_credentials_removal_is_idempotent() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-remove");
    store_account_credentials(&storage, "letsencrypt", &test_account_credentials()).unwrap();

    assert!(remove_account_credentials(&storage, "letsencrypt").unwrap());
    assert!(!remove_account_credentials(&storage, "letsencrypt").unwrap());
    assert!(
        load_account_credentials(&storage, "letsencrypt")
            .unwrap()
            .is_none()
    );
}

#[cfg(feature = "acme-client")]
#[test]
fn account_deactivation_quarantine_is_fail_closed_and_recoverable() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-deactivation");
    store_account_credentials(&storage, "letsencrypt", &test_account_credentials()).unwrap();

    let transaction = crate::begin_account_deactivation(&storage, "letsencrypt").unwrap();
    transaction.abandon();
    let pending = match load_account_credentials(&storage, "letsencrypt") {
        Ok(_) => panic!("expected pending deactivation to fail closed"),
        Err(error) => error,
    };
    assert!(pending.to_string().contains("ambiguous pending state"));
    let active = account_credentials_path(&storage, "letsencrypt").path;
    std::fs::rename(
        active
            .parent()
            .unwrap()
            .join(".credentials.deactivation.pending"),
        &active,
    )
    .unwrap();
    assert!(
        load_account_credentials(&storage, "letsencrypt")
            .unwrap()
            .is_some()
    );

    let transaction = crate::begin_account_deactivation(&storage, "letsencrypt").unwrap();
    transaction.complete().unwrap();
    assert!(
        load_account_credentials(&storage, "letsencrypt")
            .unwrap()
            .is_none()
    );
}

#[test]
fn account_credentials_store_rejects_invalid_json_and_oversized_files() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-invalid");
    let path = account_credentials_path(&storage, "letsencrypt").path;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{not-json").unwrap();

    let error = match load_account_credentials(&storage, "letsencrypt") {
        Ok(_) => panic!("expected invalid account credentials to be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, AcmeAccountStoreError::Deserialize { .. }));

    std::fs::write(
        &path,
        "x".repeat((super::MAX_ACCOUNT_CREDENTIALS_BYTES + 1) as usize),
    )
    .unwrap();

    let error = match load_account_credentials(&storage, "letsencrypt") {
        Ok(_) => panic!("expected oversized account credentials to be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, AcmeAccountStoreError::Oversized { .. }));
}

#[cfg(unix)]
#[test]
fn account_credentials_store_rejects_symlinked_file() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-symlink");
    let path = account_credentials_path(&storage, "letsencrypt").path;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let outside = storage.with_extension("outside");
    std::fs::write(&outside, test_account_credentials_json()).unwrap();
    std::os::unix::fs::symlink(&outside, &path).unwrap();

    let error = match load_account_credentials(&storage, "letsencrypt") {
        Ok(_) => panic!("expected symlinked account credentials to be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        AcmeAccountStoreError::UnsafePath { .. } | AcmeAccountStoreError::Io { .. }
    ));
}

#[test]
fn install_managed_certificate_writes_safe_files() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-install-cert");
    let paths = super::install_managed_certificate(
        &storage,
        "Example Site",
        test_certificate_pem(),
        test_private_key_pem(),
        &["example.test".to_owned()],
    )
    .unwrap();

    assert_eq!(
        std::fs::read(&paths.cert_path).unwrap(),
        test_certificate_pem()
    );
    assert_eq!(
        std::fs::read(&paths.key_path).unwrap(),
        test_private_key_pem()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(&paths.key_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn install_managed_certificate_rejects_invalid_pem_without_touching_previous_files() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-install-invalid");
    let paths = super::install_managed_certificate(
        &storage,
        "example",
        test_certificate_pem(),
        test_private_key_pem(),
        &["example.test".to_owned()],
    )
    .unwrap();

    let error = super::install_managed_certificate(
        &storage,
        "example",
        b"not a cert",
        b"not a key",
        &["example.test".to_owned()],
    )
    .unwrap_err();

    assert!(matches!(
        error,
        super::AcmeCertificateInstallError::InvalidCertificatePem(_)
    ));
    assert_eq!(
        std::fs::read(&paths.cert_path).unwrap(),
        test_certificate_pem()
    );
    assert_eq!(
        std::fs::read(&paths.key_path).unwrap(),
        test_private_key_pem()
    );
}

#[test]
fn install_managed_certificate_rejects_key_and_identifier_mismatches() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-install-identity");
    let (certificate, key) = issued_material_for(&["example.test"]);
    let (_, other_key) = issued_material_for(&["other.test"]);

    let key_error = super::install_managed_certificate(
        &storage,
        "example",
        certificate.as_bytes(),
        other_key.as_bytes(),
        &["example.test".to_owned()],
    )
    .unwrap_err();
    assert!(matches!(
        key_error,
        super::AcmeCertificateInstallError::InvalidPrivateKeyPem(_)
    ));

    let name_error = super::install_managed_certificate(
        &storage,
        "example",
        certificate.as_bytes(),
        key.as_bytes(),
        &["other.test".to_owned()],
    )
    .unwrap_err();
    assert!(matches!(
        name_error,
        super::AcmeCertificateInstallError::InvalidCertificatePem(_)
    ));
}

#[test]
fn concurrent_certificate_installs_publish_one_complete_pair() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-install-concurrent");
    let first = issued_material_for(&["example.test"]);
    let second = issued_material_for(&["example.test"]);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));

    let jobs = [first, second].map(|(certificate, key)| {
        let storage = storage.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            super::install_managed_certificate(
                &storage,
                "example",
                certificate.as_bytes(),
                key.as_bytes(),
                &["example.test".to_owned()],
            )
        })
    });
    barrier.wait();
    for job in jobs {
        job.join().unwrap().unwrap();
    }

    let paths = managed_certificate_paths(&storage, "example");
    crate::validate_issued_material(
        &std::fs::read(paths.cert_path).unwrap(),
        &std::fs::read(paths.key_path).unwrap(),
        &["example.test".to_owned()],
    )
    .unwrap();
}

#[cfg(feature = "acme-client")]
#[test]
fn revoked_certificate_quarantine_removes_the_active_pair() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-revoke-quarantine");
    let paths = install_managed_certificate(
        &storage,
        "example",
        test_certificate_pem(),
        test_private_key_pem(),
        &["example.test".to_owned()],
    )
    .unwrap();

    let mut quarantine = crate::begin_managed_certificate_quarantine(&paths).unwrap();
    quarantine.mark_remote_pending().unwrap();
    quarantine.mark_remote_confirmed().unwrap();
    let (certificate, private_key) = quarantine.complete().unwrap();

    assert!(!paths.cert_path.exists());
    assert!(!paths.key_path.exists());
    assert_eq!(std::fs::read(certificate).unwrap(), test_certificate_pem());
    assert_eq!(std::fs::read(private_key).unwrap(), test_private_key_pem());
}

#[cfg(unix)]
#[test]
fn install_managed_certificate_rejects_symlinked_destination() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-install-symlink");
    let paths = managed_certificate_paths(&storage, "example");
    std::fs::create_dir_all(paths.cert_path.parent().unwrap()).unwrap();
    let outside = storage.with_extension("outside");
    std::fs::write(&outside, "outside").unwrap();
    std::os::unix::fs::symlink(&outside, &paths.cert_path).unwrap();

    let error = super::install_managed_certificate(
        &storage,
        "example",
        test_certificate_pem(),
        test_private_key_pem(),
        &["example.test".to_owned()],
    )
    .unwrap_err();

    assert!(matches!(
        error,
        super::AcmeCertificateInstallError::UnsafePath { .. }
    ));
    assert_eq!(std::fs::read_to_string(outside).unwrap(), "outside");
}

#[test]
fn install_managed_certificate_stale_backup_does_not_replace_previous_files() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-install-stale-backup");
    let paths = super::install_managed_certificate(
        &storage,
        "example",
        test_certificate_pem(),
        test_private_key_pem(),
        &["example.test".to_owned()],
    )
    .unwrap();
    std::fs::write(
        paths
            .cert_path
            .parent()
            .unwrap()
            .join(".fullchain.pem.previous"),
        "stale",
    )
    .unwrap();

    let error = super::install_managed_certificate(
        &storage,
        "example",
        test_certificate_pem(),
        test_private_key_pem(),
        &["example.test".to_owned()],
    )
    .unwrap_err();

    assert!(matches!(
        error,
        super::AcmeCertificateInstallError::UnsafePath { .. }
    ));
    assert_eq!(
        std::fs::read(&paths.cert_path).unwrap(),
        test_certificate_pem()
    );
    assert_eq!(
        std::fs::read(&paths.key_path).unwrap(),
        test_private_key_pem()
    );
}

#[test]
fn http_01_token_from_path_accepts_single_safe_segment() {
    assert_eq!(
        http_01_token_from_path("/.well-known/acme-challenge/abc-DEF_123"),
        Some("abc-DEF_123")
    );
    assert_eq!(
        http_01_token_from_path("/.well-known/acme-challenge/abc/def"),
        None
    );
    assert_eq!(
        http_01_token_from_path("/.well-known/acme-challenge/../def"),
        None
    );
    assert_eq!(http_01_token_from_path("/other/abc"), None);
}

#[test]
fn http_01_store_loads_only_safe_token_files() {
    let root = fluxheim_common::test_support::unique_temp_path("acme-http-01-store");
    let store = AcmeHttp01ChallengeStore::new(&root, "Example Site");
    std::fs::create_dir_all(&store.root).unwrap();

    let token = "abc_DEF-123";
    std::fs::write(store.root.join(token), "abc_DEF-123.thumbprint\n").unwrap();

    assert_eq!(
        store.load_key_authorization(token).unwrap(),
        Some("abc_DEF-123.thumbprint".to_owned())
    );
    assert_eq!(store.load_key_authorization("../bad").unwrap(), None);
    assert_eq!(store.load_key_authorization("missing").unwrap(), None);
}

#[test]
fn http_01_store_installs_and_removes_challenge_files() {
    let root = fluxheim_common::test_support::unique_temp_path("acme-http-01-install");
    let store = AcmeHttp01ChallengeStore::new(&root, "Example Site");

    store
        .install_key_authorization("abc_DEF-123", "abc_DEF-123.thumbprint\n")
        .unwrap();

    assert_eq!(
        store.load_key_authorization("abc_DEF-123").unwrap(),
        Some("abc_DEF-123.thumbprint".to_owned())
    );
    assert!(store.remove_key_authorization("abc_DEF-123").unwrap());
    assert_eq!(store.load_key_authorization("abc_DEF-123").unwrap(), None);
    assert!(!store.remove_key_authorization("abc_DEF-123").unwrap());
}

#[test]
fn http_01_store_rejects_invalid_install_inputs() {
    let root = fluxheim_common::test_support::unique_temp_path("acme-http-01-invalid-install");
    let store = AcmeHttp01ChallengeStore::new(&root, "Example Site");

    assert!(
        store
            .install_key_authorization("../bad", "abc.thumbprint")
            .is_err()
    );
    assert!(
        store
            .install_key_authorization("abc", "bad\ninside")
            .is_err()
    );
    assert!(!root.exists());
}

#[cfg(unix)]
#[test]
fn http_01_store_rejects_symlinked_destination_on_install() {
    let root = fluxheim_common::test_support::unique_temp_path("acme-http-01-symlink-install");
    let store = AcmeHttp01ChallengeStore::new(&root, "Example Site");
    std::fs::create_dir_all(&store.root).unwrap();
    let outside = root.with_extension("outside");
    std::fs::write(&outside, "outside").unwrap();
    std::os::unix::fs::symlink(&outside, store.root.join("abc")).unwrap();

    assert!(
        store
            .install_key_authorization("abc", "abc.thumbprint")
            .is_err()
    );
    assert_eq!(std::fs::read_to_string(outside).unwrap(), "outside");
}

use super::*;

#[cfg(feature = "acme-client")]
#[test]
fn tls_alpn_01_challenge_store_writes_and_removes_safe_files() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-tls-alpn-store");
    let store = super::AcmeTlsAlpn01ChallengeStore::new(&storage);
    let digest = [42_u8; 32];
    let (cert_pem, key_pem) = super::tls_alpn_01_certificate("Example.TEST", &digest).unwrap();

    let paths = store
        .install_challenge_certificate("Example.TEST", &cert_pem, &key_pem)
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
    )
    .unwrap();

    let error =
        super::install_managed_certificate(&storage, "example", b"not a cert", b"not a key")
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
        b"-----BEGIN CERTIFICATE-----\nnew\n-----END CERTIFICATE-----\n",
        b"-----BEGIN PRIVATE KEY-----\nnew\n-----END PRIVATE KEY-----\n",
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

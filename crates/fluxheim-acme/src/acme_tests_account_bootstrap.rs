use super::*;

fn bootstrap_credentials(
    bootstrap: &mut PendingAccountBootstrap,
    directory: &str,
) -> instant_acme::AccountCredentials {
    let (_, key_der) = bootstrap.key_pair().unwrap();
    let encoded = base64_ng::URL_SAFE_NO_PAD
        .encode_string(key_der.secret_pkcs8_der())
        .unwrap();
    serde_json::from_value(serde_json::json!({
        "id": "https://acme.example.test/account/1",
        "key_pkcs8": encoded,
        "directory": directory,
    }))
    .unwrap()
}

#[cfg(feature = "acme-client")]
#[test]
fn account_bootstrap_recovers_the_same_pending_key_after_restart() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-bootstrap-restart");
    let directory = "https://acme.example.test/directory";
    let first = match begin_account_bootstrap(&storage, "issuer", directory).unwrap() {
        AccountBootstrap::Pending(pending) => pending,
        AccountBootstrap::Existing(_) => panic!("expected a pending account bootstrap"),
    };
    assert!(!first.recovered());
    let digest = first.key_digest();
    drop(first);

    let recovered = match begin_account_bootstrap(&storage, "issuer", directory).unwrap() {
        AccountBootstrap::Pending(pending) => pending,
        AccountBootstrap::Existing(_) => panic!("expected recovered pending account bootstrap"),
    };
    assert!(recovered.recovered());
    assert_eq!(recovered.key_digest(), digest);
}

#[cfg(feature = "acme-client")]
#[test]
fn account_bootstrap_lock_serializes_concurrent_creation() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-bootstrap-lock");
    let directory = "https://acme.example.test/directory";
    let first = match begin_account_bootstrap(&storage, "issuer", directory).unwrap() {
        AccountBootstrap::Pending(pending) => pending,
        AccountBootstrap::Existing(_) => panic!("expected a pending account bootstrap"),
    };
    let (attempting_tx, attempting_rx) = std::sync::mpsc::channel();
    let (completed_tx, completed_rx) = std::sync::mpsc::channel();
    let concurrent_storage = storage.clone();
    let worker = std::thread::spawn(move || {
        attempting_tx.send(()).unwrap();
        let result = begin_account_bootstrap(&concurrent_storage, "issuer", directory);
        completed_tx.send(result.map(drop)).unwrap();
    });
    attempting_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert!(
        completed_rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err()
    );
    drop(first);
    completed_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap()
        .unwrap();
    worker.join().unwrap();
}

#[cfg(feature = "acme-client")]
#[test]
fn account_bootstrap_promotion_is_durable_and_cleans_pending_key() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-bootstrap-promote");
    let directory = "https://acme.example.test/directory";
    let mut pending = match begin_account_bootstrap(&storage, "issuer", directory).unwrap() {
        AccountBootstrap::Pending(pending) => pending,
        AccountBootstrap::Existing(_) => panic!("expected a pending account bootstrap"),
    };
    let credentials = bootstrap_credentials(&mut pending, directory);
    pending.promote(&credentials).unwrap();

    assert!(matches!(
        begin_account_bootstrap(&storage, "issuer", directory).unwrap(),
        AccountBootstrap::Existing(_)
    ));
    let pending_path = account_credentials_path(&storage, "issuer")
        .path
        .parent()
        .unwrap()
        .join(".credentials.bootstrap.pending");
    assert!(!pending_path.exists());
}

#[cfg(unix)]
#[test]
fn account_bootstrap_sanitizes_pending_key_before_unlink() {
    let storage =
        fluxheim_common::test_support::unique_temp_path("acme-account-bootstrap-sanitize");
    let directory = "https://acme.example.test/directory";
    let mut pending = match begin_account_bootstrap(&storage, "issuer", directory).unwrap() {
        AccountBootstrap::Pending(pending) => pending,
        AccountBootstrap::Existing(_) => panic!("expected a pending account bootstrap"),
    };
    let credentials = bootstrap_credentials(&mut pending, directory);
    let pending_path = account_credentials_path(&storage, "issuer")
        .path
        .parent()
        .unwrap()
        .join(".credentials.bootstrap.pending");
    let retained_link = storage.join("pending-key-sanitization-witness");
    std::fs::hard_link(&pending_path, &retained_link).unwrap();

    pending.promote(&credentials).unwrap();

    assert_eq!(std::fs::metadata(retained_link).unwrap().len(), 0);
}

#[cfg(feature = "acme-client")]
#[test]
fn account_bootstrap_recovers_after_credentials_publish_before_cleanup() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-bootstrap-crash");
    let directory = "https://acme.example.test/directory";
    let mut pending = match begin_account_bootstrap(&storage, "issuer", directory).unwrap() {
        AccountBootstrap::Pending(pending) => pending,
        AccountBootstrap::Existing(_) => panic!("expected a pending account bootstrap"),
    };
    let credentials = bootstrap_credentials(&mut pending, directory);
    pending
        .persist_credentials_before_cleanup(&credentials)
        .unwrap();
    drop(pending);

    assert!(matches!(
        begin_account_bootstrap(&storage, "issuer", directory).unwrap(),
        AccountBootstrap::Existing(_)
    ));
    let pending_path = account_credentials_path(&storage, "issuer")
        .path
        .parent()
        .unwrap()
        .join(".credentials.bootstrap.pending");
    assert!(!pending_path.exists());
}

#[cfg(feature = "acme-client")]
#[test]
fn ordinary_credential_store_cannot_bypass_pending_bootstrap() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-bootstrap-bypass");
    let pending =
        match begin_account_bootstrap(&storage, "issuer", "https://acme.example.test/directory")
            .unwrap()
        {
            AccountBootstrap::Pending(pending) => pending,
            AccountBootstrap::Existing(_) => panic!("expected a pending account bootstrap"),
        };
    drop(pending);

    let error =
        store_account_credentials(&storage, "issuer", &test_account_credentials()).unwrap_err();
    assert!(error.to_string().contains("bootstrap is pending"));
    let error = match load_account_credentials(&storage, "issuer") {
        Ok(_) => panic!("expected ordinary credential load to fail closed"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("bootstrap is pending"));
}

#[cfg(feature = "acme-client")]
#[test]
fn account_bootstrap_rejects_mismatched_credentials_and_issuer() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-bootstrap-binding");
    let directory = "https://acme.example.test/directory";
    let pending = match begin_account_bootstrap(&storage, "issuer", directory).unwrap() {
        AccountBootstrap::Pending(pending) => pending,
        AccountBootstrap::Existing(_) => panic!("expected a pending account bootstrap"),
    };
    assert!(pending.promote(&test_account_credentials()).is_err());

    let error = match begin_account_bootstrap(
        &storage,
        "issuer",
        "https://different.example.test/directory",
    ) {
        Ok(_) => panic!("expected issuer binding mismatch"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("different issuer directory"));
}

#[cfg(all(feature = "acme-client", unix))]
#[test]
fn pending_account_bootstrap_key_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-bootstrap-mode");
    let pending =
        match begin_account_bootstrap(&storage, "issuer", "https://acme.example.test/directory")
            .unwrap()
        {
            AccountBootstrap::Pending(pending) => pending,
            AccountBootstrap::Existing(_) => panic!("expected a pending account bootstrap"),
        };
    let pending_path = account_credentials_path(&storage, "issuer")
        .path
        .parent()
        .unwrap()
        .join(".credentials.bootstrap.pending");
    assert_eq!(
        std::fs::metadata(pending_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(pending);
}

#[cfg(all(feature = "acme-client", unix))]
#[test]
fn account_bootstrap_rejects_symlinked_pending_key() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-bootstrap-symlink");
    let pending =
        match begin_account_bootstrap(&storage, "issuer", "https://acme.example.test/directory")
            .unwrap()
        {
            AccountBootstrap::Pending(pending) => pending,
            AccountBootstrap::Existing(_) => panic!("expected a pending account bootstrap"),
        };
    drop(pending);
    let pending_path = account_credentials_path(&storage, "issuer")
        .path
        .parent()
        .unwrap()
        .join(".credentials.bootstrap.pending");
    std::fs::remove_file(&pending_path).unwrap();
    let outside = storage.with_extension("outside-key");
    std::fs::write(&outside, b"outside").unwrap();
    std::os::unix::fs::symlink(&outside, &pending_path).unwrap();

    let error =
        match begin_account_bootstrap(&storage, "issuer", "https://acme.example.test/directory") {
            Ok(_) => panic!("expected symlinked pending key to fail closed"),
            Err(error) => error,
        };
    assert!(error.to_string().contains("not a regular file"));
    assert_eq!(std::fs::read(outside).unwrap(), b"outside");
}

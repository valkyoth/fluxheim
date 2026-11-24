use super::*;
use crate::acme_order::Order;
use fluxheim_config::acme_publication::{ACTIVE_DIR, ORDER_DIR};
use std::fs;

fn fixture(label: &str) -> (PathBuf, Config, AcmeHttp01ChallengeStore) {
    let storage = fluxheim_common::test_support::unique_temp_path(label);
    let mut config = acme_config_with_vhosts(vec![managed_vhost("example")]);
    config.tls.acme.storage = Some(storage.clone());
    let store = AcmeHttp01ChallengeStore::new(&storage, "example");
    (storage, config, store)
}

#[test]
fn cancellation_and_timeout_revoke_visibility_and_preserve_later_orders() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for timeout in [false, true] {
        let (storage, config, store) = fixture("cancel-owned-order");
        store
            .install_key_authorization("manual", "manual.key")
            .unwrap();
        let pending = async {
            let mut order = Order::new().unwrap();
            order
                .http(&storage, "example", "token", "first.key")
                .unwrap();
            assert_eq!(
                store.load_key_authorization("token").unwrap().as_deref(),
                Some("first.key")
            );
            crate::reconcile_managed_challenges(&config).unwrap();
            assert_eq!(
                Order::new()
                    .unwrap()
                    .http(&storage, "example", "token", "other.key")
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::WouldBlock
            );
            std::future::pending::<()>().await;
            drop(order);
        };
        rt.block_on(async {
            if timeout {
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), pending)
                        .await
                        .is_err()
                );
            } else {
                let mut fut = Box::pin(pending);
                assert!(futures::poll!(&mut fut).is_pending());
            }
        });
        assert!(store.load_key_authorization("token").unwrap().is_none());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut replacement = Order::new().unwrap();
        loop {
            match replacement.http(&storage, "example", "token", "replacement.key") {
                Ok(()) => break,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("replacement: {e}"),
            }
        }
        assert_eq!(
            store.load_key_authorization("token").unwrap().as_deref(),
            Some("replacement.key")
        );
        replacement.finish().unwrap();
        assert_eq!(
            store.load_key_authorization("manual").unwrap().as_deref(),
            Some("manual.key")
        );
        fs::remove_dir_all(storage).unwrap();
    }
}

#[test]
fn incomplete_cleanup_is_hidden_and_retried_without_following_replacements() {
    let (storage, config, store) = fixture("cleanup-reconcile");
    let mut order = Order::new().unwrap();
    for token in ["first", "second"] {
        order.http(&storage, "example", token, "some.key").unwrap();
    }
    let slot = store.root.join(ORDER_DIR);
    let broken = slot.join(ACTIVE_DIR).join("first");
    fs::remove_file(&broken).unwrap();
    fs::create_dir(&broken).unwrap();
    let err = order.finish().unwrap_err();
    let installed = crate::AcmeRenewalOutcome {
        vhost_name: "example".into(),
        issuer: "test".into(),
        certificate: managed_certificate_paths(&storage, "example"),
        published_challenges: 2,
        cleanup_pending: false,
    };
    assert!(
        crate::finish_renewal_cleanup(Ok(installed), Err(crate::acme_cleanup::order_error(err)))
            .unwrap()
            .cleanup_pending
    );
    assert!(!slot.join(ACTIVE_DIR).exists());
    assert!(!slot.join("retired/second").exists());
    assert!(slot.join("retired/first").is_dir());
    assert!(crate::reconcile_managed_challenges(&config).is_err());
    fs::remove_dir(slot.join("retired/first")).unwrap();
    crate::reconcile_managed_challenges(&config).unwrap();
    assert!(!slot.join("retired").exists());
    fs::remove_dir_all(storage).unwrap();
}

#[test]
fn changed_and_unclaimed_files_are_preserved_but_not_served() {
    let (storage, _, store) = fixture("owned-receipts");
    let mut order = Order::new().unwrap();
    for token in ["changed", "owned"] {
        order
            .http(&storage, "example", token, "original.key")
            .unwrap();
    }
    let root = store.root.join(ORDER_DIR);
    fs::write(root.join("active/changed"), b"changed.value").unwrap();
    fs::write(root.join("active/unrelated"), b"unrelated.value").unwrap();
    assert!(order.finish().is_err());
    assert_eq!(
        fs::read(root.join("retired/changed")).unwrap(),
        b"changed.value"
    );
    assert_eq!(
        fs::read(root.join("retired/unrelated")).unwrap(),
        b"unrelated.value"
    );
    assert!(!root.join("retired/owned").exists());
    for token in ["changed", "unrelated", "owned"] {
        assert!(store.load_key_authorization(token).unwrap().is_none());
    }
    fs::remove_dir_all(storage).unwrap();
}

#[test]
#[cfg(unix)]
fn publication_does_not_replace_a_dangling_link() {
    let (storage, _, store) = fixture("order-link");
    let mut order = Order::new().unwrap();
    order.http(&storage, "example", "owned", "one.key").unwrap();
    let slot = store.root.join(ORDER_DIR);
    let target = storage.join("missing");
    std::os::unix::fs::symlink(&target, slot.join("active/other")).unwrap();
    assert_eq!(
        order
            .http(&storage, "example", "other", "two.key")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert!(order.finish().is_err());
    assert_eq!(fs::read_link(slot.join("retired/other")).unwrap(), target);
    assert!(!slot.join("retired/owned").exists() && !target.exists());
    fs::remove_dir_all(storage).unwrap();
}

#[test]
fn alpn_fault_does_not_leave_a_served_partial_pair_or_skip_other_domains() {
    let (storage, _, _) = fixture("alpn-owned-pair");
    let store = AcmeTlsAlpn01ChallengeStore::new(&storage);
    let mut order = Order::new().unwrap();
    for domain in ["first.example.test", "second.example.test"] {
        let (cert, key) = tls_alpn_01_certificate(domain, &[42; 32]).unwrap();
        key.with_secret(|key| order.alpn(&storage, domain, &cert, key))
            .unwrap();
    }
    let first = store
        .certificate_paths_for_sni("first.example.test")
        .unwrap();
    let second = store
        .certificate_paths_for_sni("second.example.test")
        .unwrap();
    assert!(first.cert_path.is_file() && second.key_path.is_file());
    fs::remove_file(&first.cert_path).unwrap();
    fs::create_dir(&first.cert_path).unwrap();
    assert!(order.finish().is_err());
    assert!(!first.key_path.exists() && !second.key_path.exists() && !second.cert_path.exists());
    assert!(
        !store
            .certificate_paths_for_sni("first.example.test")
            .unwrap()
            .cert_path
            .exists()
    );
    fs::remove_dir_all(storage).unwrap();
}

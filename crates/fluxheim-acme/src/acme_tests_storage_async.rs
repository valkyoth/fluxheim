use super::*;

#[test]
fn account_credentials_store_load_and_remove_round_trip() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-account-async-roundtrip");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let stored = crate::store_account_credentials_async(
            &storage,
            "letsencrypt",
            test_account_credentials(),
        )
        .await
        .unwrap();
        assert!(stored.path.is_file());
        assert!(
            crate::load_account_credentials_async(&storage, "letsencrypt")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            crate::remove_account_credentials_async(&storage, "letsencrypt")
                .await
                .unwrap()
        );
        assert!(
            crate::load_account_credentials_async(&storage, "letsencrypt")
                .await
                .unwrap()
                .is_none()
        );
    });
}

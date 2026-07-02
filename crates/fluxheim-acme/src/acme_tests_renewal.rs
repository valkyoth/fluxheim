use super::*;

#[test]
fn execute_renewal_publishes_finalizes_installs_and_cleans_http_01() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-execute-renewal");
    let mut config = acme_config_with_vhosts(vec![managed_vhost("example")]);
    config.tls.acme.storage = Some(storage.clone());
    config.tls.acme.challenge = fluxheim_config::AcmeChallenge::Http01;
    config.tls.acme.contact_email = Some("admin@example.test".to_owned());
    let item = plan_renewal_queue(&config, &[], UNIX_EPOCH + Duration::from_secs(1_000)).remove(0);
    let mut client = FakeAcmeIssuerClient::new();

    let outcome = execute_renewal(&config, &item, &mut client).unwrap();

    assert_eq!(outcome.vhost_name, "example");
    assert_eq!(outcome.issuer, "letsencrypt");
    assert_eq!(outcome.published_challenges, 1);
    assert_eq!(client.prepare_calls, 1);
    assert_eq!(client.finalize_calls, 1);
    assert_eq!(
        std::fs::read(&outcome.certificate.cert_path).unwrap(),
        test_certificate_pem()
    );
    assert_eq!(
        std::fs::read(&outcome.certificate.key_path).unwrap(),
        test_private_key_pem()
    );

    let store = AcmeHttp01ChallengeStore::new(&storage, "example");
    assert_eq!(store.load_key_authorization("token_123").unwrap(), None);
}

#[test]
fn execute_renewal_cleans_challenge_when_finalize_fails() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-execute-finalize-fail");
    let mut config = acme_config_with_vhosts(vec![managed_vhost("example")]);
    config.tls.acme.storage = Some(storage.clone());
    config.tls.acme.challenge = fluxheim_config::AcmeChallenge::Http01;
    let item = plan_renewal_queue(&config, &[], UNIX_EPOCH + Duration::from_secs(1_000)).remove(0);
    let mut client = FakeAcmeIssuerClient::new();
    client.fail_finalize = true;

    let error = execute_renewal(&config, &item, &mut client).unwrap_err();

    assert!(matches!(error, AcmeRenewalError::Client { .. }));
    assert!(error.to_string().contains(
        "published_http_01=http://example.test/.well-known/acme-challenge/<redacted:9b>"
    ));
    assert!(!error.to_string().contains("token_123"));
    assert_eq!(client.finalize_calls, 1);
    let store = AcmeHttp01ChallengeStore::new(&storage, "example");
    assert_eq!(store.load_key_authorization("token_123").unwrap(), None);
    let paths = managed_certificate_paths(&storage, "example");
    assert!(!paths.cert_path.exists());
    assert!(!paths.key_path.exists());
}

#[test]
fn http_01_error_context_lists_all_published_urls() {
    let message = super::acme_client_error_message_with_http_01_context(
        "authorization failed",
        &["example.test".to_owned(), "www.example.test".to_owned()],
        &["token-a".to_owned(), "token-b".to_owned()],
    );

    assert!(message.starts_with("authorization failed; published_http_01="));
    assert!(message.contains("http://example.test/.well-known/acme-challenge/<redacted:7b>"));
    assert!(message.contains("http://www.example.test/.well-known/acme-challenge/<redacted:7b>"));
    assert!(!message.contains("token-a"));
    assert!(!message.contains("token-b"));
}

#[test]
fn eab_file_secrets_are_trimmed_bounded_and_redacted() {
    let root = fluxheim_common::test_support::unique_temp_path("acme-eab-file-secrets");
    std::fs::create_dir_all(&root).unwrap();
    let key_id = root.join("kid");
    let hmac_key = root.join("hmac");
    std::fs::write(&key_id, " kid-value\n").unwrap();
    std::fs::write(&hmac_key, " hmac-value\n").unwrap();
    let mut config = acme_config_with_vhosts(Vec::new());
    config.tls.acme.issuers = vec![eab_file_issuer(&key_id, &hmac_key)];

    let secrets = load_external_account_binding(&config, "actalis")
        .unwrap()
        .unwrap();

    assert_eq!(&*secrets.key_id, "kid-value");
    assert_eq!(&*secrets.hmac_key, "hmac-value");
    let debug = format!("{secrets:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("kid-value"));
    assert!(!debug.contains("hmac-value"));
}

#[test]
fn eab_file_secret_rejects_empty_value() {
    let root = fluxheim_common::test_support::unique_temp_path("acme-eab-empty-secret");
    std::fs::create_dir_all(&root).unwrap();
    let key_id = root.join("kid");
    let hmac_key = root.join("hmac");
    std::fs::write(&key_id, "\n").unwrap();
    std::fs::write(&hmac_key, "hmac-value").unwrap();
    let mut config = acme_config_with_vhosts(Vec::new());
    config.tls.acme.issuers = vec![eab_file_issuer(&key_id, &hmac_key)];

    assert_eq!(
        load_external_account_binding(&config, "actalis").unwrap_err(),
        AcmeSecretLoadError::EmptySecret {
            issuer: "actalis".to_owned(),
            field: "key_id",
        }
    );
}

#[test]
fn eab_file_secret_rejects_oversized_value() {
    let root = fluxheim_common::test_support::unique_temp_path("acme-eab-oversized-secret");
    std::fs::create_dir_all(&root).unwrap();
    let key_id = root.join("kid");
    let hmac_key = root.join("hmac");
    std::fs::write(&key_id, "k").unwrap();
    std::fs::write(
        &hmac_key,
        "h".repeat((super::MAX_EAB_SECRET_BYTES + 1) as usize),
    )
    .unwrap();
    let mut config = acme_config_with_vhosts(Vec::new());
    config.tls.acme.issuers = vec![eab_file_issuer(&key_id, &hmac_key)];

    assert_eq!(
        load_external_account_binding(&config, "actalis").unwrap_err(),
        AcmeSecretLoadError::OversizedSecret {
            issuer: "actalis".to_owned(),
            field: "hmac_key",
            max_bytes: super::MAX_EAB_SECRET_BYTES,
        }
    );
}

#[cfg(unix)]
#[test]
fn eab_file_secret_rejects_symlinked_file() {
    let root = fluxheim_common::test_support::unique_temp_path("acme-eab-symlink-secret");
    std::fs::create_dir_all(&root).unwrap();
    let real_key_id = root.join("real-kid");
    let key_id = root.join("kid");
    let hmac_key = root.join("hmac");
    std::fs::write(&real_key_id, "kid-value").unwrap();
    std::os::unix::fs::symlink(&real_key_id, &key_id).unwrap();
    std::fs::write(&hmac_key, "hmac-value").unwrap();
    let mut config = acme_config_with_vhosts(Vec::new());
    config.tls.acme.issuers = vec![eab_file_issuer(&key_id, &hmac_key)];

    assert!(matches!(
        load_external_account_binding(&config, "actalis").unwrap_err(),
        AcmeSecretLoadError::FileRead {
            issuer,
            field: "key_id",
            ..
        } if issuer == "actalis"
    ));
}

#[cfg(feature = "acme-client")]
#[test]
fn eab_hmac_key_decoder_accepts_base64url_and_rejects_invalid_values() {
    let decoded = super::decode_eab_hmac_key("actalis", "aG1hYy1zZWNyZXQ").unwrap();
    assert_eq!(&*decoded, b"hmac-secret");

    let error = match super::decode_eab_hmac_key("actalis", "not valid base64!?") {
        Ok(_) => panic!("expected invalid EAB hmac key to be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        super::AcmeInstantClientError::InvalidExternalAccountBindingHmacKey { .. }
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn retry_backoff_never_exceeds_configured_cap(
        failures in 0u32..=128,
        initial_secs in 0u64..=86_400,
        max_secs in 0u64..=604_800,
    ) {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let due_at = next_retry_at(now, failures, initial_secs, max_secs);
        let delay_secs = due_at.duration_since(now).unwrap().as_secs();
        let multiplier = 1_u64
            .checked_shl(failures.min(63))
            .unwrap_or(u64::MAX);
        let expected = initial_secs.saturating_mul(multiplier).min(max_secs);

        prop_assert_eq!(delay_secs, expected);
        prop_assert!(delay_secs <= max_secs);
    }
}

#[test]
fn converts_offset_datetime_to_utc_system_time() {
    let datetime = "1970-01-01T01:00:00+01:00"
        .parse()
        .expect("valid TOML datetime");

    assert_eq!(
        toml_offset_datetime_to_system_time(&datetime),
        Some(UNIX_EPOCH)
    );
}

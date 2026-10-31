use super::*;

fn held_config(label: &str) -> Config {
    let mut config = acme_config_with_vhosts(vec![managed_vhost("example")]);
    config.tls.acme.storage = Some(fluxheim_common::test_support::unique_temp_path(label));
    config.tls.acme.renewal.renew_after = Some("2099-01-01T00:00:00Z".parse().unwrap());
    config
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn missing_certificate_due_executor_currently_bypasses_future_hold() {
    let config = held_config("acme-guide-future-hold");
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let queue = plan_renewal_queue(&config, &[], now);
    assert_eq!(queue.len(), 1);
    assert!(!queue[0].due_now);
    assert!(queue[0].due_at > now);

    // Characterize documented contract, not the desired contract. Unaccepted terms
    // stop account creation before any network request or certificate issuance.
    let run = runtime()
        .block_on(crate::renew_due_instant_acme_targets(&config, now))
        .unwrap();
    assert_eq!(run.attempted, 1);
    assert!(run.renewed.is_empty());
    assert_eq!(run.failed.len(), 1);
    assert!(
        run.failed[0].error.contains("terms"),
        "{}",
        run.failed[0].error
    );
    std::fs::remove_dir_all(config.tls.acme.storage.unwrap()).unwrap();
}

#[test]
fn selected_missing_certificate_respects_hold_without_account_credentials() {
    let config = held_config("acme-guide-selected-hold");
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let run = runtime()
        .block_on(renew_selected_instant_acme_targets(
            &config, now, "example", false,
        ))
        .unwrap();
    assert_eq!(run.attempted, 0);
    assert!(run.failed.is_empty());
    assert!(run.renewed.is_empty());
}

#[test]
fn disabled_renewal_produces_no_targets_even_with_force() {
    let mut config = held_config("acme-guide-disabled-renewal");
    config.tls.acme.renewal.enabled = false;
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    assert!(renewal_targets(&config).is_empty());
    assert!(plan_renewal_queue(&config, &[], now).is_empty());
    let run = runtime()
        .block_on(renew_selected_instant_acme_targets(
            &config, now, "example", true,
        ))
        .unwrap();
    assert_eq!(run.attempted, 0);
}

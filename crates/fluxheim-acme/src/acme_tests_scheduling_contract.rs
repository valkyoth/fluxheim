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
fn missing_certificate_due_executor_respects_future_hold_without_creating_state() {
    let config = held_config("acme-guide-future-hold");
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let queue = plan_renewal_queue(&config, &[], now);
    assert_eq!(queue.len(), 1);
    assert!(!queue[0].due_now);
    assert!(queue[0].due_at > now);

    let run = runtime()
        .block_on(crate::renew_due_instant_acme_targets(&config, now))
        .unwrap();
    assert_eq!(run.attempted, 0);
    assert!(run.renewed.is_empty());
    assert!(run.failed.is_empty());
    assert!(!config.tls.acme.storage.unwrap().exists());
}

#[test]
fn deadline_is_inclusive_for_all_and_selected_and_only_force_bypasses_it() {
    let rt = runtime();
    let deadline = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    for selected in [false, true] {
        for (shift, force, expected) in [(0, false, 1), (1, false, 0), (1, true, 1)] {
            let mut config = held_config("acme-hold-boundary");
            config.tls.acme.renewal.renew_after =
                Some("2027-01-15T09:00:00+01:00".parse().unwrap());
            let now = deadline - Duration::from_millis(shift);
            let run = rt
                .block_on(async {
                    if selected {
                        renew_selected_instant_acme_targets(&config, now, "example", force).await
                    } else if force {
                        crate::renew_all_instant_acme_targets(&config, now).await
                    } else {
                        crate::renew_due_instant_acme_targets(&config, now).await
                    }
                })
                .unwrap();
            assert_eq!(run.attempted, expected);
            let root = config.tls.acme.storage.unwrap();
            if expected == 1 {
                assert!(run.failed[0].error.contains("terms"));
                std::fs::remove_dir_all(root).unwrap();
            } else {
                assert!(!root.exists());
            }
        }
    }
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
fn hold_blocks_execution_even_for_expired_emergency_or_advisory_candidates() {
    let config = held_config("acme-held-observed");
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    for not_after in [
        now - Duration::from_secs(1),
        now,
        now + Duration::from_secs(3600),
        now + Duration::from_secs(90 * 86400),
    ] {
        let observations = [CertificateObservation {
            vhost_name: "example".into(),
            not_after,
        }];
        let mut queue = plan_renewal_queue(&config, &observations, now);
        assert_eq!(queue.len(), 1);
        assert!(!queue[0].due_now);
        // Even a previously due plan cannot authorize a renewal during the hold.
        queue[0].due_now = true;
        let run = runtime()
            .block_on(crate::acme_ari::execute_due_queue(&config, &queue, now))
            .unwrap();
        assert_eq!(run.attempted, 0);
        assert!(!config.tls.acme.storage.as_ref().unwrap().exists());
    }
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

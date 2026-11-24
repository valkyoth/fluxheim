use super::*;

fn held_config(label: &str) -> Config {
    let mut config = acme_config_with_vhosts(vec![managed_vhost("example")]);
    config.tls.acme.storage = Some(fluxheim_common::test_support::unique_temp_path(label));
    config.tls.acme.renewal.renew_after = Some("2099-01-01T00:00:00Z".parse().unwrap());
    config.tls.acme.renewal.hold_mode = fluxheim_config::AcmeHoldMode::Absolute;
    config
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn background_failure_suppresses_the_next_due_attempt() {
    let mut config = held_config("acme-backoff");
    config.tls.acme.renewal.renew_after = None;
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let rt = runtime();
    config.tls.acme.renewal.retry_initial_secs = 3;
    config.tls.acme.renewal.retry_max_secs = 8;
    let mut worker = crate::BackgroundRenewals::new(&config);
    let start = std::time::Instant::now();
    let mut attempts = Vec::new();
    for elapsed in [0, 0, 2, 3, 8, 9, 16, 17, 24, 25] {
        let run = rt
            .block_on(worker.tick_with_clock(now, || start + Duration::from_secs(elapsed)))
            .unwrap();
        attempts.push(run.attempted);
    }
    std::fs::remove_dir_all(config.tls.acme.storage.unwrap()).unwrap();
    assert_eq!(attempts, [1, 0, 0, 1, 0, 1, 0, 1, 0, 1]);
}

#[test]
fn background_backoff_is_per_managed_vhost_and_dies_with_the_worker() {
    let mut config = held_config("acme-backoff-reset");
    config.tls.acme.renewal.renew_after = None;
    config.vhosts = (0..32)
        .map(|n| managed_vhost(&format!("target-{n}")))
        .collect();
    let rt = runtime();
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    {
        let mut worker = crate::BackgroundRenewals::new(&config);
        let run = rt.block_on(worker.tick(now)).unwrap();
        assert_eq!((run.attempted, run.failed.len()), (32, 32));
        assert_eq!(rt.block_on(worker.tick(now)).unwrap().attempted, 0);
        assert_eq!(
            rt.block_on(renew_selected_instant_acme_targets(
                &config, now, "target-0", false
            ))
            .unwrap()
            .attempted,
            1
        );
    }
    config.vhosts.truncate(1);
    let mut replacement = crate::BackgroundRenewals::new(&config);
    assert_eq!(rt.block_on(replacement.tick(now)).unwrap().attempted, 1);
    std::fs::remove_dir_all(config.tls.acme.storage.unwrap()).unwrap();
}

#[test]
fn cancelling_mid_tick_keeps_completed_failures_but_not_pending_attempts() {
    let mut config = held_config("acme-backoff-cancel");
    config.tls.acme.renewal.renew_after = None;
    let mut first = managed_vhost("a");
    first.tls.acme.issuer = Some("unknown-test-issuer".into()); // fails before any I/O
    config.vhosts = vec![first, managed_vhost("b")];
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let mut worker = crate::BackgroundRenewals::new(&config);
    rt.block_on(async {
        // Keep the second target's filesystem bootstrap pending until the tick is dropped.
        let (release, gate) = std::sync::mpsc::channel();
        let blocker =
            tokio::task::spawn_blocking(move || gate.recv_timeout(Duration::from_secs(10)));
        {
            let mut tick = Box::pin(worker.tick(now));
            assert!(futures::poll!(&mut tick).is_pending());
        }
        release.send(()).unwrap();
        blocker.await.unwrap().unwrap();
        let retried = worker.tick(now).await.unwrap();
        assert_eq!(retried.attempted, 1);
        assert_eq!(retried.failed[0].vhost_name, "b");
    });
    std::fs::remove_dir_all(config.tls.acme.storage.unwrap()).unwrap();
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
    assert_eq!(
        runtime()
            .block_on(crate::renew_all_instant_acme_targets(&config, now))
            .unwrap()
            .attempted,
        0
    );
    assert!(!config.tls.acme.storage.unwrap().exists());
}

#[test]
fn elective_hold_skips_only_routine_renewal_without_issuer_advice() {
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let week = Duration::from_secs(7 * 86400);
    for (expiry, attempts) in [
        (None, 1),
        (Some(now), 1),
        (Some(now - week), 1),
        (Some(now + week), 1),
        (Some(now + week + Duration::from_secs(1)), 0),
    ] {
        let mut config = held_config("acme-elective");
        config.tls.acme.renewal.hold_mode = fluxheim_config::AcmeHoldMode::Elective;
        let obs: Vec<_> = expiry
            .into_iter()
            .map(|not_after| CertificateObservation {
                vhost_name: "example".into(),
                not_after,
            })
            .collect();
        let queue = plan_renewal_queue(&config, &obs, now);
        assert_eq!(queue[0].due_now, attempts == 1);
        let run = runtime()
            .block_on(crate::acme_ari::execute_due_queue(&config, &queue, now))
            .unwrap();
        assert_eq!(run.attempted, attempts);
        if attempts != 0 {
            assert!(run.failed[0].error.contains("terms"));
            std::fs::remove_dir_all(config.tls.acme.storage.unwrap()).unwrap();
        }
    }
}

#[test]
fn elective_hold_accepts_due_advice_but_not_an_unavailable_lookup() {
    let mut config = held_config("acme-elective-ari");
    config.tls.acme.renewal.hold_mode = fluxheim_config::AcmeHoldMode::Elective;
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let obs = [CertificateObservation {
        vhost_name: "example".into(),
        not_after: now + Duration::from_secs(14 * 86400),
    }];
    let queue = plan_renewal_queue(&config, &obs, now);
    let item = &queue[0];
    assert!(!item.due_now);
    runtime().block_on(async {
        for advice in [true, false] {
            assert_eq!(
                crate::acme_ari::due_decision(item, now, true, async { advice }).await,
                advice
            );
        }
        assert!(!crate::acme_ari::due_decision(item, now, false, std::future::pending()).await);
        let emergency = plan_renewal_queue(&config, &[], now);
        assert!(
            crate::acme_ari::due_decision(&emergency[0], now, false, std::future::pending()).await
        );
    });
}

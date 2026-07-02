use super::*;

#[test]
fn skips_targets_when_global_acme_is_disabled() {
    let config = Config::default();

    assert!(renewal_targets(&config).is_empty());
}

#[test]
fn builds_targets_from_enabled_vhosts() {
    let config = acme_config_with_vhosts(vec![VhostConfig {
        name: "example".to_owned(),
        hosts: vec!["Example.TEST".to_owned(), "*.example.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        acme_challenge: fluxheim_config::VhostAcmeChallengeConfig::default(),
        redirect: fluxheim_config::VhostRedirectConfig::default(),
        tls: VhostTlsConfig {
            enabled: true,
            acme: VhostAcmeConfig {
                enabled: true,
                issuer: None,
                domains: Vec::new(),
            },
            certificate: None,
        },
        proxy: ProxyConfig::default(),
        cache: CacheConfig::default(),
        compression: None,
        headers: fluxheim_config::VhostHeaderPolicyConfig::default(),
        php: fluxheim_config::PhpConfig::default(),
        web: WebConfig::default(),
        routes: Vec::new(),
    }]);

    let targets = renewal_targets(&config);

    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].issuer, "letsencrypt");
    assert_eq!(targets[0].domains, vec!["example.test"]);
    assert!(targets[0].certificate.cert_path.ends_with("fullchain.pem"));
    assert!(targets[0].certificate.key_path.ends_with("privkey.pem"));
}

#[test]
fn loads_certificate_not_after_from_leaf_pem() {
    let cert_path = fluxheim_common::test_support::unique_temp_path("acme-cert-observation")
        .with_extension("pem");
    std::fs::write(&cert_path, valid_leaf_certificate_pem()).unwrap();

    let not_after = load_certificate_not_after(&cert_path).unwrap().unwrap();

    assert!(not_after > UNIX_EPOCH + Duration::from_secs(1_893_456_000));
}

#[test]
fn observes_configured_managed_certificates() {
    let storage = fluxheim_common::test_support::unique_temp_path("acme-observe-configured");
    let mut config = acme_config_with_vhosts(vec![managed_vhost("example")]);
    config.tls.acme.storage = Some(storage.clone());
    let paths = managed_certificate_paths(&storage, "example");
    std::fs::create_dir_all(paths.cert_path.parent().unwrap()).unwrap();
    std::fs::write(&paths.cert_path, valid_leaf_certificate_pem()).unwrap();

    let observations = observe_configured_certificates(&config);

    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].vhost_name, "example");
}

#[test]
fn plans_initial_issue_for_missing_certificate() {
    let now = UNIX_EPOCH + Duration::from_secs(1_000);
    let config = acme_config_with_vhosts(vec![managed_vhost("example")]);

    let queue = plan_renewal_queue(&config, &[], now);

    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].due_at, now);
    assert!(queue[0].due_now);
    assert_eq!(queue[0].not_after, None);
}

#[cfg(feature = "acme-client")]
#[test]
fn selected_renewal_skips_not_due_target_without_network() {
    let now = UNIX_EPOCH + Duration::from_secs(1_000);
    let storage = fluxheim_common::test_support::unique_temp_path("acme-selected-renewal");
    let mut config =
        acme_config_with_vhosts(vec![managed_vhost("example"), managed_vhost("other")]);
    config.tls.acme.storage = Some(storage.clone());
    for vhost in ["example", "other"] {
        let paths = managed_certificate_paths(&storage, vhost);
        std::fs::create_dir_all(paths.cert_path.parent().unwrap()).unwrap();
        std::fs::write(&paths.cert_path, valid_leaf_certificate_pem()).unwrap();
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let run = runtime
        .block_on(super::renew_selected_instant_acme_targets(
            &config, now, "example", false,
        ))
        .unwrap();

    assert_eq!(run.attempted, 0);
    assert!(run.renewed.is_empty());
    assert!(run.failed.is_empty());
}

#[test]
fn uses_later_of_renew_window_and_operator_date() {
    let now = UNIX_EPOCH + Duration::from_secs(1_000);
    let mut config = acme_config_with_vhosts(vec![managed_vhost("example")]);
    config.tls.acme.renewal.renew_before_secs = 100;
    config.tls.acme.renewal.renew_after =
        Some("1970-01-01T00:18:20Z".parse().expect("valid TOML datetime"));
    let observations = vec![CertificateObservation {
        vhost_name: "example".to_owned(),
        not_after: UNIX_EPOCH + Duration::from_secs(1_150),
    }];

    let queue = plan_renewal_queue(&config, &observations, now);

    assert_eq!(queue[0].due_at, UNIX_EPOCH + Duration::from_secs(1_100));
    assert!(!queue[0].due_now);
}

#[test]
fn sorts_queue_by_due_time() {
    let now = UNIX_EPOCH + Duration::from_secs(1_000);
    let mut config =
        acme_config_with_vhosts(vec![managed_vhost("later"), managed_vhost("earlier")]);
    config.tls.acme.renewal.renew_before_secs = 100;
    let observations = vec![
        CertificateObservation {
            vhost_name: "later".to_owned(),
            not_after: UNIX_EPOCH + Duration::from_secs(1_400),
        },
        CertificateObservation {
            vhost_name: "earlier".to_owned(),
            not_after: UNIX_EPOCH + Duration::from_secs(1_200),
        },
    ];

    let queue = plan_renewal_queue(&config, &observations, now);

    assert_eq!(queue[0].target.vhost_name, "earlier");
    assert_eq!(queue[1].target.vhost_name, "later");
}

#[test]
fn retry_backoff_is_capped() {
    let now = UNIX_EPOCH + Duration::from_secs(1_000);

    assert_eq!(
        next_retry_at(now, 0, 300, 86_400),
        UNIX_EPOCH + Duration::from_secs(1_300)
    );
    assert_eq!(
        next_retry_at(now, 20, 300, 86_400),
        UNIX_EPOCH + Duration::from_secs(87_400)
    );
}

#[test]
fn managed_certificate_paths_use_safe_hashed_segment() {
    let storage = PathBuf::from("/var/lib/fluxheim/acme");
    let paths = managed_certificate_paths(&storage, "../Example Host/../../bad");

    assert!(paths.cert_path.starts_with(&storage));
    assert!(paths.key_path.starts_with(&storage));
    assert_eq!(
        paths.cert_path.file_name().and_then(|name| name.to_str()),
        Some("fullchain.pem")
    );
    assert_eq!(
        paths.key_path.file_name().and_then(|name| name.to_str()),
        Some("privkey.pem")
    );
    let relative = paths.cert_path.strip_prefix(&storage).unwrap();
    assert!(
        !relative
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    );
}

#[test]
fn account_credentials_path_uses_safe_hashed_segment() {
    let storage = PathBuf::from("/var/lib/fluxheim/acme");
    let path = account_credentials_path(&storage, "../actalis/../../bad").path;

    assert!(path.starts_with(&storage));
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some("credentials.json")
    );
    let relative = path.strip_prefix(&storage).unwrap();
    assert!(
        !relative
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    );
}

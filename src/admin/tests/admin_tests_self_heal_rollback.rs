use super::*;

#[test]
fn self_healing_fail_rolls_back_to_previous_snapshot() {
    let baseline_config = Config {
        vhosts: vec![VhostConfig {
            name: "baseline".to_owned(),
            hosts: vec!["baseline.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: crate::config::CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };
    let app = app_with_config_and_self_healing(baseline_config.clone(), true);
    let baseline = app
        .store
        .snapshot_config(&baseline_config, Some("baseline"))
        .unwrap();
    let candidate_config = Config {
        vhosts: vec![VhostConfig {
            name: "candidate".to_owned(),
            hosts: vec!["candidate.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: crate::config::CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };
    let candidate = app
        .store
        .snapshot_config(&candidate_config, Some("candidate"))
        .unwrap();
    set_test_runtime_state(
        &app,
        Some(candidate.id.clone()),
        Some(baseline.id.clone()),
        Some(PendingValidation {
            target_snapshot: candidate.id.clone(),
            previous_snapshot: Some(baseline.id.clone()),
            impact: "snapshot".to_owned(),
            expires_unix_secs: 1,
            successful_checks: 0,
            failed_checks: 0,
            rollback_attempts: 0,
            last_rollback_failure: None,
        }),
    );
    app.proxy.reload_from_config(&candidate_config).unwrap();

    let response = app.handle("POST", "/_fluxheim/self-heal/fail", None, &auth_headers());

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(app.store.current_id().unwrap(), Some(baseline.id.clone()));
    assert_eq!(app.proxy.route_host(Some("baseline.test")), "baseline");
    let state = app.runtime_state();
    assert_eq!(state.pending_validation, None);
    assert_eq!(state.known_good_snapshot, Some(baseline.id));
}

#[test]
fn expired_self_healing_validation_rolls_back_fail_closed() {
    let baseline_config = Config {
        vhosts: vec![VhostConfig {
            name: "baseline".to_owned(),
            hosts: vec!["baseline.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: crate::config::CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };
    let app = app_with_config_and_self_healing(baseline_config.clone(), true);
    let baseline = app
        .store
        .snapshot_config(&baseline_config, Some("baseline"))
        .unwrap();
    let candidate_config = Config {
        vhosts: vec![VhostConfig {
            name: "candidate".to_owned(),
            hosts: vec!["candidate.test".to_owned()],
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: crate::config::VhostAcmeChallengeConfig::default(),
            redirect: crate::config::VhostRedirectConfig::default(),
            tls: crate::config::VhostTlsConfig::default(),
            proxy: ProxyConfig::default(),
            cache: crate::config::CacheConfig::default(),
            compression: None,
            headers: crate::config::VhostHeaderPolicyConfig::default(),
            php: crate::config::PhpConfig::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }],
        ..Config::default()
    };
    let candidate = app
        .store
        .snapshot_config(&candidate_config, Some("candidate"))
        .unwrap();
    set_test_runtime_state(
        &app,
        Some(candidate.id.clone()),
        Some(baseline.id.clone()),
        Some(PendingValidation {
            target_snapshot: candidate.id.clone(),
            previous_snapshot: Some(baseline.id.clone()),
            impact: "snapshot".to_owned(),
            expires_unix_secs: 0,
            successful_checks: 0,
            failed_checks: 0,
            rollback_attempts: 0,
            last_rollback_failure: None,
        }),
    );
    app.proxy.reload_from_config(&candidate_config).unwrap();

    let response = app.handle("GET", "/_fluxheim/status", None, &auth_headers());

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(app.store.current_id().unwrap(), Some(baseline.id.clone()));
    assert_eq!(app.proxy.route_host(Some("baseline.test")), "baseline");
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""reason":"expired""#));
    assert!(body.contains(&candidate.id));
    let state = app.runtime_state();
    assert_eq!(state.pending_validation, None);
    assert_eq!(state.known_good_snapshot, Some(baseline.id));
}

#[test]
fn reload_endpoint_rejects_process_upgrade_config() {
    let app = app();
    let new_config = Config {
        server: ServerConfig {
            listen: vec!["127.0.0.1:19081".to_owned()],
            ..ServerConfig::default()
        },
        ..Config::default()
    };
    app.store
        .snapshot_config(&new_config, Some("change listener"))
        .unwrap();

    let response = app.handle("POST", "/_fluxheim/reload", None, &auth_headers());

    assert_eq!(response.status, StatusCode::CONFLICT);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""error":"process_upgrade_required""#));
    assert!(body.contains("listener-changed"));
}

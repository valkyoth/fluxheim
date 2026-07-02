use super::*;

#[test]
fn self_healing_reload_enters_pending_validation() {
    let app = app_with_config_and_self_healing(Config::default(), true);
    let baseline = app
        .store
        .snapshot_config(&Config::default(), Some("baseline"))
        .unwrap();
    set_test_runtime_state(
        &app,
        Some(baseline.id.clone()),
        Some(baseline.id.clone()),
        None,
    );

    let new_config = Config {
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
        .snapshot_config(&new_config, Some("candidate"))
        .unwrap();

    let response = app.handle("POST", "/_fluxheim/reload", None, &auth_headers());

    assert_eq!(response.status, StatusCode::OK);
    let state = app.runtime_state();
    let pending = state.pending_validation.unwrap();
    assert_eq!(state.runtime_snapshot, Some(candidate.id.clone()));
    assert_eq!(state.known_good_snapshot, Some(baseline.id.clone()));
    assert_eq!(pending.target_snapshot, candidate.id);
    assert_eq!(pending.previous_snapshot, Some(baseline.id));
}

#[test]
fn self_healing_confirm_marks_pending_snapshot_known_good() {
    let app = app_with_config_and_self_healing(Config::default(), true);
    let snapshot = app
        .store
        .snapshot_config(&Config::default(), Some("candidate"))
        .unwrap();
    set_test_runtime_state(
        &app,
        None,
        None,
        Some(PendingValidation {
            target_snapshot: snapshot.id.clone(),
            previous_snapshot: None,
            impact: "noop".to_owned(),
            expires_unix_secs: super::super::unix_secs().saturating_add(30),
            successful_checks: 0,
            failed_checks: 0,
        }),
    );

    let response = app.handle(
        "POST",
        "/_fluxheim/self-heal/confirm",
        None,
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let state = app.runtime_state();
    assert_eq!(state.pending_validation, None);
    assert_eq!(state.known_good_snapshot, Some(snapshot.id));
}

#[test]
fn self_healing_report_confirms_after_enough_successes() {
    let mut app = app_with_config_and_self_healing(Config::default(), true);
    app.min_successful_checks = 2;
    let snapshot = app
        .store
        .snapshot_config(&Config::default(), Some("candidate"))
        .unwrap();
    set_test_runtime_state(
        &app,
        None,
        None,
        Some(PendingValidation {
            target_snapshot: snapshot.id.clone(),
            previous_snapshot: None,
            impact: "noop".to_owned(),
            expires_unix_secs: super::super::unix_secs().saturating_add(30),
            successful_checks: 0,
            failed_checks: 0,
        }),
    );

    let response = app.handle(
        "POST",
        "/_fluxheim/self-heal/report",
        Some("health=ok"),
        &auth_headers(),
    );
    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""action":"recorded""#));
    assert_eq!(
        app.runtime_state()
            .pending_validation
            .as_ref()
            .unwrap()
            .successful_checks,
        1
    );

    let response = app.handle(
        "POST",
        "/_fluxheim/self-heal/report",
        Some("success=true"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""action":"confirmed""#));
    let state = app.runtime_state();
    assert_eq!(state.pending_validation, None);
    assert_eq!(state.known_good_snapshot, Some(snapshot.id));
}

#[test]
fn self_healing_report_rolls_back_when_error_rate_exceeds_threshold() {
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
            expires_unix_secs: super::super::unix_secs().saturating_add(30),
            successful_checks: 0,
            failed_checks: 0,
        }),
    );
    app.proxy.reload_from_config(&candidate_config).unwrap();

    let response = app.handle(
        "POST",
        "/_fluxheim/self-heal/report",
        Some("health=error"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""reason":"error-rate""#));
    assert_eq!(app.store.current_id().unwrap(), Some(baseline.id.clone()));
    assert_eq!(app.proxy.route_host(Some("baseline.test")), "baseline");
    let state = app.runtime_state();
    assert_eq!(state.pending_validation, None);
    assert_eq!(state.known_good_snapshot, Some(baseline.id));
}

#[test]
fn watchdog_guard_rolls_back_persisted_error_rate() {
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
            expires_unix_secs: super::super::unix_secs().saturating_add(30),
            successful_checks: 0,
            failed_checks: 1,
        }),
    );
    app.proxy.reload_from_config(&candidate_config).unwrap();

    let response = app.handle("GET", "/_fluxheim/status", None, &auth_headers());

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(app.store.current_id().unwrap(), Some(baseline.id.clone()));
    assert_eq!(app.proxy.route_host(Some("baseline.test")), "baseline");
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains(r#""reason":"error-rate""#));
    assert_eq!(app.runtime_state().known_good_snapshot, Some(baseline.id));
}

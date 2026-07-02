#[cfg(any(feature = "load-balancer", feature = "udp-proxy"))]
use super::*;

#[cfg(feature = "udp-proxy")]
#[test]
fn udp_status_endpoint_reports_route_limits() {
    let mut config = Config::default();
    config.udp = crate::config::UdpConfig {
        enabled: true,
        routes: vec![crate::config::UdpRouteConfig {
            name: "dns-edge".to_owned(),
            mode: crate::config::UdpRouteMode::DnsLoadBalance,
            listen: vec!["127.0.0.1:5353".to_owned()],
            upstream: Some("127.0.0.1:53".to_owned()),
            upstreams: Vec::new(),
            upstream_weights: Vec::new(),
            upstream_aliases: Vec::new(),
            idle_timeout_secs: 30,
            response_timeout_secs: 3,
            max_datagram_bytes: 1232,
            max_sessions: 4096,
            max_sessions_per_source: 64,
            max_responses_per_source_per_second: 256,
            passive_health_enabled: true,
            passive_health_failures: 3,
            passive_health_ejection_secs: 10,
        }],
    };
    let app = app_with_config(config);

    let unauthenticated = app.handle("GET", "/_fluxheim/udp/status", None, &HeaderMap::new());
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);

    let response = app.handle("GET", "/_fluxheim/udp/status", None, &auth_headers());
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["udp"]["enabled"], true);
    assert_eq!(body["udp"]["route_count"], 1);
    let route = &body["udp"]["routes"][0];
    assert_eq!(route["name"], "dns-edge");
    assert_eq!(route["mode"], "dns-load-balance");
    assert_eq!(route["max_datagram_bytes"], 1232);
    assert_eq!(route["max_sessions"], 4096);
    assert_eq!(route["max_sessions_per_source"], 64);
    assert_eq!(route["max_responses_per_source_per_second"], 256);
    assert_eq!(route["passive_health_enabled"], true);
    assert_eq!(route["passive_health_failures"], 3);
    assert_eq!(route["passive_health_ejection_secs"], 10);
    assert_eq!(route["public_exposure_warning"], false);

    let response = app.handle("GET", "/_fluxheim/status", None, &auth_headers());
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["udp"]["route_count"], 1);
}

#[cfg(feature = "load-balancer")]
#[test]
fn load_balancer_status_endpoint_reports_runtime_pools() {
    #[cfg(feature = "tls-rustls-backend")]
    let _ = crate::tls::install_rustls_crypto_provider();

    let app = app_with_config(load_balancer_admin_config());

    let unauthenticated = app.handle(
        "GET",
        "/_fluxheim/load-balancer/status",
        None,
        &HeaderMap::new(),
    );
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);

    let response = app.handle(
        "GET",
        "/_fluxheim/load-balancer/status",
        None,
        &auth_headers(),
    );
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["load_balancer"]["vhosts"][0]["name"], "one");
    assert_eq!(
        body["load_balancer"]["vhosts"][0]["pool"]["backend_count"],
        2
    );
    assert_eq!(
        body["load_balancer"]["vhosts"][0]["pool"]["discovery_mode"],
        "static"
    );
    assert_eq!(
        body["load_balancer"]["vhosts"][0]["pool"]["health_check_protocol"],
        "tcp"
    );
    let discovery = &body["load_balancer"]["vhosts"][0]["pool"]["discovery"];
    assert_eq!(discovery["mode"], "static");
    assert_eq!(discovery["refresh_enabled"], false);
    assert_eq!(discovery["success_count"], 1);
    assert_eq!(discovery["failure_count"], 0);
    assert!(discovery["last_success_unix_secs"].is_number());
    assert_eq!(discovery["last_failure_unix_secs"], Value::Null);
    assert_eq!(discovery["last_error"], Value::Null);

    let wrong_method = app.handle(
        "POST",
        "/_fluxheim/load-balancer/status",
        None,
        &auth_headers(),
    );
    assert_eq!(wrong_method.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[cfg(all(feature = "load-balancer", unix))]
#[test]
fn ops_socket_exposes_load_balancer_status_without_bearer_auth() {
    #[cfg(feature = "tls-rustls-backend")]
    let _ = crate::tls::install_rustls_crypto_provider();

    let app = app_with_config(load_balancer_admin_config());
    let response =
        app.handle_ops_socket("GET", "/_fluxheim/load-balancer/status", None, None, false);

    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["load_balancer"]["vhosts"][0]["name"], "one");
}

#[cfg(feature = "load-balancer")]
#[test]
fn load_balancer_member_state_endpoint_updates_runtime_status() {
    #[cfg(feature = "tls-rustls-backend")]
    let _ = crate::tls::install_rustls_crypto_provider();

    let app = app_with_config(load_balancer_admin_config());
    let response = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-state",
        Some("vhost=one&member=app-a&state=drain"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["vhost"], "one");
    assert_eq!(body["member"], "app-a");
    assert_eq!(body["state"], "drained");
    assert_eq!(body["scope"], "vhost");
    #[cfg(not(feature = "privacy-mode"))]
    assert_eq!(body["address"], "127.0.0.1:3001");
    #[cfg(feature = "privacy-mode")]
    assert_eq!(body["address"], Value::Null);
    assert_eq!(body["alias"], "app-a");
    assert_eq!(body["persistent"], false);

    let response = app.handle("GET", "/_fluxheim/status", None, &auth_headers());
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    let pool = &body["load_balancer"]["vhosts"][0]["pool"];
    assert_eq!(pool["drained_backend_count"], 1);
    assert_eq!(pool["runtime_overridden_backend_count"], 1);
    assert_eq!(pool["runtime_drained_backend_count"], 1);
    assert_eq!(pool["runtime_disabled_backend_count"], 0);
    assert_eq!(pool["runtime_forced_down_backend_count"], 0);
    assert_eq!(pool["primary_available_backend_count"], 1);
    let app_a = pool["backends"]
        .as_array()
        .unwrap()
        .iter()
        .find(|backend| backend["alias"] == "app-a")
        .expect("app-a backend status");
    assert_eq!(
        app_a["runtime_state_override"],
        Value::String("drained".to_owned())
    );

    let response = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-state",
        Some("vhost=one&member=app-b&state=forced_down"),
        &auth_headers(),
    );
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["state"], "forced_down");

    let response = app.handle("GET", "/_fluxheim/status", None, &auth_headers());
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    let pool = &body["load_balancer"]["vhosts"][0]["pool"];
    assert_eq!(pool["runtime_forced_down_backend_count"], 1);
    assert_eq!(pool["primary_available_backend_count"], 0);
    let app_b = pool["backends"]
        .as_array()
        .unwrap()
        .iter()
        .find(|backend| backend["alias"] == "app-b")
        .expect("app-b backend status");
    assert_eq!(
        app_b["runtime_state_override"],
        Value::String("forced_down".to_owned())
    );
}

#[cfg(feature = "load-balancer")]
#[test]
fn load_balancer_member_weight_endpoint_updates_runtime_status() {
    #[cfg(feature = "tls-rustls-backend")]
    let _ = crate::tls::install_rustls_crypto_provider();

    let app = app_with_config(load_balancer_admin_config());
    let response = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-weight",
        Some("vhost=one&member=app-a&weight=7"),
        &auth_headers(),
    );

    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["vhost"], "one");
    assert_eq!(body["member"], "app-a");
    assert_eq!(body["configured_weight"], 1);
    assert_eq!(body["effective_weight"], 7);
    assert_eq!(body["runtime_weight_override"], 7);
    assert_eq!(body["persistent"], false);

    let response = app.handle("GET", "/_fluxheim/status", None, &auth_headers());
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    let pool = &body["load_balancer"]["vhosts"][0]["pool"];
    let app_a = pool["backends"]
        .as_array()
        .unwrap()
        .iter()
        .find(|backend| backend["alias"] == "app-a")
        .expect("app-a backend status");
    assert_eq!(app_a["weight"], 1);
    assert_eq!(app_a["effective_weight"], 7);
    assert_eq!(app_a["runtime_weight_override"], 7);
    assert!(app_a["runtime_weight_changed_at_unix_secs"].is_number());

    let response = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-weight",
        Some("vhost=one&member=app-a&weight=reset"),
        &auth_headers(),
    );
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["effective_weight"], 1);
    assert_eq!(body["runtime_weight_override"], Value::Null);
}

#[cfg(feature = "load-balancer")]
#[test]
fn load_balancer_member_set_endpoints_mutate_static_pool() {
    #[cfg(feature = "tls-rustls-backend")]
    let _ = crate::tls::install_rustls_crypto_provider();

    let app = app_with_config(load_balancer_admin_config());
    let added = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-add",
        Some("vhost=one&member=127.0.0.1:3003&weight=2"),
        &auth_headers(),
    );
    assert_eq!(added.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&added.body).unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["operation"], "added");
    #[cfg(not(feature = "privacy-mode"))]
    assert_eq!(body["member"], "127.0.0.1:3003");
    #[cfg(feature = "privacy-mode")]
    assert_eq!(body["member"], "redacted");
    assert_eq!(body["configured_weight"], 2);
    assert_eq!(body["backend_count"], 3);
    assert_eq!(body["persistent"], false);

    let updated = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-update",
        Some("vhost=one&member=127.0.0.1:3003&weight=4"),
        &auth_headers(),
    );
    assert_eq!(updated.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&updated.body).unwrap();
    assert_eq!(body["operation"], "updated");
    assert_eq!(body["configured_weight"], 4);
    assert_eq!(body["backend_count"], 3);

    let status = app.handle("GET", "/_fluxheim/status", None, &auth_headers());
    assert_eq!(status.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&status.body).unwrap();
    let pool = &body["load_balancer"]["vhosts"][0]["pool"];
    assert_eq!(pool["backend_count"], 3);
    #[cfg(not(feature = "privacy-mode"))]
    {
        let added_backend = pool["backends"]
            .as_array()
            .unwrap()
            .iter()
            .find(|backend| backend["address"] == "127.0.0.1:3003")
            .expect("added backend status");
        assert_eq!(added_backend["weight"], 4);
    }
    #[cfg(feature = "privacy-mode")]
    assert!(
        pool["backends"].as_array().unwrap().iter().all(|backend| {
            backend["address"].is_null() && backend["member"] != "127.0.0.1:3003"
        })
    );

    let removed = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-remove",
        Some("vhost=one&member=127.0.0.1:3003"),
        &auth_headers(),
    );
    assert_eq!(removed.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&removed.body).unwrap();
    assert_eq!(body["operation"], "removed");
    assert_eq!(body["backend_count"], 2);

    let status = app.handle("GET", "/_fluxheim/status", None, &auth_headers());
    assert_eq!(status.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&status.body).unwrap();
    assert_eq!(
        body["load_balancer"]["vhosts"][0]["pool"]["backend_count"],
        2
    );
}

#[cfg(feature = "load-balancer")]
#[test]
fn load_balancer_mutation_endpoints_report_persistent_state_file() {
    #[cfg(feature = "tls-rustls-backend")]
    let _ = crate::tls::install_rustls_crypto_provider();

    let app = app_with_config(load_balancer_persistent_admin_config());

    let response = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-state",
        Some("vhost=one&member=app-a&state=disable"),
        &auth_headers(),
    );
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["persistent"], true);

    let response = app.handle(
        "POST",
        "/_fluxheim/load-balancer/member-weight",
        Some("vhost=one&member=app-a&weight=5"),
        &auth_headers(),
    );
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["persistent"], true);

    let response = app.handle(
        "POST",
        "/_fluxheim/load-balancer/persistence/clear",
        Some("vhost=one"),
        &auth_headers(),
    );
    assert_eq!(response.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["persistent"], true);
}

use super::*;

#[path = "load_balanced_retry_support.rs"]
mod support;
use support::*;
#[path = "load_balanced_retry_cache.rs"]
mod cache_tests;
#[path = "load_balanced_retry_downstream_h2.rs"]
mod downstream_h2_tests;
#[path = "load_balanced_latency.rs"]
mod latency_tests;
#[path = "load_balanced_retry_lifecycle.rs"]
mod lifecycle_tests;

#[tokio::test]
async fn native_load_balanced_retry_switch_and_count_control_status_and_transport_failures() {
    for transport_failure in [false, true] {
        for (enabled, max_retries, expected_calls, expected_status) in [
            (false, 10, 1, if transport_failure { 502 } else { 503 }),
            (true, 0, 1, if transport_failure { 502 } else { 503 }),
            (true, 1, 2, if transport_failure { 502 } else { 503 }),
            (true, 2, 3, 200),
            (true, 10, 3, 200),
        ] {
            let failure = if transport_failure {
                String::new()
            } else {
                reply(503, "")
            };
            let origins = origins(&[failure.clone(), failure, reply(200, "")]).await;
            let mut config = config(&origins);
            config.upstream_priority_groups = vec![30, 20, 10];
            config.load_balance.retry.enabled = enabled;
            config.load_balance.retry.max_retries = max_retries;
            let proxy = proxy(&config);
            let response = dispatch(&proxy, native_proxy_test_request()).await;
            assert_eq!(response.status(), expected_status);
            assert_eq!(calls(&origins), expected_calls);
            assert_eq!(
                proxy
                    .load_balancer
                    .as_ref()
                    .unwrap()
                    .runtime_stats()
                    .retry
                    .admitted,
                (expected_calls - 1) as u64
            );
        }
    }
}

#[tokio::test]
async fn native_load_balanced_retry_http2_status_and_reset_obey_pool_policy() {
    for status in [0, 503] {
        for enabled in [false, true] {
            let origins = h2_origins(&[status, 200]).await;
            let mut config = config(&origins);
            config.load_balance.retry.enabled = enabled;
            config.upstream_http_version = fluxheim_config::UpstreamHttpVersion::Http2;
            let proxy = proxy(&config);
            let response = dispatch(&proxy, native_proxy_test_request()).await;
            assert_eq!(
                response.status(),
                if enabled {
                    200
                } else if status == 0 {
                    502
                } else {
                    503
                }
            );
            assert_eq!(calls(&origins), if enabled { 2 } else { 1 });
            assert_eq!(
                origins[0].count.load(Ordering::SeqCst),
                1,
                "no hidden H2 replay"
            );
            assert_eq!(
                proxy
                    .load_balancer
                    .as_ref()
                    .unwrap()
                    .runtime_stats()
                    .retry
                    .admitted,
                u64::from(enabled)
            );
        }
    }
}

#[tokio::test]
async fn native_load_balanced_retry_without_alternative_keeps_response_and_refunds_budget() {
    let origins = origins(&[reply(503, "X-Original: yes\r\n"), reply(200, "")]).await;
    let mut config = config(&origins);
    config.disabled_upstreams = vec![origins[1].address.to_string()];
    config.load_balance.retry.budget_per_window = 1;
    let proxy = proxy(&config);
    let response = dispatch(&proxy, native_proxy_test_request()).await;
    assert_eq!(response.status(), 503);
    assert_eq!(calls(&origins), 1);
    let pool = proxy.load_balancer.as_ref().unwrap();
    assert_eq!(pool.runtime_stats().retry.admitted, 0);
    assert!(pool.retry_sequence("GET", true).reserve(None).is_some());
}

#[tokio::test]
async fn native_load_balanced_retry_methods_bodies_trailers_and_upgrades_are_gated() {
    for (method, body, extra, expected) in [
        ("GET", "", None, 2),
        ("HEAD", "", None, 1),
        ("POST", "", None, 1),
        ("POST", "data", None, 1),
        ("GET", "data", None, 1),
        ("CONNECT", "", None, 0),
        ("GET", "", Some(("Upgrade", "websocket")), 1),
        ("GET", "", Some(("Connection", "keep-alive, Upgrade")), 1),
    ] {
        let origins = origins(&[reply(503, ""), reply(200, "")]).await;
        let mut config = config(&origins);
        config.load_balance.retry.methods = vec!["GET".into(), "POST".into(), "CONNECT".into()];
        let mut request = native_proxy_test_request();
        request.method = method.into();
        request.body = crate::NativeHttp1RequestBody::from_vec(body.as_bytes().to_vec());
        if let Some((name, value)) = extra {
            request.headers.push((name.into(), value.into()));
        }
        let _ = dispatch(&proxy(&config), request).await;
        assert_eq!(calls(&origins), expected, "{method} {body} {extra:?}");
    }
    let origins = origins(&[reply(503, ""), reply(200, "")]).await;
    let mut request = native_proxy_test_request();
    request.trailers.push(("x-test".into(), "data".into()));
    dispatch(&proxy(&config(&origins)), request).await;
    assert_eq!(calls(&origins), 1);
}

#[tokio::test]
async fn native_load_balanced_retry_status_ranges_preserve_unmatched_response() {
    for (status, expected) in [(500, 1), (502, 2), (503, 2), (504, 2), (505, 1), (429, 1)] {
        let origins = origins(&[reply(status, "X-Original: yes\r\n"), reply(200, "")]).await;
        let mut config = config(&origins);
        config.load_balance.retry.statuses.clear();
        config.load_balance.retry.status_ranges =
            vec![fluxheim_config::LoadBalanceHealthCheckExpectedStatusRange {
                start: 502,
                end: 504,
            }];
        let response = dispatch(&proxy(&config), native_proxy_test_request()).await;
        assert_eq!(calls(&origins), expected);
        assert_eq!(response.status(), if expected == 2 { 200 } else { status });
        if expected == 1 {
            assert!(
                response
                    .headers()
                    .iter()
                    .any(|(name, value)| name.eq_ignore_ascii_case("x-original") && value == "yes")
            );
        }
    }
}

#[tokio::test]
async fn native_load_balanced_retry_budget_is_shared_under_concurrency() {
    let origins = origins(&[reply(503, ""), reply(503, "")]).await;
    let mut config = config(&origins);
    config.load_balance.retry.budget_per_window = 3;
    config.load_balance.retry.budget_window_secs = 3600;
    let proxy = proxy(&config);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let proxy = proxy.clone();
        tasks.spawn(async move { dispatch(&proxy, native_proxy_test_request()).await.status() });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), 503);
    }
    assert_eq!(calls(&origins), 19);
    dispatch(&proxy, native_proxy_test_request()).await;
    assert_eq!(calls(&origins), 20);
}

#[tokio::test]
async fn native_load_balanced_retry_budget_recovers_after_window_expiry() {
    let origins = origins(&[reply(503, ""), reply(503, "")]).await;
    let mut config = config(&origins);
    config.load_balance.retry.budget_per_window = 1;
    config.load_balance.retry.budget_window_secs = 1;
    let proxy = proxy(&config);
    dispatch(&proxy, native_proxy_test_request()).await;
    assert_eq!(calls(&origins), 2);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    dispatch(&proxy, native_proxy_test_request()).await;
    assert_eq!(calls(&origins), 4);
}

#[tokio::test]
async fn native_load_balanced_retry_excludes_persisted_member_and_releases_capacity() {
    let origins = origins(&[reply(503, ""), reply(200, "")]).await;
    let mut config = config(&origins);
    config.upstream_max_in_flight = vec![1, 1];
    config.load_balance.persistence.enabled = true;
    config.load_balance.persistence.mode = fluxheim_config::LoadBalancePersistenceMode::Header;
    config.load_balance.persistence.header = Some("x-session".into());
    let proxy = proxy(&config);
    let mut request = native_proxy_test_request();
    request.headers.push(("x-session".into(), "one".into()));
    assert_eq!(
        dispatch(&proxy, request.metadata_snapshot()).await.status(),
        200
    );
    assert_eq!(calls(&origins), 2);
    assert_eq!(dispatch(&proxy, request).await.status(), 200);
    assert_eq!(origins[0].count.load(Ordering::SeqCst), 1);
    assert!(
        proxy
            .load_balancer
            .as_ref()
            .unwrap()
            .runtime_stats()
            .backends
            .iter()
            .all(|backend| backend.in_flight == 0)
    );
}

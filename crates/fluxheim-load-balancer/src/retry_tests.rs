use fluxheim_config::{
    LoadBalanceHealthCheckExpectedStatusRange, LoadBalanceRetryConfig, ProxyConfig,
};

use super::*;

fn pool(config: LoadBalanceRetryConfig) -> UpstreamLoadBalancer {
    let mut proxy = ProxyConfig {
        upstreams: vec!["127.0.0.1:3000".into(), "127.0.0.1:3001".into()],
        ..ProxyConfig::default()
    };
    proxy.load_balance.retry = config;
    UpstreamLoadBalancer::from_proxy_config(&proxy)
        .unwrap()
        .unwrap()
}

fn enabled() -> LoadBalanceRetryConfig {
    LoadBalanceRetryConfig {
        enabled: true,
        max_retries: 2,
        ..LoadBalanceRetryConfig::default()
    }
}

#[test]
fn disabled_zero_and_invalid_retry_limits_deny_admission() {
    for config in [
        LoadBalanceRetryConfig::default(),
        LoadBalanceRetryConfig {
            max_retries: 0,
            ..enabled()
        },
        LoadBalanceRetryConfig {
            max_retries: 11,
            ..enabled()
        },
    ] {
        let pool = pool(config);
        assert!(pool.retry_sequence("GET", true).reserve(None).is_none());
    }
}

#[test]
fn safe_methods_require_explicit_membership_and_replay_safety() {
    let pool = pool(LoadBalanceRetryConfig {
        methods: vec!["GET".into(), "POST".into(), "CONNECT".into(), "get".into()],
        ..enabled()
    });
    assert!(pool.retry_sequence("GET", true).reserve(None).is_some());
    for method in [
        "HEAD", "OPTIONS", "TRACE", "POST", "PUT", "CONNECT", "get", "",
    ] {
        assert!(
            pool.retry_sequence(method, true).reserve(None).is_none(),
            "{method}"
        );
    }
    assert!(pool.retry_sequence("GET", false).reserve(None).is_none());
}

#[test]
fn all_safe_methods_can_be_enabled() {
    let methods = ["GET", "HEAD", "OPTIONS", "TRACE"];
    let pool = pool(LoadBalanceRetryConfig {
        methods: methods.map(str::to_owned).into(),
        ..enabled()
    });
    for method in methods {
        assert!(pool.retry_sequence(method, true).reserve(None).is_some());
    }
}

#[test]
fn only_configured_server_errors_are_retryable() {
    let transport_only = pool(enabled());
    assert!(
        transport_only
            .retry_sequence("GET", true)
            .reserve(Some(503))
            .is_none()
    );
    let pool = pool(LoadBalanceRetryConfig {
        statuses: vec![503, 200],
        status_ranges: vec![
            LoadBalanceHealthCheckExpectedStatusRange {
                start: 510,
                end: 512,
            },
            LoadBalanceHealthCheckExpectedStatusRange {
                start: 400,
                end: 599,
            },
            LoadBalanceHealthCheckExpectedStatusRange {
                start: 520,
                end: 519,
            },
        ],
        ..enabled()
    });
    for status in 100..=600 {
        assert_eq!(
            pool.retry_sequence("GET", true)
                .reserve(Some(status))
                .is_some(),
            matches!(status, 503 | 510..=512),
            "status {status}",
        );
    }
    assert!(pool.retry_sequence("GET", true).reserve(None).is_some());
}

#[test]
fn request_limit_counts_committed_retries_not_initial_or_dropped_reservations() {
    let pool = pool(LoadBalanceRetryConfig {
        max_retries: 10,
        ..enabled()
    });
    let mut sequence = pool.retry_sequence("GET", true);
    for _ in 0..20 {
        drop(sequence.reserve(None).unwrap());
    }
    for _ in 0..10 {
        sequence.reserve(None).unwrap().commit();
    }
    assert!(sequence.reserve(None).is_none());
    // A new request has its own per-request cap.
    assert!(pool.retry_sequence("GET", true).reserve(None).is_some());
}

#[test]
fn cloned_pools_share_budget_but_separately_constructed_pools_do_not() {
    let config = LoadBalanceRetryConfig {
        budget_per_window: 1,
        budget_window_secs: 3600,
        ..enabled()
    };
    let pool_a = pool(config.clone());
    let pool_b = pool_a.clone();
    pool_a
        .retry_sequence("GET", true)
        .reserve(None)
        .unwrap()
        .commit();
    assert!(pool_b.retry_sequence("GET", true).reserve(None).is_none());
    assert!(
        pool(config)
            .retry_sequence("GET", true)
            .reserve(None)
            .is_some()
    );
}

#[test]
fn unused_candidate_reservation_preserves_request_and_pool_capacity() {
    let pool = pool(LoadBalanceRetryConfig {
        budget_per_window: 1,
        ..enabled()
    });
    let mut sequence = pool.retry_sequence("GET", true);
    let permit = sequence.reserve(None).unwrap();
    assert!(pool.retry_sequence("GET", true).reserve(None).is_none());
    drop(permit);
    assert_eq!(pool.runtime_stats().retry.admitted, 0);
    assert_eq!(sequence.remaining, 2);
    sequence.reserve(None).unwrap().commit();
    assert_eq!(pool.runtime_stats().retry.admitted, 1);
    assert_eq!(sequence.remaining, 1);
    assert!(pool.retry_sequence("GET", true).reserve(None).is_none());
}

#[tokio::test]
async fn cancelled_task_returns_uncommitted_reservation() {
    let pool = pool(LoadBalanceRetryConfig {
        budget_per_window: 1,
        ..enabled()
    });
    let task_pool = pool.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut sequence = task_pool.retry_sequence("GET", true);
        let _reservation = sequence.reserve(None).unwrap();
        ready_tx.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    ready_rx.await.unwrap();
    assert!(pool.retry_sequence("GET", true).reserve(None).is_none());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(pool.retry_sequence("GET", true).reserve(None).is_some());
}

#[test]
fn rejected_method_and_status_do_not_consume_pool_capacity() {
    let pool = pool(LoadBalanceRetryConfig {
        budget_per_window: 1,
        ..enabled()
    });
    assert!(pool.retry_sequence("POST", true).reserve(None).is_none());
    assert!(pool.retry_sequence("GET", false).reserve(None).is_none());
    assert!(
        pool.retry_sequence("GET", true)
            .reserve(Some(503))
            .is_none()
    );
    assert!(pool.retry_sequence("GET", true).reserve(None).is_some());
}

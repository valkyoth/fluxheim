use super::*;
use crate::backend::FluxBackend;

#[test]
fn slow_start_zero_duration_permits_without_division() {
    let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
    let state = SlowStartState::from_config(&LoadBalanceSlowStartConfig {
        enabled: true,
        duration_secs: 0,
    });

    assert!(state.permits(&backend));
    assert!(state.permits_read_only(&backend));
}

#[test]
fn latency_ewma_rounds_instead_of_sticking_on_fractional_update() {
    let state = BackendLatencyState::default();

    state.record_latency(1, Duration::from_micros(1000));
    state.record_latency(1, Duration::from_micros(1003));

    assert_eq!(state.score_key(1), Some(1001));
}

#[test]
fn latency_samples_expire_for_selection_but_remain_visible_until_resampled() {
    let backend = FluxBackend::new("127.0.0.1:3000").unwrap();
    let key = backend_key(&backend);
    let state = BackendLatencyState::default();
    assert_eq!(state.score(&backend), None);
    state.record_latency(key, Duration::from_millis(200));
    assert_eq!(state.score(&backend), Some(200_000));
    state
        .latency_micros
        .lock()
        .unwrap()
        .get_mut(&key)
        .unwrap()
        .observed_at = Instant::now() - LATENCY_RESAMPLE_AFTER;
    assert_eq!(state.score(&backend), None);
    assert_eq!(state.score_key(key), Some(200_000));
    state.record_latency(key, Duration::from_millis(1));
    assert_eq!(state.score(&backend), Some(1000));
    state.prune_stale(&std::collections::HashSet::new());
    assert_eq!(state.score_key(key), None);
}

#[test]
fn latency_samples_clamp_and_average_without_overflow() {
    let state = BackendLatencyState::default();
    state.record_latency(1, Duration::ZERO);
    assert_eq!(state.score_key(1), Some(1));
    state.record_latency(2, Duration::MAX);
    state.record_latency(2, Duration::MAX);
    assert_eq!(state.score_key(2), Some(u64::MAX));
}

#[test]
fn passive_latency_threshold_is_inclusive_and_zero_disables_it() {
    let mut config = LoadBalancePassiveHealthConfig {
        max_latency_ms: 100,
        ..Default::default()
    };
    let state = PassiveHealthState::from_config(&config);
    assert!(!state.status_is_failure(200, Some(Duration::from_micros(99_999))));
    assert!(state.status_is_failure(200, Some(Duration::from_millis(100))));
    assert!(state.status_is_failure(200, Some(Duration::from_millis(101))));
    assert!(!state.status_is_failure(200, None));
    config.max_latency_ms = 0;
    let state = PassiveHealthState::from_config(&config);
    assert!(!state.status_is_failure(200, Some(Duration::MAX)));
}

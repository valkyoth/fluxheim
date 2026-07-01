use super::*;

#[test]
fn runtime_backend_policy_overrides_prune_only_transient_drain_keys() {
    let policy = BackendSelectionPolicy::default();
    policy.set_runtime_backend_state(1, LoadBalancerRuntimeBackendState::Drained);
    policy.set_runtime_backend_state(2, LoadBalancerRuntimeBackendState::Disabled);
    policy.set_runtime_backend_state(3, LoadBalancerRuntimeBackendState::ForcedDown);

    assert_eq!(
        policy.runtime_backend_state(1),
        Some(LoadBalancerRuntimeBackendState::Drained)
    );
    assert_eq!(
        policy.runtime_backend_state(2),
        Some(LoadBalancerRuntimeBackendState::Disabled)
    );
    assert_eq!(
        policy.runtime_backend_state(3),
        Some(LoadBalancerRuntimeBackendState::ForcedDown)
    );
    assert!(
        policy
            .runtime_backend_state_changed_at_unix_secs(1)
            .is_some()
    );

    policy.prune_stale(&[2].into_iter().collect());

    assert_eq!(policy.runtime_backend_state(1), None);
    assert_eq!(
        policy.runtime_backend_state(2),
        Some(LoadBalancerRuntimeBackendState::Disabled)
    );
    assert_eq!(
        policy.runtime_backend_state(3),
        Some(LoadBalancerRuntimeBackendState::ForcedDown)
    );
    assert_eq!(policy.runtime_backend_state_changed_at_unix_secs(1), None);
    assert!(
        policy
            .runtime_backend_state_changed_at_unix_secs(2)
            .is_some()
    );
    assert!(
        policy
            .runtime_backend_state_changed_at_unix_secs(3)
            .is_some()
    );
}

#[test]
fn runtime_backend_policy_prune_stale_runtime_weight_keys() {
    let policy = BackendSelectionPolicy::default();
    policy.set_runtime_backend_weight(1, Some(4));
    policy.set_runtime_backend_weight(2, Some(8));

    assert_eq!(policy.runtime_backend_weight(1), Some(4));
    assert_eq!(policy.runtime_backend_weight(2), Some(8));

    policy.prune_stale(&[2].into_iter().collect());

    assert_eq!(policy.runtime_backend_weight(1), None);
    assert_eq!(policy.runtime_backend_weight(2), Some(8));
    assert_eq!(policy.runtime_backend_weight_changed_at_unix_secs(1), None);
    assert!(
        policy
            .runtime_backend_weight_changed_at_unix_secs(2)
            .is_some()
    );
}

#[test]
fn health_derived_weight_reduces_effective_weight_and_prunes() {
    let policy = BackendSelectionPolicy::default();
    let backend = FluxBackend::new_with_weight("127.0.0.1:3000", 10).unwrap();
    let key = backend_key(&backend);

    assert_eq!(policy.effective_weight(&backend), 10);
    policy.health_weights().set_percent(key, Some(40));
    assert_eq!(policy.health_weight_percent(key), Some(40));
    assert_eq!(policy.effective_weight(&backend), 4);

    policy.health_weights().set_percent(key, Some(100));
    assert_eq!(policy.health_weight_percent(key), None);
    assert_eq!(policy.effective_weight(&backend), 10);

    policy.health_weights().set_percent(key, Some(50));
    policy.prune_stale(&std::collections::HashSet::new());
    assert_eq!(policy.health_weight_percent(key), None);
}

#[test]
fn runtime_backend_policy_keeps_weight_for_disabled_churned_backend() {
    let policy = BackendSelectionPolicy::default();
    assert!(policy.set_runtime_backend_state(1, LoadBalancerRuntimeBackendState::Disabled));
    assert!(policy.set_runtime_backend_weight(1, Some(4)));

    policy.prune_stale(&std::collections::HashSet::new());

    assert_eq!(
        policy.runtime_backend_state(1),
        Some(LoadBalancerRuntimeBackendState::Disabled)
    );
    assert_eq!(policy.runtime_backend_weight(1), Some(4));
    assert!(
        policy
            .runtime_backend_weight_changed_at_unix_secs(1)
            .is_some()
    );

    assert!(policy.set_runtime_backend_state(1, LoadBalancerRuntimeBackendState::Normal));
    policy.prune_stale(&std::collections::HashSet::new());

    assert_eq!(policy.runtime_backend_state(1), None);
    assert_eq!(policy.runtime_backend_weight(1), None);
    assert_eq!(policy.runtime_backend_weight_changed_at_unix_secs(1), None);
}

#[test]
fn runtime_backend_policy_rejects_oversized_persistent_override_table() {
    let policy = BackendSelectionPolicy::default();
    for key in 0..MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES as u64 {
        assert!(policy.set_runtime_backend_state(key, LoadBalancerRuntimeBackendState::Disabled));
    }

    assert!(!policy.set_runtime_backend_state(
        MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES as u64,
        LoadBalancerRuntimeBackendState::Disabled
    ));
    assert!(policy.set_runtime_backend_state(0, LoadBalancerRuntimeBackendState::ForcedDown));
    assert!(policy.set_runtime_backend_state(0, LoadBalancerRuntimeBackendState::Normal));
    assert!(policy.set_runtime_backend_state(
        MAX_RUNTIME_BACKEND_POLICY_OVERRIDE_ENTRIES as u64,
        LoadBalancerRuntimeBackendState::Disabled
    ));
}

#[test]
fn runtime_backend_policy_snapshot_restores_overrides_atomically() {
    let policy = BackendSelectionPolicy::default();
    assert!(policy.set_runtime_backend_state(10, LoadBalancerRuntimeBackendState::Disabled));
    assert!(policy.set_runtime_backend_state(20, LoadBalancerRuntimeBackendState::ForcedDown));
    assert!(policy.set_runtime_backend_weight(10, Some(7)));

    let snapshot = policy.runtime_snapshot();
    let restored = BackendSelectionPolicy::default();
    restored.restore_runtime_snapshot(&snapshot).unwrap();

    assert_eq!(
        restored.runtime_backend_state(10),
        Some(LoadBalancerRuntimeBackendState::Disabled)
    );
    assert_eq!(
        restored.runtime_backend_state(20),
        Some(LoadBalancerRuntimeBackendState::ForcedDown)
    );
    assert_eq!(restored.runtime_backend_weight(10), Some(7));
}

#[test]
fn runtime_backend_policy_rejects_invalid_snapshot_before_replacing() {
    let policy = BackendSelectionPolicy::default();
    assert!(policy.set_runtime_backend_state(10, LoadBalancerRuntimeBackendState::Disabled));

    let invalid = RuntimeBackendPolicySnapshot {
        states: vec![RuntimeBackendPolicyStateSnapshot {
            key: 20,
            state: LoadBalancerRuntimeBackendState::Normal,
            changed_at_unix_secs: 0,
        }],
        weights: Vec::new(),
    };

    assert!(policy.restore_runtime_snapshot(&invalid).is_err());
    assert_eq!(
        policy.runtime_backend_state(10),
        Some(LoadBalancerRuntimeBackendState::Disabled)
    );
}

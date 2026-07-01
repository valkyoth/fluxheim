use super::{
    LoadBalancerBackendRuntimeStats, LoadBalancerCircuitState, LoadBalancerDiscoveryRuntimeStats,
    LoadBalancerPersistenceRuntimeStats, LoadBalancerPoolRuntimeStats,
    LoadBalancerQueueRuntimeStats, LoadBalancerRuntimeBackendState, UpstreamLoadBalancer,
};

impl UpstreamLoadBalancer {
    pub fn runtime_stats(&self) -> LoadBalancerPoolRuntimeStats {
        let health_check_frequency = self.inner.health_check_frequency();
        let live_policy_keys = self.live_backend_keys();
        let (persistence_entry_count, persistence_backend_entry_counts) = self
            .persistence
            .as_ref()
            .map_or((0, std::collections::HashMap::new()), |persistence| {
                persistence.runtime_counts_for_live_backends(Some(&live_policy_keys))
            });
        let backends = self.inner.backend_stats(
            &self.backend_aliases,
            self.passive_health.as_deref(),
            self.slow_start.as_deref(),
            &self.counters,
            &self.backend_policy,
            &persistence_backend_entry_counts,
        );
        let ready_backend_count = backends.iter().filter(|backend| backend.ready).count();
        let eligible_backend_count = backends
            .iter()
            .filter(|backend| backend_runtime_status_eligible(backend))
            .count();
        let primary_available_backend_count = backends
            .iter()
            .filter(|backend| !backend.backup && backend_runtime_status_eligible(backend))
            .count();
        let backup_available_backend_count = backends
            .iter()
            .filter(|backend| backend.backup && backend_runtime_status_eligible(backend))
            .count();
        let drained_backend_count = backends.iter().filter(|backend| backend.drained).count();
        let disabled_backend_count = backends.iter().filter(|backend| backend.disabled).count();
        let runtime_overridden_backend_count = backends
            .iter()
            .filter(|backend| backend.runtime_state_override.is_some())
            .count();
        let runtime_drained_backend_count = backends
            .iter()
            .filter(|backend| {
                backend.runtime_state_override == Some(LoadBalancerRuntimeBackendState::Drained)
            })
            .count();
        let runtime_disabled_backend_count = backends
            .iter()
            .filter(|backend| {
                backend.runtime_state_override == Some(LoadBalancerRuntimeBackendState::Disabled)
            })
            .count();
        let runtime_forced_down_backend_count = backends
            .iter()
            .filter(|backend| {
                backend.runtime_state_override == Some(LoadBalancerRuntimeBackendState::ForcedDown)
            })
            .count();
        let passive_ejected_backend_count = backends
            .iter()
            .filter(|backend| backend.passive_ejected)
            .count();
        let circuit_open_backend_count = backends
            .iter()
            .filter(|backend| backend.circuit_state == LoadBalancerCircuitState::Open)
            .count();
        let saturated_backend_count = backends
            .iter()
            .filter(|backend| {
                backend
                    .max_in_flight
                    .is_some_and(|limit| backend.in_flight >= limit)
            })
            .count();
        let discovery = LoadBalancerDiscoveryRuntimeStats::from_runtime_status(
            self.discovery_mode,
            self.inner.discovery_runtime_status(),
        );
        LoadBalancerPoolRuntimeStats {
            discovery_mode: self.discovery_mode,
            discovery,
            selection: self.selection,
            backend_count: self.inner.backend_count(),
            ready_backend_count,
            available_backend_count: eligible_backend_count,
            primary_available_backend_count,
            backup_available_backend_count,
            drained_backend_count,
            disabled_backend_count,
            runtime_overridden_backend_count,
            runtime_drained_backend_count,
            runtime_disabled_backend_count,
            runtime_forced_down_backend_count,
            passive_ejected_backend_count,
            circuit_open_backend_count,
            saturated_backend_count,
            max_iterations: self.max_iterations,
            all_down_status: self.all_down_status,
            health_check_enabled: health_check_frequency.is_some(),
            health_check_protocol: self.health_check_protocol,
            health_check_frequency_secs: health_check_frequency
                .map(|frequency| frequency.as_secs()),
            parallel_health_check: self.inner.parallel_health_check(),
            passive_health_enabled: self.passive_health.is_some(),
            slow_start_enabled: self.slow_start.is_some(),
            persistence_enabled: self.persistence.is_some(),
            passive_health: self.passive_health_policy.clone(),
            slow_start: self.slow_start_policy.clone(),
            persistence: LoadBalancerPersistenceRuntimeStats::from_policy(
                self.persistence.as_deref(),
                &self.persistence_policy,
                persistence_entry_count,
            ),
            queue: LoadBalancerQueueRuntimeStats::from_policy(
                &self.queue_policy,
                &self.queue_waiting,
            ),
            retry: self.retry.clone(),
            backends,
        }
    }
}

fn backend_runtime_status_eligible(backend: &LoadBalancerBackendRuntimeStats) -> bool {
    backend.ready
        && !backend.disabled
        && !backend.drained
        && !backend.passive_ejected
        && backend.slow_start_permitting
        && backend
            .max_in_flight
            .is_none_or(|limit| backend.in_flight < limit)
}

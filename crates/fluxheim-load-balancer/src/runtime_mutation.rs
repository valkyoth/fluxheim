use std::io;
use std::time::Instant;

use super::inner::runtime_backend_from_member;
use super::key::backend_key;
use super::{
    LoadBalancerRuntimeBackendMutation, LoadBalancerRuntimeBackendSetMutation,
    LoadBalancerRuntimeBackendSetOperation, LoadBalancerRuntimeBackendState,
    LoadBalancerRuntimeBackendWeightMutation, UpstreamLoadBalancer,
};

impl UpstreamLoadBalancer {
    pub fn set_runtime_backend_state(
        &self,
        member: &str,
        state: LoadBalancerRuntimeBackendState,
    ) -> io::Result<LoadBalancerRuntimeBackendMutation> {
        let backend = self
            .inner
            .backend_by_member(member, &self.backend_aliases)?;
        let key = backend_key(&backend);
        if !self.backend_policy.set_runtime_backend_state(key, state) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "load balancer runtime override table is full",
            ));
        }
        if state == LoadBalancerRuntimeBackendState::ManualResume {
            if let Some(passive_health) = &self.passive_health {
                passive_health.clear_key(key);
            }
            if let Some(slow_start) = &self.slow_start {
                slow_start.reset_at(key, Instant::now());
            }
        }
        self.save_runtime_state_if_configured("member_state");
        Ok(LoadBalancerRuntimeBackendMutation {
            member: member.to_owned(),
            state,
            persistent: self.runtime_state_persistent(),
            #[cfg(not(feature = "privacy-mode"))]
            address: backend.addr.to_string(),
            alias: self
                .backend_aliases
                .get(&key)
                .map(|alias| alias.to_string()),
        })
    }

    pub fn set_runtime_backend_weight(
        &self,
        member: &str,
        weight: Option<usize>,
    ) -> io::Result<LoadBalancerRuntimeBackendWeightMutation> {
        if !self.selection.supports_runtime_weight_override() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime load-balancer weight overrides are available only for round-robin, least-connections, least-sessions, and least-time selections in this release",
            ));
        }
        let backend = self
            .inner
            .backend_by_member(member, &self.backend_aliases)?;
        let key = backend_key(&backend);
        if !self.backend_policy.set_runtime_backend_weight(key, weight) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "load balancer runtime override table is full",
            ));
        }
        self.save_runtime_state_if_configured("member_weight");
        Ok(LoadBalancerRuntimeBackendWeightMutation {
            member: member.to_owned(),
            configured_weight: backend.weight,
            effective_weight: self.backend_policy.effective_weight(&backend),
            runtime_weight_override: self.backend_policy.runtime_backend_weight(key),
            persistent: self.runtime_state_persistent(),
            #[cfg(not(feature = "privacy-mode"))]
            address: backend.addr.to_string(),
            alias: self
                .backend_aliases
                .get(&key)
                .map(|alias| alias.to_string()),
        })
    }

    pub fn add_runtime_backend_member(
        &self,
        member: &str,
        weight: usize,
    ) -> io::Result<LoadBalancerRuntimeBackendSetMutation> {
        self.validate_runtime_backend_set_mutation()?;
        let backend = runtime_backend_from_member(member, weight)?;
        let key = backend_key(&backend);
        let backend_count = self.inner.add_runtime_backend(backend.clone())?;
        self.save_runtime_state_if_configured_in_background("member_add");
        Ok(LoadBalancerRuntimeBackendSetMutation {
            member: backend.addr.to_string(),
            operation: LoadBalancerRuntimeBackendSetOperation::Added,
            configured_weight: backend.weight,
            backend_count,
            persistent: false,
            #[cfg(not(feature = "privacy-mode"))]
            address: backend.addr.to_string(),
            #[cfg(not(feature = "privacy-mode"))]
            previous_address: None,
            alias: self
                .backend_aliases
                .get(&key)
                .map(|alias| alias.to_string()),
        })
    }

    pub fn remove_runtime_backend_member(
        &self,
        member: &str,
    ) -> io::Result<LoadBalancerRuntimeBackendSetMutation> {
        self.validate_runtime_backend_set_mutation()?;
        let backend = self
            .inner
            .backend_by_member(member, &self.backend_aliases)?;
        if self.counters.count(&backend) > 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "load balancer member still has in-flight connections; drain before removing",
            ));
        }
        let key = backend_key(&backend);
        let alias = self
            .backend_aliases
            .get(&key)
            .map(|alias| alias.to_string());
        let backend_count = self.inner.remove_runtime_backend(&backend)?;
        let post_remove_in_flight = self.counters.count(&backend);
        if post_remove_in_flight > 0 {
            log::warn!(
                target: "fluxheim::load_balancer",
                "load balancer member removed after zero-count gate but now has in-flight requests count={}",
                post_remove_in_flight
            );
        }
        self.clear_removed_backend_state(key);
        self.prune_stale_backend_state();
        self.save_runtime_state_if_configured_in_background("member_remove");
        Ok(LoadBalancerRuntimeBackendSetMutation {
            member: backend.addr.to_string(),
            operation: LoadBalancerRuntimeBackendSetOperation::Removed,
            configured_weight: backend.weight,
            backend_count,
            persistent: false,
            #[cfg(not(feature = "privacy-mode"))]
            address: backend.addr.to_string(),
            #[cfg(not(feature = "privacy-mode"))]
            previous_address: None,
            alias,
        })
    }

    pub fn update_runtime_backend_member(
        &self,
        member: &str,
        updated_member: Option<&str>,
        weight: Option<usize>,
    ) -> io::Result<LoadBalancerRuntimeBackendSetMutation> {
        self.validate_runtime_backend_set_mutation()?;
        let current = self
            .inner
            .backend_by_member(member, &self.backend_aliases)?;
        let updated_authority = updated_member
            .map(str::trim)
            .filter(|member| !member.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| current.addr.to_string());
        let updated_weight = weight.unwrap_or(current.weight);
        if updated_authority == current.addr.to_string() && updated_weight == current.weight {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "load balancer member update must change address or weight",
            ));
        }
        let current_key = backend_key(&current);
        let current_alias = self
            .backend_aliases
            .get(&current_key)
            .map(|alias| alias.to_string());
        if updated_authority != current.addr.to_string() && current_alias.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "load balancer aliased members cannot be retargeted without a config reload",
            ));
        }
        if updated_authority != current.addr.to_string() && self.counters.count(&current) > 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "load balancer member still has in-flight connections; drain before changing address",
            ));
        }
        let updated = runtime_backend_from_member(&updated_authority, updated_weight)?;
        let updated_key = backend_key(&updated);
        let backend_count = self
            .inner
            .update_runtime_backend(&current, updated.clone())?;
        if current_key != updated_key {
            let post_update_in_flight = self.counters.count(&current);
            if post_update_in_flight > 0 {
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member retargeted after zero-count gate but previous address now has in-flight requests count={}",
                    post_update_in_flight
                );
            }
            self.clear_removed_backend_state(current_key);
        }
        self.prune_stale_backend_state();
        self.save_runtime_state_if_configured_in_background("member_update");
        Ok(LoadBalancerRuntimeBackendSetMutation {
            member: current.addr.to_string(),
            operation: LoadBalancerRuntimeBackendSetOperation::Updated,
            configured_weight: updated.weight,
            backend_count,
            persistent: false,
            #[cfg(not(feature = "privacy-mode"))]
            address: updated.addr.to_string(),
            #[cfg(not(feature = "privacy-mode"))]
            previous_address: Some(current.addr.to_string()),
            alias: current_alias.or_else(|| {
                self.backend_aliases
                    .get(&updated_key)
                    .map(|alias| alias.to_string())
            }),
        })
    }

    pub fn clear_persistence(&self) -> usize {
        let cleared = self
            .persistence
            .as_ref()
            .map_or(0, |persistence| persistence.clear());
        if cleared > 0 {
            self.save_runtime_state_if_configured("persistence_clear");
        }
        cleared
    }

    fn clear_removed_backend_state(&self, key: u64) {
        self.backend_policy.clear_runtime_key(key);
        if let Some(passive_health) = &self.passive_health {
            passive_health.clear_key(key);
        }
    }

    fn validate_runtime_backend_set_mutation(&self) -> io::Result<()> {
        if !self.inner.supports_runtime_backend_set_mutation() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime backend-set mutation is not available for static-ring selections in this release",
            ));
        }
        if !self.inner.runtime_backend_set_mutable() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime backend-set mutation is available only for static upstream pools",
            ));
        }
        Ok(())
    }
}

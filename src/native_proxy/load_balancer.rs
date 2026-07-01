use std::io;

use fluxheim_load_balancer::{
    LoadBalancerMemberAddRequest, LoadBalancerMemberRemoveRequest,
    LoadBalancerMemberSetMutationResult, LoadBalancerMemberStateRequest,
    LoadBalancerMemberStateResult, LoadBalancerMemberUpdateRequest,
    LoadBalancerMemberWeightRequest, LoadBalancerMemberWeightResult,
    LoadBalancerPersistenceClearRequest, LoadBalancerPersistenceClearResult,
    LoadBalancerRouteRuntimeStats, LoadBalancerRuntimeStats, LoadBalancerVhostRuntimeStats,
};

use super::FluxProxy;

impl FluxProxy {
    fn native_load_balancer_pool(
        &self,
        vhost: &str,
        route: Option<&str>,
    ) -> io::Result<(
        String,
        Option<String>,
        &fluxheim_load_balancer::UpstreamLoadBalancer,
    )> {
        let vhost = vhost.trim();
        if vhost.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "load balancer vhost is required",
            ));
        }
        let route = route.map(str::trim).filter(|route| !route.is_empty());
        self.load_balancer_admin_pools
            .iter()
            .find(|pool| pool.vhost.as_ref() == vhost && pool.route.as_deref() == route)
            .map(|pool| {
                (
                    pool.vhost.to_string(),
                    pool.route.as_ref().map(ToString::to_string),
                    &pool.load_balancer,
                )
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    if route.is_some() {
                        "load balancer route has no configured pool"
                    } else {
                        "load balancer vhost has no configured pool"
                    },
                )
            })
    }

    pub fn load_balancer_runtime_stats(&self) -> LoadBalancerRuntimeStats {
        let config = self.lock_config_or_abort("load balancer runtime stats");
        let mut vhosts = Vec::new();
        for vhost in &config.vhosts {
            let pool = self
                .native_load_balancer_pool(&vhost.name, None)
                .ok()
                .map(|(_, _, pool)| pool.runtime_stats());
            let routes = self
                .load_balancer_admin_pools
                .iter()
                .filter(|pool| pool.vhost.as_ref() == vhost.name)
                .filter_map(|pool| {
                    let route = pool.route.as_ref()?;
                    Some(LoadBalancerRouteRuntimeStats {
                        name: route.to_string(),
                        pool: pool.load_balancer.runtime_stats(),
                    })
                })
                .collect::<Vec<_>>();
            if pool.is_some() || !routes.is_empty() {
                vhosts.push(LoadBalancerVhostRuntimeStats {
                    name: vhost.name.clone(),
                    pool,
                    routes,
                });
            }
        }
        for pool in &self.load_balancer_admin_pools {
            if config
                .vhosts
                .iter()
                .any(|vhost| vhost.name == pool.vhost.as_ref())
            {
                continue;
            }
            vhosts.push(LoadBalancerVhostRuntimeStats {
                name: pool.vhost.to_string(),
                pool: pool
                    .route
                    .is_none()
                    .then(|| pool.load_balancer.runtime_stats()),
                routes: pool
                    .route
                    .as_ref()
                    .map(|route| {
                        vec![LoadBalancerRouteRuntimeStats {
                            name: route.to_string(),
                            pool: pool.load_balancer.runtime_stats(),
                        }]
                    })
                    .unwrap_or_default(),
            });
        }
        LoadBalancerRuntimeStats { vhosts }
    }

    pub fn set_load_balancer_member_state(
        &self,
        request: LoadBalancerMemberStateRequest<'_>,
    ) -> io::Result<LoadBalancerMemberStateResult> {
        let member = native_load_balancer_member(request.member)?;
        let (vhost, route, pool) = self.native_load_balancer_pool(request.vhost, request.route)?;
        let mutation = pool.set_runtime_backend_state(member, request.state)?;
        Ok(LoadBalancerMemberStateResult {
            vhost,
            route,
            member: mutation.member,
            state: mutation.state,
            persistent: mutation.persistent,
            #[cfg(not(feature = "privacy-mode"))]
            address: mutation.address,
            alias: mutation.alias,
        })
    }

    pub fn set_load_balancer_member_weight(
        &self,
        request: LoadBalancerMemberWeightRequest<'_>,
    ) -> io::Result<LoadBalancerMemberWeightResult> {
        let member = native_load_balancer_member(request.member)?;
        let (vhost, route, pool) = self.native_load_balancer_pool(request.vhost, request.route)?;
        let mutation = pool.set_runtime_backend_weight(member, request.weight)?;
        Ok(LoadBalancerMemberWeightResult {
            vhost,
            route,
            member: mutation.member,
            configured_weight: mutation.configured_weight,
            effective_weight: mutation.effective_weight,
            runtime_weight_override: mutation.runtime_weight_override,
            persistent: mutation.persistent,
            #[cfg(not(feature = "privacy-mode"))]
            address: mutation.address,
            alias: mutation.alias,
        })
    }

    pub fn add_load_balancer_member(
        &self,
        request: LoadBalancerMemberAddRequest<'_>,
    ) -> io::Result<LoadBalancerMemberSetMutationResult> {
        let (vhost, route, pool) = self.native_load_balancer_pool(request.vhost, request.route)?;
        let mutation = pool.add_runtime_backend_member(request.member, request.weight)?;
        Ok(native_load_balancer_set_mutation_result(
            vhost, route, mutation,
        ))
    }

    pub fn remove_load_balancer_member(
        &self,
        request: LoadBalancerMemberRemoveRequest<'_>,
    ) -> io::Result<LoadBalancerMemberSetMutationResult> {
        let member = native_load_balancer_member(request.member)?;
        let (vhost, route, pool) = self.native_load_balancer_pool(request.vhost, request.route)?;
        let mutation = pool.remove_runtime_backend_member(member)?;
        Ok(native_load_balancer_set_mutation_result(
            vhost, route, mutation,
        ))
    }

    pub fn update_load_balancer_member(
        &self,
        request: LoadBalancerMemberUpdateRequest<'_>,
    ) -> io::Result<LoadBalancerMemberSetMutationResult> {
        let member = native_load_balancer_member(request.member)?;
        let (vhost, route, pool) = self.native_load_balancer_pool(request.vhost, request.route)?;
        let mutation =
            pool.update_runtime_backend_member(member, request.updated_member, request.weight)?;
        Ok(native_load_balancer_set_mutation_result(
            vhost, route, mutation,
        ))
    }

    pub fn clear_load_balancer_persistence(
        &self,
        request: LoadBalancerPersistenceClearRequest<'_>,
    ) -> io::Result<LoadBalancerPersistenceClearResult> {
        let (vhost, route, pool) = self.native_load_balancer_pool(request.vhost, request.route)?;
        let cleared_entries = pool.clear_persistence();
        Ok(LoadBalancerPersistenceClearResult {
            vhost,
            route,
            cleared_entries,
            persistent: pool.runtime_state_persistent(),
        })
    }
}

fn native_load_balancer_member(member: &str) -> io::Result<&str> {
    let member = member.trim();
    if member.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "load balancer member is required",
        ));
    }
    Ok(member)
}

fn native_load_balancer_set_mutation_result(
    vhost: String,
    route: Option<String>,
    mutation: fluxheim_load_balancer::LoadBalancerRuntimeBackendSetMutation,
) -> LoadBalancerMemberSetMutationResult {
    LoadBalancerMemberSetMutationResult {
        vhost,
        route,
        member: mutation.member,
        operation: mutation.operation,
        configured_weight: mutation.configured_weight,
        backend_count: mutation.backend_count,
        persistent: mutation.persistent,
        #[cfg(not(feature = "privacy-mode"))]
        address: mutation.address,
        #[cfg(not(feature = "privacy-mode"))]
        previous_address: mutation.previous_address,
        alias: mutation.alias,
    }
}

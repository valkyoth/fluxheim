use crate::{DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1RouteProxyConfigError};

#[cfg(feature = "load-balancer")]
pub(crate) struct NativeLoadBalancerCollectors<'a> {
    services: Option<&'a mut Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>>,
    admin_pools: Option<&'a mut Vec<crate::NativeLoadBalancerAdminPool>>,
}

#[cfg(feature = "load-balancer")]
impl<'a> NativeLoadBalancerCollectors<'a> {
    pub(crate) fn new(
        services: Option<&'a mut Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>>,
        admin_pools: Option<&'a mut Vec<crate::NativeLoadBalancerAdminPool>>,
    ) -> Self {
        Self {
            services,
            admin_pools,
        }
    }

    pub(crate) fn none() -> Self {
        Self {
            services: None,
            admin_pools: None,
        }
    }

    pub(crate) fn reborrow(&mut self) -> NativeLoadBalancerCollectors<'_> {
        NativeLoadBalancerCollectors {
            services: native_load_balancer_services_reborrow(&mut self.services),
            admin_pools: native_load_balancer_admin_pools_reborrow(&mut self.admin_pools),
        }
    }
}

pub(crate) struct NativeProxyBuildRequest<'a> {
    pub(crate) name: &'a str,
    pub(crate) vhost: &'a str,
    pub(crate) route: Option<&'a str>,
    pub(crate) proxy: &'a fluxheim_config::ProxyConfig,
    pub(crate) policy: DownstreamHttp1Policy,
    pub(crate) pool_max_idle: usize,
}

pub(crate) fn native_proxy_from_config_collecting_load_balancer(
    request: NativeProxyBuildRequest<'_>,
    #[cfg(feature = "load-balancer")] collectors: NativeLoadBalancerCollectors<'_>,
) -> Result<Option<NativeHttp1Proxy>, NativeHttp1RouteProxyConfigError> {
    #[cfg(feature = "load-balancer")]
    {
        let result = NativeHttp1Proxy::from_proxy_config_with_native_load_balancer(
            request.name,
            request.vhost,
            request.route,
            request.proxy,
            request.policy,
            request.pool_max_idle,
        )
        .map_err(NativeHttp1RouteProxyConfigError::Proxy)?;
        let Some((proxy, service)) = result else {
            return Ok(None);
        };
        let proxy = proxy.with_metrics_scope(request.vhost, request.route);
        if let (Some(admin_pools), Some(admin_pool)) = (
            collectors.admin_pools,
            proxy.load_balancer_admin_pool(request.vhost, request.route),
        ) {
            admin_pools.push(admin_pool);
        }
        if let (Some(services), Some(service)) = (collectors.services, service) {
            services.push(service);
        }
        Ok(Some(proxy))
    }
    #[cfg(not(feature = "load-balancer"))]
    {
        let _ = request.name;
        NativeHttp1Proxy::from_proxy_config_with_pool_size(
            request.proxy,
            request.policy,
            request.pool_max_idle,
        )
        .map(|proxy| proxy.map(|proxy| proxy.with_metrics_scope(request.vhost, request.route)))
        .map_err(NativeHttp1RouteProxyConfigError::Proxy)
    }
}

#[cfg(feature = "load-balancer")]
#[allow(clippy::option_as_ref_deref)]
fn native_load_balancer_services_reborrow<'a>(
    services: &'a mut Option<&mut Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>>,
) -> Option<&'a mut Vec<fluxheim_load_balancer::UpstreamLoadBalancerService>> {
    services.as_mut().map(|services| &mut **services)
}

#[cfg(feature = "load-balancer")]
#[allow(clippy::option_as_ref_deref)]
fn native_load_balancer_admin_pools_reborrow<'a>(
    pools: &'a mut Option<&mut Vec<crate::NativeLoadBalancerAdminPool>>,
) -> Option<&'a mut Vec<crate::NativeLoadBalancerAdminPool>> {
    pools.as_mut().map(|pools| &mut **pools)
}

use super::*;

impl AdminApp {
    #[cfg(feature = "cache")]
    pub(super) fn cache_status_response(&self) -> AdminResponse {
        match self.proxy.cache_runtime_stats() {
            Ok(stats) => json_response_value(
                StatusCode::OK,
                &json!({
                    "status": "ok",
                    "totals": cache_totals_json(&stats.totals),
                    "vhosts": cache_vhost_stats_json(&stats.vhosts),
                }),
            ),
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(not(feature = "cache"))]
    pub(super) fn cache_status_response(&self) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(feature = "cache")]
    pub(super) fn cache_activity_reset_response(&self) -> AdminResponse {
        let result = self.proxy.reset_cache_activity();
        json_response_value(
            StatusCode::OK,
            &json!({
                "status": "ok",
                "vhosts": result.vhosts,
                "enabled_vhosts": result.enabled_vhosts,
                "enabled_vhost_ratio_per_mille": ratio_per_mille(result.enabled_vhosts, result.vhosts),
                "tiered_vhosts": result.tiered_vhosts,
                "tiered_vhost_ratio_per_mille": ratio_per_mille(result.tiered_vhosts, result.vhosts),
                "configured_routes": result.configured_routes,
                "routes_total": result.routes_total,
                "cache_route_coverage_ratio_per_mille": ratio_per_mille(result.routes_total, result.configured_routes),
                "enabled_routes": result.enabled_routes,
                "enabled_route_ratio_per_mille": ratio_per_mille(result.enabled_routes, result.routes_total),
                "tiered_routes": result.tiered_routes,
                "tiered_route_ratio_per_mille": ratio_per_mille(result.tiered_routes, result.routes_total),
                "memory_tiers": result.memory_tiers,
                "disk_tiers": result.disk_tiers,
            }),
        )
    }

    #[cfg(not(feature = "cache"))]
    pub(super) fn cache_activity_reset_response(&self) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }
}

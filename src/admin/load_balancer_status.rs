use super::*;

impl AdminApp {
    #[cfg(feature = "load-balancer")]
    pub(super) fn load_balancer_status_response(&self) -> AdminResponse {
        json_response_value(
            StatusCode::OK,
            &json!({
                "status": "ok",
                "load_balancer": self.proxy.load_balancer_runtime_stats(),
            }),
        )
    }

    #[cfg(not(feature = "load-balancer"))]
    pub(super) fn load_balancer_status_response(&self) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }

    #[cfg(feature = "udp-proxy")]
    pub(super) fn udp_status_response(&self) -> AdminResponse {
        let current_config = self.current_config.load();
        json_response_value(
            StatusCode::OK,
            &json!({
                "status": "ok",
                "udp": udp_status_json(&current_config),
            }),
        )
    }

    #[cfg(not(feature = "udp-proxy"))]
    pub(super) fn udp_status_response(&self) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "UDP proxy support is not compiled in",
        )
    }

    #[cfg(feature = "load-balancer")]
    pub(super) fn load_balancer_member_state_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        member: Option<&str>,
        state: Option<&str>,
    ) -> AdminResponse {
        let Some(vhost) = vhost else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer vhost is required");
        };
        let Some(member) = member else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer member is required");
        };
        let Some(state) = state else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer state is required");
        };
        let Some(state) = LoadBalancerRuntimeBackendState::parse(state) else {
            return error_response(
                StatusCode::BAD_REQUEST,
                "load balancer state must be normal, drain, disable, forced_down, or manual_resume",
            );
        };
        match self
            .proxy
            .set_load_balancer_member_state(LoadBalancerMemberStateRequest {
                vhost,
                route,
                member,
                state,
            }) {
            Ok(result) => {
                let scope = if result.route.is_some() {
                    "route"
                } else {
                    "vhost"
                };
                let display_member =
                    load_balancer_display_member(result.alias.as_deref(), result.member.as_str());
                #[cfg(not(feature = "privacy-mode"))]
                log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer member state updated vhost={} route={} scope={} member={} state={} address={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.state.as_str(),
                    result.address,
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                #[cfg(feature = "privacy-mode")]
                log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer member state updated vhost={} route={} scope={} member={} state={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.state.as_str(),
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                log::info!(
                    target: "fluxheim::audit",
                    "load balancer member state updated vhost={} route={} scope={} member={} state={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.state.as_str(),
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                record_load_balancer_event(
                    &result.vhost,
                    result.route.as_deref(),
                    load_balancer_metric_member_label(
                        result.alias.as_deref(),
                        result.member.as_str(),
                    ),
                    "member_state",
                );
                let mut body = serde_json::Map::new();
                body.insert("status".to_owned(), json!("ok"));
                body.insert("vhost".to_owned(), json!(result.vhost));
                body.insert("route".to_owned(), json!(result.route));
                body.insert("scope".to_owned(), json!(scope));
                body.insert("member".to_owned(), json!(display_member));
                body.insert("state".to_owned(), json!(result.state));
                #[cfg(not(feature = "privacy-mode"))]
                body.insert("address".to_owned(), json!(result.address));
                body.insert("alias".to_owned(), json!(result.alias));
                body.insert("persistent".to_owned(), json!(result.persistent));
                json_response_value(StatusCode::OK, &Value::Object(body))
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member state rejected invalid input vhost={} route={} member={} state={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    state.as_str(),
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_state_invalid",
                );
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member state target not found vhost={} route={} member={} state={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    state.as_str(),
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_state_not_found",
                );
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "load-balancer")]
    pub(super) fn load_balancer_member_weight_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        member: Option<&str>,
        weight: Option<&str>,
    ) -> AdminResponse {
        let Some(vhost) = vhost else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer vhost is required");
        };
        let Some(member) = member else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer member is required");
        };
        let Some(weight) = weight else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer weight is required");
        };
        let weight = match parse_load_balancer_runtime_weight(weight) {
            Ok(weight) => weight,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
        };
        match self
            .proxy
            .set_load_balancer_member_weight(LoadBalancerMemberWeightRequest {
                vhost,
                route,
                member,
                weight,
            }) {
            Ok(result) => {
                let scope = if result.route.is_some() {
                    "route"
                } else {
                    "vhost"
                };
                let display_member =
                    load_balancer_display_member(result.alias.as_deref(), result.member.as_str());
                #[cfg(not(feature = "privacy-mode"))]
                log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer member weight updated vhost={} route={} scope={} member={} configured_weight={} effective_weight={} runtime_weight_override={} address={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.configured_weight,
                    result.effective_weight,
                    result
                        .runtime_weight_override
                        .map(|weight| weight.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    result.address,
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                #[cfg(feature = "privacy-mode")]
                log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer member weight updated vhost={} route={} scope={} member={} configured_weight={} effective_weight={} runtime_weight_override={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.configured_weight,
                    result.effective_weight,
                    result
                        .runtime_weight_override
                        .map(|weight| weight.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                log::info!(
                    target: "fluxheim::audit",
                    "load balancer member weight updated vhost={} route={} scope={} member={} configured_weight={} effective_weight={} runtime_weight_override={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.configured_weight,
                    result.effective_weight,
                    result
                        .runtime_weight_override
                        .map(|weight| weight.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                record_load_balancer_event(
                    &result.vhost,
                    result.route.as_deref(),
                    load_balancer_metric_member_label(
                        result.alias.as_deref(),
                        result.member.as_str(),
                    ),
                    "member_weight",
                );
                let mut body = serde_json::Map::new();
                body.insert("status".to_owned(), json!("ok"));
                body.insert("vhost".to_owned(), json!(result.vhost));
                body.insert("route".to_owned(), json!(result.route));
                body.insert("scope".to_owned(), json!(scope));
                body.insert("member".to_owned(), json!(display_member));
                body.insert(
                    "configured_weight".to_owned(),
                    json!(result.configured_weight),
                );
                body.insert(
                    "effective_weight".to_owned(),
                    json!(result.effective_weight),
                );
                body.insert(
                    "runtime_weight_override".to_owned(),
                    json!(result.runtime_weight_override),
                );
                #[cfg(not(feature = "privacy-mode"))]
                body.insert("address".to_owned(), json!(result.address));
                body.insert("alias".to_owned(), json!(result.alias));
                body.insert("persistent".to_owned(), json!(result.persistent));
                json_response_value(StatusCode::OK, &Value::Object(body))
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member weight rejected invalid input vhost={} route={} member={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_weight_invalid",
                );
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member weight target not found vhost={} route={} member={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_weight_not_found",
                );
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }
}

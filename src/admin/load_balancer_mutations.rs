use super::*;

impl AdminApp {
    #[cfg(feature = "load-balancer")]
    pub(super) fn load_balancer_member_add_response(
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
        let weight = match weight {
            Some(weight) => match parse_load_balancer_member_weight(weight) {
                Ok(weight) => weight,
                Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
            },
            None => 1,
        };
        let result = self
            .proxy
            .add_load_balancer_member(LoadBalancerMemberAddRequest {
                vhost,
                route,
                member,
                weight,
            });
        self.load_balancer_member_set_response(result, vhost, route, member, "member_add")
    }

    #[cfg(feature = "load-balancer")]
    pub(super) fn load_balancer_member_remove_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        member: Option<&str>,
    ) -> AdminResponse {
        let Some(vhost) = vhost else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer vhost is required");
        };
        let Some(member) = member else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer member is required");
        };
        let result = self
            .proxy
            .remove_load_balancer_member(LoadBalancerMemberRemoveRequest {
                vhost,
                route,
                member,
            });
        self.load_balancer_member_set_response(result, vhost, route, member, "member_remove")
    }

    #[cfg(feature = "load-balancer")]
    pub(super) fn load_balancer_member_update_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
        member: Option<&str>,
        updated_member: Option<&str>,
        weight: Option<&str>,
    ) -> AdminResponse {
        let Some(vhost) = vhost else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer vhost is required");
        };
        let Some(member) = member else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer member is required");
        };
        let weight = match weight {
            Some(weight) => match parse_load_balancer_member_weight(weight) {
                Ok(weight) => Some(weight),
                Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
            },
            None => None,
        };
        let result = self
            .proxy
            .update_load_balancer_member(LoadBalancerMemberUpdateRequest {
                vhost,
                route,
                member,
                updated_member,
                weight,
            });
        self.load_balancer_member_set_response(result, vhost, route, member, "member_update")
    }

    #[cfg(feature = "load-balancer")]
    pub(super) fn load_balancer_member_set_response(
        &self,
        result: io::Result<LoadBalancerMemberSetMutationResult>,
        vhost: &str,
        route: Option<&str>,
        member: &str,
        event: &'static str,
    ) -> AdminResponse {
        match result {
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
                    "load balancer member set updated vhost={} route={} scope={} member={} operation={} configured_weight={} backend_count={} address={} previous_address={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.operation.as_str(),
                    result.configured_weight,
                    result.backend_count,
                    result.address,
                    result.previous_address.as_deref().unwrap_or(""),
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                #[cfg(feature = "privacy-mode")]
                log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer member set updated vhost={} route={} scope={} member={} operation={} configured_weight={} backend_count={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.operation.as_str(),
                    result.configured_weight,
                    result.backend_count,
                    result.alias.as_deref().unwrap_or(""),
                    result.persistent
                );
                log::info!(
                    target: "fluxheim::audit",
                    "load balancer member set updated vhost={} route={} scope={} member={} operation={} configured_weight={} backend_count={} alias={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    display_member,
                    result.operation.as_str(),
                    result.configured_weight,
                    result.backend_count,
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
                    event,
                );
                let mut body = serde_json::Map::new();
                body.insert("status".to_owned(), json!("ok"));
                body.insert("vhost".to_owned(), json!(result.vhost));
                body.insert("route".to_owned(), json!(result.route));
                body.insert("scope".to_owned(), json!(scope));
                body.insert("member".to_owned(), json!(display_member));
                body.insert("operation".to_owned(), json!(result.operation));
                body.insert(
                    "configured_weight".to_owned(),
                    json!(result.configured_weight),
                );
                body.insert("backend_count".to_owned(), json!(result.backend_count));
                #[cfg(not(feature = "privacy-mode"))]
                {
                    body.insert("address".to_owned(), json!(result.address));
                    body.insert(
                        "previous_address".to_owned(),
                        json!(result.previous_address),
                    );
                }
                body.insert("alias".to_owned(), json!(result.alias));
                body.insert("persistent".to_owned(), json!(result.persistent));
                json_response_value(StatusCode::OK, &Value::Object(body))
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member set rejected invalid input vhost={} route={} member={} event={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    event,
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_set_invalid",
                );
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member set target already exists vhost={} route={} member={} event={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    event,
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_set_conflict",
                );
                error_response(StatusCode::CONFLICT, &error.to_string())
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member set blocked by active traffic vhost={} route={} member={} event={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    event,
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_set_blocked",
                );
                error_response(StatusCode::CONFLICT, &error.to_string())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let display_member = load_balancer_display_member(None, member);
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer member set target not found vhost={} route={} member={} event={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    display_member,
                    event,
                    error
                );
                record_load_balancer_event(
                    vhost,
                    route,
                    load_balancer_metric_member_label(None, member),
                    "member_set_not_found",
                );
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(feature = "load-balancer")]
    pub(super) fn load_balancer_persistence_clear_response(
        &self,
        vhost: Option<&str>,
        route: Option<&str>,
    ) -> AdminResponse {
        let Some(vhost) = vhost else {
            return error_response(StatusCode::BAD_REQUEST, "load balancer vhost is required");
        };
        match self
            .proxy
            .clear_load_balancer_persistence(LoadBalancerPersistenceClearRequest { vhost, route })
        {
            Ok(result) => {
                let scope = if result.route.is_some() {
                    "route"
                } else {
                    "vhost"
                };
                log::info!(
                    target: "fluxheim::load_balancer",
                    "load balancer persistence table cleared vhost={} route={} scope={} cleared_entries={} persistent={}",
                    result.vhost,
                    result.route.as_deref().unwrap_or(""),
                    scope,
                    result.cleared_entries,
                    result.persistent
                );
                record_load_balancer_event(
                    &result.vhost,
                    result.route.as_deref(),
                    None,
                    "persistence_clear",
                );
                json_response_value(
                    StatusCode::OK,
                    &json!({
                        "status": "ok",
                        "vhost": result.vhost,
                        "route": result.route,
                        "scope": scope,
                        "cleared_entries": result.cleared_entries,
                        "persistent": result.persistent,
                    }),
                )
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer persistence clear rejected invalid input vhost={} route={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    error
                );
                record_load_balancer_event(vhost, route, None, "persistence_clear_invalid");
                error_response(StatusCode::BAD_REQUEST, &error.to_string())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                log::warn!(
                    target: "fluxheim::load_balancer",
                    "load balancer persistence clear target not found vhost={} route={} error={}",
                    vhost,
                    route.unwrap_or(""),
                    error
                );
                record_load_balancer_event(vhost, route, None, "persistence_clear_not_found");
                error_response(StatusCode::NOT_FOUND, &error.to_string())
            }
            Err(error) => internal_error_response(&error),
        }
    }

    #[cfg(not(feature = "load-balancer"))]
    pub(super) fn load_balancer_member_weight_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _member: Option<&str>,
        _weight: Option<&str>,
    ) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }

    #[cfg(not(feature = "load-balancer"))]
    pub(super) fn load_balancer_member_state_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _member: Option<&str>,
        _state: Option<&str>,
    ) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }

    #[cfg(not(feature = "load-balancer"))]
    pub(super) fn load_balancer_member_add_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _member: Option<&str>,
        _weight: Option<&str>,
    ) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }

    #[cfg(not(feature = "load-balancer"))]
    pub(super) fn load_balancer_member_remove_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _member: Option<&str>,
    ) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }

    #[cfg(not(feature = "load-balancer"))]
    pub(super) fn load_balancer_member_update_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _member: Option<&str>,
        _updated_member: Option<&str>,
        _weight: Option<&str>,
    ) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }

    #[cfg(not(feature = "load-balancer"))]
    pub(super) fn load_balancer_persistence_clear_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
    ) -> AdminResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            "load balancer support is not compiled in",
        )
    }
}

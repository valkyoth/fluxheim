use super::*;

impl AdminApp {
    #[cfg(test)]
    pub(super) fn handle(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
    ) -> AdminResponse {
        self.handle_with_source(method, path, query, headers, None)
    }

    pub(super) fn handle_with_source(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        source: Option<IpAddr>,
    ) -> AdminResponse {
        if let Some(response) = self.enforce_self_healing_deadline() {
            return response;
        }

        if path.len() > MAX_ADMIN_PATH_BYTES {
            return json_response(StatusCode::URI_TOO_LONG, br#"{"error":"path_too_large"}"#);
        }

        let health_request = path == self.health_path;
        if health_request && self.health_unauthenticated {
            if method != "GET" {
                return json_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    br#"{"error":"method_not_allowed"}"#,
                );
            }
            return self.health_response();
        }

        if let Some(scope) = self.auth_throttle.pre_auth_check(source) {
            record_admin_auth_event("throttled", scope);
            log::warn!(
                target: "fluxheim::security",
                "admin auth request throttled source={} scope={}",
                auth_source_label(source),
                scope.as_str()
            );
            return json_response(
                StatusCode::TOO_MANY_REQUESTS,
                br#"{"error":"admin_auth_throttled"}"#,
            );
        }

        match self.client_certificate.allows(headers) {
            AdminClientCertificateDecision::Allowed => {}
            AdminClientCertificateDecision::Required => {
                let scope = self.auth_throttle.record_failure(source);
                record_admin_auth_event("failure", scope.unwrap_or(AdminAuthThrottleScope::Source));
                log::warn!(
                    target: "fluxheim::security",
                    "admin client certificate required source={} throttled={}",
                    auth_source_label(source),
                    scope.map(AdminAuthThrottleScope::as_str).unwrap_or("none")
                );
                if scope.is_some() {
                    record_admin_auth_event(
                        "throttled",
                        scope.unwrap_or(AdminAuthThrottleScope::Source),
                    );
                    return json_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        br#"{"error":"admin_auth_throttled"}"#,
                    );
                }
                return json_response(
                    StatusCode::FORBIDDEN,
                    br#"{"error":"admin_client_certificate_required"}"#,
                );
            }
            AdminClientCertificateDecision::Denied => {
                let scope = self.auth_throttle.record_failure(source);
                record_admin_auth_event("failure", scope.unwrap_or(AdminAuthThrottleScope::Source));
                log::warn!(
                    target: "fluxheim::security",
                    "admin client certificate denied source={} throttled={}",
                    auth_source_label(source),
                    scope.map(AdminAuthThrottleScope::as_str).unwrap_or("none")
                );
                if scope.is_some() {
                    record_admin_auth_event(
                        "throttled",
                        scope.unwrap_or(AdminAuthThrottleScope::Source),
                    );
                    return json_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        br#"{"error":"admin_auth_throttled"}"#,
                    );
                }
                return json_response(
                    StatusCode::FORBIDDEN,
                    br#"{"error":"admin_client_certificate_denied"}"#,
                );
            }
        }

        if !authorized(authorization_header(headers), &self.token) {
            let scope = self.auth_throttle.record_failure(source);
            record_admin_auth_event("failure", scope.unwrap_or(AdminAuthThrottleScope::Source));
            log::warn!(
                target: "fluxheim::security",
                "admin auth failed source={} throttled={}",
                auth_source_label(source),
                scope.map(AdminAuthThrottleScope::as_str).unwrap_or("none")
            );
            if scope.is_some() {
                record_admin_auth_event(
                    "throttled",
                    scope.unwrap_or(AdminAuthThrottleScope::Source),
                );
                return json_response(
                    StatusCode::TOO_MANY_REQUESTS,
                    br#"{"error":"admin_auth_throttled"}"#,
                );
            }
            return json_response(StatusCode::UNAUTHORIZED, br#"{"error":"unauthorized"}"#);
        }
        self.auth_throttle.record_success(source);
        if health_request {
            if method != "GET" {
                return json_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    br#"{"error":"method_not_allowed"}"#,
                );
            }
            return self.health_response();
        }
        if query.is_some_and(|query| query.len() > MAX_ADMIN_QUERY_BYTES) {
            return json_response(StatusCode::URI_TOO_LONG, br#"{"error":"query_too_large"}"#);
        }

        match (method, path) {
            ("GET", "/_fluxheim/status") => self.status_response(),
            ("GET", "/_fluxheim/cache/status") => self.cache_status_response(),
            ("GET", "/_fluxheim/load-balancer/status") => self.load_balancer_status_response(),
            ("GET", "/_fluxheim/udp/status") => self.udp_status_response(),
            ("GET", "/_fluxheim/snapshots") => self.snapshots_response(),
            ("POST", "/_fluxheim/cache/activity/reset") => self.cache_activity_reset_response(),
            ("POST", "/_fluxheim/self-heal/confirm") => self.self_heal_confirm_response(),
            ("POST", "/_fluxheim/self-heal/fail") => self.self_heal_fail_response(),
            ("POST", "/_fluxheim/self-heal/report") => self.self_heal_report_response(
                header_value(headers, "x-fluxheim-health")
                    .or_else(|| query_param(query, "health"))
                    .or_else(|| query_param(query, "ok"))
                    .or_else(|| query_param(query, "success")),
            ),
            ("POST", "/_fluxheim/load-balancer/member-state") => self
                .load_balancer_member_state_response(
                    header_value(headers, "x-fluxheim-lb-vhost")
                        .or_else(|| query_param(query, "vhost")),
                    header_value(headers, "x-fluxheim-lb-route")
                        .or_else(|| query_param(query, "route")),
                    header_value(headers, "x-fluxheim-lb-member")
                        .or_else(|| query_param(query, "member")),
                    header_value(headers, "x-fluxheim-lb-state")
                        .or_else(|| query_param(query, "state")),
                ),
            ("POST", "/_fluxheim/load-balancer/member-weight") => self
                .load_balancer_member_weight_response(
                    header_value(headers, "x-fluxheim-lb-vhost")
                        .or_else(|| query_param(query, "vhost")),
                    header_value(headers, "x-fluxheim-lb-route")
                        .or_else(|| query_param(query, "route")),
                    header_value(headers, "x-fluxheim-lb-member")
                        .or_else(|| query_param(query, "member")),
                    header_value(headers, "x-fluxheim-lb-weight")
                        .or_else(|| query_param(query, "weight")),
                ),
            ("POST", "/_fluxheim/load-balancer/member-add") => self
                .load_balancer_member_add_response(
                    header_value(headers, "x-fluxheim-lb-vhost")
                        .or_else(|| query_param(query, "vhost")),
                    header_value(headers, "x-fluxheim-lb-route")
                        .or_else(|| query_param(query, "route")),
                    header_value(headers, "x-fluxheim-lb-member")
                        .or_else(|| query_param(query, "member")),
                    header_value(headers, "x-fluxheim-lb-weight")
                        .or_else(|| query_param(query, "weight")),
                ),
            ("POST", "/_fluxheim/load-balancer/member-remove") => self
                .load_balancer_member_remove_response(
                    header_value(headers, "x-fluxheim-lb-vhost")
                        .or_else(|| query_param(query, "vhost")),
                    header_value(headers, "x-fluxheim-lb-route")
                        .or_else(|| query_param(query, "route")),
                    header_value(headers, "x-fluxheim-lb-member")
                        .or_else(|| query_param(query, "member")),
                ),
            ("POST", "/_fluxheim/load-balancer/member-update") => self
                .load_balancer_member_update_response(
                    header_value(headers, "x-fluxheim-lb-vhost")
                        .or_else(|| query_param(query, "vhost")),
                    header_value(headers, "x-fluxheim-lb-route")
                        .or_else(|| query_param(query, "route")),
                    header_value(headers, "x-fluxheim-lb-member")
                        .or_else(|| query_param(query, "member")),
                    header_value(headers, "x-fluxheim-lb-new-member")
                        .or_else(|| header_value(headers, "x-fluxheim-lb-address"))
                        .or_else(|| query_param(query, "new_member"))
                        .or_else(|| query_param(query, "address")),
                    header_value(headers, "x-fluxheim-lb-weight")
                        .or_else(|| query_param(query, "weight")),
                ),
            ("POST", "/_fluxheim/load-balancer/persistence/clear") => self
                .load_balancer_persistence_clear_response(
                    header_value(headers, "x-fluxheim-lb-vhost")
                        .or_else(|| query_param(query, "vhost")),
                    header_value(headers, "x-fluxheim-lb-route")
                        .or_else(|| query_param(query, "route")),
                ),
            ("POST", "/_fluxheim/cache/purge") => self.cache_purge_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-host")
                    .or_else(|| query_param(query, "host")),
                header_value(headers, "x-fluxheim-cache-method")
                    .or_else(|| query_param(query, "method")),
                header_value(headers, "x-fluxheim-cache-path")
                    .or_else(|| query_param(query, "path")),
                header_value(headers, "x-fluxheim-cache-query")
                    .or_else(|| query_param(query, "url_query"))
                    .or_else(|| query_param(query, "cache_query")),
            ),
            ("POST", "/_fluxheim/cache/purge-bulk") => self.cache_purge_bulk_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-host")
                    .or_else(|| query_param(query, "host")),
                header_value(headers, "x-fluxheim-cache-method")
                    .or_else(|| query_param(query, "method")),
                cache_purge_paths(headers, query),
                header_value(headers, "x-fluxheim-cache-query")
                    .or_else(|| query_param(query, "url_query"))
                    .or_else(|| query_param(query, "cache_query")),
            ),
            ("POST", "/_fluxheim/cache/purge-index") => self.cache_purge_index_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-limit")
                    .or_else(|| query_param(query, "limit")),
                header_value(headers, "x-fluxheim-cache-batches")
                    .or_else(|| query_param(query, "batches")),
                truthy_header(headers, "x-fluxheim-cache-soft")
                    || truthy_query_param(query, "soft"),
            ),
            ("POST", "/_fluxheim/cache/purge-prefix") => self.cache_purge_prefix_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-path-prefix")
                    .or_else(|| query_param(query, "path_prefix"))
                    .or_else(|| query_param(query, "prefix")),
                header_value(headers, "x-fluxheim-cache-limit")
                    .or_else(|| query_param(query, "limit")),
                header_value(headers, "x-fluxheim-cache-batches")
                    .or_else(|| query_param(query, "batches")),
                truthy_header(headers, "x-fluxheim-cache-soft")
                    || truthy_query_param(query, "soft"),
            ),
            ("POST", "/_fluxheim/cache/purge-tag") => self.cache_purge_tag_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-tag")
                    .or_else(|| query_param(query, "cache_tag"))
                    .or_else(|| query_param(query, "tag")),
                header_value(headers, "x-fluxheim-cache-limit")
                    .or_else(|| query_param(query, "limit")),
                header_value(headers, "x-fluxheim-cache-batches")
                    .or_else(|| query_param(query, "batches")),
                truthy_header(headers, "x-fluxheim-cache-soft")
                    || truthy_query_param(query, "soft"),
            ),
            ("POST", "/_fluxheim/cache/purge-stale") => self.cache_purge_stale_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-limit")
                    .or_else(|| query_param(query, "limit")),
                header_value(headers, "x-fluxheim-cache-batches")
                    .or_else(|| query_param(query, "batches")),
                truthy_header(headers, "x-fluxheim-cache-dry-run")
                    || truthy_query_param(query, "dry_run")
                    || truthy_query_param(query, "dry-run"),
            ),
            ("POST", "/_fluxheim/cache/purge-wildcard") => self.cache_purge_wildcard_response(
                header_value(headers, "x-fluxheim-cache-vhost")
                    .or_else(|| query_param(query, "vhost")),
                header_value(headers, "x-fluxheim-cache-route")
                    .or_else(|| query_param(query, "route")),
                header_value(headers, "x-fluxheim-cache-path-pattern")
                    .or_else(|| query_param(query, "path_pattern"))
                    .or_else(|| query_param(query, "pattern"))
                    .or_else(|| query_param(query, "wildcard")),
                header_value(headers, "x-fluxheim-cache-limit")
                    .or_else(|| query_param(query, "limit")),
                header_value(headers, "x-fluxheim-cache-batches")
                    .or_else(|| query_param(query, "batches")),
                truthy_header(headers, "x-fluxheim-cache-soft")
                    || truthy_query_param(query, "soft"),
            ),
            ("POST", "/_fluxheim/snapshot") => {
                self.create_snapshot_response(header_value(headers, "x-fluxheim-message"))
            }
            ("POST", "/_fluxheim/rollback") => self.rollback_response(
                header_value(headers, "x-fluxheim-rollback-to")
                    .or_else(|| query_param(query, "to")),
                truthy_header(headers, "x-fluxheim-live-apply")
                    || truthy_query_param(query, "live")
                    || truthy_query_param(query, "live_apply"),
            ),
            ("POST", "/_fluxheim/reload") => self.reload_response(),
            (
                _,
                "/_fluxheim/status"
                | "/_fluxheim/cache/status"
                | "/_fluxheim/load-balancer/status"
                | "/_fluxheim/udp/status"
                | "/_fluxheim/snapshots"
                | "/_fluxheim/cache/activity/reset"
                | "/_fluxheim/self-heal/confirm"
                | "/_fluxheim/self-heal/fail"
                | "/_fluxheim/self-heal/report"
                | "/_fluxheim/load-balancer/member-state"
                | "/_fluxheim/load-balancer/member-weight"
                | "/_fluxheim/load-balancer/member-add"
                | "/_fluxheim/load-balancer/member-remove"
                | "/_fluxheim/load-balancer/member-update"
                | "/_fluxheim/load-balancer/persistence/clear"
                | "/_fluxheim/cache/purge"
                | "/_fluxheim/cache/purge-bulk"
                | "/_fluxheim/cache/purge-index"
                | "/_fluxheim/cache/purge-prefix"
                | "/_fluxheim/cache/purge-tag"
                | "/_fluxheim/cache/purge-stale"
                | "/_fluxheim/cache/purge-wildcard"
                | "/_fluxheim/snapshot"
                | "/_fluxheim/rollback"
                | "/_fluxheim/reload",
            ) => json_response(
                StatusCode::METHOD_NOT_ALLOWED,
                br#"{"error":"method_not_allowed"}"#,
            ),
            ("GET" | "POST", _) => {
                json_response(StatusCode::NOT_FOUND, br#"{"error":"not_found"}"#)
            }
            _ => json_response(
                StatusCode::METHOD_NOT_ALLOWED,
                br#"{"error":"method_not_allowed"}"#,
            ),
        }
    }

    #[cfg(unix)]
    pub(super) fn handle_ops_socket(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: Option<&HeaderMap>,
        require_bearer_token: bool,
    ) -> AdminResponse {
        if path.len() > MAX_ADMIN_PATH_BYTES {
            return json_response(StatusCode::URI_TOO_LONG, br#"{"error":"path_too_large"}"#);
        }
        if query.is_some_and(|query| query.len() > MAX_ADMIN_QUERY_BYTES) {
            return json_response(StatusCode::URI_TOO_LONG, br#"{"error":"query_too_large"}"#);
        }
        let known_read_only_path = matches!(
            path,
            "/_fluxheim/status"
                | "/_fluxheim/cache/status"
                | "/_fluxheim/load-balancer/status"
                | "/_fluxheim/udp/status"
                | "/_fluxheim/snapshots"
        ) || path == self.health_path;
        if method != "GET" {
            return if known_read_only_path {
                json_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    br#"{"error":"method_not_allowed"}"#,
                )
            } else {
                json_response(StatusCode::NOT_FOUND, br#"{"error":"not_found"}"#)
            };
        }
        if (require_bearer_token || path == "/_fluxheim/snapshots")
            && !headers
                .is_some_and(|headers| authorized(authorization_header(headers), &self.token))
        {
            return json_response(StatusCode::UNAUTHORIZED, br#"{"error":"unauthorized"}"#);
        }

        match path {
            "/_fluxheim/status" => self.status_response(),
            "/_fluxheim/cache/status" => self.cache_status_response(),
            "/_fluxheim/load-balancer/status" => self.load_balancer_status_response(),
            "/_fluxheim/udp/status" => self.udp_status_response(),
            "/_fluxheim/snapshots" => self.snapshots_response(),
            path if path == self.health_path => self.health_response(),
            _ => json_response(StatusCode::NOT_FOUND, br#"{"error":"not_found"}"#),
        }
    }
}

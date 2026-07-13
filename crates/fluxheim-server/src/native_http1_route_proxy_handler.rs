use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::native_http1_cors::cors_preflight_requested_method;
use crate::native_http1_route_action::{write_takeover_limit_rejection, write_takeover_rejection};
#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use crate::native_http1_route_compression::apply_native_response_compression;
use crate::native_http1_route_grpc::native_grpc_rejection_response;
use crate::native_http1_route_limits::NativeRateLimitDecision;
use crate::native_http1_route_proxy::{NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute};
use crate::native_http1_route_redirect::https_redirect_response;
use crate::native_http1_route_request_headers::NativeRequestHeaderTemplateContext;
use crate::native_http1_route_rewrite::{
    NativeRouteRewritePolicy, request_path_and_query, rewrite_route_request,
};
#[cfg(feature = "wasm")]
use crate::native_http1_route_wasm::{
    NativeWasmHeaderContext, NativeWasmRouteContext, NativeWasmRouteOutcome, status_reason,
    wasm_access_rejection, wasm_access_rejection_status, wasm_request_header_rejection,
    wasm_response_header_failure,
};
use crate::{
    NativeHttp1ConnectionStream, NativeHttp1Error, NativeHttp1Handler, NativeHttp1Proxy,
    NativeHttp1Request, NativeHttp1Response,
};

impl NativeHttp1Handler for NativeHttp1RouteProxy {
    fn handle<'a>(
        &'a self,
        mut request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            let Some((path, query)) = request_path_and_query(&request) else {
                return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                    .close_connection();
            };
            let preflight_method = cors_preflight_requested_method(&request);
            let selected_route = preflight_method
                .and_then(|method| self.select_route(method, &path))
                .filter(|route| route.response_headers.cors_enabled())
                .or_else(|| self.select_route(&request.method, &path));
            let decoded_policy_route = preflight_method
                .and_then(|method| self.select_decoded_policy_route(method, &path))
                .filter(|route| route.response_headers.cors_enabled())
                .or_else(|| self.select_decoded_policy_route(&request.method, &path));
            if selected_route.is_none()
                && self.fallback_web.is_none()
                && self.fallback.is_none()
                && {
                    #[cfg(feature = "php-fpm")]
                    {
                        self.fallback_php.is_none()
                    }
                    #[cfg(not(feature = "php-fpm"))]
                    {
                        true
                    }
                }
            {
                return NativeHttp1Response::new(404, "Not Found", b"not found\n")
                    .close_connection();
            }
            let client_ip = self.access_client_ip(&request);
            let tls_identity = request.tls_identity.as_ref();
            let geo_context = request.geo_context.as_ref();
            if !self.access.allows(client_ip, tls_identity, geo_context)
                || selected_route
                    .is_some_and(|route| !route.access.allows(client_ip, tls_identity, geo_context))
                || decoded_policy_route
                    .is_some_and(|route| !route.access.allows(client_ip, tls_identity, geo_context))
            {
                return NativeHttp1Response::new(403, "Forbidden", b"forbidden\n")
                    .close_connection();
            }
            // Delay-mode rate limiting sleeps are still live downstream work.
            // Count them against concurrency so an attacker cannot park
            // unlimited delayed tasks outside the configured vhost/route cap.
            let _vhost_concurrency_permit = match self.acquire_vhost_concurrency_permit().await {
                Ok(permit) => permit,
                Err(status) => {
                    return NativeHttp1Response::new(
                        status,
                        "Too Many Requests",
                        b"too many requests\n",
                    )
                    .with_retry_after_secs(1)
                    .close_connection();
                }
            };
            match self.check_vhost_rate_limit(client_ip) {
                NativeRateLimitDecision::Allow => {}
                NativeRateLimitDecision::Delay(delay) => {
                    tokio::time::sleep(delay).await;
                }
                NativeRateLimitDecision::Reject(status) => {
                    return NativeHttp1Response::new(
                        status,
                        "Too Many Requests",
                        b"rate limited\n",
                    )
                    .with_retry_after_secs(1)
                    .close_connection();
                }
            }
            #[cfg(feature = "wasm")]
            let selected_route = {
                match self
                    .wasm_route_decision(&request, &path, selected_route)
                    .await
                {
                    NativeWasmRouteResolution::Continue => selected_route,
                    NativeWasmRouteResolution::Select(route) => {
                        if !route.access.allows(client_ip, tls_identity, geo_context) {
                            return NativeHttp1Response::new(403, "Forbidden", b"forbidden\n")
                                .close_connection();
                        }
                        Some(route)
                    }
                    NativeWasmRouteResolution::Reject(response) => return response,
                }
            };
            let _route_concurrency_permits = match self
                .acquire_route_concurrency_permits(decoded_policy_route, selected_route)
                .await
            {
                Ok(permits) => permits,
                Err(status) => {
                    return NativeHttp1Response::new(
                        status,
                        "Too Many Requests",
                        b"too many requests\n",
                    )
                    .with_retry_after_secs(1)
                    .close_connection();
                }
            };
            match self.check_route_rate_limits(decoded_policy_route, selected_route, client_ip) {
                NativeRateLimitDecision::Allow => {}
                NativeRateLimitDecision::Delay(delay) => {
                    tokio::time::sleep(delay).await;
                }
                NativeRateLimitDecision::Reject(status) => {
                    return NativeHttp1Response::new(
                        status,
                        "Too Many Requests",
                        b"rate limited\n",
                    )
                    .with_retry_after_secs(1)
                    .close_connection();
                }
            }
            #[cfg(feature = "wasm")]
            if let Some(response) =
                wasm_access_rejection(self, decoded_policy_route.or(selected_route)).await
            {
                return response;
            }
            if !selected_route
                .is_some_and(NativeHttp1RouteProxyRoute::https_redirect_exempt_or_redirect)
                && let Some(response) = https_redirect_response(
                    &request,
                    &self.https_redirect,
                    &self.fallback_response_headers,
                )
            {
                return response;
            }
            if let Some(response) = selected_route
                .and_then(|route| route.response_headers.cors_preflight_response(&request))
                .or_else(|| {
                    self.fallback_response_headers
                        .cors_preflight_response(&request)
                })
            {
                return response;
            }
            if let Some(route) = selected_route {
                if let Some(response) = native_grpc_rejection_response(&route.grpc, &request) {
                    return response;
                }
                let rewrite_policy = NativeRouteRewritePolicy::new(
                    &route.matcher,
                    route.strip_prefix.as_deref(),
                    route.rewrite_prefix.as_deref(),
                    route.rewrite_template.as_deref(),
                );
                let mut request =
                    match rewrite_route_request(request, rewrite_policy, &path, query.as_deref()) {
                        Some(request) => request,
                        None => {
                            return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                                .close_connection();
                        }
                    };
                if route
                    .max_request_body_bytes
                    .or(self.max_request_body_bytes)
                    .is_some_and(|limit| (request.body.len() as u64) > limit)
                {
                    return NativeHttp1Response::new(
                        413,
                        "Payload Too Large",
                        b"payload too large\n",
                    )
                    .close_connection();
                }
                let header_context = NativeRequestHeaderTemplateContext::from_captures(
                    route.matcher.header_captures(&path),
                );
                self.apply_traceparent(&mut request);
                route
                    .request_headers
                    .apply(&mut request, Some(&header_context));
                #[cfg(feature = "wasm")]
                let wasm_response_context = NativeWasmHeaderContext::from_path(&path);
                #[cfg(feature = "wasm")]
                if let Some(response) = wasm_request_header_rejection(
                    &route.wasm_hooks,
                    &mut request,
                    wasm_response_context,
                )
                .await
                {
                    return response;
                }
                let response = route.handle(request).await;
                #[cfg(feature = "wasm")]
                let mut response = response;
                #[cfg(feature = "wasm")]
                if let Some(failure) = wasm_response_header_failure(
                    &route.wasm_hooks,
                    wasm_response_context,
                    &mut response,
                )
                .await
                {
                    return failure;
                }
                return response;
            }
            #[cfg(feature = "php-fpm")]
            if let Some(php) = &self.fallback_php
                && let Some(resolved) = php.resolve_for_fallback(&path)
            {
                let cors_origin = self
                    .fallback_response_headers
                    .cors_response_origin(&request);
                #[cfg(feature = "wasm")]
                let wasm_response_context = NativeWasmHeaderContext::from_path(&path);
                #[cfg(feature = "wasm")]
                if let Some(response) = wasm_request_header_rejection(
                    &self.wasm_hooks,
                    &mut request,
                    wasm_response_context,
                )
                .await
                {
                    return response;
                }
                let mut response = php.handle_resolved(request, path, resolved).await;
                self.fallback_response_headers
                    .apply_with_cors_origin(cors_origin.as_deref(), &mut response);
                #[cfg(feature = "wasm")]
                if let Some(failure) = wasm_response_header_failure(
                    &self.wasm_hooks,
                    wasm_response_context,
                    &mut response,
                )
                .await
                {
                    return failure;
                }
                return response;
            }
            if let Some(response) = self.fallback_web_response(&request, &path) {
                return self.apply_wasm_response_headers(request, response).await;
            }
            #[cfg(feature = "php-fpm")]
            if let Some(php) = &self.fallback_php {
                let cors_origin = self
                    .fallback_response_headers
                    .cors_response_origin(&request);
                #[cfg(feature = "wasm")]
                let wasm_response_context = NativeWasmHeaderContext::from_path(&path);
                #[cfg(feature = "wasm")]
                if let Some(response) = wasm_request_header_rejection(
                    &self.wasm_hooks,
                    &mut request,
                    wasm_response_context,
                )
                .await
                {
                    return response;
                }
                let mut response = php.handle(request).await;
                self.fallback_response_headers
                    .apply_with_cors_origin(cors_origin.as_deref(), &mut response);
                #[cfg(feature = "wasm")]
                if let Some(failure) = wasm_response_header_failure(
                    &self.wasm_hooks,
                    wasm_response_context,
                    &mut response,
                )
                .await
                {
                    return failure;
                }
                return response;
            }
            if let Some(proxy) = &self.fallback {
                self.apply_traceparent(&mut request);
                #[cfg(feature = "wasm")]
                let wasm_response_context = NativeWasmHeaderContext::from_path(&path);
                #[cfg(feature = "wasm")]
                if let Some(response) = wasm_request_header_rejection(
                    &self.wasm_hooks,
                    &mut request,
                    wasm_response_context,
                )
                .await
                {
                    return response;
                }
                #[cfg(feature = "wasm")]
                let response = proxy
                    .handle_with_wasm_hooks(request, &self.wasm_hooks)
                    .await;
                #[cfg(not(feature = "wasm"))]
                let response = proxy.handle(request).await;
                #[cfg(feature = "wasm")]
                let mut response = response;
                #[cfg(feature = "wasm")]
                if let Some(failure) = wasm_response_header_failure(
                    &self.wasm_hooks,
                    wasm_response_context,
                    &mut response,
                )
                .await
                {
                    return failure;
                }
                return response;
            }
            NativeHttp1Response::new(404, "Not Found", b"not found\n").close_connection()
        })
    }

    fn request_body_timeout(&self, request: &NativeHttp1Request) -> Option<Duration> {
        let (path, _) = request_path_and_query(request)?;
        if let Some(route) = self.select_route(&request.method, &path) {
            return route.request_body_timeout();
        }
        #[cfg(feature = "php-fpm")]
        if let Some(php) = &self.fallback_php {
            return Some(Duration::from_secs(php.request_timeout_secs()));
        }
        self.fallback
            .as_ref()
            .and_then(NativeHttp1Proxy::request_body_timeout)
    }

    fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        let Some((path, _)) = request_path_and_query(request) else {
            return false;
        };
        if let Some(route) = self.select_route(&request.method, &path) {
            return route.handles_connection_takeover(request);
        }
        self.fallback
            .as_ref()
            .is_some_and(|proxy| proxy.handles_connection_takeover(request))
    }

    fn handle_connection_takeover<'a>(
        &'a self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Pin<Box<dyn Future<Output = Result<(), NativeHttp1Error>> + Send + 'a>> {
        Box::pin(async move {
            self.handle_connection_takeover_inner(request, prebuffered, stream)
                .await
        })
    }
}

#[cfg(feature = "wasm")]
enum NativeWasmRouteResolution<'a> {
    Continue,
    Select(&'a NativeHttp1RouteProxyRoute),
    Reject(NativeHttp1Response),
}

#[cfg(feature = "wasm")]
impl NativeHttp1RouteProxy {
    async fn wasm_route_decision<'a>(
        &'a self,
        request: &NativeHttp1Request,
        path: &str,
        selected_route: Option<&'a NativeHttp1RouteProxyRoute>,
    ) -> NativeWasmRouteResolution<'a> {
        let hooks = selected_route
            .map(|route| &route.wasm_hooks)
            .filter(|hooks| hooks.has_route_decision())
            .unwrap_or(&self.wasm_hooks);
        let context = NativeWasmRouteContext::from_request_path(request, path);
        match hooks.route_decision(context).await {
            NativeWasmRouteOutcome::Continue => NativeWasmRouteResolution::Continue,
            NativeWasmRouteOutcome::Select { route_name } => {
                if let Some(route) =
                    self.select_named_matching_route(&request.method, path, route_name)
                {
                    NativeWasmRouteResolution::Select(route)
                } else {
                    NativeWasmRouteResolution::Reject(
                        NativeHttp1Response::new(
                            503,
                            "Service Unavailable",
                            b"wasm route decision unavailable\n",
                        )
                        .close_connection(),
                    )
                }
            }
            NativeWasmRouteOutcome::Deny { status, reason } => NativeWasmRouteResolution::Reject(
                NativeHttp1Response::new(
                    status,
                    status_reason(status),
                    format!("{reason}\n").into_bytes(),
                )
                .close_connection(),
            ),
        }
    }
}

impl NativeHttp1RouteProxy {
    async fn handle_connection_takeover_inner(
        &self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        mut stream: NativeHttp1ConnectionStream,
    ) -> Result<(), NativeHttp1Error> {
        let Some((path, query)) = request_path_and_query(&request) else {
            return write_takeover_rejection(&mut stream, 400, "Bad Request", b"bad request\n")
                .await;
        };
        let selected_route = self.select_route(&request.method, &path);
        let decoded_policy_route = self.select_decoded_policy_route(&request.method, &path);
        if selected_route.is_none() && self.fallback.is_none() && {
            #[cfg(feature = "php-fpm")]
            {
                self.fallback_php.is_none()
            }
            #[cfg(not(feature = "php-fpm"))]
            {
                true
            }
        } {
            return write_takeover_rejection(&mut stream, 404, "Not Found", b"not found\n").await;
        }
        let client_ip = self.access_client_ip(&request);
        let tls_identity = request.tls_identity.as_ref();
        let geo_context = request.geo_context.as_ref();
        if !self.access.allows(client_ip, tls_identity, geo_context)
            || selected_route
                .is_some_and(|route| !route.access.allows(client_ip, tls_identity, geo_context))
            || decoded_policy_route
                .is_some_and(|route| !route.access.allows(client_ip, tls_identity, geo_context))
        {
            return write_takeover_rejection(&mut stream, 403, "Forbidden", b"forbidden\n").await;
        }
        #[cfg(feature = "wasm")]
        if let Some((status, reason)) =
            wasm_access_rejection_status(self, decoded_policy_route.or(selected_route)).await
        {
            return write_takeover_rejection(
                &mut stream,
                status,
                status_reason(status),
                reason.as_bytes(),
            )
            .await;
        }
        let concurrency_route = decoded_policy_route.or(selected_route);
        let concurrency_permits = match self.acquire_concurrency_permits(concurrency_route).await {
            Ok(permits) => permits,
            Err(status) => {
                return write_takeover_limit_rejection(
                    &mut stream,
                    status,
                    "Too Many Requests",
                    b"too many requests\n",
                )
                .await;
            }
        };
        match self.check_rate_limits(concurrency_route, client_ip) {
            NativeRateLimitDecision::Allow => {}
            NativeRateLimitDecision::Delay(delay) => tokio::time::sleep(delay).await,
            NativeRateLimitDecision::Reject(status) => {
                return write_takeover_limit_rejection(
                    &mut stream,
                    status,
                    "Too Many Requests",
                    b"rate limited\n",
                )
                .await;
            }
        }
        drop(concurrency_permits);
        if let Some(route) = selected_route {
            let rewrite_policy = NativeRouteRewritePolicy::new(
                &route.matcher,
                route.strip_prefix.as_deref(),
                route.rewrite_prefix.as_deref(),
                route.rewrite_template.as_deref(),
            );
            let mut request =
                match rewrite_route_request(request, rewrite_policy, &path, query.as_deref()) {
                    Some(request) => request,
                    None => {
                        return write_takeover_rejection(
                            &mut stream,
                            400,
                            "Bad Request",
                            b"bad request\n",
                        )
                        .await;
                    }
                };
            if route
                .max_request_body_bytes
                .or(self.max_request_body_bytes)
                .is_some_and(|limit| (request.body.len() as u64) > limit)
            {
                return write_takeover_rejection(
                    &mut stream,
                    413,
                    "Payload Too Large",
                    b"payload too large\n",
                )
                .await;
            }
            let header_context = NativeRequestHeaderTemplateContext::from_captures(
                route.matcher.header_captures(&path),
            );
            route
                .request_headers
                .apply(&mut request, Some(&header_context));
            return route
                .handle_connection_takeover(request, prebuffered, stream)
                .await;
        }
        if let Some(proxy) = &self.fallback {
            return proxy
                .handle_connection_takeover(request, prebuffered, stream)
                .await;
        }
        #[cfg(feature = "php-fpm")]
        if self.fallback_php.is_some() {
            return write_takeover_rejection(
                &mut stream,
                400,
                "Bad Request",
                b"unsupported upgrade target\n",
            )
            .await;
        }
        write_takeover_rejection(&mut stream, 404, "Not Found", b"not found\n").await
    }

    fn fallback_web_response(
        &self,
        request: &NativeHttp1Request,
        path: &str,
    ) -> Option<NativeHttp1Response> {
        let web = self.fallback_web.as_ref()?;
        let mut response = web.handle_optional(request, path)?;
        self.fallback_response_headers
            .apply_for_request(request, &mut response);
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        if let Some(compression) = &self.fallback_compression {
            apply_native_response_compression(request, &mut response, compression);
        }
        Some(response)
    }

    #[cfg(feature = "wasm")]
    async fn apply_wasm_response_headers(
        &self,
        request: NativeHttp1Request,
        mut response: NativeHttp1Response,
    ) -> NativeHttp1Response {
        let context = NativeWasmHeaderContext::from_request(&request);
        if let Some(failure) =
            wasm_response_header_failure(&self.wasm_hooks, context, &mut response).await
        {
            return failure;
        }
        response
    }

    #[cfg(not(feature = "wasm"))]
    async fn apply_wasm_response_headers(
        &self,
        _request: NativeHttp1Request,
        response: NativeHttp1Response,
    ) -> NativeHttp1Response {
        response
    }
}

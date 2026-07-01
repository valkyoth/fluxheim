use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

#[cfg(not(feature = "privacy-mode"))]
use fluxheim_headers::effective_client_ip;
use fluxheim_protocol::route_method_matches;

use crate::native_http1_route_action::write_takeover_rejection;
#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use crate::native_http1_route_compression::{
    apply_native_response_compression, apply_route_compression,
};
use crate::native_http1_route_grpc::native_grpc_rejection_response;
use crate::native_http1_route_limits::{
    NativeConcurrencyPermit, NativeRateLimitDecision, decoded_route_policy_path,
};
use crate::native_http1_route_matcher::NativeHttp1RouteMatcher;
use crate::native_http1_route_proxy::{NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute};
use crate::native_http1_route_redirect::https_redirect_response;
use crate::native_http1_route_request_headers::NativeRequestHeaderTemplateContext;
#[cfg(not(feature = "privacy-mode"))]
use crate::native_http1_route_request_headers::joined_header_value;
use crate::native_http1_route_rewrite::{
    NativeRouteRewritePolicy, request_path_and_query, rewrite_route_request,
};
#[cfg(feature = "otel-tracing")]
use crate::native_http1_route_trace::apply_native_route_traceparent;
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
            let selected_route = self.select_route(&request.method, &path);
            let decoded_policy_route = self.select_decoded_policy_route(&request.method, &path);
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
            let concurrency_route = decoded_policy_route.or(selected_route);
            // Delay-mode rate limiting sleeps are still live downstream work.
            // Count them against concurrency so an attacker cannot park
            // unlimited delayed tasks outside the configured vhost/route cap.
            let _concurrency_permits =
                match self.acquire_concurrency_permits(concurrency_route).await {
                    Ok(permits) => permits,
                    Err(status) => {
                        return NativeHttp1Response::new(
                            status,
                            "Too Many Requests",
                            b"too many requests\n",
                        )
                        .close_connection();
                    }
                };
            match self.check_rate_limits(concurrency_route, client_ip) {
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
                    .close_connection();
                }
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
                return route.handle(request).await;
            }
            #[cfg(feature = "php-fpm")]
            if let Some(php) = &self.fallback_php
                && let Some(resolved) = php.resolve_for_fallback(&path)
            {
                return php.handle_resolved(request, path, resolved).await;
            }
            if let Some(response) = self.fallback_web_response(&request, &path) {
                return response;
            }
            #[cfg(feature = "php-fpm")]
            if let Some(php) = &self.fallback_php {
                return php.handle(request).await;
            }
            if let Some(proxy) = &self.fallback {
                self.apply_traceparent(&mut request);
                return proxy.handle(request).await;
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
        let concurrency_route = decoded_policy_route.or(selected_route);
        let concurrency_permits = match self.acquire_concurrency_permits(concurrency_route).await {
            Ok(permits) => permits,
            Err(status) => {
                return write_takeover_rejection(
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
                return write_takeover_rejection(
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
        self.fallback_response_headers.apply(&mut response);
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
}

impl NativeHttp1RouteProxy {
    fn select_route(&self, method: &str, path: &str) -> Option<&NativeHttp1RouteProxyRoute> {
        self.select_route_with_fallback(method, path, true)
    }

    fn select_decoded_policy_route(
        &self,
        method: &str,
        path: &str,
    ) -> Option<&NativeHttp1RouteProxyRoute> {
        decoded_route_policy_path(path)
            .as_deref()
            .and_then(|decoded_path| self.select_route_with_fallback(method, decoded_path, false))
    }

    fn select_route_with_fallback(
        &self,
        method: &str,
        path: &str,
        include_fallback: bool,
    ) -> Option<&NativeHttp1RouteProxyRoute> {
        let mut fallback = None;
        let mut best_prefix = None;
        let mut first_regex = None;
        for route in &self.routes {
            if !route_method_matches(&route.methods, method) {
                continue;
            }
            match &route.matcher {
                NativeHttp1RouteMatcher::Exact(exact) if path == exact => return Some(route),
                NativeHttp1RouteMatcher::Prefix(_) if route.matcher.is_match(path) => {
                    if best_prefix
                        .map(|best: &NativeHttp1RouteProxyRoute| {
                            route.prefix_len() > best.prefix_len()
                        })
                        .unwrap_or(true)
                    {
                        best_prefix = Some(route);
                    }
                }
                NativeHttp1RouteMatcher::Regex(_)
                    if first_regex.is_none() && route.matcher.is_match(path) =>
                {
                    first_regex = Some(route);
                }
                NativeHttp1RouteMatcher::Fallback if include_fallback => fallback = Some(route),
                _ => {}
            }
        }
        best_prefix.or(first_regex).or(fallback)
    }

    fn access_client_ip(&self, request: &NativeHttp1Request) -> Option<IpAddr> {
        if let Some(addr) = request.effective_client_addr {
            return Some(addr.ip());
        }
        let direct_ip = request.peer_addr.map(|addr| addr.ip());
        #[cfg(not(feature = "privacy-mode"))]
        {
            let original_x_forwarded_for = joined_header_value(request, "x-forwarded-for");
            let trusted_direct_peer = direct_ip.is_some_and(|ip| self.trusted_source_contains(ip));
            let trusted_proxy_matcher = |ip| self.trusted_source_contains(ip);
            direct_ip.map(|ip| {
                effective_client_ip(
                    ip,
                    trusted_direct_peer,
                    original_x_forwarded_for.as_deref(),
                    Some(&trusted_proxy_matcher),
                )
            })
        }
        #[cfg(feature = "privacy-mode")]
        {
            direct_ip
        }
    }

    #[cfg(feature = "otel-tracing")]
    fn apply_traceparent(&self, request: &mut NativeHttp1Request) {
        let trusted_peer = self.trace_trusted_peer(request);
        apply_native_route_traceparent(request, self.trace_propagation, trusted_peer);
    }

    #[cfg(feature = "otel-tracing")]
    fn trace_trusted_peer(&self, request: &NativeHttp1Request) -> bool {
        #[cfg(not(feature = "privacy-mode"))]
        {
            request
                .peer_addr
                .is_some_and(|addr| self.trusted_source_contains(addr.ip()))
        }
        #[cfg(feature = "privacy-mode")]
        {
            let _ = request;
            false
        }
    }

    #[cfg(not(feature = "otel-tracing"))]
    fn apply_traceparent(&self, _request: &mut NativeHttp1Request) {}

    #[cfg(not(feature = "privacy-mode"))]
    fn trusted_source_contains(&self, address: IpAddr) -> bool {
        self.trusted_sources
            .iter()
            .any(|source| source.contains(address))
    }

    fn check_rate_limits(
        &self,
        route: Option<&NativeHttp1RouteProxyRoute>,
        client_ip: Option<IpAddr>,
    ) -> NativeRateLimitDecision {
        let mut delay = None;
        match self.rate_limit.check(client_ip) {
            NativeRateLimitDecision::Allow => {}
            NativeRateLimitDecision::Delay(vhost_delay) => delay = Some(vhost_delay),
            decision => return decision,
        }
        if let Some(route) = route {
            match route.rate_limit.check(client_ip) {
                NativeRateLimitDecision::Allow => {}
                NativeRateLimitDecision::Delay(route_delay) => {
                    delay = Some(
                        delay.map_or(route_delay, |current: Duration| current.max(route_delay)),
                    );
                }
                decision => return decision,
            }
        }

        delay
            .map(NativeRateLimitDecision::Delay)
            .unwrap_or(NativeRateLimitDecision::Allow)
    }

    async fn acquire_concurrency_permits(
        &self,
        route: Option<&NativeHttp1RouteProxyRoute>,
    ) -> Result<Vec<NativeConcurrencyPermit>, u16> {
        let mut permits = Vec::with_capacity(2);
        if let Some(permit) = self.concurrency.acquire().await? {
            permits.push(permit);
        }
        if let Some(route) = route
            && let Some(permit) = route.concurrency.acquire().await?
        {
            permits.push(permit);
        }
        Ok(permits)
    }
}

impl NativeHttp1RouteProxyRoute {
    fn request_body_timeout(&self) -> Option<Duration> {
        self.action.request_body_timeout()
    }

    fn prefix_len(&self) -> usize {
        self.matcher.prefix_len()
    }

    async fn handle(&self, request: NativeHttp1Request) -> NativeHttp1Response {
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        let compression_request = self.compression.as_ref().map(|_| request.clone());
        let mut response = self.action.handle(request).await;
        self.response_headers.apply(&mut response);
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        if let Some(compression) = &self.compression
            && let Some(compression_request) = compression_request.as_ref()
        {
            apply_route_compression(compression_request, &mut response, compression);
        }
        response
    }

    fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        self.action.handles_connection_takeover(request)
    }

    async fn handle_connection_takeover(
        &self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Result<(), NativeHttp1Error> {
        self.action
            .handle_connection_takeover(request, prebuffered, stream)
            .await
    }
}

use std::net::IpAddr;
use std::time::Duration;

#[cfg(not(feature = "privacy-mode"))]
use fluxheim_headers::effective_client_ip;
use fluxheim_protocol::route_method_matches;

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use crate::native_http1_route_compression::apply_route_compression;
use crate::native_http1_route_limits::{
    NativeConcurrencyPermit, NativeRateLimitDecision, decoded_route_policy_path,
};
use crate::native_http1_route_matcher::NativeHttp1RouteMatcher;
use crate::native_http1_route_proxy::{NativeHttp1RouteProxy, NativeHttp1RouteProxyRoute};
#[cfg(not(feature = "privacy-mode"))]
use crate::native_http1_route_request_headers::joined_header_value;
#[cfg(feature = "otel-tracing")]
use crate::native_http1_route_trace::apply_native_route_traceparent;
use crate::{
    NativeHttp1ConnectionStream, NativeHttp1Error, NativeHttp1Request, NativeHttp1Response,
};

impl NativeHttp1RouteProxy {
    pub(crate) fn select_route(
        &self,
        method: &str,
        path: &str,
    ) -> Option<&NativeHttp1RouteProxyRoute> {
        self.select_route_with_fallback(method, path, true)
    }

    pub(crate) fn select_decoded_policy_route(
        &self,
        method: &str,
        path: &str,
    ) -> Option<&NativeHttp1RouteProxyRoute> {
        decoded_route_policy_path(path)
            .as_deref()
            .and_then(|decoded_path| self.select_route_with_fallback(method, decoded_path, false))
    }

    #[cfg(feature = "wasm")]
    pub(crate) fn select_named_matching_route(
        &self,
        method: &str,
        path: &str,
        route_name: &str,
    ) -> Option<&NativeHttp1RouteProxyRoute> {
        self.routes.iter().find(|route| {
            route.name == route_name
                && route_method_matches(&route.methods, method)
                && route.matcher.is_match(path)
        })
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

    pub(crate) fn access_client_ip(&self, request: &NativeHttp1Request) -> Option<IpAddr> {
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
    pub(crate) fn apply_traceparent(&self, request: &mut NativeHttp1Request) {
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
    pub(crate) fn apply_traceparent(&self, _request: &mut NativeHttp1Request) {}

    #[cfg(not(feature = "privacy-mode"))]
    fn trusted_source_contains(&self, address: IpAddr) -> bool {
        self.trusted_sources
            .iter()
            .any(|source| source.contains(address))
    }

    pub(crate) fn check_rate_limits(
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

    pub(crate) fn check_vhost_rate_limit(
        &self,
        client_ip: Option<IpAddr>,
    ) -> NativeRateLimitDecision {
        self.rate_limit.check(client_ip)
    }

    pub(crate) fn check_route_rate_limits(
        &self,
        first: Option<&NativeHttp1RouteProxyRoute>,
        second: Option<&NativeHttp1RouteProxyRoute>,
        client_ip: Option<IpAddr>,
    ) -> NativeRateLimitDecision {
        let mut delay = None;
        for route in unique_route_pair(first, second) {
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

    pub(crate) async fn acquire_concurrency_permits(
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

    pub(crate) async fn acquire_vhost_concurrency_permit(
        &self,
    ) -> Result<Option<NativeConcurrencyPermit>, u16> {
        self.concurrency.acquire().await
    }

    pub(crate) async fn acquire_route_concurrency_permits(
        &self,
        first: Option<&NativeHttp1RouteProxyRoute>,
        second: Option<&NativeHttp1RouteProxyRoute>,
    ) -> Result<Vec<NativeConcurrencyPermit>, u16> {
        let mut permits = Vec::with_capacity(2);
        for route in unique_route_pair(first, second) {
            if let Some(permit) = route.concurrency.acquire().await? {
                permits.push(permit);
            }
        }
        Ok(permits)
    }
}

fn unique_route_pair<'a>(
    first: Option<&'a NativeHttp1RouteProxyRoute>,
    second: Option<&'a NativeHttp1RouteProxyRoute>,
) -> impl Iterator<Item = &'a NativeHttp1RouteProxyRoute> {
    first.into_iter().chain(
        second
            .into_iter()
            .filter(move |route| first.is_none_or(|first| !std::ptr::eq(first, *route))),
    )
}

impl NativeHttp1RouteProxyRoute {
    pub(crate) fn request_body_timeout(&self) -> Option<Duration> {
        self.action.request_body_timeout()
    }

    fn prefix_len(&self) -> usize {
        self.matcher.prefix_len()
    }

    pub(crate) async fn handle(&self, request: NativeHttp1Request) -> NativeHttp1Response {
        let cors_origin = self.response_headers.cors_response_origin(&request);
        let response_metadata_method = request.method.clone();
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        let compression_request = self.compression.as_ref().map(|_| request.clone());
        #[cfg(feature = "wasm")]
        let mut response = self
            .action
            .handle_with_wasm_hooks(request, &self.wasm_hooks)
            .await;
        #[cfg(not(feature = "wasm"))]
        let mut response = self.action.handle(request).await;
        self.response_headers
            .apply_with_cors_origin(cors_origin.as_deref(), &mut response);
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
        self.response_headers
            .apply_digests_for_method(&response_metadata_method, &mut response);
        response
    }

    pub(crate) fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        self.action.handles_connection_takeover(request)
    }

    pub(crate) async fn handle_connection_takeover(
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

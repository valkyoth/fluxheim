use std::future::Future;
use std::pin::Pin;

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use bytes::Bytes;
use fluxheim_common::path_safety::safe_forward_path;
#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use fluxheim_compression::{
    ResponseCompressionEncoder, cache_control_directive_blocks_compression,
    content_encoding_value_is_active, content_type_is_compressible,
    input_length_within_compression_bounds, parse_accept_encoding_qvalue,
};
#[cfg(not(feature = "privacy-mode"))]
use fluxheim_config::ForwardedClientIpHeaderMode;
use fluxheim_config::{
    HeaderPolicyConfig, HeaderValues, RequestHeaderPolicyConfig, ResponseHeaderPolicyConfig,
    ResponseHeaderPolicyOverlayConfig, ResponseHeaderRewriteConfig,
};
#[cfg(not(feature = "privacy-mode"))]
use fluxheim_headers::build_forwarded_header;
use fluxheim_headers::{
    SPOOFABLE_CLIENT_IP_HEADERS, rewrite_header_prefix, rewrite_refresh_url,
    rewrite_set_cookie_value,
};
use fluxheim_protocol::{
    Http1RequestTarget, http1_request_target, route_method_matches, route_prefix_matches_path,
    route_strip_prefix_suffix,
};

use crate::{
    DownstreamHttp1Policy, NativeHttp1Handler, NativeHttp1Proxy, NativeHttp1ProxyConfigError,
    NativeHttp1Request, NativeHttp1Response, NativeHttp1StaticWeb,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1RouteProxy {
    routes: Vec<NativeHttp1RouteProxyRoute>,
    fallback: Option<NativeHttp1Proxy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1RouteProxyRoute {
    methods: Vec<String>,
    matcher: NativeHttp1RouteMatcher,
    strip_prefix: Option<String>,
    rewrite_prefix: Option<String>,
    max_request_body_bytes: Option<u64>,
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    compression: Option<fluxheim_config::CompressionConfig>,
    request_headers: NativeRouteRequestHeaderPolicy,
    response_headers: NativeRouteResponseHeaderPolicy,
    action: NativeHttp1RouteAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeHttp1RouteMatcher {
    Exact(String),
    Prefix(String),
    Fallback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeHttp1RouteAction {
    Proxy(Box<NativeHttp1Proxy>),
    Redirect(NativeHttp1RouteRedirect),
    StaticWeb(NativeHttp1StaticWeb),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeHttp1RouteRedirect {
    to: String,
    status: u16,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeRouteRequestHeaderPolicy {
    enabled: bool,
    strip_inbound_client_ip_headers: bool,
    #[cfg(not(feature = "privacy-mode"))]
    x_forwarded_for: ForwardedClientIpHeaderMode,
    #[cfg(not(feature = "privacy-mode"))]
    x_real_ip: bool,
    #[cfg(not(feature = "privacy-mode"))]
    x_forwarded_host: bool,
    #[cfg(not(feature = "privacy-mode"))]
    x_forwarded_proto: bool,
    #[cfg(not(feature = "privacy-mode"))]
    forwarded: bool,
    unset: Vec<String>,
    set: Vec<(String, String)>,
    append: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeRouteResponseHeaderPolicy {
    enabled: bool,
    unset: Vec<String>,
    set: Vec<(String, String)>,
    append: Vec<(String, String)>,
    rewrite: ResponseHeaderRewriteConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttp1RouteProxyConfigError {
    MissingRouteAction,
    Proxy(NativeHttp1ProxyConfigError),
    RegexRoute,
    RewriteTemplate,
    StaticWeb,
}

impl std::fmt::Display for NativeHttp1RouteProxyConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRouteAction => {
                formatter.write_str("native route proxy requires an action")
            }
            Self::Proxy(error) => write!(formatter, "{error}"),
            Self::RegexRoute => {
                formatter.write_str("native route proxy does not yet support regex routes")
            }
            Self::RewriteTemplate => {
                formatter.write_str("native route proxy does not yet support rewrite_template")
            }
            Self::StaticWeb => formatter.write_str("native route static web config is invalid"),
        }
    }
}

impl std::error::Error for NativeHttp1RouteProxyConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Proxy(error) => Some(error),
            Self::MissingRouteAction
            | Self::RegexRoute
            | Self::RewriteTemplate
            | Self::StaticWeb => None,
        }
    }
}

impl NativeHttp1RouteProxy {
    pub fn new(
        routes: Vec<NativeHttp1RouteProxyRoute>,
        fallback: Option<NativeHttp1Proxy>,
    ) -> Self {
        Self { routes, fallback }
    }

    pub fn routes(&self) -> &[NativeHttp1RouteProxyRoute] {
        &self.routes
    }

    pub fn fallback(&self) -> Option<&NativeHttp1Proxy> {
        self.fallback.as_ref()
    }

    pub fn from_vhost_config(
        vhost: &fluxheim_config::VhostConfig,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        policy: DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        let headers = base_headers.with_vhost_overlay(&vhost.headers);
        let inherited_compression = vhost.compression.as_ref().or(inherited_compression);
        let fallback =
            NativeHttp1Proxy::from_proxy_config_with_pool_size(&vhost.proxy, policy, pool_max_idle)
                .map_err(NativeHttp1RouteProxyConfigError::Proxy)?;
        let fallback = fallback.map(|proxy| proxy.with_header_policy(&headers));
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        let fallback = fallback.map(|proxy| {
            if let Some(compression) = inherited_compression.cloned() {
                proxy.with_compression_config(compression)
            } else {
                proxy
            }
        });

        let mut routes = Vec::new();
        for route in vhost
            .acme_challenge
            .route_config()
            .into_iter()
            .chain(vhost.routes.iter().cloned())
            .chain(vhost.redirect.route_config())
        {
            let proxy = if let Some(proxy_config) = route.proxy.as_ref() {
                NativeHttp1Proxy::from_proxy_config_with_pool_size(
                    proxy_config,
                    policy,
                    pool_max_idle,
                )
                .map_err(NativeHttp1RouteProxyConfigError::Proxy)?
            } else {
                None
            };
            routes.push(NativeHttp1RouteProxyRoute::from_config_with_inherited(
                &route,
                proxy,
                &headers,
                inherited_compression,
            )?);
        }

        Ok(Self { routes, fallback })
    }
}

impl NativeHttp1RouteProxyRoute {
    pub fn exact(path: impl Into<String>, methods: Vec<String>, proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Exact(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            action: NativeHttp1RouteAction::Proxy(Box::new(proxy)),
        }
    }

    pub fn prefix(path: impl Into<String>, methods: Vec<String>, proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            action: NativeHttp1RouteAction::Proxy(Box::new(proxy)),
        }
    }

    pub fn fallback(proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods: Vec::new(),
            matcher: NativeHttp1RouteMatcher::Fallback,
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            action: NativeHttp1RouteAction::Proxy(Box::new(proxy)),
        }
    }

    pub fn exact_redirect(
        path: impl Into<String>,
        methods: Vec<String>,
        to: impl Into<String>,
        status: u16,
    ) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Exact(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            action: NativeHttp1RouteAction::Redirect(NativeHttp1RouteRedirect {
                to: to.into(),
                status,
            }),
        }
    }

    pub fn prefix_redirect(
        path: impl Into<String>,
        methods: Vec<String>,
        to: impl Into<String>,
        status: u16,
    ) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            action: NativeHttp1RouteAction::Redirect(NativeHttp1RouteRedirect {
                to: to.into(),
                status,
            }),
        }
    }

    pub fn prefix_static_web(
        path: impl Into<String>,
        methods: Vec<String>,
        web: NativeHttp1StaticWeb,
    ) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            action: NativeHttp1RouteAction::StaticWeb(web),
        }
    }

    pub fn from_config(
        route: &fluxheim_config::RouteConfig,
        proxy: Option<NativeHttp1Proxy>,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_config_with_inherited(route, proxy, &HeaderPolicyConfig::default(), None)
    }

    pub fn from_config_with_inherited(
        route: &fluxheim_config::RouteConfig,
        proxy: Option<NativeHttp1Proxy>,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        #[cfg(not(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        )))]
        let _ = inherited_compression;
        if route.path_regex.is_some() {
            return Err(NativeHttp1RouteProxyConfigError::RegexRoute);
        }
        if route.rewrite_template.is_some() {
            return Err(NativeHttp1RouteProxyConfigError::RewriteTemplate);
        }
        let matcher = if let Some(path) = &route.path_exact {
            NativeHttp1RouteMatcher::Exact(path.clone())
        } else if let Some(path) = &route.path_prefix {
            NativeHttp1RouteMatcher::Prefix(path.clone())
        } else if route.fallback {
            NativeHttp1RouteMatcher::Fallback
        } else {
            return Err(NativeHttp1RouteProxyConfigError::MissingRouteAction);
        };
        let action = if let Some(redirect) = &route.redirect {
            NativeHttp1RouteAction::Redirect(NativeHttp1RouteRedirect {
                to: redirect.to.clone(),
                status: redirect.status,
            })
        } else if let Some(web) = route.web.as_ref().filter(|web| web.enabled()) {
            NativeHttp1RouteAction::StaticWeb(
                NativeHttp1StaticWeb::from_config(web)
                    .map_err(|_| NativeHttp1RouteProxyConfigError::StaticWeb)?
                    .ok_or(NativeHttp1RouteProxyConfigError::MissingRouteAction)?,
            )
        } else {
            NativeHttp1RouteAction::Proxy(Box::new(
                proxy.ok_or(NativeHttp1RouteProxyConfigError::MissingRouteAction)?,
            ))
        };
        let headers = base_headers.with_vhost_overlay(&route.headers);
        Ok(Self {
            methods: route.methods.clone(),
            matcher,
            strip_prefix: route.strip_prefix.clone(),
            rewrite_prefix: route.rewrite_prefix.clone(),
            max_request_body_bytes: route.max_request_body_bytes.map(|bytes| bytes.as_u64()),
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: route
                .compression
                .clone()
                .or_else(|| inherited_compression.cloned()),
            request_headers: NativeRouteRequestHeaderPolicy::from_policy(&headers.request),
            response_headers: NativeRouteResponseHeaderPolicy::from_policy(&headers.response),
            action,
        })
    }

    pub fn with_strip_prefix(mut self, strip_prefix: impl Into<String>) -> Self {
        self.strip_prefix = Some(strip_prefix.into());
        self
    }

    pub fn with_rewrite_prefix(mut self, rewrite_prefix: impl Into<String>) -> Self {
        self.rewrite_prefix = Some(rewrite_prefix.into());
        self
    }

    pub const fn with_max_request_body_bytes(mut self, max_request_body_bytes: u64) -> Self {
        self.max_request_body_bytes = Some(max_request_body_bytes);
        self
    }

    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    pub fn with_compression_config(
        mut self,
        compression: fluxheim_config::CompressionConfig,
    ) -> Self {
        self.compression = Some(compression);
        self
    }

    pub fn with_response_header_policy(
        mut self,
        response_headers: &ResponseHeaderPolicyOverlayConfig,
    ) -> Self {
        // Programmatic builders apply overlays over the safe default response
        // policy. Config-built routes should use from_config_with_inherited()
        // when root/vhost policy inheritance is required.
        self.response_headers = NativeRouteResponseHeaderPolicy::from_overlay(response_headers);
        self
    }

    pub fn with_request_header_policy(
        mut self,
        request_headers: &fluxheim_config::RequestHeaderPolicyOverlayConfig,
    ) -> Self {
        // Programmatic builders apply overlays over the safe default request
        // policy. Config-built routes should use from_config_with_inherited()
        // when root/vhost policy inheritance is required.
        self.request_headers = NativeRouteRequestHeaderPolicy::from_overlay(request_headers);
        self
    }

    pub fn proxy(&self) -> Option<&NativeHttp1Proxy> {
        match &self.action {
            NativeHttp1RouteAction::Proxy(proxy) => Some(proxy.as_ref()),
            NativeHttp1RouteAction::Redirect(_) | NativeHttp1RouteAction::StaticWeb(_) => None,
        }
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self.action, NativeHttp1RouteAction::Redirect(_))
    }

    pub fn is_static_web(&self) -> bool {
        matches!(self.action, NativeHttp1RouteAction::StaticWeb(_))
    }
}

impl NativeHttp1Handler for NativeHttp1RouteProxy {
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            let Some((path, query)) = request_path_and_query(&request) else {
                return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                    .close_connection();
            };
            let route = self.select_route(&request.method, &path);
            let Some(route_or_fallback) = route
                .map(RouteOrFallback::Route)
                .or_else(|| self.fallback.as_ref().map(RouteOrFallback::Fallback))
            else {
                return NativeHttp1Response::new(404, "Not Found", b"not found\n")
                    .close_connection();
            };
            let mut request =
                match route_or_fallback.rewrite_request(request, &path, query.as_deref()) {
                    Some(request) => request,
                    None => {
                        return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                            .close_connection();
                    }
                };
            if route_or_fallback.request_body_too_large(&request) {
                return NativeHttp1Response::new(413, "Payload Too Large", b"payload too large\n")
                    .close_connection();
            }
            route_or_fallback.apply_request_headers(&mut request);
            match route_or_fallback {
                RouteOrFallback::Route(route) => route.handle(request).await,
                RouteOrFallback::Fallback(proxy) => proxy.handle(request).await,
            }
        })
    }
}

#[derive(Clone, Copy)]
enum RouteOrFallback<'a> {
    Route(&'a NativeHttp1RouteProxyRoute),
    Fallback(&'a NativeHttp1Proxy),
}

impl<'a> RouteOrFallback<'a> {
    fn rewrite_request(
        self,
        request: NativeHttp1Request,
        path: &str,
        query: Option<&str>,
    ) -> Option<NativeHttp1Request> {
        match self {
            Self::Route(route) => rewrite_route_request(request, route, path, query),
            Self::Fallback(_) => Some(request),
        }
    }

    fn request_body_too_large(self, request: &NativeHttp1Request) -> bool {
        match self {
            Self::Route(route) => route
                .max_request_body_bytes
                .is_some_and(|limit| (request.body.len() as u64) > limit),
            Self::Fallback(_) => false,
        }
    }

    fn apply_request_headers(self, request: &mut NativeHttp1Request) {
        if let Self::Route(route) = self {
            route.request_headers.apply(request);
        }
    }
}

impl NativeHttp1RouteProxy {
    fn select_route(&self, method: &str, path: &str) -> Option<&NativeHttp1RouteProxyRoute> {
        let mut fallback = None;
        let mut best_prefix = None;
        for route in &self.routes {
            if !route_method_matches(&route.methods, method) {
                continue;
            }
            match &route.matcher {
                NativeHttp1RouteMatcher::Exact(exact) if path == exact => return Some(route),
                NativeHttp1RouteMatcher::Prefix(prefix)
                    if route_prefix_matches_path(prefix, path) =>
                {
                    if best_prefix
                        .map(|best: &NativeHttp1RouteProxyRoute| {
                            route.prefix_len() > best.prefix_len()
                        })
                        .unwrap_or(true)
                    {
                        best_prefix = Some(route);
                    }
                }
                NativeHttp1RouteMatcher::Fallback => fallback = Some(route),
                _ => {}
            }
        }
        best_prefix.or(fallback)
    }
}

impl NativeHttp1RouteProxyRoute {
    fn prefix_len(&self) -> usize {
        match &self.matcher {
            NativeHttp1RouteMatcher::Prefix(prefix) => prefix.len(),
            _ => 0,
        }
    }

    async fn handle(&self, request: NativeHttp1Request) -> NativeHttp1Response {
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        let compression_request = self.compression.as_ref().map(|_| request.clone());
        let mut response = match &self.action {
            NativeHttp1RouteAction::Proxy(proxy) => proxy.handle(request).await,
            NativeHttp1RouteAction::Redirect(redirect) => redirect_response(&request, redirect),
            NativeHttp1RouteAction::StaticWeb(web) => {
                let Some((path, _)) = request_path_and_query(&request) else {
                    return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                        .close_connection();
                };
                web.handle(&request, &path)
            }
        };
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
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn apply_route_compression(
    request: &NativeHttp1Request,
    response: &mut NativeHttp1Response,
    config: &fluxheim_config::CompressionConfig,
) {
    apply_native_response_compression(request, response, config);
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
pub(crate) fn apply_native_response_compression(
    request: &NativeHttp1Request,
    response: &mut NativeHttp1Response,
    config: &fluxheim_config::CompressionConfig,
) {
    let Some(mut encoder) = selected_route_compression(request, response, config) else {
        return;
    };
    let input = Bytes::copy_from_slice(response.body());
    match encoder.encode_chunk(Some(&input), true) {
        Ok(encoded) => {
            response.remove_header("content-encoding");
            response.remove_header("content-length");
            response.remove_header("etag");
            response.push_header("content-encoding", encoder.encoding);
            append_vary_accept_encoding(response);
            response.replace_body(encoded.to_vec());
        }
        Err(error) => {
            log::debug!(
                target: "fluxheim::native",
                "native route response compression skipped: {error}"
            );
        }
    }
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn selected_route_compression(
    request: &NativeHttp1Request,
    response: &NativeHttp1Response,
    config: &fluxheim_config::CompressionConfig,
) -> Option<ResponseCompressionEncoder> {
    if !(config.enabled
        && request.method == "GET"
        && response.status() == 200
        && !response_has_content_encoding(response)
        && !response_has_header(response, "content-range")
        && !response_has_header(response, "set-cookie")
        && !request_has_header(request, "authorization")
        && !request_has_header(request, "cookie")
        && !response_cache_control_blocks_compression(response)
        && response_content_type_is_compressible(response)
        && response_content_length_in_compression_bounds(response, config))
    {
        return None;
    }

    let mut candidates = Vec::new();
    #[cfg(feature = "compression-brotli")]
    if config.brotli
        && let Some(quality) = request_accept_encoding_quality(request, "br")
    {
        candidates.push((quality, 0u8, "br"));
    }
    #[cfg(feature = "compression-zstd")]
    if config.zstd
        && let Some(quality) = request_accept_encoding_quality(request, "zstd")
    {
        candidates.push((quality, 1u8, "zstd"));
    }
    #[cfg(feature = "compression-gzip")]
    if config.gzip
        && let Some(quality) = request_accept_encoding_quality(request, "gzip")
    {
        candidates.push((quality, 2u8, "gzip"));
    }
    candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));

    for (_, _, encoding) in candidates {
        if let Some(encoder) = route_compression_encoder(encoding, config) {
            return Some(encoder);
        }
    }

    None
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn route_compression_encoder(
    encoding: &str,
    config: &fluxheim_config::CompressionConfig,
) -> Option<ResponseCompressionEncoder> {
    match encoding {
        #[cfg(feature = "compression-brotli")]
        "br" => Some(ResponseCompressionEncoder::brotli(
            config.brotli_quality,
            compression_max_output_bytes(config),
        )),
        #[cfg(feature = "compression-zstd")]
        "zstd" => ResponseCompressionEncoder::zstd(
            config.zstd_level,
            compression_max_output_bytes(config),
        )
        .ok(),
        #[cfg(feature = "compression-gzip")]
        "gzip" => Some(ResponseCompressionEncoder::gzip(
            config.gzip_level,
            compression_max_output_bytes(config),
        )),
        _ => None,
    }
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn compression_max_output_bytes(config: &fluxheim_config::CompressionConfig) -> usize {
    usize::try_from(config.max_output_bytes.as_u64()).unwrap_or(usize::MAX)
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn request_accept_encoding_quality(request: &NativeHttp1Request, expected: &str) -> Option<u16> {
    let mut wildcard_quality = None;
    for token in request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
        .flat_map(|(_, value)| value.split(','))
    {
        let Some((coding, quality)) = accept_encoding_token_quality(token) else {
            continue;
        };
        if coding.eq_ignore_ascii_case(expected) {
            return (quality > 0).then_some(quality);
        }
        if coding == "*" && quality > 0 {
            wildcard_quality = Some(wildcard_quality.unwrap_or(0).max(quality));
        }
    }
    wildcard_quality
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn accept_encoding_token_quality(token: &str) -> Option<(&str, u16)> {
    let mut parts = token.split(';');
    let coding = parts.next().unwrap_or_default().trim();
    if coding.is_empty() {
        return None;
    }
    let mut quality = 1000u16;
    for (name, value) in parts
        .map(str::trim)
        .filter_map(|parameter| parameter.split_once('='))
    {
        if !name.trim().eq_ignore_ascii_case("q") {
            continue;
        }
        quality = parse_accept_encoding_qvalue(value.trim())?;
        break;
    }
    Some((coding, quality))
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_has_content_encoding(response: &NativeHttp1Response) -> bool {
    response
        .headers()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .any(|(_, value)| content_encoding_value_is_active(value))
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn request_has_header(request: &NativeHttp1Request, name: &str) -> bool {
    request
        .headers
        .iter()
        .any(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_has_header(response: &NativeHttp1Response, name: &str) -> bool {
    response
        .headers()
        .iter()
        .any(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_cache_control_blocks_compression(response: &NativeHttp1Response) -> bool {
    response
        .headers()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("cache-control"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .any(cache_control_directive_blocks_compression)
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_content_type_is_compressible(response: &NativeHttp1Response) -> bool {
    response
        .headers()
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .is_some_and(|(_, value)| content_type_is_compressible(value))
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_content_length_in_compression_bounds(
    response: &NativeHttp1Response,
    config: &fluxheim_config::CompressionConfig,
) -> bool {
    let length = response
        .content_length()
        .unwrap_or_else(|| response.body().len() as u64);
    input_length_within_compression_bounds(
        length,
        config.min_bytes.as_u64(),
        config.max_input_bytes.as_u64(),
    )
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn append_vary_accept_encoding(response: &mut NativeHttp1Response) {
    let has_accept_encoding = response
        .headers()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("vary"))
        .flat_map(|(_, value)| value.split(','))
        .any(|field| field.trim().eq_ignore_ascii_case("accept-encoding"));
    if !has_accept_encoding {
        response.push_header("vary", "accept-encoding");
    }
}

fn request_path_and_query(request: &NativeHttp1Request) -> Option<(String, Option<String>)> {
    match http1_request_target(&request.method, &request.target).ok()? {
        Http1RequestTarget::Origin { path, query, .. } => {
            Some((path.to_owned(), query.map(str::to_owned)))
        }
        Http1RequestTarget::AbsoluteUri { path, query, .. } => {
            Some((path.unwrap_or("/").to_owned(), query.map(str::to_owned)))
        }
        Http1RequestTarget::Authority { .. } | Http1RequestTarget::Asterisk => None,
    }
}

fn rewrite_route_request(
    mut request: NativeHttp1Request,
    route: &NativeHttp1RouteProxyRoute,
    path: &str,
    query: Option<&str>,
) -> Option<NativeHttp1Request> {
    let Some(strip_prefix) = route.strip_prefix.as_deref() else {
        return Some(request);
    };
    let suffix = route_strip_prefix_suffix(strip_prefix, path)?;
    let rewritten_path = if let Some(rewrite_prefix) = route.rewrite_prefix.as_deref() {
        join_route_rewrite_prefix(rewrite_prefix, suffix)?
    } else if suffix.is_empty() {
        "/".to_owned()
    } else if suffix.starts_with('/') {
        suffix.to_owned()
    } else {
        format!("/{suffix}")
    };
    if !safe_forward_path(&rewritten_path) {
        return None;
    }
    request.target = query
        .map(|query| format!("{rewritten_path}?{query}"))
        .unwrap_or(rewritten_path);
    Some(request)
}

fn join_route_rewrite_prefix(rewrite_prefix: &str, suffix: &str) -> Option<String> {
    if rewrite_prefix == "/" {
        return Some(if suffix.is_empty() {
            "/".to_owned()
        } else if suffix.starts_with('/') {
            suffix.to_owned()
        } else {
            format!("/{suffix}")
        });
    }

    let rewritten_path = if suffix.is_empty() {
        rewrite_prefix.to_owned()
    } else if rewrite_prefix.ends_with('/') && suffix.starts_with('/') {
        format!("{}{}", rewrite_prefix, &suffix[1..])
    } else if rewrite_prefix.ends_with('/') || suffix.starts_with('/') {
        format!("{rewrite_prefix}{suffix}")
    } else {
        format!("{rewrite_prefix}/{suffix}")
    };

    safe_forward_path(&rewritten_path).then_some(rewritten_path)
}

fn redirect_response(
    request: &NativeHttp1Request,
    redirect: &NativeHttp1RouteRedirect,
) -> NativeHttp1Response {
    let Some(location) = route_redirect_location(request, redirect) else {
        return NativeHttp1Response::new(400, "Bad Request", b"invalid redirect target\n")
            .close_connection();
    };
    NativeHttp1Response::new(
        redirect.status,
        redirect_reason(redirect.status),
        Vec::new(),
    )
    .with_header("location", location)
}

fn redirect_reason(status: u16) -> &'static str {
    match status {
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        _ => "Redirect",
    }
}

fn route_redirect_location(
    request: &NativeHttp1Request,
    redirect: &NativeHttp1RouteRedirect,
) -> Option<String> {
    let (path, query) = request_path_and_query(request)?;
    let uri = query
        .as_deref()
        .map(|query| format!("{path}?{query}"))
        .unwrap_or_else(|| path.clone());
    if !safe_forward_path(&path) || uri.chars().any(char::is_control) {
        return None;
    }
    if redirect_template_substitutes_query_into_path(&redirect.to)
        && !redirect_query_path_expansion_safe(query.as_deref().unwrap_or_default())
    {
        return None;
    }

    let location = redirect
        .to
        .replace("{uri}", &uri)
        .replace("{path}", &path)
        .replace("{query}", query.as_deref().unwrap_or_default());
    valid_redirect_location(&location).then_some(location)
}

fn redirect_template_substitutes_query_into_path(template: &str) -> bool {
    let Some(query_token) = template.find("{query}") else {
        return false;
    };
    let query_tail = template.find(['?', '#']).unwrap_or(template.len());
    query_token < query_tail
}

fn redirect_query_path_expansion_safe(query: &str) -> bool {
    if query.is_empty() || query.chars().any(char::is_control) {
        return query.is_empty();
    }
    safe_forward_path(&format!("/{query}"))
}

fn valid_redirect_location(location: &str) -> bool {
    if !(location.starts_with("https://") || location.starts_with("http://"))
        || !redirect_location_path_safe(location)
    {
        return false;
    }
    !location.contains('{')
        && !location.contains('}')
        && !location.contains('\\')
        && !location
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn redirect_location_path_safe(location: &str) -> bool {
    let Some(rest) = location
        .strip_prefix("https://")
        .or_else(|| location.strip_prefix("http://"))
    else {
        return false;
    };
    let path_and_tail = rest
        .find('/')
        .map(|path_start| &rest[path_start..])
        .unwrap_or_default();
    let path_end = path_and_tail
        .find(['?', '#'])
        .unwrap_or(path_and_tail.len());
    let path = &path_and_tail[..path_end];
    path.is_empty() || safe_forward_path(path)
}

#[cfg(not(feature = "privacy-mode"))]
fn header_value<'a>(request: &'a NativeHttp1Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(header_name, value)| {
            header_name.eq_ignore_ascii_case(name) && !value.trim().is_empty()
        })
        .map(|(_, value)| value.trim())
}

fn strip_spoofable_client_ip_headers(request: &mut NativeHttp1Request) {
    request.headers.retain(|(header_name, _)| {
        !SPOOFABLE_CLIENT_IP_HEADERS
            .iter()
            .any(|blocked| header_name.eq_ignore_ascii_case(blocked))
    });
}

#[cfg(not(feature = "privacy-mode"))]
fn remove_request_header(request: &mut NativeHttp1Request, name: &str) {
    request
        .headers
        .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
}

#[cfg(not(feature = "privacy-mode"))]
fn replace_request_header(
    request: &mut NativeHttp1Request,
    name: impl Into<String>,
    value: impl Into<String>,
) {
    let name = name.into();
    remove_request_header(request, &name);
    request.headers.push((name, value.into()));
}

impl NativeRouteRequestHeaderPolicy {
    pub(crate) fn from_policy(policy: &RequestHeaderPolicyConfig) -> Self {
        Self {
            enabled: policy.enabled,
            strip_inbound_client_ip_headers: policy.strip_inbound_client_ip_headers,
            #[cfg(not(feature = "privacy-mode"))]
            x_forwarded_for: policy.x_forwarded_for,
            #[cfg(not(feature = "privacy-mode"))]
            x_real_ip: policy.x_real_ip,
            #[cfg(not(feature = "privacy-mode"))]
            x_forwarded_host: policy.x_forwarded_host,
            #[cfg(not(feature = "privacy-mode"))]
            x_forwarded_proto: policy.x_forwarded_proto,
            #[cfg(not(feature = "privacy-mode"))]
            forwarded: policy.forwarded,
            unset: policy.effective_unset(),
            set: policy.effective_set().into_iter().collect(),
            append: flatten_append_headers(&policy.append),
        }
    }

    fn from_overlay(overlay: &fluxheim_config::RequestHeaderPolicyOverlayConfig) -> Self {
        let mut policy = Self::from_policy(&RequestHeaderPolicyConfig::default());
        if let Some(enabled) = overlay.enabled {
            policy.enabled = enabled;
        }
        if let Some(strip) = overlay.strip_inbound_client_ip_headers {
            policy.strip_inbound_client_ip_headers = strip;
        }
        #[cfg(not(feature = "privacy-mode"))]
        {
            if let Some(mode) = overlay.x_forwarded_for {
                policy.x_forwarded_for = mode;
            }
            if let Some(x_real_ip) = overlay.x_real_ip {
                policy.x_real_ip = x_real_ip;
            }
            if let Some(x_forwarded_host) = overlay.x_forwarded_host {
                policy.x_forwarded_host = x_forwarded_host;
            }
            if let Some(x_forwarded_proto) = overlay.x_forwarded_proto {
                policy.x_forwarded_proto = x_forwarded_proto;
            }
            if let Some(forwarded) = overlay.forwarded {
                policy.forwarded = forwarded;
            }
        }
        policy.unset = overlay.effective_unset();
        policy.set = overlay.effective_set().into_iter().collect();
        policy.append = flatten_append_headers(&overlay.append);
        policy
    }

    pub(crate) fn apply(&self, request: &mut NativeHttp1Request) {
        if !self.enabled {
            #[cfg(feature = "privacy-mode")]
            strip_spoofable_client_ip_headers(request);
            return;
        }
        #[cfg(not(feature = "privacy-mode"))]
        self.apply_forwarded_headers(request);
        for name in &self.unset {
            request
                .headers
                .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
        }
        for (name, value) in &self.set {
            request
                .headers
                .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
            request.headers.push((name.clone(), value.clone()));
        }
        for (name, value) in &self.append {
            request.headers.push((name.clone(), value.clone()));
        }
        #[cfg(feature = "privacy-mode")]
        strip_spoofable_client_ip_headers(request);
    }

    #[cfg(not(feature = "privacy-mode"))]
    fn apply_forwarded_headers(&self, request: &mut NativeHttp1Request) {
        let original_host = header_value(request, "host").map(str::to_owned);
        let proto = if request.downstream_tls {
            "https"
        } else {
            "http"
        };

        if self.strip_inbound_client_ip_headers {
            strip_spoofable_client_ip_headers(request);
        }

        let original_x_forwarded_for = header_value(request, "x-forwarded-for").map(str::to_owned);
        let client_ip = request.peer_addr.map(|addr| addr.ip());
        match (self.x_forwarded_for, client_ip) {
            (ForwardedClientIpHeaderMode::Off, _) => {
                remove_request_header(request, "x-forwarded-for")
            }
            (ForwardedClientIpHeaderMode::Replace, Some(ip)) => {
                replace_request_header(request, "x-forwarded-for", ip.to_string());
            }
            (ForwardedClientIpHeaderMode::Append, Some(ip)) => {
                let value = original_x_forwarded_for
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| format!("{value}, {ip}"))
                    .unwrap_or_else(|| ip.to_string());
                replace_request_header(request, "x-forwarded-for", value);
            }
            (ForwardedClientIpHeaderMode::Replace | ForwardedClientIpHeaderMode::Append, None) => {
                remove_request_header(request, "x-forwarded-for");
            }
        }

        if self.x_real_ip {
            if let Some(ip) = client_ip {
                replace_request_header(request, "x-real-ip", ip.to_string());
            } else {
                remove_request_header(request, "x-real-ip");
            }
        }

        if self.x_forwarded_host {
            if let Some(host) = &original_host {
                replace_request_header(request, "x-forwarded-host", host.clone());
            } else {
                remove_request_header(request, "x-forwarded-host");
            }
        }

        if self.x_forwarded_proto {
            replace_request_header(request, "x-forwarded-proto", proto);
        }

        if self.forwarded {
            if let Some(ip) = client_ip {
                replace_request_header(
                    request,
                    "forwarded",
                    build_forwarded_header(ip, original_host.as_deref(), proto),
                );
            } else {
                remove_request_header(request, "forwarded");
            }
        }
    }
}

fn default_native_request_header_policy() -> NativeRouteRequestHeaderPolicy {
    NativeRouteRequestHeaderPolicy::from_policy(&RequestHeaderPolicyConfig::default())
}

impl NativeRouteResponseHeaderPolicy {
    pub(crate) fn from_policy(policy: &ResponseHeaderPolicyConfig) -> Self {
        let mut native = Self {
            enabled: policy.enabled,
            unset: policy.effective_unset(),
            set: policy.effective_set().into_iter().collect(),
            append: flatten_append_headers(&policy.append),
            rewrite: policy.rewrite.clone(),
        };
        native.apply_standard_headers_from_policy(policy);
        native
    }

    fn from_overlay(overlay: &ResponseHeaderPolicyOverlayConfig) -> Self {
        let mut policy = Self {
            enabled: overlay.enabled.unwrap_or(true),
            unset: overlay.effective_unset(),
            set: overlay.effective_set().into_iter().collect(),
            append: flatten_append_headers(&overlay.append),
            rewrite: overlay.rewrite.clone(),
        };
        policy.apply_standard_headers(overlay);
        policy
    }

    fn apply_standard_headers_from_policy(&mut self, policy: &ResponseHeaderPolicyConfig) {
        if let Some(value) = &policy.strict_transport_security {
            self.set_optional_header("strict-transport-security", Some(value.clone()));
        } else if let Some(hsts) = &policy.hsts
            && let Some(value) = hsts.header_value()
        {
            self.set_optional_header("strict-transport-security", Some(value));
        }
        if let Some(value) = &policy.content_security_policy {
            self.set_optional_header("content-security-policy", Some(value.clone()));
        }
        if let Some(value) = &policy.x_content_type_options {
            self.set_optional_header("x-content-type-options", Some(value.clone()));
        }
        if let Some(value) = &policy.x_frame_options {
            self.set_optional_header("x-frame-options", Some(value.clone()));
        }
        if let Some(value) = &policy.referrer_policy {
            self.set_optional_header("referrer-policy", Some(value.clone()));
        }
    }

    fn apply_standard_headers(&mut self, overlay: &ResponseHeaderPolicyOverlayConfig) {
        if let Some(value) = &overlay.hsts {
            self.set_optional_header(
                "strict-transport-security",
                value.as_ref().and_then(|hsts| hsts.header_value()),
            );
        }
        if let Some(value) = &overlay.strict_transport_security {
            self.set_optional_header("strict-transport-security", value.clone());
        }
        if let Some(value) = &overlay.content_security_policy {
            self.set_optional_header("content-security-policy", value.clone());
        }
        if let Some(value) = &overlay.x_content_type_options {
            self.set_optional_header("x-content-type-options", value.clone());
        }
        if let Some(value) = &overlay.x_frame_options {
            self.set_optional_header("x-frame-options", value.clone());
        }
        if let Some(value) = &overlay.referrer_policy {
            self.set_optional_header("referrer-policy", value.clone());
        }
    }

    fn set_optional_header(&mut self, name: &str, value: Option<String>) {
        if let Some(value) = value {
            self.set.push((name.to_owned(), value));
        } else {
            self.unset.push(name.to_owned());
        }
    }

    pub(crate) fn apply(&self, response: &mut NativeHttp1Response) {
        if !self.enabled {
            return;
        }
        apply_response_rewrites(response, &self.rewrite);
        for name in &self.unset {
            response.remove_header(name);
        }
        for (name, value) in &self.set {
            response.remove_header(name);
            response.push_header(name.clone(), value.clone());
        }
        for (name, value) in &self.append {
            response.push_header(name.clone(), value.clone());
        }
    }
}

fn apply_response_rewrites(
    response: &mut NativeHttp1Response,
    rewrite: &ResponseHeaderRewriteConfig,
) {
    rewrite_response_header_values(
        response,
        "location",
        &rewrite.location,
        rewrite_header_prefix,
    );
    rewrite_response_header_values(response, "refresh", &rewrite.refresh, rewrite_refresh_url);
    rewrite_set_cookie_header_values(response, rewrite);
}

fn rewrite_response_header_values(
    response: &mut NativeHttp1Response,
    name: &'static str,
    rules: &[fluxheim_config::ResponseHeaderRewriteRuleConfig],
    rewrite_value: fn(&str, &[fluxheim_config::ResponseHeaderRewriteRuleConfig]) -> Option<String>,
) {
    if rules.is_empty() {
        return;
    }
    let mut changed = false;
    let mut rewritten = Vec::with_capacity(response.headers().len());
    for (header_name, header_value) in response.headers() {
        if header_name.eq_ignore_ascii_case(name)
            && let Some(value) = rewrite_value(header_value, rules)
        {
            rewritten.push((header_name.clone(), value));
            changed = true;
        } else {
            rewritten.push((header_name.clone(), header_value.clone()));
        }
    }
    if changed {
        replace_response_headers(response, rewritten);
    }
}

fn rewrite_set_cookie_header_values(
    response: &mut NativeHttp1Response,
    rewrite: &ResponseHeaderRewriteConfig,
) {
    if rewrite.cookie_domain.is_empty() && rewrite.cookie_path.is_empty() {
        return;
    }
    let mut changed = false;
    let mut rewritten = Vec::with_capacity(response.headers().len());
    for (header_name, header_value) in response.headers() {
        if header_name.eq_ignore_ascii_case("set-cookie")
            && let Some(value) = rewrite_set_cookie_value(header_value, rewrite)
        {
            rewritten.push((header_name.clone(), value));
            changed = true;
        } else {
            rewritten.push((header_name.clone(), header_value.clone()));
        }
    }
    if changed {
        replace_response_headers(response, rewritten);
    }
}

fn replace_response_headers(response: &mut NativeHttp1Response, headers: Vec<(String, String)>) {
    let names = response
        .headers()
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    for name in names {
        response.remove_header(&name);
    }
    for (name, value) in headers {
        response.push_header(name, value);
    }
}

fn flatten_append_headers(
    append: &std::collections::BTreeMap<String, HeaderValues>,
) -> Vec<(String, String)> {
    let mut flattened = Vec::new();
    for (name, values) in append {
        for value in values.iter() {
            flattened.push((name.clone(), value.to_owned()));
        }
    }
    flattened
}

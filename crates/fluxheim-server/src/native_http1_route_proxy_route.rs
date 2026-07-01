#[cfg(feature = "acme")]
use crate::NativeHttp1AcmeHttp01Store;
#[cfg(not(feature = "privacy-mode"))]
use crate::ProxyProtocolTrustedSource;
use crate::native_http1_route_action::NativeHttp1RouteAction;
use crate::native_http1_route_cache_policy::native_route_cache_policy_blocked;
use crate::native_http1_route_limits::{
    NativeConcurrencyLimit, NativeIpAccessPolicy, NativeRateLimit,
};
use crate::native_http1_route_matcher::{NativeHttp1RouteMatcher, NativeRegexRouteMatcher};
#[cfg(feature = "php-fpm")]
use crate::native_http1_route_php::NativePhpFpmRoute;
use crate::native_http1_route_proxy::{
    NativeHttp1RouteProxyConfigError, NativeHttp1RouteProxyRoute,
};
use crate::native_http1_route_redirect::NativeHttp1RouteRedirect;
use crate::native_http1_route_request_headers::{
    NativeRouteRequestHeaderPolicy, default_native_request_header_policy,
};
use crate::native_http1_route_response_headers::NativeRouteResponseHeaderPolicy;
use crate::{NativeHttp1Proxy, NativeHttp1ProxyConfigError, NativeHttp1StaticWeb};
use fluxheim_config::{GrpcRouteConfig, HeaderPolicyConfig, ResponseHeaderPolicyOverlayConfig};

impl NativeHttp1RouteProxyRoute {
    pub fn exact(path: impl Into<String>, methods: Vec<String>, proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Exact(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::Proxy(Box::new(proxy.without_header_policy())),
        }
    }

    pub fn prefix(path: impl Into<String>, methods: Vec<String>, proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::Proxy(Box::new(proxy.without_header_policy())),
        }
    }

    pub fn fallback(proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods: Vec::new(),
            matcher: NativeHttp1RouteMatcher::Fallback,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::Proxy(Box::new(proxy.without_header_policy())),
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
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
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
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
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
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::StaticWeb(Box::new(web)),
        }
    }

    #[cfg(feature = "acme")]
    pub(crate) fn acme_http_01(
        vhost_name: &str,
        storage: &std::path::Path,
        base_headers: &HeaderPolicyConfig,
    ) -> Self {
        Self {
            methods: Vec::new(),
            matcher: NativeHttp1RouteMatcher::Prefix("/.well-known/acme-challenge/".to_owned()),
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            https_redirect_exempt: true,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            request_headers: NativeRouteRequestHeaderPolicy::from_policy(&base_headers.request),
            response_headers: NativeRouteResponseHeaderPolicy::from_policy(&base_headers.response),
            access: NativeIpAccessPolicy::default(),
            rate_limit: NativeRateLimit::default(),
            concurrency: NativeConcurrencyLimit::default(),
            grpc: GrpcRouteConfig::default(),
            action: NativeHttp1RouteAction::AcmeHttp01(NativeHttp1AcmeHttp01Store::new(
                storage, vhost_name,
            )),
        }
    }

    pub fn from_config(
        route: &fluxheim_config::RouteConfig,
        proxy: Option<NativeHttp1Proxy>,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        Self::from_config_with_inherited(route, proxy, &HeaderPolicyConfig::default(), None, "")
    }

    pub fn from_config_with_inherited(
        route: &fluxheim_config::RouteConfig,
        proxy: Option<NativeHttp1Proxy>,
        base_headers: &HeaderPolicyConfig,
        inherited_compression: Option<&fluxheim_config::CompressionConfig>,
        #[cfg_attr(not(feature = "php-fpm"), allow(unused_variables))] vhost_name: &str,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        if native_route_cache_policy_blocked(route) {
            return Err(NativeHttp1RouteProxyConfigError::Proxy(
                NativeHttp1ProxyConfigError::CachePolicy,
            ));
        }
        #[cfg(not(feature = "php-fpm"))]
        if route.php.as_ref().is_some_and(|php| php.enabled) {
            return Err(NativeHttp1RouteProxyConfigError::Proxy(
                NativeHttp1ProxyConfigError::PhpFpm,
            ));
        }
        #[cfg(not(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        )))]
        let _ = inherited_compression;
        let matcher = if let Some(path) = &route.path_exact {
            NativeHttp1RouteMatcher::Exact(path.clone())
        } else if let Some(path) = &route.path_prefix {
            NativeHttp1RouteMatcher::Prefix(path.clone())
        } else if let Some(pattern) = &route.path_regex {
            NativeHttp1RouteMatcher::Regex(
                NativeRegexRouteMatcher::from_pattern(pattern)
                    .map_err(|_| NativeHttp1RouteProxyConfigError::RegexRoute)?,
            )
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
        } else if let Some(php) = route.php.as_ref().filter(|php| php.enabled) {
            #[cfg(feature = "php-fpm")]
            {
                NativeHttp1RouteAction::PhpFpm(Box::new(
                    NativePhpFpmRoute::from_config(
                        format!("route {}", route.name),
                        vhost_name,
                        &route.name,
                        php,
                    )?
                    .ok_or(NativeHttp1RouteProxyConfigError::MissingRouteAction)?,
                ))
            }
            #[cfg(not(feature = "php-fpm"))]
            {
                let _ = php;
                return Err(NativeHttp1RouteProxyConfigError::Proxy(
                    NativeHttp1ProxyConfigError::PhpFpm,
                ));
            }
        } else if let Some(web) = route.web.as_ref().filter(|web| web.enabled()) {
            NativeHttp1RouteAction::StaticWeb(Box::new(
                NativeHttp1StaticWeb::from_config_with_cache(web, route.cache.as_ref())
                    .map_err(|_| NativeHttp1RouteProxyConfigError::StaticWeb)?
                    .ok_or(NativeHttp1RouteProxyConfigError::MissingRouteAction)?,
            ))
        } else {
            NativeHttp1RouteAction::Proxy(Box::new(
                proxy
                    .ok_or(NativeHttp1RouteProxyConfigError::MissingRouteAction)?
                    .without_header_policy(),
            ))
        };
        let headers = base_headers.with_vhost_overlay(&route.headers);
        Ok(Self {
            methods: route.methods.clone(),
            matcher,
            strip_prefix: route.strip_prefix.clone(),
            rewrite_prefix: route.rewrite_prefix.clone(),
            rewrite_template: route.rewrite_template.clone(),
            max_request_body_bytes: route.max_request_body_bytes.map(|bytes| bytes.as_u64()),
            https_redirect_exempt: route.https_redirect_exempt,
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
            access: NativeIpAccessPolicy::from_config(&route.access)?,
            rate_limit: NativeRateLimit::from_config(&route.rate_limit),
            concurrency: NativeConcurrencyLimit::from_config(&route.concurrency),
            grpc: route.grpc,
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

    #[cfg(test)]
    pub const fn with_grpc_policy(mut self, grpc: GrpcRouteConfig) -> Self {
        self.grpc = grpc;
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

    #[cfg(not(feature = "privacy-mode"))]
    pub fn with_trusted_sources(mut self, trusted_sources: &[ProxyProtocolTrustedSource]) -> Self {
        self.request_headers
            .set_trusted_sources(trusted_sources.to_vec());
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
        self.action.proxy()
    }

    pub fn is_redirect(&self) -> bool {
        self.action.is_redirect()
    }

    pub(crate) fn https_redirect_exempt_or_redirect(&self) -> bool {
        self.https_redirect_exempt || self.is_redirect() || self.action.https_redirect_exempt()
    }

    pub fn is_static_web(&self) -> bool {
        self.action.is_static_web()
    }
}

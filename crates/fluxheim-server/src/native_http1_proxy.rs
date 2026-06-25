#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
use crate::NativeHttp1UpstreamTls;
#[cfg(not(feature = "privacy-mode"))]
use crate::ProxyProtocolTrustedSource;
#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use crate::native_http1_route_proxy::apply_native_response_compression;
use crate::native_http1_route_proxy::{
    NativeRouteRequestHeaderPolicy, NativeRouteResponseHeaderPolicy,
    default_native_request_header_policy,
};
use crate::{
    DownstreamHttp2Policy, NativeHttp1ConnectionStream, NativeHttp1Handler, NativeHttp1Request,
    NativeHttp1Response, NativeHttp1ResponseWritePolicy, NativeHttp1StaticWeb, NativeHttp1Upstream,
    NativeTcpKeepalivePolicy,
};
#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
use sanitization::ct::ConstantTimeEq;

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
const NATIVE_TRAFFIC_MIRROR_INFLIGHT_MAX_KEYS: usize = 4096;
const MAX_NATIVE_UPSTREAM_H2_STREAMS: usize = 1024;

#[cfg(feature = "load-balancer")]
type NativeProxyConfigBuild = (
    NativeHttp1Proxy,
    Option<fluxheim_load_balancer::UpstreamLoadBalancerService>,
);

#[cfg(not(feature = "load-balancer"))]
type NativeProxyConfigBuild = NativeHttp1Proxy;

#[derive(Clone, Debug)]
pub struct NativeHttp1Proxy {
    upstreams: Vec<NativeHttp1Upstream>,
    upstream_slots: Vec<usize>,
    #[cfg(feature = "load-balancer")]
    load_balancer: Option<fluxheim_load_balancer::UpstreamLoadBalancer>,
    #[cfg(feature = "load-balancer")]
    load_balancer_upstream_template: Option<NativeHttp1Upstream>,
    error_pages: Vec<NativeHttp1ProxyErrorPage>,
    request_headers: NativeRouteRequestHeaderPolicy,
    response_headers: NativeRouteResponseHeaderPolicy,
    response_write_policy: NativeHttp1ResponseWritePolicy,
    request_body_timeout: Option<Duration>,
    websocket: bool,
    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    compression: Option<fluxheim_config::CompressionConfig>,
    #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
    mirror: Option<NativeTrafficMirror>,
    #[cfg(feature = "auth-request")]
    auth_request: Option<NativeAuthRequest>,
    next_upstream: Arc<AtomicUsize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeHttp1ProxyErrorPage {
    status: u16,
    path: String,
    web: NativeHttp1StaticWeb,
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeTrafficMirror {
    base_url: String,
    sample_per_mille: u16,
    methods: Vec<String>,
    forward_headers: Vec<String>,
    timeout: Duration,
    max_response_bytes: u64,
    max_in_flight: usize,
    slot_key: String,
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
#[derive(Debug)]
struct NativeTrafficMirrorRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    timeout: Duration,
    max_response_bytes: u64,
    max_in_flight: usize,
    slot_key: String,
}

#[cfg(feature = "auth-request")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeAuthRequest {
    url: String,
    forward_headers: Vec<String>,
    allow_response_headers: Vec<String>,
    timeout: Duration,
    max_response_bytes: u64,
}

#[cfg(feature = "auth-request")]
#[derive(Debug)]
enum NativeAuthRequestDecision {
    Allow {
        headers: Vec<(String, zeroize::Zeroizing<String>)>,
    },
    Deny {
        status: u16,
        body: Vec<u8>,
    },
}

#[cfg(feature = "auth-request")]
#[derive(Debug)]
struct NativeAuthRequestInput {
    headers: Vec<(String, zeroize::Zeroizing<String>)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttp1ProxyConfigError {
    CachePolicy,
    DynamicUpstreamDiscovery,
    ErrorPages,
    HttpPolicy,
    LoadBalancing,
    MissingUpstream,
    RecvBufferTooLarge,
    TrafficMirror,
    AuthRequest,
    PhpFpm,
    UpstreamHttp2,
    UpstreamProxyProtocol,
    UpstreamTls,
    UpstreamTlsPolicy,
    UpstreamTransportPolicy,
    WebSocket,
}

impl std::fmt::Display for NativeHttp1ProxyConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CachePolicy => {
                formatter.write_str("native HTTP/1 proxy does not yet support cache policy")
            }
            Self::DynamicUpstreamDiscovery => formatter
                .write_str("native HTTP/1 proxy does not yet support dynamic upstream discovery"),
            Self::ErrorPages => {
                formatter.write_str("native HTTP/1 proxy rejected proxy error page config")
            }
            Self::HttpPolicy => formatter
                .write_str("native HTTP/1 proxy does not yet support Fluxheim HTTP policy layers"),
            Self::LoadBalancing => formatter.write_str(
                "native HTTP/1 proxy does not yet support advanced load-balancer policy",
            ),
            Self::MissingUpstream => {
                formatter.write_str("native HTTP/1 proxy requires an upstream")
            }
            Self::RecvBufferTooLarge => {
                formatter.write_str("native HTTP/1 proxy upstream receive buffer size is too large")
            }
            Self::TrafficMirror => {
                formatter.write_str(
                    "native HTTP/1 proxy traffic mirroring requires the traffic-mirror feature and a non-privacy build",
                )
            }
            Self::AuthRequest => {
                formatter.write_str(
                    "native HTTP/1 proxy auth subrequests require the auth-request feature",
                )
            }
            Self::PhpFpm => {
                formatter.write_str("native HTTP/1 proxy rejected PHP-FPM policy")
            }
            Self::UpstreamHttp2 => formatter.write_str(
                "native HTTP/1 proxy rejected unsupported upstream HTTP/2 mode",
            ),
            Self::UpstreamProxyProtocol => formatter
                .write_str("native HTTP/1 proxy only supports upstream PROXY protocol with forced HTTP/1 origins"),
            Self::UpstreamTls => {
                formatter.write_str("native HTTP/1 proxy does not yet support upstream TLS")
            }
            Self::UpstreamTlsPolicy => {
                formatter.write_str("native HTTP/1 proxy rejected upstream TLS policy")
            }
            Self::UpstreamTransportPolicy => formatter.write_str(
                "native HTTP/1 proxy does not yet support advanced upstream transport policy",
            ),
            Self::WebSocket => formatter.write_str(
                "native HTTP/1 proxy only supports websocket upgrade with forced HTTP/1 static upstreams",
            ),
        }
    }
}

impl std::error::Error for NativeHttp1ProxyConfigError {}

impl NativeHttp1Proxy {
    pub fn new(upstream: NativeHttp1Upstream) -> Self {
        Self {
            upstreams: vec![upstream],
            upstream_slots: vec![0],
            #[cfg(feature = "load-balancer")]
            load_balancer: None,
            #[cfg(feature = "load-balancer")]
            load_balancer_upstream_template: None,
            error_pages: Vec::new(),
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            response_write_policy: NativeHttp1ResponseWritePolicy::default(),
            request_body_timeout: None,
            websocket: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
            mirror: None,
            #[cfg(feature = "auth-request")]
            auth_request: None,
            next_upstream: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn from_upstreams(
        upstreams: Vec<NativeHttp1Upstream>,
    ) -> Result<Self, NativeHttp1ProxyConfigError> {
        if upstreams.is_empty() {
            return Err(NativeHttp1ProxyConfigError::MissingUpstream);
        }
        let upstream_slots = (0..upstreams.len()).collect();
        Ok(Self {
            upstreams,
            upstream_slots,
            #[cfg(feature = "load-balancer")]
            load_balancer: None,
            #[cfg(feature = "load-balancer")]
            load_balancer_upstream_template: None,
            error_pages: Vec::new(),
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            response_write_policy: NativeHttp1ResponseWritePolicy::default(),
            request_body_timeout: None,
            websocket: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
            mirror: None,
            #[cfg(feature = "auth-request")]
            auth_request: None,
            next_upstream: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn from_weighted_upstreams(
        upstreams: Vec<NativeHttp1Upstream>,
        weights: &[usize],
    ) -> Result<Self, NativeHttp1ProxyConfigError> {
        if upstreams.is_empty() {
            return Err(NativeHttp1ProxyConfigError::MissingUpstream);
        }
        let mut upstream_slots = Vec::new();
        for (index, _) in upstreams.iter().enumerate() {
            let weight = weights.get(index).copied().unwrap_or(1);
            upstream_slots.extend(std::iter::repeat_n(index, weight));
        }
        if upstream_slots.is_empty() {
            return Err(NativeHttp1ProxyConfigError::MissingUpstream);
        }
        Ok(Self {
            upstreams,
            upstream_slots,
            #[cfg(feature = "load-balancer")]
            load_balancer: None,
            #[cfg(feature = "load-balancer")]
            load_balancer_upstream_template: None,
            error_pages: Vec::new(),
            request_headers: default_native_request_header_policy(),
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            response_write_policy: NativeHttp1ResponseWritePolicy::default(),
            request_body_timeout: None,
            websocket: false,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression: None,
            #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
            mirror: None,
            #[cfg(feature = "auth-request")]
            auth_request: None,
            next_upstream: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn upstream(&self) -> &NativeHttp1Upstream {
        &self.upstreams[0]
    }

    pub fn upstreams(&self) -> &[NativeHttp1Upstream] {
        &self.upstreams
    }

    pub fn upstream_slots(&self) -> &[usize] {
        &self.upstream_slots
    }

    pub const fn response_write_policy(&self) -> NativeHttp1ResponseWritePolicy {
        self.response_write_policy
    }

    pub const fn request_body_timeout(&self) -> Option<Duration> {
        self.request_body_timeout
    }

    pub const fn with_request_body_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.request_body_timeout = timeout;
        self
    }

    pub const fn with_websocket_enabled(mut self, enabled: bool) -> Self {
        self.websocket = enabled;
        self
    }

    pub fn with_header_policy(mut self, headers: &fluxheim_config::HeaderPolicyConfig) -> Self {
        self.request_headers = NativeRouteRequestHeaderPolicy::from_policy(&headers.request);
        self.response_headers = NativeRouteResponseHeaderPolicy::from_policy(&headers.response);
        self
    }

    pub(crate) fn without_header_policy(mut self) -> Self {
        self.request_headers = NativeRouteRequestHeaderPolicy::default();
        self.response_headers = NativeRouteResponseHeaderPolicy::default();
        self
    }

    #[cfg(not(feature = "privacy-mode"))]
    pub fn with_trusted_sources(mut self, trusted_sources: &[ProxyProtocolTrustedSource]) -> Self {
        self.request_headers
            .set_trusted_sources(trusted_sources.to_vec());
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

    pub fn from_proxy_config(
        proxy: &fluxheim_config::ProxyConfig,
        policy: crate::DownstreamHttp1Policy,
    ) -> Result<Option<Self>, NativeHttp1ProxyConfigError> {
        Self::from_proxy_config_with_pool_size(proxy, policy, 0)
    }

    pub fn from_root_config(
        config: &fluxheim_config::Config,
        policy: crate::DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Option<Self>, NativeHttp1ProxyConfigError> {
        let native = Self::from_proxy_config_with_pool_size(&config.proxy, policy, pool_max_idle)?
            .map(|proxy| proxy.with_header_policy(&config.headers));
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        let native = native.map(|proxy| {
            if config.compression.enabled {
                proxy.with_compression_config(config.compression.clone())
            } else {
                proxy
            }
        });
        Ok(native)
    }

    pub fn from_proxy_config_with_pool_size(
        proxy: &fluxheim_config::ProxyConfig,
        policy: crate::DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<Option<Self>, NativeHttp1ProxyConfigError> {
        #[cfg(feature = "load-balancer")]
        {
            Self::from_proxy_config_with_pool_size_and_load_balancer(
                proxy,
                policy,
                pool_max_idle,
                None,
            )
            .map(|result| result.map(|build| build.0))
        }
        #[cfg(not(feature = "load-balancer"))]
        {
            Self::from_proxy_config_with_pool_size_and_load_balancer(proxy, policy, pool_max_idle)
        }
    }

    #[cfg(feature = "load-balancer")]
    pub fn from_proxy_config_with_native_load_balancer(
        name: &str,
        vhost: &str,
        route: Option<&str>,
        proxy: &fluxheim_config::ProxyConfig,
        policy: crate::DownstreamHttp1Policy,
        pool_max_idle: usize,
    ) -> Result<
        Option<(
            Self,
            Option<fluxheim_load_balancer::UpstreamLoadBalancerService>,
        )>,
        NativeHttp1ProxyConfigError,
    > {
        Self::from_proxy_config_with_pool_size_and_load_balancer(
            proxy,
            policy,
            pool_max_idle,
            Some((name, vhost, route)),
        )
    }

    fn from_proxy_config_with_pool_size_and_load_balancer(
        proxy: &fluxheim_config::ProxyConfig,
        policy: crate::DownstreamHttp1Policy,
        pool_max_idle: usize,
        #[cfg(feature = "load-balancer")] load_balancer_scope: Option<(&str, &str, Option<&str>)>,
    ) -> Result<Option<NativeProxyConfigBuild>, NativeHttp1ProxyConfigError> {
        if !proxy.has_configured_upstream() {
            return Ok(None);
        }
        if !proxy.upstream_tls
            && (proxy.upstream_ca_path.is_some()
                || proxy.upstream_client_cert_path.is_some()
                || proxy.upstream_client_key_path.is_some())
        {
            return Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy);
        }
        #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
        if proxy.upstream_http_version == fluxheim_config::UpstreamHttpVersion::Http1AndHttp2
            && !proxy.upstream_h2c_upgrade
        {
            return Err(NativeHttp1ProxyConfigError::UpstreamHttp2);
        }
        #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
        if proxy.upstream_tls {
            return Err(NativeHttp1ProxyConfigError::UpstreamTls);
        }
        if proxy.websocket
            && proxy.upstream_http_version != fluxheim_config::UpstreamHttpVersion::Http1
        {
            return Err(NativeHttp1ProxyConfigError::WebSocket);
        }
        match proxy.upstream_http_version {
            fluxheim_config::UpstreamHttpVersion::Http1
                if proxy.upstream_h2_max_streams.is_none() => {}
            fluxheim_config::UpstreamHttpVersion::Http2 => {}
            fluxheim_config::UpstreamHttpVersion::Http1AndHttp2 if proxy.upstream_tls => {}
            fluxheim_config::UpstreamHttpVersion::Http1AndHttp2 if proxy.upstream_h2c_upgrade => {}
            fluxheim_config::UpstreamHttpVersion::Http1AndHttp2 => {
                return Err(NativeHttp1ProxyConfigError::UpstreamHttp2);
            }
            fluxheim_config::UpstreamHttpVersion::Http1 => {
                return Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy);
            }
        }
        if proxy.upstream_proxy_protocol != fluxheim_config::UpstreamProxyProtocol::Off
            && proxy.upstream_http_version != fluxheim_config::UpstreamHttpVersion::Http1
        {
            return Err(NativeHttp1ProxyConfigError::UpstreamProxyProtocol);
        }
        #[cfg(not(feature = "auth-request"))]
        if proxy_requires_auth_request(proxy) {
            return Err(NativeHttp1ProxyConfigError::AuthRequest);
        }
        #[cfg(not(all(feature = "traffic-mirror", not(feature = "privacy-mode"))))]
        if proxy.mirror.enabled {
            return Err(NativeHttp1ProxyConfigError::TrafficMirror);
        }
        if proxy_requires_advanced_upstream_transport(proxy) {
            return Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy);
        }
        #[cfg(feature = "load-balancer")]
        let load_balancer = native_load_balancer_from_config(proxy, load_balancer_scope)?;
        #[cfg(feature = "load-balancer")]
        let native_load_balancer_enabled = load_balancer.is_some();
        #[cfg(not(feature = "load-balancer"))]
        let native_load_balancer_enabled = false;
        if proxy_uses_dynamic_upstream_discovery(proxy) && !native_load_balancer_enabled {
            return Err(NativeHttp1ProxyConfigError::DynamicUpstreamDiscovery);
        }
        if proxy_requires_advanced_load_balancer(proxy, native_load_balancer_enabled) {
            return Err(NativeHttp1ProxyConfigError::LoadBalancing);
        }
        let upstreams = configured_native_upstreams(proxy).unwrap_or_default();
        let mut native_upstreams = Vec::with_capacity(upstreams.len());
        for upstream in upstreams {
            native_upstreams.push(native_upstream_from_proxy_config(
                upstream,
                proxy,
                policy,
                pool_max_idle,
            )?);
        }
        #[cfg(feature = "load-balancer")]
        let template = native_load_balancer_enabled
            .then(|| {
                native_upstream_from_proxy_config(
                    "127.0.0.1:0",
                    proxy,
                    policy,
                    if proxy_uses_dynamic_upstream_discovery(proxy) {
                        0
                    } else {
                        pool_max_idle
                    },
                )
            })
            .transpose()?;
        let mut native = if native_upstreams.is_empty() {
            Self {
                upstreams: Vec::new(),
                upstream_slots: Vec::new(),
                #[cfg(feature = "load-balancer")]
                load_balancer: None,
                #[cfg(feature = "load-balancer")]
                load_balancer_upstream_template: None,
                error_pages: Vec::new(),
                request_headers: default_native_request_header_policy(),
                response_headers: NativeRouteResponseHeaderPolicy::default(),
                response_write_policy: NativeHttp1ResponseWritePolicy::default(),
                request_body_timeout: None,
                websocket: false,
                #[cfg(any(
                    feature = "compression-brotli",
                    feature = "compression-gzip",
                    feature = "compression-zstd"
                ))]
                compression: None,
                #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
                mirror: None,
                #[cfg(feature = "auth-request")]
                auth_request: None,
                next_upstream: Arc::new(AtomicUsize::new(0)),
            }
        } else {
            Self::from_weighted_upstreams(native_upstreams, &proxy.upstream_weights)?
        };
        native.error_pages = native_error_pages_from_config(proxy)?;
        native.response_write_policy = native_response_write_policy_from_config(proxy);
        native.request_body_timeout = proxy.downstream_read_timeout_secs.map(Duration::from_secs);
        native.websocket = proxy.websocket;
        #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
        {
            native.mirror = NativeTrafficMirror::from_config(&proxy.mirror);
        }
        #[cfg(feature = "auth-request")]
        {
            native.auth_request = NativeAuthRequest::from_config(&proxy.auth_request);
        }
        #[cfg(feature = "load-balancer")]
        {
            native.load_balancer = load_balancer
                .as_ref()
                .map(|(load_balancer, _)| load_balancer.clone());
            native.load_balancer_upstream_template = template;
            let service = load_balancer.and_then(|(_, service)| service);
            Ok(Some((native, service)))
        }
        #[cfg(not(feature = "load-balancer"))]
        {
            Ok(Some(native))
        }
    }
}

impl PartialEq for NativeHttp1Proxy {
    fn eq(&self, other: &Self) -> bool {
        let base_equal = self.upstreams == other.upstreams
            && self.upstream_slots == other.upstream_slots
            && self.error_pages == other.error_pages
            && self.request_headers == other.request_headers
            && self.response_headers == other.response_headers
            && self.response_write_policy == other.response_write_policy
            && self.request_body_timeout == other.request_body_timeout
            && self.websocket == other.websocket;
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd",
            feature = "auth-request",
            feature = "load-balancer",
            all(feature = "traffic-mirror", not(feature = "privacy-mode"))
        ))]
        let mut equal = base_equal;
        #[cfg(feature = "load-balancer")]
        {
            equal = equal
                && self.load_balancer_upstream_template == other.load_balancer_upstream_template;
        }
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        {
            equal = equal && self.compression == other.compression;
        }
        #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
        {
            equal = equal && self.mirror == other.mirror;
        }
        #[cfg(feature = "auth-request")]
        {
            equal = equal && self.auth_request == other.auth_request;
        }
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd",
            feature = "auth-request",
            feature = "load-balancer",
            all(feature = "traffic-mirror", not(feature = "privacy-mode"))
        ))]
        {
            equal
        }
        #[cfg(not(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd",
            feature = "auth-request",
            feature = "load-balancer",
            all(feature = "traffic-mirror", not(feature = "privacy-mode"))
        )))]
        {
            base_equal
        }
    }
}

impl Eq for NativeHttp1Proxy {}

impl NativeHttp1Handler for NativeHttp1Proxy {
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            let retry_allowed = native_http1_static_failover_method_allowed(&request.method);
            let mut request = request;
            #[cfg(feature = "auth-request")]
            if let Some(auth_request) = &self.auth_request {
                match auth_request.authorize(&request).await {
                    Ok(NativeAuthRequestDecision::Allow { headers }) => {
                        apply_native_auth_request_headers(&mut request, &headers);
                    }
                    Ok(NativeAuthRequestDecision::Deny { status, body }) => {
                        return NativeHttp1Response::new(
                            status,
                            native_auth_status_reason(status),
                            body,
                        )
                        .close_connection();
                    }
                    Err(error) => {
                        log::debug!(
                            target: "fluxheim::auth_request",
                            "native auth_request failed: {error}"
                        );
                        return NativeHttp1Response::new(
                            502,
                            "Bad Gateway",
                            b"auth_request failed\n".as_slice(),
                        )
                        .close_connection();
                    }
                }
            }
            #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
            {
                let already_mirrored = native_request_has_valid_mirror_marker(&request);
                strip_native_traffic_mirror_headers(&mut request);
                if !already_mirrored && let Some(mirror) = &self.mirror {
                    mirror.spawn_if_selected(&request);
                }
            }
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            let compression_request = self.compression.as_ref().map(|_| request.clone());
            self.request_headers.apply(&mut request);
            #[cfg(feature = "load-balancer")]
            if self.load_balancer.is_some() {
                return self
                    .handle_load_balanced(
                        request,
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request.as_ref(),
                    )
                    .await;
            }
            let mut last_error = None;
            let start = self.next_upstream.fetch_add(1, Ordering::Relaxed);
            let total = self.upstream_slots.len();
            let mut attempted = vec![false; self.upstreams.len()];
            let mut unique_attempts = 0usize;
            for attempt in 0..total {
                let slot = start.wrapping_add(attempt) % total;
                let index = self.upstream_slots[slot];
                if attempted[index] {
                    continue;
                }
                attempted[index] = true;
                unique_attempts += 1;
                let upstream = &self.upstreams[index];
                match upstream.send(&request).await {
                    Ok(mut response) => {
                        self.response_headers.apply(&mut response);
                        response = response.with_write_policy(self.response_write_policy);
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        {
                            if let Some(compression) = &self.compression
                                && let Some(compression_request) = compression_request.as_ref()
                            {
                                apply_native_response_compression(
                                    compression_request,
                                    &mut response,
                                    compression,
                                );
                            }
                            return response;
                        }
                        #[cfg(not(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        )))]
                        return response;
                    }
                    Err(error) if retry_allowed && unique_attempts < self.upstreams.len() => {
                        log::debug!(
                            target: "fluxheim::native_http1",
                            "native HTTP/1 upstream attempt failed before retry: {error:?}"
                        );
                        last_error = Some(error);
                    }
                    Err(error) => {
                        log::debug!(
                            target: "fluxheim::native_http1",
                            "native HTTP/1 upstream attempt failed: {error:?}"
                        );
                        last_error = Some(error);
                        break;
                    }
                }
            }
            let status = if last_error
                .as_ref()
                .is_some_and(native_proxy_error_is_timeout)
            {
                504
            } else {
                502
            };
            self.error_page_response(&request, status)
                .unwrap_or_else(|| {
                    if status == 504 {
                        NativeHttp1Response::new(504, "Gateway Timeout", b"gateway timeout\n")
                            .close_connection()
                    } else {
                        NativeHttp1Response::new(502, "Bad Gateway", b"bad gateway\n")
                            .close_connection()
                    }
                })
        })
    }

    fn request_body_timeout(&self, _request: &NativeHttp1Request) -> Option<Duration> {
        self.request_body_timeout
    }

    fn handles_connection_takeover(&self, request: &NativeHttp1Request) -> bool {
        self.websocket && native_request_is_websocket_upgrade(request)
    }

    fn handle_connection_takeover<'a>(
        &'a self,
        mut request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::NativeHttp1Error>> + Send + 'a>> {
        Box::pin(async move {
            self.request_headers.apply(&mut request);
            #[cfg(feature = "load-balancer")]
            if self.load_balancer.is_some() {
                return self
                    .handle_load_balanced_connection_takeover(request, prebuffered, stream)
                    .await;
            }
            let start = self.next_upstream.fetch_add(1, Ordering::Relaxed);
            let total = self.upstream_slots.len();
            if total == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "native WebSocket proxy has no upstream",
                )
                .into());
            }
            let index = self.upstream_slots[start % total];
            self.upstreams[index]
                .websocket_tunnel(&request, prebuffered, stream)
                .await
        })
    }
}

impl NativeHttp1Proxy {
    #[cfg(feature = "load-balancer")]
    async fn handle_load_balanced_connection_takeover(
        &self,
        request: NativeHttp1Request,
        prebuffered: Vec<u8>,
        stream: NativeHttp1ConnectionStream,
    ) -> Result<(), crate::NativeHttp1Error> {
        let Some(load_balancer) = &self.load_balancer else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "native WebSocket load balancer is not configured",
            )
            .into());
        };
        let client_ip = request
            .effective_client_addr
            .or(request.peer_addr)
            .map(|address| address.ip());
        let Some(selected) = load_balancer.select_or_wait(&request, client_ip).await else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "native WebSocket load balancer did not select an upstream",
            )
            .into());
        };
        let authority = selected.authority();
        let dynamic_upstream = self
            .upstream_for_authority(&authority)
            .is_none()
            .then(|| self.dynamic_upstream_for_authority(&authority))
            .flatten();
        let Some(upstream) = self
            .upstream_for_authority(&authority)
            .or(dynamic_upstream.as_ref())
        else {
            if let Some(reporter) = selected.reporter() {
                reporter.record_failure();
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!("native WebSocket selected upstream {authority} has no transport"),
            )
            .into());
        };
        let result = upstream
            .websocket_tunnel(&request, prebuffered, stream)
            .await;
        if let Some(reporter) = selected.reporter() {
            if result.is_ok() {
                reporter.record_status(101, None);
            } else {
                reporter.record_failure();
            }
        }
        result
    }

    #[cfg(feature = "load-balancer")]
    async fn handle_load_balanced(
        &self,
        request: NativeHttp1Request,
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        compression_request: Option<&NativeHttp1Request>,
    ) -> NativeHttp1Response {
        let Some(load_balancer) = &self.load_balancer else {
            return NativeHttp1Response::new(502, "Bad Gateway", b"bad gateway\n")
                .close_connection();
        };
        let retry_allowed = native_http1_static_failover_method_allowed(&request.method);
        let client_ip = request
            .effective_client_addr
            .or(request.peer_addr)
            .map(|address| address.ip());
        let mut last_error_timed_out = false;
        let max_attempts = self.upstreams.len().max(1);
        for attempt in 0..max_attempts {
            let Some(selected) = load_balancer.select_or_wait(&request, client_ip).await else {
                break;
            };
            let authority = selected.authority();
            let dynamic_upstream = self
                .upstream_for_authority(&authority)
                .is_none()
                .then(|| self.dynamic_upstream_for_authority(&authority))
                .flatten();
            let upstream = self
                .upstream_for_authority(&authority)
                .or(dynamic_upstream.as_ref());
            let Some(upstream) = upstream else {
                if let Some(reporter) = selected.reporter() {
                    reporter.record_failure();
                }
                log::debug!(
                    target: "fluxheim::native_http1",
                    "native load-balanced upstream {authority} has no configured transport"
                );
                continue;
            };
            let managed_affinity_cookie = selected
                .managed_affinity_cookie()
                .map(|cookie| cookie.header_value.clone());
            match upstream.send(&request).await {
                Ok(mut response) => {
                    if let Some(reporter) = selected.reporter() {
                        reporter.record_status(response.status(), None);
                    }
                    if (200..400).contains(&response.status())
                        && let Some(cookie) = managed_affinity_cookie
                    {
                        response.push_header("set-cookie", cookie);
                    }
                    self.response_headers.apply(&mut response);
                    response = response.with_write_policy(self.response_write_policy);
                    #[cfg(any(
                        feature = "compression-brotli",
                        feature = "compression-gzip",
                        feature = "compression-zstd"
                    ))]
                    {
                        if let Some(compression) = &self.compression
                            && let Some(compression_request) = compression_request
                        {
                            apply_native_response_compression(
                                compression_request,
                                &mut response,
                                compression,
                            );
                        }
                    }
                    return response;
                }
                Err(error) if retry_allowed && attempt + 1 < max_attempts => {
                    if let Some(reporter) = selected.reporter() {
                        reporter.record_failure();
                    }
                    last_error_timed_out = native_proxy_error_is_timeout(&error);
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native load-balanced upstream attempt failed before retry: {error:?}"
                    );
                }
                Err(error) => {
                    if let Some(reporter) = selected.reporter() {
                        reporter.record_failure();
                    }
                    last_error_timed_out = native_proxy_error_is_timeout(&error);
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native load-balanced upstream attempt failed: {error:?}"
                    );
                    break;
                }
            }
        }
        let status = if last_error_timed_out { 504 } else { 502 };
        self.error_page_response(&request, status)
            .unwrap_or_else(|| {
                if status == 504 {
                    NativeHttp1Response::new(504, "Gateway Timeout", b"gateway timeout\n")
                        .close_connection()
                } else {
                    NativeHttp1Response::new(502, "Bad Gateway", b"bad gateway\n")
                        .close_connection()
                }
            })
    }

    #[cfg(feature = "load-balancer")]
    fn upstream_for_authority(&self, authority: &str) -> Option<&NativeHttp1Upstream> {
        self.upstreams
            .iter()
            .find(|upstream| upstream.authority() == authority)
    }

    #[cfg(feature = "load-balancer")]
    fn dynamic_upstream_for_authority(&self, authority: &str) -> Option<NativeHttp1Upstream> {
        self.load_balancer_upstream_template
            .clone()
            .map(|upstream| upstream.with_authority(authority.to_owned()))
    }

    fn error_page_response(
        &self,
        request: &NativeHttp1Request,
        status: u16,
    ) -> Option<NativeHttp1Response> {
        self.error_pages
            .iter()
            .find(|page| page.status == status)
            .and_then(|page| page.web.handle_error_page(request, &page.path, status))
            .map(|response| response.with_write_policy(self.response_write_policy))
            .map(NativeHttp1Response::close_connection)
    }
}

fn native_response_write_policy_from_config(
    proxy: &fluxheim_config::ProxyConfig,
) -> NativeHttp1ResponseWritePolicy {
    NativeHttp1ResponseWritePolicy::new(
        proxy.downstream_write_timeout_secs.map(Duration::from_secs),
        proxy
            .downstream_total_response_timeout_secs
            .map(Duration::from_secs),
        proxy.downstream_min_send_rate_bytes_per_sec,
    )
}

fn native_request_is_websocket_upgrade(request: &NativeHttp1Request) -> bool {
    request.method == "GET"
        && native_request_header_values(request, "upgrade")
            .any(|value| value.trim().eq_ignore_ascii_case("websocket"))
        && native_request_header_values(request, "connection").any(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
        && native_request_header_values(request, "sec-websocket-key").count() == 1
        && native_request_header_values(request, "sec-websocket-version")
            .any(|value| value.trim() == "13")
}

fn native_request_header_values<'a>(
    request: &'a NativeHttp1Request,
    name: &'a str,
) -> impl Iterator<Item = &'a str> {
    request
        .headers
        .iter()
        .filter(move |(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

#[cfg(feature = "auth-request")]
impl NativeAuthRequest {
    fn from_config(config: &fluxheim_config::AuthRequestConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        Some(Self {
            url: config.url.clone()?,
            forward_headers: config.forward_headers.clone(),
            allow_response_headers: config.allow_response_headers.clone(),
            timeout: Duration::from_secs(
                config
                    .connect_timeout_secs
                    .saturating_add(config.read_timeout_secs),
            ),
            max_response_bytes: config.max_response_bytes.as_u64(),
        })
    }

    async fn authorize(
        &self,
        request: &NativeHttp1Request,
    ) -> std::io::Result<NativeAuthRequestDecision> {
        let auth = self.clone();
        let input = self.input(request);
        tokio::task::spawn_blocking(move || auth.fetch_decision(&input))
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?
    }

    fn input(&self, request: &NativeHttp1Request) -> NativeAuthRequestInput {
        let mut headers = Vec::new();
        for name in &self.forward_headers {
            if let Some(value) = native_auth_context_header_value(name, request)
                .or_else(|| native_request_header_values_joined_for_auth(request, name))
            {
                headers.push((name.clone(), zeroize::Zeroizing::new(value)));
            }
        }
        NativeAuthRequestInput { headers }
    }

    fn fetch_decision(
        &self,
        input: &NativeAuthRequestInput,
    ) -> std::io::Result<NativeAuthRequestDecision> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .into();
        let mut builder = agent.get(&self.url).header("cache-control", "no-store");
        for (name, value) in &input.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let mut response = builder
            .call()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            let body = zeroize::Zeroizing::new(
                response
                    .body_mut()
                    .with_config()
                    .limit(self.max_response_bytes.saturating_add(1))
                    .read_to_vec()
                    .map_err(|error| std::io::Error::other(error.to_string()))?,
            );
            if body.len() as u64 > self.max_response_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "auth_request response exceeds configured body limit",
                ));
            }
            return Ok(NativeAuthRequestDecision::Allow {
                headers: self.allowed_response_headers(&response),
            });
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(self.max_response_bytes.saturating_add(1))
            .read_to_vec()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if body.len() as u64 > self.max_response_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "auth_request response exceeds configured body limit",
            ));
        }
        let status = if (400..600).contains(&status) {
            status
        } else {
            500
        };
        Ok(NativeAuthRequestDecision::Deny { status, body })
    }

    fn allowed_response_headers(
        &self,
        response: &ureq::http::Response<ureq::Body>,
    ) -> Vec<(String, zeroize::Zeroizing<String>)> {
        response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                if !self
                    .allow_response_headers
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(name.as_str()))
                {
                    return None;
                }
                value.to_str().ok().map(|value| {
                    (
                        name.as_str().to_ascii_lowercase(),
                        zeroize::Zeroizing::new(value.to_owned()),
                    )
                })
            })
            .collect()
    }
}

#[cfg(feature = "auth-request")]
fn native_auth_context_header_value(name: &str, request: &NativeHttp1Request) -> Option<String> {
    if name.eq_ignore_ascii_case("x-original-uri")
        || name.eq_ignore_ascii_case("x-forwarded-uri")
        || name.eq_ignore_ascii_case("x-auth-request-redirect")
    {
        return Some(request.target.clone());
    }
    if name.eq_ignore_ascii_case("x-forwarded-for") || name.eq_ignore_ascii_case("x-real-ip") {
        #[cfg(not(feature = "privacy-mode"))]
        {
            return request.peer_addr.map(|peer| peer.ip().to_string());
        }
        #[cfg(feature = "privacy-mode")]
        {
            return None;
        }
    }
    if name.eq_ignore_ascii_case("x-forwarded-host") {
        return native_request_header_values(request, "host")
            .next()
            .map(str::to_owned);
    }
    if name.eq_ignore_ascii_case("x-forwarded-proto") {
        return Some(
            if request.downstream_tls {
                "https"
            } else {
                "http"
            }
            .to_owned(),
        );
    }
    None
}

#[cfg(feature = "auth-request")]
fn apply_native_auth_request_headers(
    request: &mut NativeHttp1Request,
    headers: &[(String, zeroize::Zeroizing<String>)],
) {
    for (name, value) in headers {
        native_request_replace_header(request, name, value);
    }
}

#[cfg(feature = "auth-request")]
fn native_request_replace_header(request: &mut NativeHttp1Request, name: &str, value: &str) {
    request
        .headers
        .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
    request.headers.push((name.to_owned(), value.to_owned()));
}

#[cfg(feature = "auth-request")]
fn native_auth_status_reason(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Forbidden",
    }
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
impl NativeTrafficMirror {
    fn from_config(config: &fluxheim_config::TrafficMirrorConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        Some(Self {
            base_url: config.base_url.clone()?,
            sample_per_mille: config.sample_per_mille,
            methods: config.methods.clone(),
            forward_headers: config.forward_headers.clone(),
            timeout: Duration::from_secs(config.timeout_secs),
            max_response_bytes: config.max_response_bytes.as_u64(),
            max_in_flight: config.max_in_flight,
            slot_key: config.base_url.as_deref().unwrap_or_default().to_owned(),
        })
    }

    fn spawn_if_selected(&self, request: &NativeHttp1Request) {
        let Some(mirror_request) = self.request(request) else {
            return;
        };
        let Some(_slot) = acquire_native_traffic_mirror_slot(
            &mirror_request.slot_key,
            mirror_request.max_in_flight,
        ) else {
            return;
        };
        tokio::task::spawn_blocking(move || {
            let _slot = _slot;
            if let Err(error) = send_native_traffic_mirror_request(&mirror_request) {
                log::debug!(
                    target: "fluxheim::traffic_mirror",
                    "native traffic mirror request failed: {error}"
                );
            }
        });
    }

    fn request(&self, request: &NativeHttp1Request) -> Option<NativeTrafficMirrorRequest> {
        if native_request_has_valid_mirror_marker(request)
            || !self.methods.iter().any(|method| method == &request.method)
            || !native_traffic_mirror_sample_selected(request, self.sample_per_mille)
        {
            return None;
        }
        let path_and_query = native_request_path_and_query(request)?;
        let url = native_traffic_mirror_url(&self.base_url, path_and_query)?;
        let mut headers = Vec::new();
        for name in &self.forward_headers {
            if let Some(value) = native_request_header_values_joined(request, name) {
                headers.push((name.clone(), value));
            }
        }
        Some(NativeTrafficMirrorRequest {
            method: request.method.clone(),
            url,
            headers,
            timeout: self.timeout,
            max_response_bytes: self.max_response_bytes,
            max_in_flight: self.max_in_flight,
            slot_key: self.slot_key.clone(),
        })
    }
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
struct NativeTrafficMirrorSlot {
    counter: Arc<AtomicUsize>,
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
impl Drop for NativeTrafficMirrorSlot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
fn acquire_native_traffic_mirror_slot(
    key: &str,
    max_in_flight: usize,
) -> Option<NativeTrafficMirrorSlot> {
    static NATIVE_TRAFFIC_MIRROR_INFLIGHT: OnceLock<Mutex<HashMap<String, Arc<AtomicUsize>>>> =
        OnceLock::new();
    let mut map = NATIVE_TRAFFIC_MIRROR_INFLIGHT
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|_| {
            log::error!(
                target: "fluxheim::security",
                "native traffic mirror in-flight lock poisoned; aborting"
            );
            std::process::abort();
        });
    if map.len() >= NATIVE_TRAFFIC_MIRROR_INFLIGHT_MAX_KEYS && !map.contains_key(key) {
        map.retain(|_, counter| counter.load(Ordering::Acquire) > 0);
        if map.len() >= NATIVE_TRAFFIC_MIRROR_INFLIGHT_MAX_KEYS {
            return None;
        }
    }
    let counter = map
        .entry(key.to_owned())
        .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
        .clone();
    drop(map);

    loop {
        let current = counter.load(Ordering::Acquire);
        if current >= max_in_flight {
            return None;
        }
        let next = current.checked_add(1)?;
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(NativeTrafficMirrorSlot { counter }),
            Err(_) => continue,
        }
    }
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
fn native_traffic_mirror_url(base_url: &str, path_and_query: &str) -> Option<String> {
    if path_and_query.contains('#')
        || !fluxheim_common::path_safety::safe_forward_path_and_query(path_and_query)
    {
        return None;
    }
    let mut url = base_url.trim_end_matches('/').to_owned();
    url.push_str(path_and_query);
    Some(url)
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
fn native_request_path_and_query(request: &NativeHttp1Request) -> Option<&str> {
    if request.target.starts_with('/') {
        return Some(request.target.as_str());
    }
    None
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
fn native_traffic_mirror_sample_selected(
    request: &NativeHttp1Request,
    sample_per_mille: u16,
) -> bool {
    if sample_per_mille >= 1000 {
        return true;
    }
    use sha2::{Digest, Sha256};

    static NATIVE_TRAFFIC_MIRROR_SAMPLE_SALT: OnceLock<[u8; 16]> = OnceLock::new();
    let salt = NATIVE_TRAFFIC_MIRROR_SAMPLE_SALT.get_or_init(|| {
        let mut salt = [0_u8; 16];
        if let Err(error) = getrandom::fill(&mut salt) {
            log::error!(
                target: "fluxheim::security",
                "native traffic mirror sampling salt generation failed: {error}; aborting"
            );
            std::process::abort();
        }
        salt
    });

    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(b"\n");
    hasher.update(request.method.as_bytes());
    hasher.update(b"\n");
    hasher.update(request.target.as_bytes());
    if let Some(host) = native_request_header_values(request, "host").next() {
        hasher.update(b"\n");
        hasher.update(host.as_bytes());
    }
    let digest = hasher.finalize();
    let bucket = u16::from_be_bytes([digest[0], digest[1]]) % 1000;
    bucket < sample_per_mille
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
fn send_native_traffic_mirror_request(request: &NativeTrafficMirrorRequest) -> std::io::Result<()> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(request.timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into();
    let mut builder = match request.method.as_str() {
        "GET" => agent.get(&request.url),
        "HEAD" => agent.head(&request.url),
        "OPTIONS" => agent.options(&request.url),
        "TRACE" => agent.trace(&request.url),
        _ => {
            return Err(std::io::Error::other(
                "traffic mirror method is not supported",
            ));
        }
    }
    .header("cache-control", "no-store")
    .header("x-fluxheim-mirror", "1")
    .header(
        "x-fluxheim-mirror-signature",
        native_traffic_mirror_marker_signature(),
    );
    for (name, value) in &request.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let mut response = builder
        .call()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let body = response
        .body_mut()
        .with_config()
        .limit(request.max_response_bytes.saturating_add(1))
        .read_to_vec()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    if body.len() as u64 > request.max_response_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "traffic mirror response exceeds configured body limit",
        ));
    }
    Ok(())
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
fn native_request_has_valid_mirror_marker(request: &NativeHttp1Request) -> bool {
    let marker_present =
        native_request_header_values(request, "x-fluxheim-mirror").any(|value| value.trim() == "1");
    if !marker_present {
        return false;
    }
    native_request_header_values(request, "x-fluxheim-mirror-signature")
        .any(native_traffic_mirror_marker_signature_matches)
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
fn strip_native_traffic_mirror_headers(request: &mut NativeHttp1Request) {
    request.headers.retain(|(name, _)| {
        !name.eq_ignore_ascii_case("x-fluxheim-mirror")
            && !name.eq_ignore_ascii_case("x-fluxheim-mirror-signature")
    });
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
fn native_traffic_mirror_marker_signature_matches(value: &str) -> bool {
    let candidate = value.trim().as_bytes();
    let expected = native_traffic_mirror_marker_signature().as_bytes();
    candidate.len() == expected.len()
        && candidate
            .ct_eq(expected)
            .declassify("native traffic mirror marker match result is public")
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
fn native_traffic_mirror_marker_signature() -> &'static str {
    static SIGNATURE: OnceLock<String> = OnceLock::new();
    SIGNATURE.get_or_init(|| {
        use sha2::{Digest, Sha256};
        let mut secret = [0_u8; 32];
        if let Err(error) = getrandom::fill(&mut secret) {
            log::error!(
                target: "fluxheim::security",
                "native traffic mirror marker secret generation failed: {error}; aborting"
            );
            std::process::abort();
        }
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(b"\nfluxheim-native-mirror-v1");
        let digest = hasher.finalize();
        let mut signature = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(&mut signature, "{byte:02x}");
        }
        signature
    })
}

#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
fn native_request_header_values_joined(request: &NativeHttp1Request, name: &str) -> Option<String> {
    fluxheim_headers::join_header_values(
        native_request_header_values(request, name).filter(|value| !value.trim().is_empty()),
    )
}

#[cfg(feature = "auth-request")]
fn native_request_header_values_joined_for_auth(
    request: &NativeHttp1Request,
    name: &str,
) -> Option<String> {
    let separator = if name.eq_ignore_ascii_case("cookie") {
        "; "
    } else {
        ", "
    };
    fluxheim_headers::join_header_values_with_separator(
        native_request_header_values(request, name).filter(|value| !value.trim().is_empty()),
        separator,
    )
}

fn native_error_pages_from_config(
    proxy: &fluxheim_config::ProxyConfig,
) -> Result<Vec<NativeHttp1ProxyErrorPage>, NativeHttp1ProxyConfigError> {
    let mut pages = Vec::with_capacity(proxy.error_pages.len());
    for page in &proxy.error_pages {
        let web = NativeHttp1StaticWeb::from_config(&page.web)
            .map_err(|_| NativeHttp1ProxyConfigError::ErrorPages)?
            .ok_or(NativeHttp1ProxyConfigError::ErrorPages)?;
        pages.push(NativeHttp1ProxyErrorPage {
            status: page.status,
            path: page.path.clone(),
            web,
        });
    }
    Ok(pages)
}

fn native_proxy_error_is_timeout(error: &crate::NativeHttp1Error) -> bool {
    matches!(
        error,
        crate::NativeHttp1Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut
    )
}

fn native_upstream_from_proxy_config(
    authority: impl Into<String>,
    proxy: &fluxheim_config::ProxyConfig,
    policy: crate::DownstreamHttp1Policy,
    pool_max_idle: usize,
) -> Result<NativeHttp1Upstream, NativeHttp1ProxyConfigError> {
    let mut native_upstream = NativeHttp1Upstream::from_policy(authority, policy);
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    if let Some(tls) = NativeHttp1UpstreamTls::from_proxy_config(proxy)? {
        native_upstream = native_upstream.with_tls(tls);
    }
    if let Some(timeout) = proxy.connect_timeout_secs {
        native_upstream = native_upstream.with_connect_timeout(Duration::from_secs(timeout));
    }
    native_upstream = native_upstream.with_total_connection_timeout(
        proxy
            .upstream_total_connection_timeout_secs
            .map(Duration::from_secs),
    );
    if let Some(timeout) = proxy.read_timeout_secs {
        native_upstream = native_upstream.with_read_timeout(Duration::from_secs(timeout));
    }
    if let Some(timeout) = proxy.send_timeout_secs {
        native_upstream = native_upstream.with_write_timeout(Duration::from_secs(timeout));
    }
    native_upstream = native_upstream.with_proxy_protocol(proxy.upstream_proxy_protocol);
    if matches!(
        proxy.upstream_http_version,
        fluxheim_config::UpstreamHttpVersion::Http2
            | fluxheim_config::UpstreamHttpVersion::Http1AndHttp2
    ) {
        let http2_policy = native_http2_policy_from_config(proxy)?;
        native_upstream =
            if proxy.upstream_http_version == fluxheim_config::UpstreamHttpVersion::Http2 {
                native_upstream.with_http2_policy(http2_policy)
            } else {
                native_upstream
                    .with_http1_and_http2_policy(http2_policy)
                    .with_h2c_upgrade(proxy.upstream_h2c_upgrade)
            };
        native_upstream = native_upstream.with_http2_keepalive_interval(
            proxy
                .upstream_h2_ping_interval_secs
                .map(Duration::from_secs),
        );
    }
    let recv_buffer_size = match proxy
        .upstream_tcp_recv_buffer_bytes
        .map(fluxheim_config::ByteSize::as_u64)
        .map(u32::try_from)
    {
        Some(Ok(bytes)) => Some(bytes),
        Some(Err(_)) => return Err(NativeHttp1ProxyConfigError::RecvBufferTooLarge),
        None => None,
    };
    native_upstream = native_upstream.with_recv_buffer_size(recv_buffer_size);
    native_upstream = native_upstream.with_dscp(proxy.upstream_dscp);
    native_upstream = native_upstream.with_tcp_keepalive(native_tcp_keepalive(proxy)?);
    native_upstream = native_upstream.with_tcp_user_timeout(native_tcp_user_timeout(proxy)?);
    native_upstream = native_upstream
        .with_pool_idle_timeout(proxy.upstream_idle_timeout_secs.map(Duration::from_secs));
    let pool_max_idle =
        if proxy.upstream_proxy_protocol == fluxheim_config::UpstreamProxyProtocol::Off {
            pool_max_idle
        } else {
            0
        };
    Ok(native_upstream.with_pool_max_idle(pool_max_idle))
}

fn configured_native_upstreams(proxy: &fluxheim_config::ProxyConfig) -> Option<Vec<String>> {
    if !proxy.upstreams.is_empty() {
        return Some(proxy.upstreams.clone());
    }
    proxy
        .configured_primary_upstream()
        .map(|upstream| vec![upstream.to_owned()])
}

#[cfg(feature = "load-balancer")]
fn native_load_balancer_from_config(
    proxy: &fluxheim_config::ProxyConfig,
    scope: Option<(&str, &str, Option<&str>)>,
) -> Result<
    Option<(
        fluxheim_load_balancer::UpstreamLoadBalancer,
        Option<fluxheim_load_balancer::UpstreamLoadBalancerService>,
    )>,
    NativeHttp1ProxyConfigError,
> {
    let Some((name, vhost, route)) = scope else {
        return Ok(None);
    };
    if !native_load_balancer_pool_configured(proxy) {
        return Ok(None);
    }
    if proxy.load_balance.health_check.enabled || proxy_uses_dynamic_upstream_discovery(proxy) {
        return fluxheim_load_balancer::UpstreamLoadBalancer::background_service_from_proxy_config(
            name, vhost, route, proxy,
        )
        .map(|result| result.map(|(load_balancer, service)| (load_balancer, Some(service))))
        .map_err(|_| NativeHttp1ProxyConfigError::LoadBalancing);
    }
    fluxheim_load_balancer::UpstreamLoadBalancer::from_proxy_config(proxy)
        .map(|result| result.map(|load_balancer| (load_balancer, None)))
        .map_err(|_| NativeHttp1ProxyConfigError::LoadBalancing)
}

fn proxy_requires_advanced_load_balancer(
    proxy: &fluxheim_config::ProxyConfig,
    native_load_balancer_enabled: bool,
) -> bool {
    if !native_load_balancer_pool_configured(proxy) {
        return false;
    }
    if native_load_balancer_enabled {
        return false;
    }
    if !native_load_balancer_enabled
        && !native_static_load_balance_config_supported(&proxy.load_balance)
    {
        return true;
    }
    !proxy.upstream_priority_groups.is_empty()
        || !proxy.upstream_localities.is_empty()
        || !proxy.preferred_upstream_localities.is_empty()
        || !proxy.upstream_max_in_flight.is_empty()
        || !proxy.upstream_aliases.is_empty()
        || !proxy.upstream_tags.is_empty()
        || !proxy.backup_upstreams.is_empty()
        || !proxy.drain_upstreams.is_empty()
        || !proxy.disabled_upstreams.is_empty()
}

fn native_load_balancer_pool_configured(proxy: &fluxheim_config::ProxyConfig) -> bool {
    proxy.upstreams.len() >= 2
        || proxy.upstreams_file.is_some()
        || proxy.upstreams_http_url.is_some()
        || proxy.upstream_dns_refresh_secs.is_some()
}

fn proxy_uses_dynamic_upstream_discovery(proxy: &fluxheim_config::ProxyConfig) -> bool {
    proxy.upstreams_file.is_some()
        || proxy.upstreams_http_url.is_some()
        || proxy.upstream_dns_refresh_secs.is_some()
}

fn native_static_load_balance_config_supported(
    load_balance: &fluxheim_config::LoadBalanceConfig,
) -> bool {
    let mut disabled_health = fluxheim_config::LoadBalanceConfig::default();
    disabled_health.health_check.enabled = false;
    load_balance == &disabled_health
}

#[cfg(not(feature = "auth-request"))]
fn proxy_requires_auth_request(proxy: &fluxheim_config::ProxyConfig) -> bool {
    proxy.auth_request.enabled
        || proxy.auth_request.url.is_some()
        || !proxy.auth_request.forward_headers.is_empty()
        || !proxy.auth_request.allow_response_headers.is_empty()
}

fn proxy_requires_advanced_upstream_transport(proxy: &fluxheim_config::ProxyConfig) -> bool {
    proxy.upstream_tcp_user_timeout_ms.is_some() && !native_tcp_user_timeout_supported()
        || proxy.upstream_tcp_fast_open
}

fn native_http2_policy_from_config(
    proxy: &fluxheim_config::ProxyConfig,
) -> Result<DownstreamHttp2Policy, NativeHttp1ProxyConfigError> {
    let mut policy = DownstreamHttp2Policy::default();
    if let Some(read_timeout_secs) = proxy.read_timeout_secs {
        let timeout = Duration::from_secs(read_timeout_secs);
        policy = policy
            .with_response_body_timeout(timeout)
            .with_handler_timeout(timeout);
    }
    if let Some(write_timeout_secs) = proxy.send_timeout_secs {
        policy = policy.with_response_write_lifetime(Duration::from_secs(write_timeout_secs));
    }
    if let Some(max_streams) = proxy.upstream_h2_max_streams {
        let max_streams = u32::try_from(max_streams)
            .ok()
            .filter(|max_streams| {
                *max_streams > 0 && (*max_streams as usize) <= MAX_NATIVE_UPSTREAM_H2_STREAMS
            })
            .ok_or(NativeHttp1ProxyConfigError::UpstreamHttp2)?;
        policy = policy.with_max_concurrent_streams(max_streams);
    }
    Ok(policy)
}

const fn native_tcp_user_timeout_supported() -> bool {
    cfg!(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    ))
}

fn native_tcp_keepalive(
    proxy: &fluxheim_config::ProxyConfig,
) -> Result<Option<NativeTcpKeepalivePolicy>, NativeHttp1ProxyConfigError> {
    match (
        proxy.upstream_tcp_keepalive_idle_secs,
        proxy.upstream_tcp_keepalive_interval_secs,
        proxy.upstream_tcp_keepalive_count,
    ) {
        (None, None, None) => Ok(None),
        (Some(idle_secs), Some(interval_secs), Some(count)) => {
            let count = u32::try_from(count)
                .map_err(|_| NativeHttp1ProxyConfigError::UpstreamTransportPolicy)?;
            Ok(Some(NativeTcpKeepalivePolicy::new(
                Duration::from_secs(idle_secs),
                Duration::from_secs(interval_secs),
                count,
            )))
        }
        _ => Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy),
    }
}

fn native_tcp_user_timeout(
    proxy: &fluxheim_config::ProxyConfig,
) -> Result<Option<Duration>, NativeHttp1ProxyConfigError> {
    let Some(timeout_ms) = proxy.upstream_tcp_user_timeout_ms else {
        return Ok(None);
    };
    if !native_tcp_user_timeout_supported() {
        return Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy);
    }
    Ok(Some(Duration::from_millis(timeout_ms)))
}

fn native_http1_static_failover_method_allowed(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

#[cfg(all(test, feature = "traffic-mirror", not(feature = "privacy-mode")))]
mod tests {
    use super::{
        native_traffic_mirror_marker_signature, native_traffic_mirror_marker_signature_matches,
    };

    #[test]
    fn native_mirror_marker_signature_uses_sanitization_constant_time_match() {
        let signature = native_traffic_mirror_marker_signature();

        assert!(native_traffic_mirror_marker_signature_matches(signature));
        assert!(native_traffic_mirror_marker_signature_matches(&format!(
            " {signature} "
        )));
        assert!(!native_traffic_mirror_marker_signature_matches("attacker"));
        assert!(!native_traffic_mirror_marker_signature_matches(
            &signature[..signature.len() - 1]
        ));
    }
}

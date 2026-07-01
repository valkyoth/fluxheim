use crate::native_http1_proxy::NativeHttp1Proxy;

impl PartialEq for NativeHttp1Proxy {
    fn eq(&self, other: &Self) -> bool {
        let base_equal = self.upstreams == other.upstreams
            && self.upstream_slots == other.upstream_slots
            && self.error_pages == other.error_pages
            && self.request_headers == other.request_headers
            && self.response_headers == other.response_headers
            && self.response_write_policy == other.response_write_policy
            && self.request_body_timeout == other.request_body_timeout
            && self.websocket == other.websocket
            && self.cache == other.cache;
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

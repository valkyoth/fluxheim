use crate::native_http1_cache::with_native_cache_status;
use crate::native_http1_proxy::NativeHttp1Proxy;
use crate::native_http1_proxy_metrics::record_native_proxy_outcome;
use crate::native_http1_proxy_peer_fill::native_request_is_peer_fill;
use crate::native_http1_proxy_peer_fill_auth::{
    native_peer_fill_request_signature_matches, native_peer_fill_sign_response,
};
#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use crate::native_http1_route_compression::apply_native_response_compression;
use crate::{NativeHttp1Request, NativeHttp1Response};
use fluxheim_config::CacheConfig;

impl NativeHttp1Proxy {
    pub(crate) fn finish_response(
        &self,
        request: &NativeHttp1Request,
        mut response: NativeHttp1Response,
        cache_status: Option<(
            &CacheConfig,
            &'static str,
            Option<&'static str>,
            Option<u64>,
        )>,
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        compression_request: Option<&NativeHttp1Request>,
    ) -> NativeHttp1Response {
        record_native_proxy_outcome(&self.metrics_vhost, &request.method, response.status());
        if let Some((cache, status, reason, age_secs)) = cache_status {
            response = with_native_cache_status(response, cache, status, reason, age_secs);
        }
        self.response_headers
            .apply_for_request(request, &mut response);
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
                apply_native_response_compression(compression_request, &mut response, compression);
            }
        }
        self.response_headers
            .apply_digests_for_method(&request.method, &mut response);
        if let Some(cache) = &self.cache
            && let Some(auth) = cache.peer_fill_auth.as_deref()
        {
            native_peer_fill_sign_response(auth, request, &mut response);
        }
        response
    }

    pub(crate) fn finish_cache_fill_wait_timeout(
        &self,
        request: &NativeHttp1Request,
        cache: &CacheConfig,
        #[cfg(any(
            feature = "compression-brotli",
            feature = "compression-gzip",
            feature = "compression-zstd"
        ))]
        compression_request: Option<&NativeHttp1Request>,
    ) -> NativeHttp1Response {
        self.finish_response(
            request,
            NativeHttp1Response::new(503, "Service Unavailable", b"cache fill wait timed out\n")
                .with_retry_after_secs(1)
                .close_connection(),
            Some((cache, "BYPASS", Some("lock-wait-timeout"), None)),
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression_request,
        )
    }

    pub(crate) fn rejects_invalid_authenticated_peer_fill(
        &self,
        request: &NativeHttp1Request,
    ) -> bool {
        if !native_request_is_peer_fill(request) {
            return false;
        }
        let Some(cache) = &self.cache else {
            return false;
        };
        let Some(auth) = cache.peer_fill_auth.as_deref() else {
            return false;
        };
        !native_peer_fill_request_signature_matches(auth, request)
    }
}

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[cfg(feature = "load-balancer")]
use crate::NativeHttp1Upstream;
use crate::native_http1_cache::{
    NativeMemoryCacheEntry, lock_native_memory_cache, with_native_cache_status,
};
use crate::native_http1_proxy::NativeHttp1Proxy;
#[cfg(feature = "auth-request")]
use crate::native_http1_proxy_auth::{
    NativeAuthRequestDecision, apply_native_auth_request_headers, native_auth_status_reason,
};
use crate::native_http1_proxy_cache_fill::NativeCacheFillGate;
use crate::native_http1_proxy_cache_headers::{
    native_cache_revalidation_request, native_request_cache_only_if_cached,
};
use crate::native_http1_proxy_cache_policy::native_cache_stale_event_for_error;
use crate::native_http1_proxy_cache_response::native_cached_hit_response;
use crate::native_http1_proxy_cache_slice::native_origin_slice_request;
use crate::native_http1_proxy_config::native_http1_static_failover_method_allowed;
use crate::native_http1_proxy_error_page::native_error_page_response;
#[cfg(feature = "load-balancer")]
use crate::native_http1_proxy_error_page::native_proxy_status_reason;
use crate::native_http1_proxy_memory_cache::{
    NativePeerFillDecision, NativeProxyCacheLookup, NativeProxyMemoryCache,
};
use crate::native_http1_proxy_metrics::record_native_proxy_outcome;
#[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
use crate::native_http1_proxy_mirror::{
    native_request_has_valid_mirror_marker, strip_native_traffic_mirror_headers,
};
use crate::native_http1_proxy_peer_fill::{
    native_request_is_peer_fill, strip_native_peer_fill_header,
};
use crate::native_http1_proxy_peer_fill_auth::{
    native_peer_fill_request_signature_matches, native_peer_fill_sign_response,
};
use crate::native_http1_proxy_request::{
    native_proxy_error_is_timeout, native_request_is_websocket_upgrade,
};
#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use crate::native_http1_route_compression::apply_native_response_compression;
use crate::{
    NativeHttp1ConnectionStream, NativeHttp1Handler, NativeHttp1Request, NativeHttp1Response,
};
use fluxheim_cache::{CacheSliceBounds, CacheStaleEvent};
use fluxheim_config::CacheConfig;

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
            if self.rejects_invalid_authenticated_peer_fill(&request) {
                return NativeHttp1Response::new(
                    403,
                    "Forbidden",
                    b"invalid peer-fill authentication\n".as_slice(),
                )
                .close_connection();
            }
            strip_native_peer_fill_header(&mut request);
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            let compression_request = self.compression.as_ref().map(|_| request.clone());
            self.request_headers.apply(&mut request, None);
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
            let mut proxy_cache_fill = None::<(
                NativeProxyMemoryCache,
                String,
                &'static str,
                Option<&'static str>,
                Option<NativeMemoryCacheEntry>,
            )>;
            let mut proxy_cache_status = None::<(
                &CacheConfig,
                &'static str,
                Option<&'static str>,
                Option<u64>,
            )>;
            if let Some(cache) = &self.cache {
                if let Some(slice) = cache.slice_response(&request, self).await {
                    return self.finish_response(
                        &request,
                        slice.response,
                        Some((
                            &cache.config,
                            if slice.filled { "MISS" } else { "HIT" },
                            Some(if slice.filled { "slice-fill" } else { "slice" }),
                            None,
                        )),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request.as_ref(),
                    );
                }
                match cache.lookup(&request).await {
                    NativeProxyCacheLookup::Hit { entry, range } => {
                        let response = native_cached_hit_response(&entry, &request, range);
                        return self.finish_response(
                            &request,
                            response,
                            Some((&cache.config, "HIT", None, Some(entry.age_secs()))),
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request.as_ref(),
                        );
                    }
                    NativeProxyCacheLookup::StaleWhileRevalidate { key, entry } => {
                        cache.record_policy_activity("stale");
                        self.spawn_cache_revalidation(
                            cache.clone(),
                            key,
                            request.clone(),
                            entry.clone(),
                        );
                        return self.finish_response(
                            &request,
                            entry.to_response(),
                            Some((
                                &cache.config,
                                "STALE-UPDATING",
                                Some("stale-while-revalidate"),
                                Some(entry.age_secs()),
                            )),
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request.as_ref(),
                        );
                    }
                    NativeProxyCacheLookup::Miss {
                        key,
                        status,
                        reason,
                    } => {
                        if status == "REVALIDATED" {
                            cache.record_policy_activity("revalidate");
                        }
                        proxy_cache_fill = Some((cache.clone(), key, status, reason, None));
                    }
                    NativeProxyCacheLookup::Revalidate { key, entry } => {
                        cache.record_policy_activity("revalidate");
                        request = native_cache_revalidation_request(request, &entry);
                        proxy_cache_fill = Some((cache.clone(), key, "EXPIRED", None, Some(entry)));
                    }
                    NativeProxyCacheLookup::Bypass(reason) => {
                        cache.record_policy_activity("bypass");
                        proxy_cache_status = Some((&cache.config, "BYPASS", Some(reason), None));
                    }
                }
            }
            if let Some((cache, key, _, _, _)) = proxy_cache_fill.as_ref() {
                if native_request_cache_only_if_cached(&request) {
                    let response =
                        NativeHttp1Response::new(504, "Gateway Timeout", b"cache miss\n")
                            .close_connection();
                    return self.finish_response(
                        &request,
                        response,
                        Some((&cache.config, "MISS", Some("only-if-cached-miss"), None)),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request.as_ref(),
                    );
                }
                match cache.peer_fill(key, &request).await {
                    NativePeerFillDecision::Skip => {}
                    NativePeerFillDecision::Hit(response) => {
                        return self.finish_response(
                            &request,
                            response,
                            Some((&cache.config, "PEER-HIT", None, None)),
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request.as_ref(),
                        );
                    }
                    NativePeerFillDecision::FailClosed(reason) => {
                        let response =
                            NativeHttp1Response::new(504, "Gateway Timeout", b"cache miss\n")
                                .close_connection();
                        return self.finish_response(
                            &request,
                            response,
                            Some((&cache.config, "MISS", Some(reason), None)),
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request.as_ref(),
                        );
                    }
                }
            }
            let _cache_fill_permit = if let Some((cache, key, _, _, _)) = proxy_cache_fill.as_ref()
            {
                loop {
                    match cache.cache_fill_gate(key) {
                        NativeCacheFillGate::Disabled => break None,
                        NativeCacheFillGate::Writer(permit) => break Some(permit),
                        NativeCacheFillGate::Waiter { notify, timeout } => {
                            if let Some(entry) = cache
                                .wait_for_cache_fill(notify, timeout, key, &request)
                                .await
                            {
                                return self.finish_response(
                                    &request,
                                    entry.to_response(),
                                    Some((&cache.config, "HIT", None, Some(entry.age_secs()))),
                                    #[cfg(any(
                                        feature = "compression-brotli",
                                        feature = "compression-gzip",
                                        feature = "compression-zstd"
                                    ))]
                                    compression_request.as_ref(),
                                );
                            }
                        }
                    }
                }
            } else {
                None
            };
            let _origin_fill_permit = if let Some((cache, _, _, _, _)) = proxy_cache_fill.as_ref() {
                match cache.acquire_origin_fill_permit() {
                    Some(permit) => permit,
                    None => {
                        let response = NativeHttp1Response::new(
                            503,
                            "Service Unavailable",
                            b"cache origin fill budget exhausted\n",
                        )
                        .close_connection();
                        return self.finish_response(
                            &request,
                            response,
                            Some((&cache.config, "BYPASS", Some("origin-protected"), None)),
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request.as_ref(),
                        );
                    }
                }
            } else {
                None
            };
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
                    Ok(response) => {
                        let mut cache_status = proxy_cache_status;
                        if let Some((cache, key, status, reason, stale_entry)) =
                            proxy_cache_fill.as_ref()
                        {
                            if let Some(stale) = cache
                                .get_stale(
                                    key,
                                    &request,
                                    CacheStaleEvent::UpstreamHttpStatus(response.status()),
                                )
                                .await
                            {
                                cache.record_policy_activity("stale");
                                return self.finish_response(
                                    &request,
                                    stale.to_response(),
                                    Some((
                                        &cache.config,
                                        "STALE",
                                        Some("upstream-status"),
                                        Some(stale.age_secs()),
                                    )),
                                    #[cfg(any(
                                        feature = "compression-brotli",
                                        feature = "compression-gzip",
                                        feature = "compression-zstd"
                                    ))]
                                    compression_request.as_ref(),
                                );
                            }
                            let revalidated = if response.status() == 304 {
                                if let Some(entry) = stale_entry.as_ref() {
                                    cache
                                        .store_not_modified_revalidated(
                                            key, &request, entry, &response,
                                        )
                                        .await
                                        .ok()
                                } else {
                                    None
                                }
                            } else {
                                None
                            };
                            if let Some(revalidated) = revalidated {
                                return self.finish_response(
                                    &request,
                                    revalidated.to_response(),
                                    Some((
                                        &cache.config,
                                        "REVALIDATED",
                                        None,
                                        Some(revalidated.age_secs()),
                                    )),
                                    #[cfg(any(
                                        feature = "compression-brotli",
                                        feature = "compression-gzip",
                                        feature = "compression-zstd"
                                    ))]
                                    compression_request.as_ref(),
                                );
                            }
                            let store_result = if *status == "REVALIDATED" {
                                cache.store_revalidated(key, &request, &response).await
                            } else {
                                cache.store(key, &request, &response).await
                            };
                            cache_status = Some(match store_result {
                                Ok(()) => (&cache.config, *status, *reason, None),
                                Err(reason) => (&cache.config, "BYPASS", Some(reason), None),
                            });
                        }
                        return self.finish_response(
                            &request,
                            response,
                            cache_status,
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request.as_ref(),
                        );
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
            if let (Some((cache, key, _, _, _)), Some(error)) =
                (proxy_cache_fill.as_ref(), last_error.as_ref())
                && let Some(stale) = cache
                    .get_stale(key, &request, native_cache_stale_event_for_error(error))
                    .await
            {
                cache.record_policy_activity("stale");
                return self.finish_response(
                    &request,
                    stale.to_response(),
                    Some((
                        &cache.config,
                        "STALE",
                        Some("upstream-error"),
                        Some(stale.age_secs()),
                    )),
                    #[cfg(any(
                        feature = "compression-brotli",
                        feature = "compression-gzip",
                        feature = "compression-zstd"
                    ))]
                    compression_request.as_ref(),
                );
            }
            let error_response = native_error_page_response(
                &self.error_pages,
                self.response_write_policy,
                &request,
                status,
            )
            .unwrap_or_else(|| {
                if status == 504 {
                    NativeHttp1Response::new(504, "Gateway Timeout", b"gateway timeout\n")
                        .close_connection()
                } else {
                    NativeHttp1Response::new(502, "Bad Gateway", b"bad gateway\n")
                        .close_connection()
                }
            });
            self.finish_response(
                &request,
                error_response,
                proxy_cache_status,
                #[cfg(any(
                    feature = "compression-brotli",
                    feature = "compression-gzip",
                    feature = "compression-zstd"
                ))]
                compression_request.as_ref(),
            )
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
            self.request_headers.apply(&mut request, None);
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
    fn spawn_cache_revalidation(
        &self,
        cache: NativeProxyMemoryCache,
        key: String,
        request: NativeHttp1Request,
        entry: NativeMemoryCacheEntry,
    ) {
        {
            let mut state = lock_native_memory_cache(&cache.state, "proxy");
            if !state.revalidating.insert(key.clone()) {
                return;
            }
        }
        let proxy = self.clone();
        tokio::spawn(async move {
            proxy
                .revalidate_cache_entry(cache.clone(), key.clone(), request, entry)
                .await;
            let mut state = lock_native_memory_cache(&cache.state, "proxy");
            state.revalidating.remove(&key);
        });
    }

    async fn revalidate_cache_entry(
        self,
        cache: NativeProxyMemoryCache,
        key: String,
        request: NativeHttp1Request,
        entry: NativeMemoryCacheEntry,
    ) {
        let _origin_fill_permit = match cache.acquire_origin_fill_permit() {
            Some(permit) => permit,
            None => return,
        };
        let request = native_cache_revalidation_request(request, &entry);
        match self.send_cache_revalidation_request(&request).await {
            Ok(response) => {
                let result = if response.status() == 304 {
                    cache
                        .store_not_modified_revalidated(&key, &request, &entry, &response)
                        .await
                        .map(|_| ())
                } else {
                    cache.store_revalidated(&key, &request, &response).await
                };
                if let Err(reason) = result {
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native proxy cache stale-while-revalidate refresh bypassed storage: {reason}"
                    );
                }
            }
            Err(error) => {
                log::debug!(
                    target: "fluxheim::native_http1",
                    "native proxy cache stale-while-revalidate refresh failed: {error:?}"
                );
            }
        }
    }

    pub(crate) async fn fetch_origin_slice(
        &self,
        request: &NativeHttp1Request,
        bounds: CacheSliceBounds,
    ) -> Option<NativeHttp1Response> {
        let cache = self.cache.as_ref()?;
        let max_body_bytes = cache.config.range.slice.size_bytes.as_u64();
        let capped_body_bytes = usize::try_from(max_body_bytes.saturating_add(1)).ok()?;
        let request = native_origin_slice_request(request, bounds)?;
        let start = self.next_upstream.fetch_add(1, Ordering::Relaxed);
        let total = self.upstream_slots.len();
        let mut attempted = vec![false; self.upstreams.len()];
        for attempt in 0..total {
            let slot = start.wrapping_add(attempt) % total;
            let index = self.upstream_slots[slot];
            if attempted[index] {
                continue;
            }
            attempted[index] = true;
            let upstream = self.upstreams[index]
                .clone()
                .with_max_body_bytes(capped_body_bytes);
            match upstream.send(&request).await {
                Ok(response) if response.body().len() as u64 <= max_body_bytes => {
                    return Some(response);
                }
                Ok(_) => return None,
                Err(error) => {
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native proxy cache slice fill failed: {error:?}"
                    );
                }
            }
        }
        None
    }

    #[cfg(not(feature = "load-balancer"))]
    async fn send_cache_revalidation_request(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, crate::NativeHttp1Error> {
        let retry_allowed = native_http1_static_failover_method_allowed(&request.method);
        let start = self.next_upstream.fetch_add(1, Ordering::Relaxed);
        let total = self.upstream_slots.len();
        let mut attempted = vec![false; self.upstreams.len()];
        let mut unique_attempts = 0usize;
        let mut last_error = None;
        for attempt in 0..total {
            let slot = start.wrapping_add(attempt) % total;
            let index = self.upstream_slots[slot];
            if attempted[index] {
                continue;
            }
            attempted[index] = true;
            unique_attempts += 1;
            match self.upstreams[index].send(request).await {
                Ok(response) => return Ok(response),
                Err(error) if retry_allowed && unique_attempts < self.upstreams.len() => {
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "native proxy cache refresh has no upstream",
            )
            .into()
        }))
    }

    #[cfg(feature = "load-balancer")]
    async fn send_cache_revalidation_request(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, crate::NativeHttp1Error> {
        let Some(load_balancer) = &self.load_balancer else {
            return self.send_static_cache_revalidation_request(request).await;
        };
        let client_ip = request
            .effective_client_addr
            .or(request.peer_addr)
            .map(|address| address.ip());
        let Some(selected) = load_balancer.select_or_wait(request, client_ip).await else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "native proxy cache refresh did not select an upstream",
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
                format!(
                    "native proxy cache refresh selected upstream {authority} without transport"
                ),
            )
            .into());
        };
        let result = upstream.send(request).await;
        if let Some(reporter) = selected.reporter() {
            match &result {
                Ok(response) => reporter.record_status(response.status(), None),
                Err(_) => reporter.record_failure(),
            };
        }
        result
    }

    #[cfg(feature = "load-balancer")]
    async fn send_static_cache_revalidation_request(
        &self,
        request: &NativeHttp1Request,
    ) -> Result<NativeHttp1Response, crate::NativeHttp1Error> {
        let retry_allowed = native_http1_static_failover_method_allowed(&request.method);
        let start = self.next_upstream.fetch_add(1, Ordering::Relaxed);
        let total = self.upstream_slots.len();
        let mut attempted = vec![false; self.upstreams.len()];
        let mut unique_attempts = 0usize;
        let mut last_error = None;
        for attempt in 0..total {
            let slot = start.wrapping_add(attempt) % total;
            let index = self.upstream_slots[slot];
            if attempted[index] {
                continue;
            }
            attempted[index] = true;
            unique_attempts += 1;
            match self.upstreams[index].send(request).await {
                Ok(response) => return Ok(response),
                Err(error) if retry_allowed && unique_attempts < self.upstreams.len() => {
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "native proxy cache refresh has no upstream",
            )
            .into()
        }))
    }

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
        mut request: NativeHttp1Request,
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
        let mut proxy_cache_fill = None::<(
            NativeProxyMemoryCache,
            String,
            &'static str,
            Option<&'static str>,
            Option<NativeMemoryCacheEntry>,
        )>;
        let mut proxy_cache_status = None::<(
            &CacheConfig,
            &'static str,
            Option<&'static str>,
            Option<u64>,
        )>;
        if let Some(cache) = &self.cache {
            if let Some(slice) = cache.slice_response(&request, self).await {
                return self.finish_response(
                    &request,
                    slice.response,
                    Some((
                        &cache.config,
                        if slice.filled { "MISS" } else { "HIT" },
                        Some(if slice.filled { "slice-fill" } else { "slice" }),
                        None,
                    )),
                    #[cfg(any(
                        feature = "compression-brotli",
                        feature = "compression-gzip",
                        feature = "compression-zstd"
                    ))]
                    compression_request,
                );
            }
            match cache.lookup(&request).await {
                NativeProxyCacheLookup::Hit { entry, range } => {
                    let response = native_cached_hit_response(&entry, &request, range);
                    return self.finish_response(
                        &request,
                        response,
                        Some((&cache.config, "HIT", None, Some(entry.age_secs()))),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
                NativeProxyCacheLookup::StaleWhileRevalidate { key, entry } => {
                    cache.record_policy_activity("stale");
                    self.spawn_cache_revalidation(
                        cache.clone(),
                        key,
                        request.clone(),
                        entry.clone(),
                    );
                    return self.finish_response(
                        &request,
                        entry.to_response(),
                        Some((
                            &cache.config,
                            "STALE-UPDATING",
                            Some("stale-while-revalidate"),
                            Some(entry.age_secs()),
                        )),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
                NativeProxyCacheLookup::Miss {
                    key,
                    status,
                    reason,
                } => {
                    if status == "REVALIDATED" {
                        cache.record_policy_activity("revalidate");
                    }
                    proxy_cache_fill = Some((cache.clone(), key, status, reason, None));
                }
                NativeProxyCacheLookup::Revalidate { key, entry } => {
                    cache.record_policy_activity("revalidate");
                    request = native_cache_revalidation_request(request, &entry);
                    proxy_cache_fill = Some((cache.clone(), key, "EXPIRED", None, Some(entry)));
                }
                NativeProxyCacheLookup::Bypass(reason) => {
                    cache.record_policy_activity("bypass");
                    proxy_cache_status = Some((&cache.config, "BYPASS", Some(reason), None));
                }
            }
        }
        if let Some((cache, key, _, _, _)) = proxy_cache_fill.as_ref() {
            if native_request_cache_only_if_cached(&request) {
                let response = NativeHttp1Response::new(504, "Gateway Timeout", b"cache miss\n")
                    .close_connection();
                return self.finish_response(
                    &request,
                    response,
                    Some((&cache.config, "MISS", Some("only-if-cached-miss"), None)),
                    #[cfg(any(
                        feature = "compression-brotli",
                        feature = "compression-gzip",
                        feature = "compression-zstd"
                    ))]
                    compression_request,
                );
            }
            match cache.peer_fill(key, &request).await {
                NativePeerFillDecision::Skip => {}
                NativePeerFillDecision::Hit(response) => {
                    return self.finish_response(
                        &request,
                        response,
                        Some((&cache.config, "PEER-HIT", None, None)),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
                NativePeerFillDecision::FailClosed(reason) => {
                    let response =
                        NativeHttp1Response::new(504, "Gateway Timeout", b"cache miss\n")
                            .close_connection();
                    return self.finish_response(
                        &request,
                        response,
                        Some((&cache.config, "MISS", Some(reason), None)),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
            }
        }
        let _cache_fill_permit = if let Some((cache, key, _, _, _)) = proxy_cache_fill.as_ref() {
            loop {
                match cache.cache_fill_gate(key) {
                    NativeCacheFillGate::Disabled => break None,
                    NativeCacheFillGate::Writer(permit) => break Some(permit),
                    NativeCacheFillGate::Waiter { notify, timeout } => {
                        if let Some(entry) = cache
                            .wait_for_cache_fill(notify, timeout, key, &request)
                            .await
                        {
                            return self.finish_response(
                                &request,
                                entry.to_response(),
                                Some((&cache.config, "HIT", None, Some(entry.age_secs()))),
                                #[cfg(any(
                                    feature = "compression-brotli",
                                    feature = "compression-gzip",
                                    feature = "compression-zstd"
                                ))]
                                compression_request,
                            );
                        }
                    }
                }
            }
        } else {
            None
        };
        let _origin_fill_permit = if let Some((cache, _, _, _, _)) = proxy_cache_fill.as_ref() {
            match cache.acquire_origin_fill_permit() {
                Some(permit) => permit,
                None => {
                    let response = NativeHttp1Response::new(
                        503,
                        "Service Unavailable",
                        b"cache origin fill budget exhausted\n",
                    )
                    .close_connection();
                    return self.finish_response(
                        &request,
                        response,
                        Some((&cache.config, "BYPASS", Some("origin-protected"), None)),
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
            }
        } else {
            None
        };
        let mut last_error = None;
        let max_attempts = self.upstreams.len().max(1);
        for attempt in 0..max_attempts {
            let Some(selected) = load_balancer.select_or_wait(&request, client_ip).await else {
                if attempt == 0 {
                    let status = load_balancer.all_down_status();
                    if let Some((cache, key, _, _, _)) = proxy_cache_fill.as_ref()
                        && let Some(stale) = cache
                            .get_stale(
                                key,
                                &request,
                                CacheStaleEvent::UpstreamError(
                                    fluxheim_config::CacheStaleErrorKind::Connect,
                                ),
                            )
                            .await
                    {
                        cache.record_policy_activity("stale");
                        return self.finish_response(
                            &request,
                            stale.to_response(),
                            Some((
                                &cache.config,
                                "STALE",
                                Some("upstream-error"),
                                Some(stale.age_secs()),
                            )),
                            #[cfg(any(
                                feature = "compression-brotli",
                                feature = "compression-gzip",
                                feature = "compression-zstd"
                            ))]
                            compression_request,
                        );
                    }
                    let error_response = native_error_page_response(
                        &self.error_pages,
                        self.response_write_policy,
                        &request,
                        status,
                    )
                    .unwrap_or_else(|| {
                        NativeHttp1Response::new(
                            status,
                            native_proxy_status_reason(status),
                            b"service unavailable\n",
                        )
                        .close_connection()
                    });
                    return self.finish_response(
                        &request,
                        error_response,
                        proxy_cache_status,
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
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
                    let mut cache_status = proxy_cache_status;
                    if let Some((cache, key, status, reason, stale_entry)) =
                        proxy_cache_fill.as_ref()
                    {
                        if let Some(stale) = cache
                            .get_stale(
                                key,
                                &request,
                                CacheStaleEvent::UpstreamHttpStatus(response.status()),
                            )
                            .await
                        {
                            cache.record_policy_activity("stale");
                            return self.finish_response(
                                &request,
                                stale.to_response(),
                                Some((
                                    &cache.config,
                                    "STALE",
                                    Some("upstream-status"),
                                    Some(stale.age_secs()),
                                )),
                                #[cfg(any(
                                    feature = "compression-brotli",
                                    feature = "compression-gzip",
                                    feature = "compression-zstd"
                                ))]
                                compression_request,
                            );
                        }
                        let revalidated = if response.status() == 304 {
                            if let Some(entry) = stale_entry.as_ref() {
                                cache
                                    .store_not_modified_revalidated(key, &request, entry, &response)
                                    .await
                                    .ok()
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        if let Some(revalidated) = revalidated {
                            return self.finish_response(
                                &request,
                                revalidated.to_response(),
                                Some((
                                    &cache.config,
                                    "REVALIDATED",
                                    None,
                                    Some(revalidated.age_secs()),
                                )),
                                #[cfg(any(
                                    feature = "compression-brotli",
                                    feature = "compression-gzip",
                                    feature = "compression-zstd"
                                ))]
                                compression_request,
                            );
                        }
                        let store_result = if *status == "REVALIDATED" {
                            cache.store_revalidated(key, &request, &response).await
                        } else {
                            cache.store(key, &request, &response).await
                        };
                        cache_status = Some(match store_result {
                            Ok(()) => (&cache.config, *status, *reason, None),
                            Err(reason) => (&cache.config, "BYPASS", Some(reason), None),
                        });
                    }
                    if (200..400).contains(&response.status())
                        && let Some(cookie) = managed_affinity_cookie
                    {
                        response.push_header("set-cookie", cookie);
                    }
                    return self.finish_response(
                        &request,
                        response,
                        cache_status,
                        #[cfg(any(
                            feature = "compression-brotli",
                            feature = "compression-gzip",
                            feature = "compression-zstd"
                        ))]
                        compression_request,
                    );
                }
                Err(error) if retry_allowed && attempt + 1 < max_attempts => {
                    if let Some(reporter) = selected.reporter() {
                        reporter.record_failure();
                    }
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native load-balanced upstream attempt failed before retry: {error:?}"
                    );
                    last_error = Some(error);
                }
                Err(error) => {
                    if let Some(reporter) = selected.reporter() {
                        reporter.record_failure();
                    }
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native load-balanced upstream attempt failed: {error:?}"
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
        if let (Some((cache, key, _, _, _)), Some(error)) =
            (proxy_cache_fill.as_ref(), last_error.as_ref())
            && let Some(stale) = cache
                .get_stale(key, &request, native_cache_stale_event_for_error(error))
                .await
        {
            cache.record_policy_activity("stale");
            return self.finish_response(
                &request,
                stale.to_response(),
                Some((
                    &cache.config,
                    "STALE",
                    Some("upstream-error"),
                    Some(stale.age_secs()),
                )),
                #[cfg(any(
                    feature = "compression-brotli",
                    feature = "compression-gzip",
                    feature = "compression-zstd"
                ))]
                compression_request,
            );
        }
        let error_response = native_error_page_response(
            &self.error_pages,
            self.response_write_policy,
            &request,
            status,
        )
        .unwrap_or_else(|| {
            if status == 504 {
                NativeHttp1Response::new(504, "Gateway Timeout", b"gateway timeout\n")
                    .close_connection()
            } else {
                NativeHttp1Response::new(502, "Bad Gateway", b"bad gateway\n").close_connection()
            }
        });
        self.finish_response(
            &request,
            error_response,
            proxy_cache_status,
            #[cfg(any(
                feature = "compression-brotli",
                feature = "compression-gzip",
                feature = "compression-zstd"
            ))]
            compression_request,
        )
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

    fn finish_response(
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
                apply_native_response_compression(compression_request, &mut response, compression);
            }
        }
        if let Some(cache) = &self.cache
            && let Some(auth) = cache.peer_fill_auth.as_deref()
        {
            native_peer_fill_sign_response(auth, request, &mut response);
        }
        response
    }

    fn rejects_invalid_authenticated_peer_fill(&self, request: &NativeHttp1Request) -> bool {
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

use crate::native_http1_cache::NativeMemoryCacheEntry;
use crate::native_http1_proxy::NativeHttp1Proxy;
use crate::native_http1_proxy_cache_fill::NativeCacheFillGate;
use crate::native_http1_proxy_cache_headers::{
    native_cache_revalidation_request, native_request_cache_only_if_cached,
};
use crate::native_http1_proxy_cache_policy::native_cache_stale_event_for_error;
use crate::native_http1_proxy_cache_response::native_cached_hit_response;
use crate::native_http1_proxy_config::native_http1_static_failover_method_allowed;
use crate::native_http1_proxy_error_page::{
    native_error_page_response, native_proxy_status_reason,
};
#[cfg(feature = "wasm")]
use crate::native_http1_proxy_memory_cache::NativeProxyCacheKeyComponent;
use crate::native_http1_proxy_memory_cache::{
    NativePeerFillDecision, NativeProxyCacheLookup, NativeProxyMemoryCache,
};
use crate::native_http1_proxy_request::native_proxy_error_is_timeout;
use crate::native_http1_response_metadata::native_proxy_status_error;
#[cfg(feature = "wasm")]
use crate::native_http1_route_wasm::{
    NativeWasmCacheLookupContext, NativeWasmCacheLookupOutcome, NativeWasmCacheStoreContext,
    NativeWasmCacheStoreOutcome, NativeWasmHooks, status_reason,
};
use crate::{NativeHttp1Request, NativeHttp1Response};
use fluxheim_cache::CacheStaleEvent;
use fluxheim_config::CacheConfig;

impl NativeHttp1Proxy {
    pub(crate) async fn handle_load_balanced(
        &self,
        mut request: NativeHttp1Request,
        #[cfg(feature = "wasm")] wasm_hooks: Option<&NativeWasmHooks>,
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
        let retry_allowed =
            request.body.is_empty() && native_http1_static_failover_method_allowed(&request.method);
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
        #[cfg(feature = "wasm")]
        let mut wasm_cache_key_components = Vec::<NativeProxyCacheKeyComponent>::new();
        if let Some(cache) = &self.cache {
            #[cfg(feature = "wasm")]
            if let Some(hooks) = wasm_hooks {
                let decision = hooks
                    .cache_lookup_decision(NativeWasmCacheLookupContext::from_request(&request))
                    .await;
                wasm_cache_key_components = decision.key_components;
                match decision.outcome {
                    NativeWasmCacheLookupOutcome::Continue => {}
                    NativeWasmCacheLookupOutcome::Pass(reason) => {
                        cache.record_policy_activity("pass");
                        proxy_cache_status = Some((&cache.config, "BYPASS", Some(reason), None));
                    }
                    NativeWasmCacheLookupOutcome::Bypass(reason) => {
                        cache.record_policy_activity("bypass");
                        proxy_cache_status = Some((&cache.config, "BYPASS", Some(reason), None));
                    }
                    NativeWasmCacheLookupOutcome::Deny { status, reason } => {
                        let response = NativeHttp1Response::new(
                            status,
                            status_reason(status),
                            format!("{reason}\n").into_bytes(),
                        )
                        .close_connection();
                        return self.finish_response(
                            &request,
                            response,
                            Some((&cache.config, "BYPASS", Some("wasm-deny"), None)),
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
            if proxy_cache_status.is_none()
                && let Some(slice) = cache
                    .slice_response(
                        &request,
                        self,
                        #[cfg(feature = "wasm")]
                        &wasm_cache_key_components,
                    )
                    .await
            {
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
            if proxy_cache_status.is_none() {
                match cache
                    .lookup_with_key_components(
                        &request,
                        #[cfg(feature = "wasm")]
                        &wasm_cache_key_components,
                        #[cfg(not(feature = "wasm"))]
                        &[],
                    )
                    .await
                {
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
                            request.metadata_snapshot(),
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
                    NativeProxyCacheLookup::Unavailable(reason) => {
                        cache.record_policy_activity("error");
                        let response = NativeHttp1Response::new(
                            503,
                            "Service Unavailable",
                            b"cache temporarily unavailable\n",
                        )
                        .close_connection();
                        return self.finish_response(
                            &request,
                            response,
                            Some((&cache.config, "BYPASS", Some(reason), None)),
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
                        match cache
                            .wait_for_cache_fill(notify, timeout, key, &request)
                            .await
                        {
                            Ok(Some(entry)) => {
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
                            Ok(None) => {}
                            Err(error) => {
                                cache.record_policy_activity("error");
                                let response = NativeHttp1Response::new(
                                    503,
                                    "Service Unavailable",
                                    b"cache temporarily unavailable\n",
                                )
                                .close_connection();
                                return self.finish_response(
                                    &request,
                                    response,
                                    Some((&cache.config, "BYPASS", Some(error.reason()), None)),
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
                    .await
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
            match upstream.send(&mut request).await {
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
                        #[cfg(feature = "wasm")]
                        let store_result = if let Some(hooks) = wasm_hooks {
                            let decision = hooks
                                .cache_store_decision(
                                    NativeWasmCacheStoreContext::from_request_response(
                                        &request, &response,
                                    ),
                                )
                                .await;
                            match decision.outcome {
                                NativeWasmCacheStoreOutcome::Continue => {
                                    if *status == "REVALIDATED" {
                                        cache
                                            .store_revalidated_with_metadata(
                                                key,
                                                &request,
                                                &response,
                                                decision.metadata,
                                            )
                                            .await
                                    } else {
                                        cache
                                            .store_with_metadata(
                                                key,
                                                &request,
                                                &response,
                                                decision.metadata,
                                            )
                                            .await
                                    }
                                }
                                NativeWasmCacheStoreOutcome::Skip(reason) => Err(reason),
                                NativeWasmCacheStoreOutcome::Deny { status, reason } => {
                                    let denied = NativeHttp1Response::new(
                                        status,
                                        status_reason(status),
                                        format!("{reason}\n").into_bytes(),
                                    )
                                    .close_connection();
                                    return self.finish_response(
                                        &request,
                                        denied,
                                        Some((
                                            &cache.config,
                                            "BYPASS",
                                            Some("wasm-store-deny"),
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
                            }
                        } else if *status == "REVALIDATED" {
                            cache.store_revalidated(key, &request, &response).await
                        } else {
                            cache.store(key, &request, &response).await
                        };
                        #[cfg(not(feature = "wasm"))]
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
        let mut error_response = native_error_page_response(
            &self.error_pages,
            self.response_write_policy,
            &request,
            status,
        )
        .await
        .unwrap_or_else(|| {
            if status == 504 {
                NativeHttp1Response::new(504, "Gateway Timeout", b"gateway timeout\n")
                    .close_connection()
            } else {
                NativeHttp1Response::new(502, "Bad Gateway", b"bad gateway\n").close_connection()
            }
        });
        if let Some(error) = last_error.as_ref() {
            error_response =
                error_response.with_proxy_status_error(native_proxy_status_error(error));
        }
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
}

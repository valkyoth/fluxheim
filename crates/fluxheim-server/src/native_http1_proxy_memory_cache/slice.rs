use std::collections::HashMap;
use std::sync::Arc;

use crate::native_http1_cache::{
    NativeMemoryCacheEntry, native_cache_entry_weight, native_cache_ttl, native_response_header_map,
};
use crate::native_http1_proxy::NativeHttp1Proxy;
use crate::native_http1_proxy_cache_fill::{NativeCacheFillGate, NativeCacheFillWaitBudget};
use crate::native_http1_proxy_cache_headers::{
    cached_proxy_headers, native_response_cache_tags, native_vary_cache_key,
};
use crate::native_http1_proxy_cache_policy::native_cache_expiry_times;
use crate::native_http1_proxy_cache_slice::{
    NativeCacheSliceObject, NativeCacheSliceResponse, native_compose_slice_response,
    native_if_range_matches_slice_identity, native_response_has_non_identity_encoding,
    native_slice_cache_key, native_slice_identity, native_slice_not_satisfiable_response,
    native_slice_object_from_entry, native_slice_request_within_policy, native_slice_strong_etag,
};
use crate::{NativeHttp1Request, NativeHttp1Response};
use fluxheim_cache::{
    CacheRequestView, CacheSliceBounds, VaryCachePolicy, cache_vary_policy,
    request_cache_bypass_reason, resolve_client_slice_ranges,
    response_cache_control_stale_reuse_forbidden, response_range_cache_admission_rejection,
    selected_cache_slice_range_request,
};

use super::NativeProxyMemoryCache;

#[cfg(test)]
#[path = "slice_storage_tests.rs"]
mod storage_tests;

impl NativeProxyMemoryCache {
    pub(crate) async fn slice_response(
        &self,
        request: &NativeHttp1Request,
        proxy: &NativeHttp1Proxy,
        #[cfg(feature = "wasm")] key_components: &[super::NativeProxyCacheKeyComponent],
    ) -> Result<Option<NativeCacheSliceResponse>, &'static str> {
        if !self.config.range.enabled
            || !self.config.range.slice.enabled
            || self
                .config
                .hide_response_headers
                .iter()
                .any(|name| name.eq_ignore_ascii_case("etag"))
        {
            return Ok(None);
        }
        let Some(primary_key) = self.key_with_components(
            request,
            #[cfg(feature = "wasm")]
            key_components,
            #[cfg(not(feature = "wasm"))]
            &[],
        ) else {
            return Ok(None);
        };
        let base_key = if self.config.vary_request_headers.is_empty() {
            primary_key.clone()
        } else {
            let Some(base_key) =
                native_vary_cache_key(&primary_key, &self.config.vary_request_headers, request)
            else {
                return Ok(None);
            };
            base_key
        };
        if request_cache_bypass_reason(request, &self.config).is_some()
            || self.cache_pass_should_bypass(&primary_key)
            || self.slice_probe_suppressed(&base_key)
        {
            return Ok(None);
        }
        let Some(slice_request) = selected_cache_slice_range_request(request, &self.config) else {
            return Ok(None);
        };
        let slice_size = self.config.range.slice.size_bytes.as_u64();
        let Some((total, first_slice, first_filled)) = self
            .discover_slice_total(&base_key, &primary_key, request, proxy, slice_size)
            .await?
        else {
            return Ok(None);
        };
        let Some(ranges) = resolve_client_slice_ranges(&slice_request.ranges, total) else {
            return Ok(None);
        };
        let Some(max_slices) = usize::try_from(self.config.range.slice.max_slices).ok() else {
            return Ok(None);
        };
        if ranges.is_empty()
            || !native_slice_request_within_policy(
                &ranges,
                self.config.range.max_bytes.as_u64(),
                max_slices,
                slice_size,
            )
        {
            return Ok(Some(NativeCacheSliceResponse {
                response: native_slice_not_satisfiable_response(total),
                filled: false,
            }));
        }

        let identity = native_slice_identity(&first_slice);
        if let Some(if_range) = slice_request.if_range.as_deref()
            && !native_if_range_matches_slice_identity(if_range, &identity)
        {
            return Ok(None);
        }

        let mut filled = first_filled;
        let mut slices = HashMap::<(u64, u64), NativeCacheSliceObject>::new();
        slices.insert(
            (first_slice.bounds.start, first_slice.bounds.end),
            first_slice,
        );
        for bounds in fluxheim_cache::required_slice_bounds(&ranges, slice_size, total) {
            if slices.contains_key(&(bounds.start, bounds.end)) {
                continue;
            }
            let Some(result) = self
                .lookup_or_fill_slice(&base_key, &primary_key, request, proxy, bounds)
                .await?
            else {
                return Ok(None);
            };
            filled |= result.1;
            if native_slice_identity(&result.0) != identity {
                return Ok(None);
            }
            slices.insert((result.0.bounds.start, result.0.bounds.end), result.0);
        }

        Ok(native_compose_slice_response(
            &ranges, &slices, &identity, filled,
        ))
    }

    async fn discover_slice_total(
        &self,
        base_key: &str,
        primary_key: &str,
        request: &NativeHttp1Request,
        proxy: &NativeHttp1Proxy,
        slice_size: u64,
    ) -> Result<Option<(u64, NativeCacheSliceObject, bool)>, &'static str> {
        let first_bounds = CacheSliceBounds {
            start: 0,
            end: slice_size.saturating_sub(1),
        };
        let Some((slice, filled)) = self
            .lookup_or_fill_slice(base_key, primary_key, request, proxy, first_bounds)
            .await?
        else {
            return Ok(None);
        };
        Ok(Some((slice.total, slice, filled)))
    }

    async fn lookup_or_fill_slice(
        &self,
        base_key: &str,
        primary_key: &str,
        request: &NativeHttp1Request,
        proxy: &NativeHttp1Proxy,
        bounds: CacheSliceBounds,
    ) -> Result<Option<(NativeCacheSliceObject, bool)>, &'static str> {
        if self.slice_probe_suppressed(base_key) {
            return Ok(None);
        }
        let key = native_slice_cache_key(base_key, bounds.range_request());
        if let Some(slice) = self.lookup_cached_slice(&key, bounds).await? {
            return Ok(Some((slice, false)));
        }
        if !self.config.range.slice.fill_missing {
            return Ok(None);
        }
        let mut wait_budget = NativeCacheFillWaitBudget::new();
        let _fill_permit = loop {
            if self.slice_probe_suppressed(base_key) {
                return Ok(None);
            }
            match self.cache_fill_gate(&key) {
                NativeCacheFillGate::Disabled => break None,
                NativeCacheFillGate::Writer(permit) => break Some(permit),
                NativeCacheFillGate::Waiter(waiter) => {
                    if !wait_budget.wait(waiter).await {
                        return Err("lock-wait-timeout");
                    }
                    if let Some(slice) = self.lookup_cached_slice(&key, bounds).await? {
                        return Ok(Some((slice, false)));
                    }
                }
            }
        };
        let Some(_origin_permit) = self.acquire_origin_fill_permit() else {
            return Ok(None);
        };
        if let Some(slice) = self.lookup_cached_slice(&key, bounds).await? {
            return Ok(Some((slice, false)));
        }
        if self.slice_probe_suppressed(base_key) {
            return Ok(None);
        }
        let Some(response) = proxy.fetch_origin_slice(request, bounds).await else {
            return Ok(None);
        };
        if response.status() == 206 && native_slice_strong_etag(response.headers()).is_none() {
            crate::native_http1_cache::lock_native_memory_cache(&self.state, "slice backoff")
                .slice_backoff
                .record(primary_key, base_key, std::time::Instant::now());
            return Ok(None);
        }
        let Some(slice) = self
            .store_origin_slice(primary_key, &key, request, bounds, &response)
            .await
        else {
            return Ok(None);
        };
        Ok(Some((slice, true)))
    }

    fn slice_probe_suppressed(&self, base_key: &str) -> bool {
        crate::native_http1_cache::lock_native_memory_cache(&self.state, "slice backoff")
            .slice_backoff
            .contains(base_key, std::time::Instant::now())
    }

    async fn store_origin_slice(
        &self,
        primary_key: &str,
        key: &str,
        request: &NativeHttp1Request,
        bounds: CacheSliceBounds,
        response: &NativeHttp1Response,
    ) -> Option<NativeCacheSliceObject> {
        if response.status() == 416
            || self
                .config
                .hide_response_headers
                .iter()
                .any(|name| name.eq_ignore_ascii_case("etag"))
        {
            return None;
        }
        let headers = native_response_header_map(response);
        if !slice_vary_policy_covered_by_config(&headers, &self.config) {
            return None;
        }
        if fluxheim_cache::range_response_cache_admission_rejection(
            response.status(),
            &headers,
            Some(bounds.range_request()),
        )
        .is_some()
            || response_range_cache_admission_rejection(&headers, &self.config).is_some()
            || native_response_has_non_identity_encoding(response)
        {
            return None;
        }
        let ttl = native_cache_ttl(response.status(), &headers, &self.config)?;
        if ttl.is_zero() {
            return None;
        }
        let now = std::time::Instant::now();
        let stale_reuse_forbidden = response_cache_control_stale_reuse_forbidden(&headers);
        let stale_while_revalidate_secs = (!stale_reuse_forbidden)
            .then_some(self.config.stale_while_revalidate_secs)
            .flatten();
        let stale_if_error_secs = (!stale_reuse_forbidden)
            .then_some(self.config.stale_if_error_secs)
            .flatten();
        let (expires_at, stale_while_revalidate_until, stale_if_error_until) =
            native_cache_expiry_times(now, ttl, stale_while_revalidate_secs, stale_if_error_secs)?;
        let body_len = response.body().len() as u64;
        if body_len > self.config.range.slice.size_bytes.as_u64()
            || body_len > self.config.max_object_bytes.as_u64()
        {
            return None;
        }
        let entry = NativeMemoryCacheEntry {
            status: response.status(),
            reason: response.reason().to_owned(),
            headers: cached_proxy_headers(response, &self.config),
            content_length: response.content_length(),
            body: Arc::from(response.body().to_vec()),
            body_sha256: Arc::new(crate::native_http1_cache::native_cache_body_sha256(
                response.body(),
            )),
            expires_at,
            stale_while_revalidate_until,
            stale_if_error_until,
            stale_reuse_forbidden,
            stored_at: now,
            weight: native_cache_entry_weight(key, response, body_len),
        };
        let slice = native_slice_object_from_entry(entry.clone())?;
        let cache_tags = native_response_cache_tags(response, &self.config);
        self.store_slice_entry(primary_key, key, request.path(), cache_tags, entry)
            .await;
        Some(slice)
    }
}

fn slice_vary_policy_covered_by_config(
    headers: &http::HeaderMap,
    config: &fluxheim_config::CacheConfig,
) -> bool {
    match cache_vary_policy(headers, config) {
        VaryCachePolicy::None => true,
        VaryCachePolicy::Fields(fields) => fields.iter().all(|field| {
            config
                .vary_request_headers
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(field))
        }),
        VaryCachePolicy::Uncacheable(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::slice_vary_policy_covered_by_config;

    #[test]
    fn slice_vary_policy_requires_response_fields_to_be_configured() {
        let mut headers = http::HeaderMap::new();
        headers.insert("vary", http::HeaderValue::from_static("accept-language"));

        assert!(!slice_vary_policy_covered_by_config(
            &headers,
            &fluxheim_config::CacheConfig::default(),
        ));
    }

    #[test]
    fn slice_vary_policy_accepts_configured_response_fields() {
        let mut headers = http::HeaderMap::new();
        headers.insert("vary", http::HeaderValue::from_static("Accept-Language"));
        let config = fluxheim_config::CacheConfig {
            vary_request_headers: vec!["accept-language".to_owned()],
            ..Default::default()
        };

        assert!(slice_vary_policy_covered_by_config(&headers, &config));
    }
}

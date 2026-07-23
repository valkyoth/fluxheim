use std::collections::HashMap;
use std::sync::Arc;

use crate::native_http1_cache::{
    NativeMemoryCacheEntry, lock_native_memory_cache, native_cache_entry_weight, native_cache_ttl,
    native_response_header_map, prune_native_memory_cache, remove_native_memory_cache_entry,
};
use crate::native_http1_proxy::NativeHttp1Proxy;
use crate::native_http1_proxy_cache_headers::{
    cached_proxy_headers, native_response_cache_tags, native_vary_cache_key,
};
use crate::native_http1_proxy_cache_policy::native_cache_expiry_times;
use crate::native_http1_proxy_cache_slice::{
    NativeCacheSliceObject, NativeCacheSliceResponse, native_compose_slice_response,
    native_if_range_matches_slice_identity, native_response_has_non_identity_encoding,
    native_slice_cache_key, native_slice_identity, native_slice_not_satisfiable_response,
    native_slice_object_from_entry, native_slice_request_within_policy,
};
use crate::{NativeHttp1Request, NativeHttp1Response};
use fluxheim_cache::{
    CacheRequestView, CacheSliceBounds, VaryCachePolicy, cache_vary_policy,
    request_cache_bypass_reason, resolve_client_slice_ranges,
    response_cache_control_stale_reuse_forbidden, response_range_cache_admission_rejection,
    selected_cache_slice_range_request,
};

use super::NativeProxyMemoryCache;

impl NativeProxyMemoryCache {
    pub(crate) async fn slice_response(
        &self,
        request: &NativeHttp1Request,
        proxy: &NativeHttp1Proxy,
        #[cfg(feature = "wasm")] key_components: &[super::NativeProxyCacheKeyComponent],
    ) -> Option<NativeCacheSliceResponse> {
        if !self.config.range.enabled || !self.config.range.slice.enabled {
            return None;
        }
        let primary_key = self.key_with_components(
            request,
            #[cfg(feature = "wasm")]
            key_components,
            #[cfg(not(feature = "wasm"))]
            &[],
        )?;
        let base_key = if self.config.vary_request_headers.is_empty() {
            primary_key.clone()
        } else {
            native_vary_cache_key(&primary_key, &self.config.vary_request_headers, request)?
        };
        if request_cache_bypass_reason(request, &self.config).is_some()
            || self.cache_pass_should_bypass(&primary_key)
        {
            return None;
        }
        let slice_request = selected_cache_slice_range_request(request, &self.config)?;
        let slice_size = self.config.range.slice.size_bytes.as_u64();
        let (total, first_slice, first_filled) = self
            .discover_slice_total(&base_key, &primary_key, request, proxy, slice_size)
            .await?;
        let ranges = resolve_client_slice_ranges(&slice_request.ranges, total)?;
        if ranges.is_empty()
            || !native_slice_request_within_policy(
                &ranges,
                self.config.range.max_bytes.as_u64(),
                usize::try_from(self.config.range.slice.max_slices).ok()?,
                slice_size,
            )
        {
            return Some(NativeCacheSliceResponse {
                response: native_slice_not_satisfiable_response(total),
                filled: false,
            });
        }

        let identity = native_slice_identity(&first_slice);
        if let Some(if_range) = slice_request.if_range.as_deref()
            && !native_if_range_matches_slice_identity(if_range, &identity)
        {
            return None;
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
            let result = self
                .lookup_or_fill_slice(&base_key, &primary_key, request, proxy, bounds)
                .await?;
            filled |= result.1;
            if native_slice_identity(&result.0) != identity {
                return None;
            }
            slices.insert((result.0.bounds.start, result.0.bounds.end), result.0);
        }

        native_compose_slice_response(&ranges, &slices, &identity, filled)
    }

    async fn discover_slice_total(
        &self,
        base_key: &str,
        primary_key: &str,
        request: &NativeHttp1Request,
        proxy: &NativeHttp1Proxy,
        slice_size: u64,
    ) -> Option<(u64, NativeCacheSliceObject, bool)> {
        let first_bounds = CacheSliceBounds {
            start: 0,
            end: slice_size.saturating_sub(1),
        };
        let (slice, filled) = self
            .lookup_or_fill_slice(base_key, primary_key, request, proxy, first_bounds)
            .await?;
        Some((slice.total, slice, filled))
    }

    async fn lookup_or_fill_slice(
        &self,
        base_key: &str,
        primary_key: &str,
        request: &NativeHttp1Request,
        proxy: &NativeHttp1Proxy,
        bounds: CacheSliceBounds,
    ) -> Option<(NativeCacheSliceObject, bool)> {
        let key = native_slice_cache_key(base_key, bounds.range_request());
        if let Some(slice) = self.lookup_cached_slice(&key) {
            return Some((slice, false));
        }
        if !self.config.range.slice.fill_missing {
            return None;
        }
        let _permit = self.acquire_origin_fill_permit()?;
        if let Some(slice) = self.lookup_cached_slice(&key) {
            return Some((slice, false));
        }
        let response = proxy.fetch_origin_slice(request, bounds).await?;
        let slice = self.store_origin_slice(primary_key, &key, request, bounds, &response)?;
        Some((slice, true))
    }

    fn lookup_cached_slice(&self, key: &str) -> Option<NativeCacheSliceObject> {
        let now = std::time::Instant::now();
        let mut state = lock_native_memory_cache(&self.state, "proxy");
        match state.objects.get(key) {
            Some(entry) if entry.expires_at > now => native_slice_object_from_entry(entry.clone()),
            Some(entry) => {
                let weight = entry.weight;
                remove_native_memory_cache_entry(&mut state, key);
                state.bytes = state.bytes.saturating_sub(weight);
                None
            }
            None => None,
        }
    }

    fn store_origin_slice(
        &self,
        primary_key: &str,
        key: &str,
        request: &NativeHttp1Request,
        bounds: CacheSliceBounds,
        response: &NativeHttp1Response,
    ) -> Option<NativeCacheSliceObject> {
        if response.status() == 416 {
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
        if body_len > self.config.range.slice.size_bytes.as_u64() || body_len > self.max_bytes {
            return None;
        }
        let mut entry = NativeMemoryCacheEntry {
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
        entry.weight = native_cache_entry_weight(key, response, body_len);
        let cache_tags = native_response_cache_tags(response, &self.config);
        let needs_prune = {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            if let Some(previous) = remove_native_memory_cache_entry(&mut state, key) {
                state.bytes = state.bytes.saturating_sub(previous.weight);
            }
            state.bytes = state.bytes.saturating_add(entry.weight);
            state.purge_index.insert_with_path_and_tags(
                key.to_owned(),
                primary_key.to_owned(),
                self.user_tag(),
                Some(request.path().to_owned()),
                cache_tags,
            );
            state.objects.insert(key.to_owned(), entry);
            state.bytes > self.max_bytes
        };
        if needs_prune {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            prune_native_memory_cache(&mut state, self.max_bytes);
        }
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

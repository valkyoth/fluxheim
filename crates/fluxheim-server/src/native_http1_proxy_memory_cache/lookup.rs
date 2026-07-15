use std::time::Instant;

use crate::NativeHttp1Request;
use crate::native_http1_cache::{
    NativeMemoryCacheEntry, lock_native_memory_cache, remove_native_memory_cache_entry,
};
use crate::native_http1_proxy_cache_headers::{
    native_cache_entry_revalidatable, native_vary_cache_key,
};
use crate::native_http1_proxy_cache_policy::{
    native_cache_entry_has_stale_window, native_cache_entry_serve_stale_while_revalidate,
};
use crate::native_http1_proxy_request::native_request_header;
use fluxheim_cache::{
    CacheRequest, CacheRequestView, CacheStaleEvent, StoredCachePolicy, append_cache_key_component,
    cache_key_with_component, cache_method_temporarily_bypassed, cache_should_serve_stale,
    image_cache_key, request_cache_bypass_reason, request_cache_revalidation_requested,
    selected_cache_range_request,
};

use super::{NativeProxyCacheKeyComponent, NativeProxyCacheLookup, NativeProxyMemoryCache};
use crate::native_http1_proxy_memory_cache::disk::NativeDiskCacheLookupError;

impl NativeProxyMemoryCache {
    pub(crate) async fn lookup_with_key_components(
        &self,
        request: &NativeHttp1Request,
        key_components: &[NativeProxyCacheKeyComponent],
    ) -> NativeProxyCacheLookup {
        if cache_method_temporarily_bypassed(request.method()) {
            return NativeProxyCacheLookup::Bypass("method-head");
        }
        if let Some(reason) = request_cache_bypass_reason(request, &self.config) {
            return NativeProxyCacheLookup::Bypass(reason);
        }
        let Some(key) = self.key_with_components(request, key_components) else {
            return NativeProxyCacheLookup::Bypass("proxy-ineligible");
        };
        if self.cache_pass_should_bypass(&key) {
            return NativeProxyCacheLookup::Bypass("cache-pass");
        }
        let lookup_started_at = Instant::now();
        let range = selected_cache_range_request(request, &self.config);
        let range_requested = self.config.range.enabled && request.contains_header("range");
        if range_requested && range.is_none() {
            return NativeProxyCacheLookup::Bypass("range-unsupported");
        }
        let revalidation = request_cache_revalidation_requested(request, &self.config);
        let mut disk_error = None;
        if !revalidation {
            match self.get(&key, request).await {
                Ok(Some(hit)) => {
                    self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
                    return NativeProxyCacheLookup::Hit { entry: hit, range };
                }
                Ok(None) => {}
                Err(error) => disk_error = Some(error),
            }
        }
        let range_key =
            range.map(|range| cache_key_with_component(&key, "range", &range.component()));
        if !revalidation && let Some(range_key) = range_key.as_deref() {
            match self.get(range_key, request).await {
                Ok(Some(hit)) => {
                    self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
                    return NativeProxyCacheLookup::Hit {
                        entry: hit,
                        range: None,
                    };
                }
                Ok(None) => {}
                Err(error) => disk_error = Some(error),
            }
        }
        if !revalidation && !range_requested {
            match self.get_stale_while_revalidate(&key, request).await {
                Ok(Some(stale)) => {
                    self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
                    return NativeProxyCacheLookup::StaleWhileRevalidate { key, entry: stale };
                }
                Ok(None) => {}
                Err(error) => disk_error = Some(error),
            }
        }
        if !revalidation && !range_requested {
            match self.get_revalidatable(&key, request).await {
                Ok(Some(entry)) => {
                    self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
                    return NativeProxyCacheLookup::Revalidate { key, entry };
                }
                Ok(None) => {}
                Err(error) => disk_error = Some(error),
            }
        }
        if let Some(error) = disk_error {
            self.record_operation_duration("error", "lookup", lookup_started_at.elapsed());
            return NativeProxyCacheLookup::Unavailable(error.reason());
        }
        if range_key.is_some() && !self.config.range.slice.enabled {
            self.record_operation_duration("miss", "lookup", lookup_started_at.elapsed());
            return NativeProxyCacheLookup::Bypass("range-miss");
        }
        if let Some(range_key) = range_key {
            self.record_operation_duration("miss", "lookup", lookup_started_at.elapsed());
            return NativeProxyCacheLookup::Miss {
                key: range_key,
                status: "MISS",
                reason: Some("range-miss"),
            };
        }
        self.record_operation_duration("miss", "lookup", lookup_started_at.elapsed());
        NativeProxyCacheLookup::Miss {
            key,
            status: if revalidation { "REVALIDATED" } else { "MISS" },
            reason: revalidation.then_some("request-refresh"),
        }
    }

    pub(super) fn key_with_components(
        &self,
        request: &NativeHttp1Request,
        key_components: &[NativeProxyCacheKeyComponent],
    ) -> Option<String> {
        let mut key = image_cache_key(
            &self.config,
            &CacheRequest {
                method: request.method(),
                host: native_request_header(request, "host"),
                path: request.path(),
                query: request.query(),
            },
        )
        .map(|key| key.as_str().to_owned())?;
        for component in key_components {
            append_cache_key_component(&mut key, component.label, component.value);
        }
        Some(key)
    }

    pub(super) async fn get(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Result<Option<NativeMemoryCacheEntry>, NativeDiskCacheLookupError> {
        let now = std::time::Instant::now();
        if self.memory_enabled() {
            let mut state = lock_native_memory_cache(&self.state, "proxy");

            if let Some(variants) = state.variants.get(key).cloned() {
                for variant in variants {
                    let Some(variant_key) = native_vary_cache_key(key, &variant.fields, request)
                    else {
                        continue;
                    };
                    if variant_key != variant.key {
                        continue;
                    }
                    match state.objects.get(&variant.key) {
                        Some(entry) if entry.expires_at > now => return Ok(Some(entry.clone())),
                        Some(entry) => {
                            if !native_cache_entry_has_stale_window(entry, now) {
                                let weight = entry.weight;
                                remove_native_memory_cache_entry(&mut state, &variant.key);
                                state.bytes = state.bytes.saturating_sub(weight);
                            }
                            break;
                        }
                        None => {}
                    }
                }
            }

            if !state.variants.contains_key(key) {
                match state.objects.get(key) {
                    Some(entry) if entry.expires_at > now => return Ok(Some(entry.clone())),
                    Some(entry) if !native_cache_entry_has_stale_window(entry, now) => {
                        let weight = entry.weight;
                        remove_native_memory_cache_entry(&mut state, key);
                        state.bytes = state.bytes.saturating_sub(weight);
                    }
                    _ => {}
                }
            }
        }
        self.get_disk_fresh(key, request).await
    }

    async fn get_stale_while_revalidate(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Result<Option<NativeMemoryCacheEntry>, NativeDiskCacheLookupError> {
        let now = std::time::Instant::now();
        if self.memory_enabled() {
            let state = lock_native_memory_cache(&self.state, "proxy");
            if let Some(variants) = state.variants.get(key).cloned() {
                for variant in variants {
                    let Some(variant_key) = native_vary_cache_key(key, &variant.fields, request)
                    else {
                        continue;
                    };
                    if variant_key != variant.key {
                        continue;
                    }
                    if let Some(entry) = state.objects.get(&variant.key)
                        && native_cache_entry_serve_stale_while_revalidate(entry, now)
                    {
                        return Ok(Some(entry.clone()));
                    }
                }
            }

            if !state.variants.contains_key(key)
                && let Some(entry) = state.objects.get(key)
                && native_cache_entry_serve_stale_while_revalidate(entry, now)
            {
                return Ok(Some(entry.clone()));
            }
        }
        self.get_disk_stale_while_revalidate(key, request).await
    }

    pub(crate) async fn get_stale(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        event: CacheStaleEvent,
    ) -> Option<NativeMemoryCacheEntry> {
        if !cache_should_serve_stale(&self.config, event, StoredCachePolicy::default()) {
            return None;
        }

        let now = std::time::Instant::now();
        if self.memory_enabled() {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            if let Some(variants) = state.variants.get(key).cloned() {
                for variant in variants {
                    let Some(variant_key) = native_vary_cache_key(key, &variant.fields, request)
                    else {
                        continue;
                    };
                    if variant_key != variant.key {
                        continue;
                    }
                    match state.objects.get(&variant.key) {
                        Some(entry)
                            if cache_should_serve_stale(
                                &self.config,
                                event,
                                StoredCachePolicy {
                                    stale_reuse_forbidden: entry.stale_reuse_forbidden,
                                },
                            ) && entry.expires_at <= now
                                && entry.stale_if_error_until.is_some_and(|until| until > now) =>
                        {
                            return Some(entry.clone());
                        }
                        Some(entry)
                            if entry.stale_if_error_until.is_some_and(|until| until <= now) =>
                        {
                            let weight = entry.weight;
                            remove_native_memory_cache_entry(&mut state, &variant.key);
                            state.bytes = state.bytes.saturating_sub(weight);
                            break;
                        }
                        _ => {}
                    }
                }
            }

            if !state.variants.contains_key(key) {
                match state.objects.get(key) {
                    Some(entry)
                        if cache_should_serve_stale(
                            &self.config,
                            event,
                            StoredCachePolicy {
                                stale_reuse_forbidden: entry.stale_reuse_forbidden,
                            },
                        ) && entry.expires_at <= now
                            && entry.stale_if_error_until.is_some_and(|until| until > now) =>
                    {
                        return Some(entry.clone());
                    }
                    Some(entry) if entry.stale_if_error_until.is_some_and(|until| until <= now) => {
                        let weight = entry.weight;
                        remove_native_memory_cache_entry(&mut state, key);
                        state.bytes = state.bytes.saturating_sub(weight);
                    }
                    _ => {}
                }
            }
        }
        match self.get_disk_stale_if_error(key, request).await {
            Ok(entry) => entry,
            Err(error) => {
                log::debug!(
                    target: "fluxheim::native_http1",
                    "native disk stale lookup unavailable: {error:?}"
                );
                None
            }
        }
    }

    async fn get_revalidatable(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Result<Option<NativeMemoryCacheEntry>, NativeDiskCacheLookupError> {
        let now = std::time::Instant::now();
        if self.memory_enabled() {
            let state = lock_native_memory_cache(&self.state, "proxy");
            if let Some(variants) = state.variants.get(key).cloned() {
                for variant in variants {
                    let Some(variant_key) = native_vary_cache_key(key, &variant.fields, request)
                    else {
                        continue;
                    };
                    if variant_key != variant.key {
                        continue;
                    }
                    if let Some(entry) = state.objects.get(&variant.key)
                        && native_cache_entry_revalidatable(entry, now)
                    {
                        return Ok(Some(entry.clone()));
                    }
                }
            }

            if !state.variants.contains_key(key)
                && let Some(entry) = state.objects.get(key)
                && native_cache_entry_revalidatable(entry, now)
            {
                return Ok(Some(entry.clone()));
            }
        }
        self.get_disk_revalidatable(key, request).await
    }
}

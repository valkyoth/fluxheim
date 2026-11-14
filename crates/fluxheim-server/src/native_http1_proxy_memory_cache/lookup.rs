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

#[cfg(test)]
#[path = "lookup_tests.rs"]
mod tests;

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
        let mut disk_entry = None;
        let mut disk_error = None;
        if !revalidation {
            if let Some(hit) = self.get_memory_fresh(&key, request) {
                self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
                return NativeProxyCacheLookup::Hit { entry: hit, range };
            }
            // One disk read/retry window supplies fresh, stale and validator
            // classification. Saturation is terminal, not another read phase.
            disk_entry = match self.disk_entry(&key, request).await {
                Ok(entry) => entry,
                Err(error) => {
                    disk_error = Some(error);
                    None
                }
            };
            if let Some(hit) = self.fresh_disk_entry(&key, request, disk_entry.clone()) {
                self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
                return NativeProxyCacheLookup::Hit { entry: hit, range };
            }
        }
        let range_key =
            range.map(|range| cache_key_with_component(&key, "range", &range.component()));
        if !revalidation && let Some(range_key) = range_key.as_deref() {
            let range_entry = if disk_error.is_some() {
                Ok(self.get_memory_fresh(range_key, request))
            } else {
                self.get(range_key, request).await
            };
            match range_entry {
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
            let stale = self
                .get_memory_stale_while_revalidate(&key, request)
                .or_else(|| {
                    disk_entry
                        .as_ref()
                        .filter(|entry| {
                            native_cache_entry_serve_stale_while_revalidate(entry, Instant::now())
                        })
                        .cloned()
                });
            if let Some(entry) = stale {
                self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
                return NativeProxyCacheLookup::StaleWhileRevalidate { key, entry };
            }
        }
        if !revalidation && !range_requested {
            let revalidatable = self.get_memory_revalidatable(&key, request).or_else(|| {
                disk_entry.filter(|entry| native_cache_entry_revalidatable(entry, Instant::now()))
            });
            if let Some(entry) = revalidatable {
                self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
                return NativeProxyCacheLookup::Revalidate { key, entry };
            }
        }
        if let Some(error) = disk_error {
            return self.unavailable_lookup(error, lookup_started_at);
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

    fn unavailable_lookup(
        &self,
        error: NativeDiskCacheLookupError,
        started: Instant,
    ) -> NativeProxyCacheLookup {
        self.record_operation_duration("error", "lookup", started.elapsed());
        NativeProxyCacheLookup::Unavailable(error.reason())
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
        if let Some(entry) = self.get_memory_fresh(key, request) {
            return Ok(Some(entry));
        }
        self.get_disk_fresh(key, request).await
    }

    fn get_memory_fresh(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
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
                        Some(entry) if entry.expires_at > now => return Some(entry.clone()),
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
                    Some(entry) if entry.expires_at > now => return Some(entry.clone()),
                    Some(entry) if !native_cache_entry_has_stale_window(entry, now) => {
                        let weight = entry.weight;
                        remove_native_memory_cache_entry(&mut state, key);
                        state.bytes = state.bytes.saturating_sub(weight);
                    }
                    _ => {}
                }
            }
        }
        None
    }

    fn get_memory_stale_while_revalidate(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
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
                        return Some(entry.clone());
                    }
                }
            }

            if !state.variants.contains_key(key)
                && let Some(entry) = state.objects.get(key)
                && native_cache_entry_serve_stale_while_revalidate(entry, now)
            {
                return Some(entry.clone());
            }
        }
        None
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

    fn get_memory_revalidatable(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
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
                        return Some(entry.clone());
                    }
                }
            }

            if !state.variants.contains_key(key)
                && let Some(entry) = state.objects.get(key)
                && native_cache_entry_revalidatable(entry, now)
            {
                return Some(entry.clone());
            }
        }
        None
    }
}

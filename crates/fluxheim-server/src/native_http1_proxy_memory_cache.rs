use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::native_http1_cache::{
    NativeDiskCache, NativeDiskCacheStoreKey, NativeMemoryCacheCounter, NativeMemoryCacheEntry,
    NativeMemoryCacheFill, NativeMemoryCacheState, NativeMemoryCacheVariant,
    lock_native_memory_cache, native_cache_entry_weight, native_cache_ttl,
    native_peer_fill_cache_ttl, native_response_header_map, prune_native_memory_cache,
    register_native_disk_cache_purge_handle, remove_native_memory_cache_entry,
    remove_native_memory_cache_variants,
};
use crate::native_http1_proxy::NativeHttp1Proxy;
use crate::native_http1_proxy_cache_fill::{
    NativeCacheFillGate, NativeCacheFillPermit, NativeOriginFillPermit, NativePeerFillPermit,
    acquire_native_origin_fill_permit, acquire_native_peer_fill_permit,
};
use crate::native_http1_proxy_cache_headers::{
    cached_proxy_headers, native_cache_entry_revalidatable,
    native_not_modified_refresh_header_skipped, native_request_cache_only_if_cached,
    native_response_cache_tags, native_vary_cache_key,
};
use crate::native_http1_proxy_cache_policy::{
    native_cache_entry_has_stale_window, native_cache_entry_serve_stale_while_revalidate,
    native_cache_expiry_times, native_predictor_counter_uses, prune_native_predictor_counters,
};
use crate::native_http1_proxy_cache_slice::{
    NativeCacheSliceObject, NativeCacheSliceResponse, native_compose_slice_response,
    native_if_range_matches_slice_identity, native_response_has_non_identity_encoding,
    native_slice_cache_key, native_slice_identity, native_slice_not_satisfiable_response,
    native_slice_object_from_entry, native_slice_request_within_policy,
};
use crate::native_http1_proxy_metrics::{
    record_native_cache_activity, record_native_cache_activity_scope,
    record_native_cache_operation_duration,
};
use crate::native_http1_proxy_peer_fill::{
    NativePeerFillPeer, native_peer_fill_fetch, native_peer_fill_peers, native_request_is_peer_fill,
};
use crate::native_http1_proxy_peer_fill_auth::{
    NativePeerFillAuth, native_peer_fill_auth_from_config,
};
use crate::native_http1_proxy_request::native_request_header;
use crate::native_http1_proxy_runtime::{
    register_native_cache_stats_handle, register_native_memory_cache_purge_handle,
};
use crate::{NativeHttp1Request, NativeHttp1Response};
use fluxheim_cache::{
    CacheRangeRequest, CacheRequest, CacheRequestView, CacheSliceBounds, CacheStaleEvent,
    VaryCachePolicy, cache_key_with_component, cache_method_temporarily_bypassed,
    cache_should_serve_stale, cache_vary_policy, image_cache_key,
    range_response_cache_admission_rejection, request_cache_bypass_reason,
    request_cache_revalidation_requested, resolve_client_slice_ranges, response_age_secs,
    response_cache_admission_rejection, response_range_cache_admission_rejection,
    selected_cache_range_request, selected_cache_slice_range_request,
};
use fluxheim_config::CacheConfig;
use tokio::sync::Notify;

static NATIVE_PROXY_CACHE_ID: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug)]
pub(crate) struct NativeProxyMemoryCache {
    pub(crate) config: CacheConfig,
    pub(crate) max_bytes: u64,
    pub(crate) state: Arc<Mutex<NativeMemoryCacheState>>,
    pub(crate) disk: Option<Arc<NativeDiskCache>>,
    pub(crate) metrics_vhost: Arc<str>,
    pub(crate) metrics_route: Option<Arc<str>>,
    pub(crate) origin_fill_key: Arc<str>,
    pub(crate) peer_fill_key: Arc<str>,
    pub(crate) peer_fill_peers: Vec<NativePeerFillPeer>,
    pub(crate) peer_fill_auth: Option<Arc<NativePeerFillAuth>>,
}

impl Eq for NativeProxyMemoryCache {}

impl PartialEq for NativeProxyMemoryCache {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config && self.max_bytes == other.max_bytes
    }
}

#[derive(Debug)]
pub(crate) enum NativeProxyCacheLookup {
    Bypass(&'static str),
    Miss {
        key: String,
        status: &'static str,
        reason: Option<&'static str>,
    },
    Hit {
        entry: NativeMemoryCacheEntry,
        range: Option<CacheRangeRequest>,
    },
    StaleWhileRevalidate {
        key: String,
        entry: NativeMemoryCacheEntry,
    },
    Revalidate {
        key: String,
        entry: NativeMemoryCacheEntry,
    },
}

#[derive(Debug)]
pub(crate) enum NativePeerFillDecision {
    Skip,
    Hit(NativeHttp1Response),
    FailClosed(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeCacheStoreMode {
    Origin,
    Revalidated,
    PeerFill,
}

impl NativeProxyMemoryCache {
    pub(crate) fn from_config(config: &CacheConfig) -> Option<Self> {
        Self::from_config_with_metrics(config, "native", None)
    }

    pub(crate) fn from_config_with_metrics(
        config: &CacheConfig,
        vhost: &str,
        route: Option<&str>,
    ) -> Option<Self> {
        let id = NATIVE_PROXY_CACHE_ID.fetch_add(1, Ordering::Relaxed);
        if !NativeHttp1Proxy::proxy_cache_supported(config) {
            return None;
        }
        let peer_fill_auth = match native_peer_fill_auth_from_config(config) {
            Ok(auth) => auth,
            Err(error) => {
                log::error!(
                    target: "fluxheim::security",
                    "native peer-fill shared secret could not be loaded; disabling native proxy cache for this policy: {error}"
                );
                return None;
            }
        };
        let disk = NativeDiskCache::from_config(config).map(Arc::new);
        if !config.memory.enabled && disk.is_none() {
            return None;
        }
        let state = Arc::new(Mutex::new(NativeMemoryCacheState::default()));
        let metrics_vhost = Arc::<str>::from(vhost);
        let metrics_route = route.map(Arc::<str>::from);
        if config.memory.enabled {
            register_native_memory_cache_purge_handle(
                metrics_vhost.clone(),
                metrics_route.clone(),
                &state,
            );
        }
        if let Some(disk) = disk.as_ref() {
            register_native_disk_cache_purge_handle(
                metrics_vhost.clone(),
                metrics_route.clone(),
                disk,
            );
        }
        register_native_cache_stats_handle(
            config.memory.enabled,
            config.memory.max_size_bytes.as_u64(),
            &state,
            disk.as_ref(),
        );
        Some(Self {
            config: config.clone(),
            max_bytes: if config.memory.enabled {
                config.memory.max_size_bytes.as_u64()
            } else {
                0
            },
            state,
            disk,
            metrics_vhost,
            metrics_route,
            origin_fill_key: Arc::from(format!("native-proxy-cache:{id}:origin")),
            peer_fill_key: Arc::from(format!("native-proxy-cache:{id}:peer-fill")),
            peer_fill_peers: native_peer_fill_peers(config),
            peer_fill_auth,
        })
    }

    pub(crate) fn memory_enabled(&self) -> bool {
        self.config.memory.enabled
    }

    fn user_tag(&self) -> String {
        self.metrics_route
            .as_deref()
            .map(|route| format!("{}:route:{route}", self.metrics_vhost))
            .unwrap_or_else(|| self.metrics_vhost.to_string())
    }

    pub(crate) fn record_policy_activity(&self, event: &'static str) {
        self.record_activity("policy", event);
        self.record_activity_scope("policy", event);
    }

    pub(crate) fn record_activity(&self, tier: &'static str, event: &'static str) {
        record_native_cache_activity(tier, event);
    }

    pub(crate) fn record_activity_scope(&self, tier: &'static str, event: &'static str) {
        record_native_cache_activity_scope(
            &self.metrics_vhost,
            self.metrics_route.as_deref(),
            tier,
            event,
        );
    }

    pub(crate) fn record_operation_duration(
        &self,
        phase: &'static str,
        operation: &'static str,
        duration: Duration,
    ) {
        record_native_cache_operation_duration(
            &self.metrics_vhost,
            self.metrics_route.as_deref(),
            phase,
            operation,
            duration,
        );
    }

    pub(crate) async fn lookup(&self, request: &NativeHttp1Request) -> NativeProxyCacheLookup {
        if cache_method_temporarily_bypassed(request.method()) {
            return NativeProxyCacheLookup::Bypass("method-head");
        }
        if let Some(reason) = request_cache_bypass_reason(request, &self.config) {
            return NativeProxyCacheLookup::Bypass(reason);
        }
        if request.contains_header("authorization") {
            return NativeProxyCacheLookup::Bypass("request-authorization");
        }
        let Some(key) = self.key(request) else {
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
        if !revalidation && let Some(hit) = self.get(&key, request).await {
            self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
            return NativeProxyCacheLookup::Hit { entry: hit, range };
        }
        let range_key =
            range.map(|range| cache_key_with_component(&key, "range", &range.component()));
        if !revalidation
            && let Some(range_key) = range_key.as_deref()
            && let Some(hit) = self.get(range_key, request).await
        {
            self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
            return NativeProxyCacheLookup::Hit {
                entry: hit,
                range: None,
            };
        }
        if !revalidation
            && !range_requested
            && let Some(stale) = self.get_stale_while_revalidate(&key, request).await
        {
            self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
            return NativeProxyCacheLookup::StaleWhileRevalidate { key, entry: stale };
        }
        if !revalidation
            && !range_requested
            && let Some(entry) = self.get_revalidatable(&key, request).await
        {
            self.record_operation_duration("hit", "lookup", lookup_started_at.elapsed());
            return NativeProxyCacheLookup::Revalidate { key, entry };
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

    pub(crate) fn acquire_origin_fill_permit(&self) -> Option<Option<NativeOriginFillPermit>> {
        if !self.config.origin_protection.enabled {
            return Some(None);
        }
        acquire_native_origin_fill_permit(
            self.origin_fill_key.as_ref().to_owned(),
            self.config.origin_protection.max_concurrent_fills,
        )
        .map(Some)
    }

    pub(crate) fn cache_fill_gate(&self, key: &str) -> NativeCacheFillGate {
        if !self.config.lock.enabled {
            return NativeCacheFillGate::Disabled;
        }
        let mut state = lock_native_memory_cache(&self.state, "proxy");
        let now = std::time::Instant::now();
        let age_timeout = Duration::from_secs(self.config.lock.age_timeout_secs);
        if let Some(fill) = state.filling.get(key) {
            if now.saturating_duration_since(fill.started_at) < age_timeout {
                return NativeCacheFillGate::Waiter {
                    notify: fill.notify.clone(),
                    timeout: Duration::from_secs(self.config.lock.wait_timeout_secs),
                };
            }
            let expired = state.filling.remove(key);
            if let Some(expired) = expired {
                expired.notify.notify_waiters();
            }
        }

        let notify = Arc::new(Notify::new());
        state.filling.insert(
            key.to_owned(),
            NativeMemoryCacheFill {
                notify: notify.clone(),
                started_at: now,
            },
        );
        NativeCacheFillGate::Writer(NativeCacheFillPermit::new(
            self.state.clone(),
            key.to_owned(),
            notify,
        ))
    }

    pub(crate) async fn wait_for_cache_fill(
        &self,
        notify: Arc<Notify>,
        timeout: Duration,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let _ = tokio::time::timeout(timeout, notify.notified()).await;
        self.get(key, request).await
    }

    pub(crate) async fn slice_response(
        &self,
        request: &NativeHttp1Request,
        proxy: &NativeHttp1Proxy,
    ) -> Option<NativeCacheSliceResponse> {
        if !self.config.range.enabled || !self.config.range.slice.enabled {
            return None;
        }
        if request_cache_bypass_reason(request, &self.config).is_some()
            || self.cache_pass_should_bypass(&self.key(request)?)
        {
            return None;
        }
        let slice_request = selected_cache_slice_range_request(request, &self.config)?;
        let base_key = self.key(request)?;
        let slice_size = self.config.range.slice.size_bytes.as_u64();
        let (total, first_slice, first_filled) = self
            .discover_slice_total(&base_key, request, proxy, slice_size)
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
                .lookup_or_fill_slice(&base_key, request, proxy, bounds)
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
        request: &NativeHttp1Request,
        proxy: &NativeHttp1Proxy,
        slice_size: u64,
    ) -> Option<(u64, NativeCacheSliceObject, bool)> {
        let first_bounds = CacheSliceBounds {
            start: 0,
            end: slice_size.saturating_sub(1),
        };
        let (slice, filled) = self
            .lookup_or_fill_slice(base_key, request, proxy, first_bounds)
            .await?;
        Some((slice.total, slice, filled))
    }

    async fn lookup_or_fill_slice(
        &self,
        base_key: &str,
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
        let slice = self.store_origin_slice(base_key, &key, request, bounds, &response)?;
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
        base_key: &str,
        key: &str,
        request: &NativeHttp1Request,
        bounds: CacheSliceBounds,
        response: &NativeHttp1Response,
    ) -> Option<NativeCacheSliceObject> {
        if response.status() == 416 {
            return None;
        }
        let headers = native_response_header_map(response);
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
        let (expires_at, stale_while_revalidate_until, stale_if_error_until) =
            native_cache_expiry_times(
                now,
                ttl,
                self.config.stale_while_revalidate_secs,
                self.config.stale_if_error_secs,
            )?;
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
            expires_at,
            stale_while_revalidate_until,
            stale_if_error_until,
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
                base_key.to_owned(),
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

    fn acquire_peer_fill_permit(&self) -> Option<NativePeerFillPermit> {
        acquire_native_peer_fill_permit(
            self.peer_fill_key.as_ref().to_owned(),
            self.config.peer_fill.max_concurrent_requests,
        )
    }

    pub(crate) async fn peer_fill(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> NativePeerFillDecision {
        if !self.config.peer_fill.enabled
            || request.method != "GET"
            || (native_request_is_peer_fill(request)
                && native_request_cache_only_if_cached(request))
        {
            return NativePeerFillDecision::Skip;
        }
        let Some(_permit) = self.acquire_peer_fill_permit() else {
            return if self.config.peer_fill.fail_open {
                self.record_policy_activity("peer_fill_fallback");
                NativePeerFillDecision::Skip
            } else {
                self.record_policy_activity("peer_fill_fail_closed");
                NativePeerFillDecision::FailClosed("peer-fill-concurrency-limit")
            };
        };
        let max_body_bytes = self
            .config
            .peer_fill
            .max_object_bytes
            .unwrap_or(self.config.max_object_bytes)
            .as_u64()
            .min(self.config.max_object_bytes.as_u64());

        for peer in &self.peer_fill_peers {
            match native_peer_fill_fetch(
                peer,
                &self.config,
                self.peer_fill_auth.as_deref(),
                request,
                max_body_bytes,
            )
            .await
            {
                Ok(Some(response)) => {
                    if response.status() != 200 {
                        continue;
                    }
                    if self.store_peer_fill(key, request, &response).await.is_err() {
                        self.record_policy_activity("peer_fill_error");
                        continue;
                    }
                    self.record_policy_activity("peer_fill_hit");
                    return NativePeerFillDecision::Hit(response);
                }
                Ok(None) => {}
                Err(error) => {
                    self.record_policy_activity("peer_fill_error");
                    log::warn!(
                        target: "fluxheim::native_http1",
                        "native peer fill from {} failed: {error:?}",
                        peer.name
                    );
                }
            }
        }

        if self.config.peer_fill.fail_open {
            self.record_policy_activity("peer_fill_miss");
            self.record_policy_activity("peer_fill_fallback");
            NativePeerFillDecision::Skip
        } else {
            self.record_policy_activity("peer_fill_miss");
            self.record_policy_activity("peer_fill_fail_closed");
            NativePeerFillDecision::FailClosed("peer-fill-miss")
        }
    }

    fn key(&self, request: &NativeHttp1Request) -> Option<String> {
        image_cache_key(
            &self.config,
            &CacheRequest {
                method: request.method(),
                host: native_request_header(request, "host"),
                path: request.path(),
                query: request.query(),
            },
        )
        .map(|key| key.as_str().to_owned())
    }

    async fn get(&self, key: &str, request: &NativeHttp1Request) -> Option<NativeMemoryCacheEntry> {
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
        self.get_disk_fresh(key, request).await
    }

    async fn get_stale_while_revalidate(
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
        self.get_disk_stale_while_revalidate(key, request).await
    }

    pub(crate) async fn get_stale(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        event: CacheStaleEvent,
    ) -> Option<NativeMemoryCacheEntry> {
        if !cache_should_serve_stale(&self.config, event) {
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
                            if entry.expires_at <= now
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
                        if entry.expires_at <= now
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
        self.get_disk_stale_if_error(key, request).await
    }

    async fn get_revalidatable(
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
        self.get_disk_revalidatable(key, request).await
    }

    async fn get_disk_fresh(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let entry = self.disk_entry(key, request).await?;
        (entry.expires_at > std::time::Instant::now()).then(|| {
            self.record_activity("disk", "hit");
            self.record_activity_scope("disk", "hit");
            self.promote_disk_entry(key, request, &entry);
            entry
        })
    }

    async fn get_disk_stale_while_revalidate(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let entry = self.disk_entry(key, request).await?;
        native_cache_entry_serve_stale_while_revalidate(&entry, std::time::Instant::now())
            .then_some(entry)
    }

    async fn get_disk_stale_if_error(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let entry = self.disk_entry(key, request).await?;
        let now = std::time::Instant::now();
        (entry.expires_at <= now && entry.stale_if_error_until.is_some_and(|until| until > now))
            .then_some(entry)
    }

    async fn get_disk_revalidatable(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let entry = self.disk_entry(key, request).await?;
        native_cache_entry_revalidatable(&entry, std::time::Instant::now()).then_some(entry)
    }

    async fn disk_entry(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let disk = self.disk.as_ref()?.clone();
        let key = key.to_owned();
        let request = request.clone();
        match tokio::task::spawn_blocking(move || {
            disk.get(&key, |fields| native_vary_cache_key(&key, fields, &request))
        })
        .await
        {
            Ok(entry) => entry,
            Err(error) => {
                log::debug!(
                    target: "fluxheim::native_http1",
                    "native disk cache lookup task failed: {error}"
                );
                None
            }
        }
    }

    fn promote_disk_entry(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        entry: &NativeMemoryCacheEntry,
    ) {
        if !self.memory_enabled() || entry.weight > self.max_bytes {
            return;
        }
        let headers = native_response_header_map(&entry.to_response());
        let vary_fields = match cache_vary_policy(&headers, &self.config) {
            VaryCachePolicy::None => None,
            VaryCachePolicy::Fields(fields) => Some(fields),
            VaryCachePolicy::Uncacheable(_) => return,
        };
        let store_key = if let Some(fields) = vary_fields.as_ref() {
            let Some(key) = native_vary_cache_key(key, fields, request) else {
                return;
            };
            key
        } else {
            key.to_owned()
        };
        let needs_prune = {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            if let Some(fields) = vary_fields {
                let variants = state.variants.entry(key.to_owned()).or_default();
                variants.retain(|variant| variant.key != store_key);
                variants.push(NativeMemoryCacheVariant {
                    fields,
                    key: store_key.clone(),
                });
            }
            if let Some(previous) = state.objects.insert(store_key, entry.clone()) {
                state.bytes = state.bytes.saturating_sub(previous.weight);
            }
            state.bytes = state.bytes.saturating_add(entry.weight);
            state.bytes > self.max_bytes
        };
        if needs_prune {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            prune_native_memory_cache(&mut state, self.max_bytes);
        }
    }

    pub(crate) async fn store(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        response: &NativeHttp1Response,
    ) -> Result<(), &'static str> {
        let result = self
            .store_inner(key, request, response, NativeCacheStoreMode::Origin)
            .await;
        if let Err(reason) = result
            && reason != "cache-min-uses"
        {
            self.record_uncacheable(key);
        }
        result
    }

    pub(crate) async fn store_revalidated(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        response: &NativeHttp1Response,
    ) -> Result<(), &'static str> {
        let result = self
            .store_inner(key, request, response, NativeCacheStoreMode::Revalidated)
            .await;
        if let Err(reason) = result
            && reason != "cache-min-uses"
        {
            self.record_uncacheable(key);
        }
        result
    }

    pub(crate) async fn store_not_modified_revalidated(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        entry: &NativeMemoryCacheEntry,
        response: &NativeHttp1Response,
    ) -> Result<NativeMemoryCacheEntry, &'static str> {
        if response.status() != 304 {
            return Err("not-modified-status");
        }
        let headers = native_response_header_map(response);
        let ttl = native_cache_ttl(response.status(), &headers, &self.config)
            .or_else(|| native_cache_ttl(entry.status, &headers, &self.config))
            .ok_or("ttl-missing")?;
        if ttl.is_zero() {
            return Err("ttl-zero");
        }
        let now = std::time::Instant::now();
        let (expires_at, stale_while_revalidate_until, stale_if_error_until) =
            native_cache_expiry_times(
                now,
                ttl,
                self.config.stale_while_revalidate_secs,
                self.config.stale_if_error_secs,
            )
            .ok_or("ttl-overflow")?;
        let mut refreshed = entry.to_response();
        for (name, value) in cached_proxy_headers(response, &self.config) {
            if native_not_modified_refresh_header_skipped(&name) {
                continue;
            }
            refreshed.remove_header(&name);
            refreshed.push_header(name, value);
        }
        let mut refreshed_entry = NativeMemoryCacheEntry {
            status: entry.status,
            reason: entry.reason.clone(),
            headers: cached_proxy_headers(&refreshed, &self.config),
            content_length: refreshed.content_length(),
            body: entry.body.clone(),
            expires_at,
            stale_while_revalidate_until,
            stale_if_error_until,
            stored_at: now,
            weight: native_cache_entry_weight(key, &refreshed, entry.body.len() as u64),
        };
        refreshed_entry.weight =
            native_cache_entry_weight(key, &refreshed, entry.body.len() as u64);
        self.store_inner(
            key,
            request,
            &refreshed_entry.to_response(),
            NativeCacheStoreMode::Revalidated,
        )
        .await?;
        Ok(refreshed_entry)
    }

    pub(crate) async fn store_peer_fill(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        response: &NativeHttp1Response,
    ) -> Result<(), &'static str> {
        let result = self
            .store_inner(key, request, response, NativeCacheStoreMode::PeerFill)
            .await;
        if let Err(reason) = result
            && reason != "cache-min-uses"
        {
            self.record_uncacheable(key);
        }
        result
    }

    async fn store_inner(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        response: &NativeHttp1Response,
        mode: NativeCacheStoreMode,
    ) -> Result<(), &'static str> {
        let body_len = response.body().len() as u64;
        if body_len > self.config.max_object_bytes.as_u64() {
            return Err("object-too-large");
        }
        let headers = native_response_header_map(response);
        let vary_fields = match cache_vary_policy(&headers, &self.config) {
            VaryCachePolicy::None => None,
            VaryCachePolicy::Fields(fields) => Some(fields),
            VaryCachePolicy::Uncacheable(reason) => return Err(reason),
        };
        let range = selected_cache_range_request(request, &self.config);
        if response.status() == 206 {
            if let Some(reason) =
                range_response_cache_admission_rejection(response.status(), &headers, range)
            {
                return Err(reason);
            }
            if let Some(reason) = response_range_cache_admission_rejection(&headers, &self.config) {
                return Err(reason);
            }
        } else {
            if let Some(reason) =
                range_response_cache_admission_rejection(response.status(), &headers, None)
            {
                return Err(reason);
            }
            if let Some(reason) =
                response_cache_admission_rejection(response.status(), &headers, &self.config)
            {
                return Err(reason);
            }
        }
        let ttl = match mode {
            NativeCacheStoreMode::Origin | NativeCacheStoreMode::Revalidated => {
                native_cache_ttl(response.status(), &headers, &self.config)
            }
            NativeCacheStoreMode::PeerFill => {
                native_peer_fill_cache_ttl(response.status(), &headers, &self.config)
            }
        };
        let Some(ttl) = ttl else {
            return Err("ttl-missing");
        };
        if body_len == 0 && !self.config.status_ttls.contains_key(&response.status()) {
            return Err("empty-body");
        }
        if ttl.is_zero() {
            return Err("ttl-zero");
        }
        self.record_cacheable(key);
        if mode == NativeCacheStoreMode::Origin && !self.min_uses_allows_store(key) {
            return Err("cache-min-uses");
        }

        let store_key = if let Some(fields) = vary_fields.as_ref() {
            native_vary_cache_key(key, fields, request).ok_or("vary-invalid")?
        } else {
            key.to_owned()
        };
        let now = std::time::Instant::now();
        let stored_at = if mode == NativeCacheStoreMode::PeerFill {
            now.checked_sub(Duration::from_secs(response_age_secs(&headers)))
                .unwrap_or(now)
        } else {
            now
        };
        let Some((expires_at, stale_while_revalidate_until, stale_if_error_until)) =
            native_cache_expiry_times(
                now,
                ttl,
                self.config.stale_while_revalidate_secs,
                self.config.stale_if_error_secs,
            )
        else {
            return Err("ttl-overflow");
        };
        let weight = native_cache_entry_weight(&store_key, response, body_len);
        if self.memory_enabled() && weight > self.max_bytes {
            return Err("object-too-large");
        }
        let entry = NativeMemoryCacheEntry {
            status: response.status(),
            reason: response.reason().to_owned(),
            headers: cached_proxy_headers(response, &self.config),
            content_length: response.content_length(),
            body: Arc::from(response.body().to_vec()),
            expires_at,
            stale_while_revalidate_until,
            stale_if_error_until,
            stored_at,
            weight,
        };
        let cache_tags = native_response_cache_tags(response, &self.config);
        let disk_key = NativeDiskCacheStoreKey {
            combined: store_key.clone(),
            primary: key.to_owned(),
            user_tag: self.user_tag(),
            index_path: Some(request.path().to_owned()),
            cache_tags: cache_tags.clone(),
            vary_fields: vary_fields.clone().unwrap_or_default(),
        };
        if self.memory_enabled() {
            let needs_prune = {
                let mut state = lock_native_memory_cache(&self.state, "proxy");
                if let Some(fields) = vary_fields {
                    if let Some(previous) = remove_native_memory_cache_entry(&mut state, key) {
                        state.bytes = state.bytes.saturating_sub(previous.weight);
                    }
                    if let Some(previous) = remove_native_memory_cache_entry(&mut state, &store_key)
                    {
                        state.bytes = state.bytes.saturating_sub(previous.weight);
                    }
                    let variants = state.variants.entry(key.to_owned()).or_default();
                    variants.retain(|variant| variant.key != store_key);
                    variants.push(NativeMemoryCacheVariant {
                        fields,
                        key: store_key.clone(),
                    });
                } else {
                    let removed_bytes = remove_native_memory_cache_variants(&mut state, key);
                    state.bytes = state.bytes.saturating_sub(removed_bytes);
                    if let Some(previous) = remove_native_memory_cache_entry(&mut state, &store_key)
                    {
                        state.bytes = state.bytes.saturating_sub(previous.weight);
                    }
                }
                state.purge_index.insert_with_path_and_tags(
                    store_key.clone(),
                    key.to_owned(),
                    self.user_tag(),
                    Some(request.path().to_owned()),
                    cache_tags,
                );
                if let Some(previous) = state.objects.insert(store_key, entry.clone()) {
                    state.bytes = state.bytes.saturating_sub(previous.weight);
                }
                state.bytes = state.bytes.saturating_add(weight);
                state.bytes > self.max_bytes
            };
            if needs_prune {
                let mut state = lock_native_memory_cache(&self.state, "proxy");
                prune_native_memory_cache(&mut state, self.max_bytes);
            }
        }
        if let Some(disk) = &self.disk {
            let disk = Arc::clone(disk);
            let entry = entry.clone();
            match tokio::task::spawn_blocking(move || disk.store(disk_key, &entry)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native disk cache store failed: {error}"
                    );
                }
                Err(error) => {
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "native disk cache store task failed: {error}"
                    );
                }
            }
        }
        Ok(())
    }

    fn cache_pass_should_bypass(&self, key: &str) -> bool {
        (self.config.predictor.enabled || self.config.pass_uncacheable_after > 0) && {
            let mut state = lock_native_memory_cache(&self.state, "proxy");
            prune_native_predictor_counters(&mut state.cache_pass, self.config.predictor.capacity);
            native_predictor_counter_uses(&mut state.cache_pass, key).is_some_and(|uses| {
                self.config.predictor.enabled || uses >= self.config.pass_uncacheable_after.max(1)
            })
        }
    }

    fn record_cacheable(&self, key: &str) {
        let mut state = lock_native_memory_cache(&self.state, "proxy");
        state.cache_pass.remove(key);
    }

    fn record_uncacheable(&self, key: &str) {
        if !self.config.predictor.enabled && self.config.pass_uncacheable_after == 0 {
            return;
        }

        let mut state = lock_native_memory_cache(&self.state, "proxy");
        prune_native_predictor_counters(&mut state.cache_pass, self.config.predictor.capacity);
        let threshold = self.config.pass_uncacheable_after.max(1);
        let uses = native_predictor_counter_uses(&mut state.cache_pass, key)
            .unwrap_or(0)
            .saturating_add(1)
            .min(threshold);
        state.cache_pass.insert(
            key.to_owned(),
            NativeMemoryCacheCounter {
                uses,
                seen_at: std::time::Instant::now(),
            },
        );
    }

    fn min_uses_allows_store(&self, key: &str) -> bool {
        if self.config.min_uses <= 1 {
            return true;
        }

        let mut state = lock_native_memory_cache(&self.state, "proxy");
        prune_native_predictor_counters(&mut state.min_uses, self.config.predictor.capacity);
        let uses = native_predictor_counter_uses(&mut state.min_uses, key)
            .unwrap_or(0)
            .saturating_add(1);
        if uses >= self.config.min_uses {
            state.min_uses.remove(key);
            true
        } else {
            state.min_uses.insert(
                key.to_owned(),
                NativeMemoryCacheCounter {
                    uses,
                    seen_at: std::time::Instant::now(),
                },
            );
            false
        }
    }
}

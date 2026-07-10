use std::sync::Arc;
use std::time::Duration;

use crate::native_http1_cache::{
    NativeDiskCacheStoreKey, NativeMemoryCacheEntry, NativeMemoryCacheVariant,
    lock_native_memory_cache, native_cache_entry_weight, native_cache_ttl,
    native_peer_fill_cache_ttl, native_response_header_map, prune_native_memory_cache,
    remove_native_memory_cache_entry, remove_native_memory_cache_variants,
};
use crate::native_http1_proxy_cache_headers::{
    cached_proxy_headers, native_not_modified_refresh_header_skipped, native_response_cache_tags,
    native_vary_cache_key,
};
use crate::native_http1_proxy_cache_policy::native_cache_expiry_times;
use crate::{NativeHttp1Request, NativeHttp1Response};
use fluxheim_cache::{
    CacheRequestView, VaryCachePolicy, cache_vary_policy, collect_cache_tags,
    range_response_cache_admission_rejection, response_age_secs,
    response_cache_admission_rejection, response_range_cache_admission_rejection,
    selected_cache_range_request,
};

use super::{NativeProxyCacheStoreMetadata, NativeProxyMemoryCache};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeCacheStoreMode {
    Origin,
    Revalidated,
    PeerFill,
}

impl NativeProxyMemoryCache {
    pub(crate) async fn store(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        response: &NativeHttp1Response,
    ) -> Result<(), &'static str> {
        self.store_with_metadata(
            key,
            request,
            response,
            NativeProxyCacheStoreMetadata::default(),
        )
        .await
    }

    pub(crate) async fn store_with_metadata(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        response: &NativeHttp1Response,
        metadata: NativeProxyCacheStoreMetadata,
    ) -> Result<(), &'static str> {
        let result = self
            .store_inner(
                key,
                request,
                response,
                NativeCacheStoreMode::Origin,
                metadata,
            )
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
        self.store_revalidated_with_metadata(
            key,
            request,
            response,
            NativeProxyCacheStoreMetadata::default(),
        )
        .await
    }

    pub(crate) async fn store_revalidated_with_metadata(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        response: &NativeHttp1Response,
        metadata: NativeProxyCacheStoreMetadata,
    ) -> Result<(), &'static str> {
        let result = self
            .store_inner(
                key,
                request,
                response,
                NativeCacheStoreMode::Revalidated,
                metadata,
            )
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
            NativeProxyCacheStoreMetadata::default(),
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
            .store_inner(
                key,
                request,
                response,
                NativeCacheStoreMode::PeerFill,
                NativeProxyCacheStoreMetadata::default(),
            )
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
        metadata: NativeProxyCacheStoreMetadata,
    ) -> Result<(), &'static str> {
        let body_len = response.body().len() as u64;
        if body_len > self.config.max_object_bytes.as_u64() {
            return Err("object-too-large");
        }
        let stored_response;
        let response = if metadata.response_headers.is_empty() {
            response
        } else {
            stored_response = native_cache_store_response_with_metadata(response, &metadata);
            &stored_response
        };
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
            NativeCacheStoreMode::Origin | NativeCacheStoreMode::Revalidated => metadata
                .ttl_override
                .or_else(|| native_cache_ttl(response.status(), &headers, &self.config)),
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
        let mut cache_tags = native_response_cache_tags(response, &self.config);
        let mut cache_tag_bytes = cache_tags.iter().map(String::len).sum();
        for tag in metadata.cache_tags {
            collect_cache_tags(tag, &mut cache_tags, &mut cache_tag_bytes);
        }
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
            let Ok(blocking_permit) = crate::blocking_work::try_acquire_request_blocking_work()
            else {
                return Ok(());
            };
            match tokio::task::spawn_blocking(move || {
                let _blocking_permit = blocking_permit;
                disk.store(disk_key, &entry)
            })
            .await
            {
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
}

fn native_cache_store_response_with_metadata(
    response: &NativeHttp1Response,
    metadata: &NativeProxyCacheStoreMetadata,
) -> NativeHttp1Response {
    let mut response = response.clone();
    for (name, value) in &metadata.response_headers {
        response.remove_header(name);
        response.push_header(*name, *value);
    }
    response
}

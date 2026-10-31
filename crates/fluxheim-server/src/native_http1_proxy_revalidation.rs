use std::sync::atomic::Ordering;

#[cfg(feature = "load-balancer")]
use crate::NativeHttp1Upstream;
use crate::native_http1_cache::{NativeMemoryCacheEntry, lock_native_memory_cache};
use crate::native_http1_proxy::NativeHttp1Proxy;
use crate::native_http1_proxy_cache_headers::native_cache_revalidation_request;
use crate::native_http1_proxy_cache_slice::native_origin_slice_request;
use crate::native_http1_proxy_config::native_http1_static_failover_method_allowed;
use crate::{NativeHttp1Request, NativeHttp1Response};
use fluxheim_cache::CacheSliceBounds;

impl NativeHttp1Proxy {
    pub(crate) fn spawn_cache_revalidation(
        &self,
        cache: crate::native_http1_proxy_memory_cache::NativeProxyMemoryCache,
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
        cache: crate::native_http1_proxy_memory_cache::NativeProxyMemoryCache,
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
        let mut request = native_origin_slice_request(request, bounds)?;
        #[cfg(feature = "load-balancer")]
        if let Some(pool) = &self.load_balancer {
            let client_ip = request
                .effective_client_addr
                .or(request.peer_addr)
                .map(|addr| addr.ip());
            let selected = pool.select_or_wait(&request, client_ip).await?;
            let (_, result) = self
                .send_load_balanced(&mut request, selected, Some(capped_body_bytes))
                .await;
            return result
                .ok()
                .filter(|response| response.body().len() as u64 <= max_body_bytes);
        }
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
            match upstream.send(&mut request).await {
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
            let mut outbound = request.metadata_snapshot();
            match self.upstreams[index].send(&mut outbound).await {
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
        let mut outbound = request.metadata_snapshot();
        self.send_load_balanced(&mut outbound, selected, None)
            .await
            .1
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
            let mut outbound = request.metadata_snapshot();
            match self.upstreams[index].send(&mut outbound).await {
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
    pub(crate) fn upstream_for_authority(&self, authority: &str) -> Option<&NativeHttp1Upstream> {
        self.upstreams
            .iter()
            .find(|upstream| upstream.authority() == authority)
    }

    #[cfg(feature = "load-balancer")]
    pub(crate) fn dynamic_upstream_for_authority(
        &self,
        authority: &str,
    ) -> Option<NativeHttp1Upstream> {
        self.load_balancer_upstream_template
            .clone()
            .map(|upstream| upstream.with_authority(authority.to_owned()))
    }
}

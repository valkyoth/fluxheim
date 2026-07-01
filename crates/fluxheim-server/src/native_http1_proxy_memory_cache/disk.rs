use crate::NativeHttp1Request;
use crate::native_http1_cache::{
    NativeMemoryCacheEntry, NativeMemoryCacheVariant, lock_native_memory_cache,
    native_response_header_map, prune_native_memory_cache,
};
use crate::native_http1_proxy_cache_headers::{
    native_cache_entry_revalidatable, native_vary_cache_key,
};
use crate::native_http1_proxy_cache_policy::native_cache_entry_serve_stale_while_revalidate;
use fluxheim_cache::{VaryCachePolicy, cache_vary_policy};

use super::NativeProxyMemoryCache;

impl NativeProxyMemoryCache {
    pub(super) async fn get_disk_fresh(
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

    pub(super) async fn get_disk_stale_while_revalidate(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let entry = self.disk_entry(key, request).await?;
        native_cache_entry_serve_stale_while_revalidate(&entry, std::time::Instant::now())
            .then_some(entry)
    }

    pub(super) async fn get_disk_stale_if_error(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Option<NativeMemoryCacheEntry> {
        let entry = self.disk_entry(key, request).await?;
        let now = std::time::Instant::now();
        (entry.expires_at <= now && entry.stale_if_error_until.is_some_and(|until| until > now))
            .then_some(entry)
    }

    pub(super) async fn get_disk_revalidatable(
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
}

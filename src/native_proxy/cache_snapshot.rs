use std::io;

use fluxheim_cache::{
    CacheKeyPreview, CacheKeyPreviewScope, CacheObjectHeaderValue, CacheObjectLookup,
    CacheObjectMetadata, CacheObjectTier,
};

#[derive(Clone, Debug)]
pub struct NativeProxySnapshot {
    pub(super) config: crate::config::Config,
}

impl NativeProxySnapshot {
    pub(crate) fn native_image_cache_key_preview_for_request(
        &self,
        request: &fluxheim_cache::NativeCachePreviewRequest,
    ) -> CacheKeyPreview {
        let host = request
            .headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let selected = self
            .config
            .vhosts
            .iter()
            .find(|vhost| super::native_vhost_matches_host(vhost, host))
            .or_else(|| {
                self.config
                    .server
                    .default_vhost
                    .as_deref()
                    .and_then(|name| self.config.vhosts.iter().find(|vhost| vhost.name == name))
            })
            .or_else(|| self.config.vhosts.first());
        let vhost_name = selected
            .map(|vhost| vhost.name.clone())
            .unwrap_or_else(|| host.to_owned());
        let selected_route = selected.and_then(|vhost| {
            super::native_cache_preview_route(
                &vhost.routes,
                request.method.as_str(),
                request.uri.path(),
            )
        });
        let route_cache = selected_route.and_then(|route| route.cache.as_ref());
        let cache_config = route_cache.or_else(|| selected.map(|vhost| &vhost.cache));
        let cache_config = cache_config.unwrap_or(&self.config.cache);
        let memory_tier_enabled = cache_config.memory.enabled;
        let disk_tier_enabled = cache_config.disk.enabled;
        let method_cacheable = cache_config
            .methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(request.method.as_str()));
        let method_temporarily_bypassed =
            fluxheim_cache::cache_method_temporarily_bypassed(request.method.as_str());
        let safe_path = request
            .uri
            .path_and_query()
            .map(|path| fluxheim_common::path_safety::safe_forward_path_and_query(path.as_str()))
            .unwrap_or(false);
        let eligible = selected.is_some()
            && cache_config.enabled
            && !method_temporarily_bypassed
            && method_cacheable
            && safe_path;
        let cache_request = fluxheim_cache::CacheRequest {
            method: request.method.as_str(),
            host: Some(host),
            path: request.uri.path(),
            query: request.uri.query(),
        };
        let key = eligible
            .then(|| fluxheim_cache::image_cache_key(cache_config, &cache_request))
            .flatten();
        let reason = if selected.is_none() {
            Some("no matching vhost".to_owned())
        } else if !cache_config.enabled {
            Some("cache disabled".to_owned())
        } else if method_temporarily_bypassed {
            Some(format!(
                "method {} currently bypasses proxy cache storage",
                request.method
            ))
        } else if !method_cacheable {
            Some(format!("method {} is not cacheable", request.method))
        } else if !safe_path {
            Some("request path is not safe for cache lookup".to_owned())
        } else if key.is_none() {
            Some("path or query is not admitted by selected image cache policy".to_owned())
        } else {
            None
        };
        CacheKeyPreview {
            vhost: vhost_name.clone(),
            route: route_cache.and_then(|_| selected_route.map(|route| route.name.clone())),
            scope: if route_cache.is_some() {
                CacheKeyPreviewScope::Route
            } else {
                CacheKeyPreviewScope::Vhost
            },
            eligible: key.is_some(),
            cache_lock_enabled: cache_config.lock.enabled,
            cache_lock_wait_timeout_secs: cache_config.lock.wait_timeout_secs,
            cache_predictor_enabled: cache_config.predictor.enabled,
            origin_protection_enabled: cache_config.origin_protection.enabled,
            origin_protection_max_concurrent_fills: cache_config
                .origin_protection
                .max_concurrent_fills,
            peer_fill_enabled: cache_config.peer_fill.enabled,
            peer_fill_peer_count: cache_config.peer_fill.peers.len(),
            peer_fill_max_concurrent_requests: cache_config.peer_fill.max_concurrent_requests,
            peer_fill_fail_open: cache_config.peer_fill.fail_open,
            memory_tier_enabled,
            disk_tier_enabled,
            storage_tiers: fluxheim_cache::cache_storage_tiers(
                memory_tier_enabled,
                disk_tier_enabled,
            ),
            reason,
            namespace: key.as_ref().map(|_| "fluxheim-image-v1".to_owned()),
            key_namespace: cache_config.key_namespace.clone(),
            primary_key: key.as_ref().map(|key| key.as_str().to_owned()),
            primary_hash: key.as_ref().map(|key| key.as_str().to_owned()),
            variance_hash: None,
            combined_hash: key.as_ref().map(|key| key.as_str().to_owned()),
            user_tag: key.as_ref().map(|_| {
                route_cache
                    .and_then(|_| {
                        selected_route.map(|route| format!("{vhost_name}:route:{}", route.name))
                    })
                    .unwrap_or(vhost_name)
            }),
        }
    }

    pub(crate) fn native_image_cache_object_lookup_for_request(
        &self,
        request: &fluxheim_cache::NativeCachePreviewRequest,
    ) -> io::Result<CacheObjectLookup> {
        let preview = self.native_image_cache_key_preview_for_request(request);
        let mut objects = Vec::new();
        if let Some(primary_key) = preview.primary_key.as_deref()
            && let Some(vhost) = self
                .config
                .vhosts
                .iter()
                .find(|vhost| vhost.name == preview.vhost)
            && let Some(cache_config) = preview
                .route
                .as_deref()
                .and_then(|route_name| {
                    vhost
                        .routes
                        .iter()
                        .find(|route| route.name == route_name)
                        .and_then(|route| route.cache.as_ref())
                })
                .or(Some(&vhost.cache))
            && let Some(metadata) = fluxheim_server::inspect_native_disk_cache_object(
                &vhost.name,
                preview.route.as_deref(),
                cache_config,
                primary_key,
                &native_cache_lookup_request_headers(request),
            )
        {
            objects.push(native_cache_object_metadata(metadata));
        }
        Ok(CacheObjectLookup { preview, objects })
    }
}

fn native_cache_object_metadata(
    metadata: fluxheim_server::NativeDiskCacheObjectMetadata,
) -> CacheObjectMetadata {
    CacheObjectMetadata {
        tier: CacheObjectTier::Disk,
        purge_indexed: true,
        status: metadata.status,
        fresh: metadata.fresh,
        freshness_state: metadata.freshness_state,
        serve_stale_while_revalidate: metadata.serve_stale_while_revalidate,
        serve_stale_if_error: metadata.serve_stale_if_error,
        body_bytes: metadata.body_bytes,
        weight_bytes: metadata.weight_bytes,
        created_unix_secs: metadata.created_unix_secs,
        updated_unix_secs: metadata.updated_unix_secs,
        fresh_until_unix_secs: metadata.fresh_until_unix_secs,
        age_secs: metadata.age_secs,
        fresh_ttl_secs: metadata.fresh_ttl_secs,
        stale_while_revalidate_secs: metadata.stale_while_revalidate_secs,
        stale_if_error_secs: metadata.stale_if_error_secs,
        cache_tags: metadata.cache_tags,
        header_names: metadata.header_names,
        header_values: metadata
            .header_values
            .into_iter()
            .map(|(name, value)| CacheObjectHeaderValue { name, value })
            .collect(),
    }
}

fn native_cache_lookup_request_headers(
    request: &fluxheim_cache::NativeCachePreviewRequest,
) -> Vec<(String, String)> {
    request
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

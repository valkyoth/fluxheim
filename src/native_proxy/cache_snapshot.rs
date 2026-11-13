use std::io;

use fluxheim_cache::{
    CacheKeyPreview, CacheObjectHeaderValue, CacheObjectLookup, CacheObjectMetadata,
    CacheObjectTier,
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
        let selection = super::cache_selection::PreviewSelection::new(&self.config, request);
        let vhost_name = selection.vhost.map_or_else(String::new, |v| v.name.clone());
        let disabled = crate::config::CacheConfig {
            enabled: false,
            ..Default::default()
        };
        let cache_config = selection.cache.unwrap_or(&disabled);
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
        let bypass = fluxheim_cache::request_cache_bypass_reason(request, cache_config);
        let supported = selection.proxy.is_some_and(|proxy| {
            proxy.has_configured_upstream()
                && fluxheim_server::NativeHttp1Proxy::proxy_cache_supported_for_proxy(
                    cache_config,
                    proxy,
                )
        });
        let rewritten = selection.route.is_some_and(|route| {
            route.strip_prefix.is_some()
                || route.rewrite_prefix.is_some()
                || route.rewrite_template.is_some()
        });
        let eligible = (selection.root || selection.vhost.is_some())
            && cache_config.enabled
            && !method_temporarily_bypassed
            && method_cacheable
            && safe_path
            && supported
            && !rewritten
            && bypass.is_none();
        let cache_request = fluxheim_cache::CacheRequest {
            method: request.method.as_str(),
            host: Some(host),
            path: request.uri.path(),
            query: request.uri.query(),
        };
        let representation = fluxheim_server::native_cache_representation(&self.config).ok();
        let scoped_cache = representation.as_ref().map(|identity| {
            fluxheim_server::native_representation_cache_config(
                cache_config,
                identity,
                selection.runtime_identity(),
                selection.route.map(|route| route.name.as_str()),
            )
        });
        let key = eligible
            .then(|| {
                scoped_cache
                    .as_ref()
                    .and_then(|cache| fluxheim_cache::image_cache_key(cache, &cache_request))
            })
            .flatten();
        let reason = if !selection.root && selection.vhost.is_none() {
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
        } else if !supported {
            Some("selected action has no supported proxy cache".to_owned())
        } else if rewritten {
            Some("offline preview does not support rewritten routes".to_owned())
        } else if let Some(reason) = bypass {
            Some(reason.to_owned())
        } else if representation.is_none() {
            Some("cache representation identity could not be established".to_owned())
        } else if key.is_none() {
            Some("path or query is not admitted by selected image cache policy".to_owned())
        } else {
            None
        };
        CacheKeyPreview {
            vhost: vhost_name.clone(),
            route: selection.route.map(|route| route.name.clone()),
            scope: selection.scope(),
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
                selection
                    .route
                    .map(|route| format!("{vhost_name}:route:{}", route.name))
                    .unwrap_or_else(|| selection.runtime_identity().to_owned())
            }),
        }
    }

    pub(crate) fn native_image_cache_object_lookup_for_request(
        &self,
        request: &fluxheim_cache::NativeCachePreviewRequest,
    ) -> io::Result<CacheObjectLookup> {
        let preview = self.native_image_cache_key_preview_for_request(request);
        let selection = super::cache_selection::PreviewSelection::new(&self.config, request);
        let mut objects = Vec::new();
        if let Some(primary_key) = preview.primary_key.as_deref()
            && let Some(cache_config) = selection.cache.filter(|cache| cache.disk.enabled)
        {
            if cache_config.disk.backend == crate::config::CacheDiskBackend::StorageBin {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "standalone storage-bin lookup is unsupported; it cannot share the serving process's allocator",
                ));
            }
            if let Some(metadata) = fluxheim_server::inspect_native_disk_cache_object(
                selection.runtime_identity(),
                preview.route.as_deref(),
                cache_config,
                primary_key,
                &native_cache_lookup_request_headers(request),
            ) {
                objects.push(native_cache_object_metadata(metadata));
            }
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

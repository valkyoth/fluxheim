use std::collections::HashMap;

use fluxheim_config::{CacheConfig, CacheDiskBackend, Config};

use super::NativeHttp1HostRouterConfigError;

pub(super) fn validate_unique_storage_bin_roots(
    config: &Config,
) -> Result<(), NativeHttp1HostRouterConfigError> {
    let mut policies = Vec::new();
    if config.vhosts.is_empty() {
        policies.push(("cache".to_owned(), &config.cache));
    } else {
        for vhost in &config.vhosts {
            policies.push((format!("vhost {:?} cache", vhost.name), &vhost.cache));
            for route in &vhost.routes {
                if let Some(cache) = route.cache.as_ref() {
                    policies.push((
                        format!("vhost {:?} route {:?} cache", vhost.name, route.name),
                        cache,
                    ));
                }
            }
        }
    }

    let mut roots = HashMap::new();
    for (scope, cache) in policies {
        if !storage_bin_policy_enabled(cache) {
            continue;
        }
        crate::native_http1_cache::ensure_native_storage_bin_index_service().map_err(|error| {
            NativeHttp1HostRouterConfigError::StorageBinRoot {
                scope: scope.clone(),
                reason: error.to_string(),
            }
        })?;
        let layout = crate::native_http1_cache::prepare_native_storage_bin_layout(cache).map_err(
            |error| NativeHttp1HostRouterConfigError::StorageBinRoot {
                scope: scope.clone(),
                reason: error.to_string(),
            },
        )?;
        if let Some(first_scope) = roots.insert(layout.root.clone(), scope.clone()) {
            return Err(NativeHttp1HostRouterConfigError::DuplicateStorageBinRoot {
                path: layout.root.display().to_string(),
                first_scope,
                second_scope: scope,
            });
        }
    }
    Ok(())
}

fn storage_bin_policy_enabled(cache: &CacheConfig) -> bool {
    cache.enabled && cache.disk.enabled && cache.disk.backend == CacheDiskBackend::StorageBin
}

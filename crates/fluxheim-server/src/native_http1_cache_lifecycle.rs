use std::sync::{Arc, Mutex, Weak};

use fluxheim_config::CacheConfig;

use crate::NativeHttp1ProxyConfigError;
use crate::native_http1_cache::NativeDiskCache;
use crate::native_http1_cache::prepare_native_disk_cache_root;

struct SharedDiskCache {
    policy: CacheConfig,
    vhost: String,
    route: Option<String>,
    cache: Weak<NativeDiskCache>,
}

static DISK_CACHES: Mutex<Vec<SharedDiskCache>> = Mutex::new(Vec::new());
const MAX_LIVE_DISK_CACHES: usize = 4096;

pub(crate) fn shared_disk_cache(
    config: &CacheConfig,
    vhost: &str,
    route: Option<&str>,
) -> Result<Option<Arc<NativeDiskCache>>, NativeHttp1ProxyConfigError> {
    if !config.disk.enabled {
        return Ok(None);
    }
    let initialization = || NativeHttp1ProxyConfigError::CacheInitialization;
    let path = config.disk.path.as_deref().ok_or_else(initialization)?;
    let root = prepare_native_disk_cache_root(path).map_err(|_| initialization())?;
    let mut policy = config.clone();
    policy.disk.path = Some(root);
    // Presentation-only changes do not alter persisted objects or allocator state.
    policy.status_header = None;
    policy.status_reason_header = None;

    // Serialize initialization, not requests. Weak entries never prolong a lease.
    let mut caches = DISK_CACHES.lock().map_err(|_| initialization())?;
    caches.retain(|entry| entry.cache.strong_count() > 0);
    for entry in caches.iter() {
        if entry.policy.disk.path != policy.disk.path {
            continue;
        }
        if let Some(cache) = entry.cache.upgrade() {
            if entry.policy != policy
                || entry.vhost != vhost
                || entry.route.as_deref() != route
                || config.disk.encryption.enabled
            {
                return Err(NativeHttp1ProxyConfigError::CacheRestartRequired);
            }
            return Ok(Some(cache));
        }
    }
    if caches.len() >= MAX_LIVE_DISK_CACHES {
        return Err(initialization());
    }
    let cache = Arc::new(
        NativeDiskCache::try_from_config(&policy)
            .map_err(|_| initialization())?
            .ok_or_else(initialization)?,
    );
    caches.push(SharedDiskCache {
        policy,
        vhost: vhost.to_owned(),
        route: route.map(str::to_owned),
        cache: Arc::downgrade(&cache),
    });
    Ok(Some(cache))
}

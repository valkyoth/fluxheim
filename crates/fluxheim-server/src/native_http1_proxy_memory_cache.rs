use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::native_http1_cache::{
    NativeDiskCache, NativeMemoryCacheCounter, NativeMemoryCacheEntry, NativeMemoryCacheFill,
    NativeMemoryCacheState, lock_native_memory_cache, register_native_disk_cache_purge_handle,
};
use crate::native_http1_proxy::NativeHttp1Proxy;
use crate::native_http1_proxy_cache_fill::{
    NativeCacheFillGate, NativeCacheFillPermit, NativeCacheFillWaitBudget, NativeCacheFillWaiter,
    NativeOriginFillPermit, acquire_native_origin_fill_permit,
};
use crate::native_http1_proxy_cache_policy::{
    native_predictor_counter_uses, prune_native_predictor_counters,
};
use crate::native_http1_proxy_metrics::{
    record_native_cache_activity, record_native_cache_activity_scope,
    record_native_cache_operation_duration,
};
use crate::native_http1_proxy_peer_fill::{NativePeerFillPeer, native_peer_fill_peers};
use crate::native_http1_proxy_peer_fill_auth::{
    NativePeerFillAuth, native_peer_fill_auth_from_config,
};
use crate::native_http1_proxy_runtime::{
    register_native_cache_stats_handle, register_native_memory_cache_purge_handle,
};
use crate::{NativeHttp1Request, NativeHttp1Response};
use fluxheim_cache::CacheRangeRequest;
use fluxheim_config::CacheConfig;
use tokio::sync::Notify;

mod disk;
mod lookup;
mod peer_fill;
mod slice;
mod store;

static NATIVE_PROXY_CACHE_ID: AtomicUsize = AtomicUsize::new(0);

fn native_cache_fill_wait_timeout(
    configured_wait: Duration,
    writer_age: Duration,
    writer_age_timeout: Duration,
) -> Duration {
    configured_wait.min(writer_age_timeout.saturating_sub(writer_age))
}

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
    Unavailable(&'static str),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeProxyCacheKeyComponent {
    pub(crate) label: &'static str,
    pub(crate) value: &'static str,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeProxyCacheStoreMetadata {
    pub(crate) ttl_override: Option<Duration>,
    pub(crate) cache_tags: Vec<&'static str>,
    pub(crate) response_headers: Vec<(&'static str, &'static str)>,
}

#[derive(Debug)]
pub(crate) enum NativePeerFillDecision {
    Skip,
    Hit(NativeHttp1Response),
    FailClosed(&'static str),
}

#[derive(Debug)]
pub(crate) enum NativeCacheFillWaitResult {
    Hit(NativeMemoryCacheEntry),
    Miss,
    TimedOut,
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
            let fill_age = now.saturating_duration_since(fill.started_at);
            if fill_age < age_timeout {
                let wait_timeout = native_cache_fill_wait_timeout(
                    Duration::from_secs(self.config.lock.wait_timeout_secs),
                    fill_age,
                    age_timeout,
                );
                return NativeCacheFillGate::Waiter(NativeCacheFillWaiter::new(
                    fill.notify.clone(),
                    wait_timeout,
                ));
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
        waiter: NativeCacheFillWaiter,
        budget: &mut NativeCacheFillWaitBudget,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Result<NativeCacheFillWaitResult, self::disk::NativeDiskCacheLookupError> {
        if !budget.wait(waiter).await {
            return Ok(NativeCacheFillWaitResult::TimedOut);
        }
        Ok(match self.get(key, request).await? {
            Some(entry) => NativeCacheFillWaitResult::Hit(entry),
            None => NativeCacheFillWaitResult::Miss,
        })
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

#[cfg(test)]
mod tests {
    use super::native_cache_fill_wait_timeout;
    use std::time::Duration;

    #[test]
    fn cache_fill_wait_timeout_cannot_outlive_writer_age() {
        assert_eq!(
            native_cache_fill_wait_timeout(
                Duration::from_secs(30),
                Duration::from_secs(29),
                Duration::from_secs(30),
            ),
            Duration::from_secs(1)
        );
        assert_eq!(
            native_cache_fill_wait_timeout(
                Duration::from_secs(5),
                Duration::from_secs(1),
                Duration::from_secs(30),
            ),
            Duration::from_secs(5)
        );
    }
}

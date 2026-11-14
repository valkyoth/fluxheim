use crate::NativeHttp1Request;
use crate::native_http1_cache::{
    NativeMemoryCacheEntry, NativeMemoryCacheVariant, lock_native_memory_cache,
    native_response_header_map, prune_native_memory_cache,
};
use crate::native_http1_proxy_cache_headers::native_vary_cache_key;
use fluxheim_cache::{VaryCachePolicy, cache_vary_policy};

use super::NativeProxyMemoryCache;

pub(super) async fn bounded_disk_lookup<T: Send + 'static>(
    lookup: impl Fn() -> std::io::Result<Option<T>> + Send + Sync + 'static,
) -> Result<Option<T>, NativeDiskCacheLookupError> {
    let lookup = std::sync::Arc::new(lookup);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(250);
    for attempt in 0..=10 {
        if attempt > 0 && tokio::time::Instant::now() >= deadline {
            return Err(NativeDiskCacheLookupError::Saturated);
        }
        let permit = crate::blocking_work::try_acquire_request_blocking_work(
            crate::blocking_work::NativeBlockingWorkClass::DiskCache,
        )
        .map_err(|_| NativeDiskCacheLookupError::Saturated)?;
        let read = std::sync::Arc::clone(&lookup);
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            read()
        })
        .await
        .map_err(|_| NativeDiskCacheLookupError::WorkerFailed)?;
        match result {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && attempt < 10 => {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(NativeDiskCacheLookupError::Saturated);
                }
                // Neither a bin handle nor a blocking-work permit is retained
                // during this bounded async delay. Cancellation drops the wait.
                tokio::time::sleep(remaining.min(std::time::Duration::from_millis(25))).await;
            }
            result => return result.map_err(NativeDiskCacheLookupError::from_io),
        }
    }
    Err(NativeDiskCacheLookupError::Saturated)
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn transient_busy_retries_and_permanent_busy_is_bounded() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        assert_eq!(
            bounded_disk_lookup(move || {
                if observed.fetch_add(1, Ordering::SeqCst) < 2 {
                    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
                } else {
                    Ok(Some(42))
                }
            })
            .await,
            Ok(Some(42))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        calls.store(0, Ordering::SeqCst);
        let observed = Arc::clone(&calls);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            bounded_disk_lookup::<()>(move || {
                observed.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            }),
        )
        .await
        .unwrap();
        assert_eq!(result, Err(NativeDiskCacheLookupError::Saturated));
        assert!((1..=11).contains(&calls.load(Ordering::SeqCst)));
    }

    #[tokio::test]
    async fn cancellation_stops_async_retries_and_other_errors_do_not_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let task = tokio::spawn(bounded_disk_lookup::<()>(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        }));
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        calls.store(0, Ordering::SeqCst);
        let observed = Arc::clone(&calls);
        assert_eq!(
            bounded_disk_lookup::<()>(move || {
                observed.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::other("fixture"))
            })
            .await,
            Err(NativeDiskCacheLookupError::WorkerFailed)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeDiskCacheLookupError {
    Saturated,
    WorkerFailed,
}

impl NativeDiskCacheLookupError {
    pub(super) fn from_io(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            Self::Saturated
        } else {
            Self::WorkerFailed
        }
    }

    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Saturated => "disk-cache-saturated",
            Self::WorkerFailed => "disk-cache-worker-failed",
        }
    }
}

impl NativeProxyMemoryCache {
    pub(super) async fn get_disk_fresh(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Result<Option<NativeMemoryCacheEntry>, NativeDiskCacheLookupError> {
        Ok(self.fresh_disk_entry(key, request, self.disk_entry(key, request).await?))
    }

    pub(super) fn fresh_disk_entry(
        &self,
        key: &str,
        request: &NativeHttp1Request,
        entry: Option<NativeMemoryCacheEntry>,
    ) -> Option<NativeMemoryCacheEntry> {
        let entry = entry?;
        (entry.expires_at > std::time::Instant::now()).then(|| {
            self.record_activity("disk", "hit");
            self.record_activity_scope("disk", "hit");
            self.promote_disk_entry(key, request, &entry);
            entry
        })
    }

    pub(super) async fn get_disk_stale_if_error(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Result<Option<NativeMemoryCacheEntry>, NativeDiskCacheLookupError> {
        let Some(entry) = self.disk_entry(key, request).await? else {
            return Ok(None);
        };
        let now = std::time::Instant::now();
        Ok((!entry.stale_reuse_forbidden
            && entry.expires_at <= now
            && entry.stale_if_error_until.is_some_and(|until| until > now))
        .then_some(entry))
    }

    pub(super) async fn disk_entry(
        &self,
        key: &str,
        request: &NativeHttp1Request,
    ) -> Result<Option<NativeMemoryCacheEntry>, NativeDiskCacheLookupError> {
        let Some(disk) = self.disk.as_ref().cloned() else {
            return Ok(None);
        };
        let key = key.to_owned();
        let request = request.metadata_snapshot();
        let result = bounded_disk_lookup(move || {
            disk.lookup(&key, |fields| native_vary_cache_key(&key, fields, &request))
        })
        .await;
        match result {
            Err(NativeDiskCacheLookupError::Saturated) => {
                fluxheim_observability::operational::security(
                    fluxheim_observability::event::SecurityReason::AdmissionRejected,
                );
            }
            Err(NativeDiskCacheLookupError::WorkerFailed) => {
                fluxheim_observability::operational::failure(
                    fluxheim_observability::event::FailureReason::CacheRead,
                );
                log::debug!(
                    target: "fluxheim::native_http1",
                    "native disk cache lookup worker failed"
                );
            }
            Ok(_) => {}
        }
        result
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

use super::*;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
const PLANNING_BUDGET: Duration = Duration::from_secs(30);
const LOOKUP_CONCURRENCY: usize = 4;
const MAX_CACHE_ENTRIES: usize = 4096;

#[derive(Clone, Copy)]
struct AriCacheEntry {
    scheduled_unix_secs: Option<u64>,
    refresh_after: SystemTime,
}

static CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, AriCacheEntry>>,
> = std::sync::OnceLock::new();

pub(super) async fn execute_due_queue(
    config: &Config,
    queue: &[AcmeRenewalItem],
    now: SystemTime,
) -> Result<AcmeRenewalRun, AcmeRenewalError> {
    let started = std::time::Instant::now();
    let mut run = AcmeRenewalRun {
        attempted: 0,
        renewed: Vec::new(),
        failed: Vec::new(),
    };
    for chunk in queue.chunks(LOOKUP_CONCURRENCY) {
        let decisions = if started.elapsed() >= PLANNING_BUDGET {
            chunk.iter().map(|item| item.due_now).collect::<Vec<_>>()
        } else {
            futures::future::join_all(chunk.iter().map(|item| async move {
                if item.not_after.is_none() {
                    true
                } else {
                    allows_renewal_now_bounded(config, item, now).await
                }
            }))
            .await
        };
        for (item, should_renew) in chunk.iter().zip(decisions) {
            if should_renew {
                acme_instant::execute_instant_acme_item(config, item, &mut run).await;
            }
        }
    }
    Ok(run)
}

pub(super) async fn allows_renewal_now_bounded(
    config: &Config,
    item: &AcmeRenewalItem,
    now: SystemTime,
) -> bool {
    tokio::time::timeout(LOOKUP_TIMEOUT, allows_renewal_now(config, item, now))
        .await
        .unwrap_or(item.due_now)
}

async fn allows_renewal_now(config: &Config, item: &AcmeRenewalItem, now: SystemTime) -> bool {
    let fallback = item.due_now;
    let Some(storage) = config.tls.acme.storage.as_deref() else {
        return fallback;
    };
    let Ok(Some(credentials)) = load_account_credentials(storage, &item.target.issuer) else {
        return fallback;
    };
    let Some(issuer) = config
        .tls
        .acme
        .issuers
        .iter()
        .find(|issuer| issuer.name == item.target.issuer)
    else {
        return fallback;
    };
    let Ok(Some(certificate_pem)) =
        read_bounded_certificate_file(&item.target.certificate.cert_path)
    else {
        return fallback;
    };
    use rustls::pki_types::pem::PemObject as _;
    let Some(Ok(leaf)) = rustls::pki_types::CertificateDer::pem_slice_iter(&certificate_pem).next()
    else {
        return fallback;
    };
    let Ok(identifier) = instant_acme::CertificateIdentifier::try_from(&leaf) else {
        return fallback;
    };
    let cache_key = identifier.to_string();
    if let Some(decision) = cached_decision(&cache_key, now, fallback) {
        return decision;
    }
    let Ok(builder) = bounded_acme_account_builder(issuer) else {
        return fallback;
    };
    let Ok(Ok(account)) = tokio::time::timeout(
        ACME_ACCOUNT_OPERATION_TIMEOUT,
        builder.from_credentials(credentials),
    )
    .await
    else {
        return fallback;
    };
    let renewal_info = tokio::time::timeout(
        ACME_ACCOUNT_OPERATION_TIMEOUT,
        account.renewal_info(&identifier),
    )
    .await;
    let (info, retry_after) = match renewal_info {
        Ok(Ok(result)) => result,
        Ok(Err(instant_acme::Error::Unsupported(_))) => {
            store_cache(&cache_key, None, now, Duration::from_secs(3600));
            return fallback;
        }
        Ok(Err(error)) => {
            log::warn!(
                target: "fluxheim::acme",
                "ACME ARI lookup failed for vhost {}: {error}; using configured renewal window",
                item.target.vhost_name
            );
            return fallback;
        }
        Err(_) => {
            log::warn!(
                target: "fluxheim::acme",
                "ACME ARI lookup timed out for vhost {}; using configured renewal window",
                item.target.vhost_name
            );
            return fallback;
        }
    };
    let start = info.suggested_window.start.unix_timestamp();
    let end = info.suggested_window.end.unix_timestamp();
    if end <= start {
        return fallback;
    }
    let scheduled = deterministic_renewal_time(leaf.as_ref(), start, end).max(0) as u64;
    store_cache(&cache_key, Some(scheduled), now, retry_after);
    unix_secs(now) >= scheduled
}

fn cached_decision(key: &str, now: SystemTime, fallback: bool) -> Option<bool> {
    let cache = CACHE.get_or_init(Default::default);
    let mut cache = cache.lock().unwrap_or_else(|_| {
        log::error!(target: "fluxheim::security", "ACME ARI cache lock poisoned");
        std::process::abort();
    });
    cache.retain(|_, entry| entry.refresh_after > now);
    cache.get(key).map(|entry| {
        entry
            .scheduled_unix_secs
            .map_or(fallback, |due| unix_secs(now) >= due)
    })
}

fn store_cache(key: &str, scheduled: Option<u64>, now: SystemTime, retry_after: Duration) {
    let cache = CACHE.get_or_init(Default::default);
    let mut cache = cache.lock().unwrap_or_else(|_| {
        log::error!(target: "fluxheim::security", "ACME ARI cache lock poisoned");
        std::process::abort();
    });
    cache.retain(|_, entry| entry.refresh_after > now);
    if cache.len() >= MAX_CACHE_ENTRIES && !cache.contains_key(key) {
        cache.clear();
    }
    cache.insert(
        key.to_owned(),
        AriCacheEntry {
            scheduled_unix_secs: scheduled,
            refresh_after: now
                + retry_after.clamp(Duration::from_secs(60), Duration::from_secs(86_400)),
        },
    );
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn deterministic_renewal_time(certificate_der: &[u8], start: i64, end: i64) -> i64 {
    if end <= start {
        return start;
    }
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(certificate_der);
    let mut seed = [0_u8; 8];
    seed.copy_from_slice(&digest[..8]);
    start.saturating_add((u64::from_be_bytes(seed) % (end - start) as u64) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_is_stable_and_inside_suggested_window() {
        let first = deterministic_renewal_time(b"certificate", 100, 200);
        assert_eq!(first, deterministic_renewal_time(b"certificate", 100, 200));
        assert!((100..200).contains(&first));
        assert_eq!(deterministic_renewal_time(b"certificate", 50, 50), 50);
    }

    #[test]
    fn cache_honors_retry_after_and_schedule() {
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        store_cache(
            "test-cache-key",
            Some(10_100),
            now,
            Duration::from_secs(300),
        );
        assert_eq!(cached_decision("test-cache-key", now, true), Some(false));
        assert_eq!(
            cached_decision("test-cache-key", now + Duration::from_secs(100), false),
            Some(true)
        );
        assert_eq!(
            cached_decision("test-cache-key", now + Duration::from_secs(301), false),
            None
        );
    }

    #[test]
    fn planning_limits_are_bounded() {
        assert_eq!(LOOKUP_CONCURRENCY, 4);
        assert!(LOOKUP_TIMEOUT <= Duration::from_secs(10));
        assert!(PLANNING_BUDGET <= Duration::from_secs(30));
    }
}

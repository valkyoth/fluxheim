use super::*;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
const PLANNING_BUDGET: Duration = Duration::from_secs(30);
const LOOKUP_CONCURRENCY: usize = 4;
const MAX_CACHE_ENTRIES: usize = 4096;
const EMERGENCY_RENEWAL_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AriCacheKey {
    issuer_directory: String,
    certificate_identifier: String,
}

#[derive(Clone, Copy)]
struct AriCacheEntry {
    scheduled_unix_secs: Option<u64>,
    refresh_after: SystemTime,
}

type AriCache = std::collections::HashMap<AriCacheKey, AriCacheEntry>;

static CACHE: std::sync::OnceLock<std::sync::Mutex<AriCache>> = std::sync::OnceLock::new();

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
    if emergency_renewal_required(item.not_after, now) {
        return true;
    }
    let cache_key = AriCacheKey {
        issuer_directory: issuer.directory_url.clone(),
        certificate_identifier: identifier.to_string(),
    };
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
    let Some(scheduled) = safe_ari_schedule(item.not_after, leaf.as_ref(), start, end) else {
        log::warn!(
            target: "fluxheim::security",
            "issuer {} returned an ACME ARI window outside certificate validity for vhost {}",
            item.target.issuer,
            item.target.vhost_name
        );
        return fallback;
    };
    store_cache(&cache_key, Some(scheduled), now, retry_after);
    unix_secs(now) >= scheduled
}

fn emergency_renewal_required(not_after: Option<SystemTime>, now: SystemTime) -> bool {
    let Some(emergency_deadline) = now.checked_add(EMERGENCY_RENEWAL_WINDOW) else {
        return true;
    };
    not_after.is_none_or(|not_after| not_after <= emergency_deadline)
}

fn safe_ari_schedule(
    not_after: Option<SystemTime>,
    certificate_der: &[u8],
    start: i64,
    end: i64,
) -> Option<u64> {
    let not_after = not_after?.duration_since(UNIX_EPOCH).ok()?.as_secs();
    if start < 0 || end <= start || end as u64 > not_after {
        return None;
    }
    Some(deterministic_renewal_time(certificate_der, start, end) as u64)
}

fn cached_decision(key: &AriCacheKey, now: SystemTime, fallback: bool) -> Option<bool> {
    let mut cache = lock_cache();
    cache.retain(|_, entry| entry.refresh_after > now);
    cache.get(key).map(|entry| {
        entry
            .scheduled_unix_secs
            .map_or(fallback, |due| unix_secs(now) >= due)
    })
}

fn store_cache(key: &AriCacheKey, scheduled: Option<u64>, now: SystemTime, retry_after: Duration) {
    let refresh_after = cache_refresh_after(now, retry_after);
    let mut cache = lock_cache();
    cache.retain(|_, entry| entry.refresh_after > now);
    if cache.len() >= MAX_CACHE_ENTRIES && !cache.contains_key(key) {
        cache.clear();
    }
    cache.insert(
        key.clone(),
        AriCacheEntry {
            scheduled_unix_secs: scheduled,
            refresh_after,
        },
    );
}

fn cache_refresh_after(now: SystemTime, retry_after: Duration) -> SystemTime {
    now.checked_add(retry_after.clamp(Duration::from_secs(60), Duration::from_secs(86_400)))
        .unwrap_or(now)
}

fn lock_cache() -> std::sync::MutexGuard<'static, AriCache> {
    let cache = CACHE.get_or_init(Default::default);
    match cache.lock() {
        Ok(cache) => cache,
        Err(poisoned) => {
            log::error!(
                target: "fluxheim::security",
                "ACME ARI advisory cache lock poisoned; discarding cached decisions"
            );
            let mut recovered = poisoned.into_inner();
            recovered.clear();
            cache.clear_poison();
            recovered
        }
    }
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

    static CACHE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn schedule_is_stable_and_inside_suggested_window() {
        let first = deterministic_renewal_time(b"certificate", 100, 200);
        assert_eq!(first, deterministic_renewal_time(b"certificate", 100, 200));
        assert!((100..200).contains(&first));
        assert_eq!(deterministic_renewal_time(b"certificate", 50, 50), 50);
    }

    #[test]
    fn cache_honors_retry_after_and_schedule() {
        let _test_lock = CACHE_TEST_LOCK.lock().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(10_000);
        let key = AriCacheKey {
            issuer_directory: "https://issuer.example/directory".to_owned(),
            certificate_identifier: "identifier".to_owned(),
        };
        store_cache(&key, Some(10_100), now, Duration::from_secs(300));
        assert_eq!(cached_decision(&key, now, true), Some(false));
        assert_eq!(
            cached_decision(&key, now + Duration::from_secs(100), false),
            Some(true)
        );
        assert_eq!(
            cached_decision(&key, now + Duration::from_secs(301), false),
            None
        );
    }

    #[test]
    fn cache_is_namespaced_by_issuer_directory() {
        let _test_lock = CACHE_TEST_LOCK.lock().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(20_000);
        let first = AriCacheKey {
            issuer_directory: "https://first.example/directory".to_owned(),
            certificate_identifier: "same-aki-and-serial".to_owned(),
        };
        let second = AriCacheKey {
            issuer_directory: "https://second.example/directory".to_owned(),
            certificate_identifier: "same-aki-and-serial".to_owned(),
        };
        store_cache(&first, Some(20_100), now, Duration::from_secs(300));
        store_cache(&second, Some(19_900), now, Duration::from_secs(300));

        assert_eq!(cached_decision(&first, now, true), Some(false));
        assert_eq!(cached_decision(&second, now, false), Some(true));
    }

    #[test]
    fn cache_refresh_deadline_overflow_expires_immediately() {
        let near_limit = UNIX_EPOCH
            .checked_add(Duration::from_secs(i64::MAX as u64))
            .unwrap();
        assert_eq!(
            cache_refresh_after(near_limit, Duration::from_secs(86_400)),
            near_limit
        );
    }

    #[test]
    fn poisoned_advisory_cache_is_cleared_and_recovers() {
        let _test_lock = CACHE_TEST_LOCK.lock().unwrap();
        let cache = CACHE.get_or_init(Default::default);
        let poisoned = std::panic::catch_unwind(|| {
            let _cache = cache.lock().unwrap();
            panic!("poison ARI cache for recovery test");
        });
        assert!(poisoned.is_err());
        assert!(cache.is_poisoned());

        let now = UNIX_EPOCH + Duration::from_secs(25_000);
        let key = AriCacheKey {
            issuer_directory: "https://issuer.example/directory".to_owned(),
            certificate_identifier: "recovered-identifier".to_owned(),
        };
        store_cache(&key, Some(25_100), now, Duration::from_secs(300));

        assert!(!cache.is_poisoned());
        assert_eq!(cached_decision(&key, now, true), Some(false));
    }

    #[test]
    fn ari_window_must_end_within_certificate_validity() {
        let not_after = UNIX_EPOCH + Duration::from_secs(30_000);
        assert_eq!(
            safe_ari_schedule(Some(not_after), b"certificate", 29_000, 30_001),
            None
        );
        assert!(safe_ari_schedule(Some(not_after), b"certificate", 29_000, 30_000).is_some());
    }

    #[test]
    fn expired_and_emergency_window_certificates_renew_immediately() {
        let now = UNIX_EPOCH + Duration::from_secs(40_000);
        assert!(emergency_renewal_required(
            Some(now - Duration::from_secs(1)),
            now
        ));
        assert!(emergency_renewal_required(
            Some(now + EMERGENCY_RENEWAL_WINDOW),
            now
        ));
        assert!(!emergency_renewal_required(
            Some(now + EMERGENCY_RENEWAL_WINDOW + Duration::from_secs(1)),
            now
        ));
    }

    #[test]
    fn planning_limits_are_bounded() {
        assert_eq!(LOOKUP_CONCURRENCY, 4);
        assert!(LOOKUP_TIMEOUT <= Duration::from_secs(10));
        assert!(PLANNING_BUDGET <= Duration::from_secs(30));
    }
}

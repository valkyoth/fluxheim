use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::thread;

use openssl::ssl::Ssl;

use super::*;

#[test]
fn retained_connection_blocks_third_generation_until_lease_is_released() {
    let (config, selector, certificate) = openssl_sni_test_config();
    let store = OpenSslDownstreamCertificateStore::new(&selector, &config.tls, None).unwrap();
    let acceptor = build_openssl_downstream_acceptor(&config.tls, &certificate).unwrap();
    let mut retained_ssl = Ssl::new(acceptor.context()).unwrap();
    store
        .apply_certificate_for_sni(None, &mut retained_ssl)
        .unwrap();
    store.reload().unwrap();
    assert!(poll_connection_drain_once(&retained_ssl).is_pending());
    assert!(matches!(
        store.reload(),
        Err(
            OpenSslDownstreamCertificateStoreError::TooManyLiveGenerations {
                count: 2,
                maximum: OPENSSL_RELOAD_POLICY_GENERATIONS,
            }
        )
    ));
    assert!(poll_connection_drain_once(&retained_ssl).is_ready());

    drop(retained_ssl);
    store.reload().unwrap();
}

#[test]
fn bounded_reload_retry_completes_after_drained_generation_is_released() {
    let (config, selector, certificate) = openssl_sni_test_config();
    let store =
        Arc::new(OpenSslDownstreamCertificateStore::new(&selector, &config.tls, None).unwrap());
    let acceptor = build_openssl_downstream_acceptor(&config.tls, &certificate).unwrap();
    let mut retained_ssl = Ssl::new(acceptor.context()).unwrap();
    store
        .apply_certificate_for_sni(None, &mut retained_ssl)
        .unwrap();
    store.reload().unwrap();

    let reload_store = store.clone();
    let reload = thread::spawn(move || {
        reload_store.reload_after_generation_drain(std::time::Duration::from_secs(2))
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while poll_connection_drain_once(&retained_ssl).is_pending()
        && std::time::Instant::now() < deadline
    {
        thread::yield_now();
    }
    assert!(poll_connection_drain_once(&retained_ssl).is_ready());

    drop(retained_ssl);
    reload.join().unwrap().unwrap();
}

#[test]
fn bounded_reload_wakes_every_connection_in_drained_generation() {
    let (config, selector, certificate) = openssl_sni_test_config();
    let store =
        Arc::new(OpenSslDownstreamCertificateStore::new(&selector, &config.tls, None).unwrap());
    let acceptor = build_openssl_downstream_acceptor(&config.tls, &certificate).unwrap();
    let mut retained = Vec::new();
    let mut wake_counts = Vec::new();
    for _ in 0..2 {
        let mut ssl = Ssl::new(acceptor.context()).unwrap();
        store.apply_certificate_for_sni(None, &mut ssl).unwrap();
        let wake_count = Arc::new(CountingWake(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(wake_count.clone());
        assert!(poll_connection_drain_with_waker(&ssl, &waker).is_pending());
        retained.push(ssl);
        wake_counts.push(wake_count);
    }
    store.reload().unwrap();

    let reload_store = store.clone();
    let reload = thread::spawn(move || {
        reload_store.reload_after_generation_drain(std::time::Duration::from_secs(2))
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while wake_counts
        .iter()
        .any(|count| count.0.load(Ordering::Acquire) == 0)
        && std::time::Instant::now() < deadline
    {
        thread::yield_now();
    }
    assert!(
        wake_counts
            .iter()
            .all(|count| count.0.load(Ordering::Acquire) == 1)
    );
    for ssl in &retained {
        assert!(poll_connection_drain_once(ssl).is_ready());
    }

    drop(retained);
    reload.join().unwrap().unwrap();
}

#[test]
fn concurrent_reload_generation_construction_is_serialized() {
    let (config, selector, certificate) = openssl_sni_test_config();
    let store =
        Arc::new(OpenSslDownstreamCertificateStore::new(&selector, &config.tls, None).unwrap());
    let acceptor = build_openssl_downstream_acceptor(&config.tls, &certificate).unwrap();
    let mut retained_ssl = Ssl::new(acceptor.context()).unwrap();
    store
        .apply_certificate_for_sni(None, &mut retained_ssl)
        .unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let store = store.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            store.reload()
        }));
    }
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(
                        OpenSslDownstreamCertificateStoreError::TooManyLiveGenerations {
                            count: 2,
                            maximum: OPENSSL_RELOAD_POLICY_GENERATIONS,
                        }
                    )
                )
            })
            .count(),
        1
    );
}

fn openssl_sni_test_config() -> (
    fluxheim_config::Config,
    DownstreamCertificateSelector,
    StaticCertificateConfig,
) {
    let certificate = StaticCertificateConfig {
        cert_path: PathBuf::from("../../tests/fixtures/tls/localhost-cert.pem"),
        key_path: PathBuf::from("../../tests/fixtures/tls/localhost-key.pem"),
    };
    let config = fluxheim_config::Config {
        tls: TlsConfig {
            enabled: true,
            certificates: vec![certificate.clone()],
            ..TlsConfig::default()
        },
        ..fluxheim_config::Config::default()
    };
    let selector = DownstreamCertificateSelector::from_config(&config).unwrap();
    (config, selector, certificate)
}

fn poll_connection_drain_once(ssl: &openssl::ssl::SslRef) -> Poll<()> {
    let wake = std::task::Waker::noop();
    poll_connection_drain_with_waker(ssl, wake)
}

fn poll_connection_drain_with_waker(
    ssl: &openssl::ssl::SslRef,
    wake: &std::task::Waker,
) -> Poll<()> {
    let mut context = std::task::Context::from_waker(wake);
    poll_openssl_connection_drain(ssl, &mut context)
}

struct CountingWake(AtomicUsize);

impl std::task::Wake for CountingWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

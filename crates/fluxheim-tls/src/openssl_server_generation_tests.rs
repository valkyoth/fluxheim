use std::path::PathBuf;
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
    assert!(matches!(
        store.reload(),
        Err(
            OpenSslDownstreamCertificateStoreError::TooManyLiveGenerations {
                count: 2,
                maximum: OPENSSL_RELOAD_POLICY_GENERATIONS,
            }
        )
    ));

    drop(retained_ssl);
    store.reload().unwrap();
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

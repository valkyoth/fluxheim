use std::io::Write as _;
use std::path::PathBuf;

use fluxheim_config::{Config, StaticCertificateConfig, TlsConfig};

use super::*;

#[test]
fn resolver_can_reload_certificate_files() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let certificate = StaticCertificateConfig {
        cert_path: PathBuf::from("../../tests/fixtures/tls/localhost-cert.pem"),
        key_path: PathBuf::from("../../tests/fixtures/tls/localhost-key.pem"),
    };
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            certificates: vec![certificate],
            ..TlsConfig::default()
        },
        ..Config::default()
    };
    let selector = DownstreamCertificateSelector::from_config(&config)
        .ok_or("expected downstream certificate selector")?;
    let resolver = RustlsDownstreamCertificateResolver::new(&selector)?;
    resolver.reload()?;
    assert_eq!(resolver.certificate_slot_count(), 1);
    assert_eq!(resolver.loaded_certificate_count(), 1);
    Ok(())
}

#[test]
fn managed_certificate_is_pending_when_either_file_is_missing()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let existing_cert = PathBuf::from("../../tests/fixtures/tls/localhost-cert.pem");
    let existing_key = PathBuf::from("../../tests/fixtures/tls/localhost-key.pem");
    assert!(certificate_paths_are_absent(&StaticCertificateConfig {
        cert_path: existing_cert,
        key_path: PathBuf::from("../../tests/fixtures/tls/missing-key.pem"),
    })?);
    assert!(certificate_paths_are_absent(&StaticCertificateConfig {
        cert_path: PathBuf::from("../../tests/fixtures/tls/missing-cert.pem"),
        key_path: existing_key,
    })?);
    Ok(())
}

#[test]
fn certificate_chain_count_is_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let cert_path = directory.path().join("chain.pem");
    let certificate = std::fs::read("../../tests/fixtures/tls/localhost-cert.pem").unwrap();
    let mut file = std::fs::File::create(&cert_path).unwrap();
    for _ in 0..=MAX_CHAIN_CERTIFICATES {
        file.write_all(&certificate).unwrap();
    }
    assert!(matches!(
        read_certificate_chain(&cert_path),
        Err(RustlsDownstreamCertificateError::TooManyCertificates { path, .. })
            if path == cert_path
    ));
}

#[test]
fn malformed_private_key_base64_error_is_redacted() {
    let error = decode_private_key_pem(
        b"-----BEGIN PRIVATE KEY-----\nAAAA!AAA\n-----END PRIVATE KEY-----\n",
    )
    .err()
    .unwrap();

    assert_eq!(error, "private-key PEM base64 is invalid: invalid-input");
    assert!(!error.contains('!'));
    assert!(!error.contains("index"));
}

#[test]
fn tls_alpn_challenge_store_normalizes_sni_and_resolves_from_memory()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let certificate = Arc::new(load_rustls_certified_key_from_paths(
        Path::new("../../tests/fixtures/tls/localhost-cert.pem"),
        Path::new("../../tests/fixtures/tls/localhost-key.pem"),
    )?);
    let store = RustlsTlsAlpnCertificateStore::new();
    store.replace([("EXAMPLE.COM.".to_owned(), certificate.clone())])?;
    let resolved = store.resolve(Some("example.com"));
    assert!(resolved.is_some());
    assert!(Arc::ptr_eq(&resolved.unwrap(), &certificate));
    assert!(store.resolve(Some("other.example")).is_none());
    Ok(())
}

#[test]
fn tls_alpn_challenge_store_rejects_duplicate_normalized_sni()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let certificate = Arc::new(load_rustls_certified_key_from_paths(
        Path::new("../../tests/fixtures/tls/localhost-cert.pem"),
        Path::new("../../tests/fixtures/tls/localhost-key.pem"),
    )?);
    let store = RustlsTlsAlpnCertificateStore::new();
    let error = store
        .replace([
            ("EXAMPLE.COM".to_owned(), certificate.clone()),
            ("example.com.".to_owned(), certificate),
        ])
        .unwrap_err();
    assert!(matches!(
        error,
        RustlsDownstreamCertificateError::DuplicateTlsAlpnSni { sni } if sni == "example.com"
    ));
    assert!(store.resolve(Some("example.com")).is_none());
    Ok(())
}

#[test]
fn tls_alpn_challenge_store_bounds_published_entries()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let certificate = Arc::new(load_rustls_certified_key_from_paths(
        Path::new("../../tests/fixtures/tls/localhost-cert.pem"),
        Path::new("../../tests/fixtures/tls/localhost-key.pem"),
    )?);
    let certificates = (0..=MAX_TLS_ALPN_CHALLENGE_CERTIFICATES)
        .map(|index| (format!("host-{index}.example"), certificate.clone()));
    let store = RustlsTlsAlpnCertificateStore::new();
    let error = store.replace(certificates).unwrap_err();
    assert!(matches!(
        error,
        RustlsDownstreamCertificateError::TooManyTlsAlpnCertificates { maximum }
            if maximum == MAX_TLS_ALPN_CHALLENGE_CERTIFICATES
    ));
    assert!(store.resolve(Some("host-0.example")).is_none());
    Ok(())
}

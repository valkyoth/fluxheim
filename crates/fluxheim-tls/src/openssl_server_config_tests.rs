use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;

use fluxheim_config::{TlsCipherSuite, TlsClientAuthConfig, TlsClientAuthMode};
use openssl::ssl::{SslConnector, SslVerifyMode};
use openssl::{pkey::PKey, rsa::Rsa, ssl::Ssl, x509::X509};

use super::*;
use crate::tls_input::MAX_CA_CERTIFICATES;

#[test]
fn tls13_only_allowlist_disables_tls12_defaults() {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    let tls = TlsConfig {
        min_protocol: Some(TlsProtocolVersion::Tls12),
        cipher_suites: vec![TlsCipherSuite::Tls13Aes256GcmSha384],
        ..TlsConfig::default()
    };
    apply_tls_policy(&mut builder, &tls).unwrap();
    assert_eq!(builder.min_proto_version(), Some(SslVersion::TLS1_3));
    assert_eq!(builder.max_proto_version(), None);
}

#[test]
fn tls12_only_allowlist_disables_tls13_defaults() {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    let tls = TlsConfig {
        min_protocol: Some(TlsProtocolVersion::Tls12),
        cipher_suites: vec![TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256],
        ..TlsConfig::default()
    };
    apply_tls_policy(&mut builder, &tls).unwrap();
    assert_eq!(builder.min_proto_version(), Some(SslVersion::TLS1_2));
    assert_eq!(builder.max_proto_version(), Some(SslVersion::TLS1_2));
}

#[test]
fn certificate_chain_count_is_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let cert_path = directory.path().join("chain.pem");
    let certificate = std::fs::read("../../tests/fixtures/tls/localhost-cert.pem").unwrap();
    let mut chain = Vec::new();
    for _ in 0..=MAX_CHAIN_CERTIFICATES {
        chain.extend_from_slice(&certificate);
    }
    std::fs::write(&cert_path, chain).unwrap();
    let config = StaticCertificateConfig {
        cert_path: cert_path.clone(),
        key_path: PathBuf::from("unused"),
    };
    assert!(matches!(
        load_certificate_chain(&config),
        Err(OpenSslDownstreamAcceptorError::TooManyCertificates { path, .. }) if path == cert_path
    ));
}

#[test]
fn client_auth_ca_certificate_count_is_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let ca_path = directory.path().join("ca.pem");
    let certificate = std::fs::read("../../tests/fixtures/tls/localhost-cert.pem").unwrap();
    let mut file = std::fs::File::create(&ca_path).unwrap();
    for _ in 0..=MAX_CA_CERTIFICATES {
        file.write_all(&certificate).unwrap();
    }
    let tls = TlsConfig {
        client_auth: TlsClientAuthConfig {
            mode: TlsClientAuthMode::Required,
            ca_path: Some(ca_path.clone()),
            crl_path: None,
        },
        ..TlsConfig::default()
    };
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    assert!(matches!(
        apply_client_auth(&mut builder, &tls),
        Err(OpenSslDownstreamAcceptorError::TooManyClientAuthCa { path, .. }) if path == ca_path
    ));
}

#[test]
fn client_auth_crl_rejects_revoked_certificate_handshake() {
    assert!(client_auth_handshake_succeeds(ClientAuthCrl::None));
    assert!(!client_auth_handshake_succeeds(ClientAuthCrl::Revoked));
}

#[test]
fn client_auth_crl_rejects_expired_revocation_list_handshake() {
    assert!(!client_auth_handshake_succeeds(ClientAuthCrl::Expired));
}

#[test]
fn sni_store_reload_rejects_mismatched_certificate_key_without_replacing_context() {
    let directory = tempfile::tempdir().unwrap();
    let cert_path = directory.path().join("certificate.pem");
    let key_path = directory.path().join("private-key.pem");
    std::fs::copy("../../tests/fixtures/tls/localhost-cert.pem", &cert_path).unwrap();
    std::fs::copy("../../tests/fixtures/tls/localhost-key.pem", &key_path).unwrap();
    let certificate = StaticCertificateConfig {
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
    };
    let config = fluxheim_config::Config {
        tls: TlsConfig {
            enabled: true,
            certificates: vec![certificate],
            ..TlsConfig::default()
        },
        ..fluxheim_config::Config::default()
    };
    let selector = DownstreamCertificateSelector::from_config(&config).unwrap();
    let store = OpenSslDownstreamCertificateStore::new(&selector, &config.tls, None).unwrap();
    let original_public_key = store.certificates.load()[0]
        .as_ref()
        .unwrap()
        .context
        .certificate()
        .unwrap()
        .public_key()
        .unwrap();

    let replacement_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    std::fs::write(
        &key_path,
        replacement_key.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    assert!(matches!(
        store.reload(),
        Err(OpenSslDownstreamCertificateStoreError::Certificate(
            OpenSslDownstreamAcceptorError::CertificateKeyMismatch { .. }
        ))
    ));

    let active_public_key = store.certificates.load()[0]
        .as_ref()
        .unwrap()
        .context
        .certificate()
        .unwrap()
        .public_key()
        .unwrap();
    assert!(active_public_key.public_eq(&original_public_key));
}

#[test]
fn sni_store_switches_the_complete_connection_context() {
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
    let store = OpenSslDownstreamCertificateStore::new(&selector, &config.tls, None).unwrap();
    let acceptor = build_openssl_downstream_acceptor(&config.tls, &certificate).unwrap();
    let original_context = acceptor.context();
    let mut ssl = Ssl::new(original_context).unwrap();

    store.apply_certificate_for_sni(None, &mut ssl).unwrap();

    assert!(!std::ptr::eq(original_context, ssl.ssl_context()));
    assert!(ssl.ssl_context().certificate().is_some());
}

#[test]
fn tls13_only_allowlist_rejects_tls12_handshake() {
    let suites = vec![TlsCipherSuite::Tls13Aes256GcmSha384];
    assert!(handshake_succeeds(suites.clone(), SslVersion::TLS1_3));
    assert!(!handshake_succeeds(suites, SslVersion::TLS1_2));
}

#[test]
fn tls12_only_allowlist_rejects_tls13_handshake() {
    let suites = vec![TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256];
    assert!(handshake_succeeds(suites.clone(), SslVersion::TLS1_2));
    assert!(!handshake_succeeds(suites, SslVersion::TLS1_3));
}

fn handshake_succeeds(cipher_suites: Vec<TlsCipherSuite>, client_protocol: SslVersion) -> bool {
    let certificate = StaticCertificateConfig {
        cert_path: PathBuf::from("../../tests/fixtures/tls/localhost-cert.pem"),
        key_path: PathBuf::from("../../tests/fixtures/tls/localhost-key.pem"),
    };
    let tls = TlsConfig {
        enabled: true,
        min_protocol: Some(TlsProtocolVersion::Tls12),
        cipher_suites,
        ..TlsConfig::default()
    };
    let acceptor = build_openssl_downstream_acceptor(&tls, &certificate).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        acceptor
            .accept(stream)
            .map(|_| ())
            .map_err(|error| error.to_string())
    });

    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    connector
        .set_min_proto_version(Some(client_protocol))
        .unwrap();
    connector
        .set_max_proto_version(Some(client_protocol))
        .unwrap();
    if client_protocol == SslVersion::TLS1_3 {
        connector
            .set_ciphersuites("TLS_AES_256_GCM_SHA384")
            .unwrap();
    } else {
        connector
            .set_cipher_list("ECDHE-RSA-AES128-GCM-SHA256")
            .unwrap();
    }
    let client = connector
        .build()
        .connect("localhost", TcpStream::connect(address).unwrap())
        .is_ok();
    let server = server.join().unwrap();
    client && server.is_ok()
}

#[derive(Clone, Copy)]
enum ClientAuthCrl {
    None,
    Revoked,
    Expired,
}

fn client_auth_handshake_succeeds(crl: ClientAuthCrl) -> bool {
    let directory = tempfile::tempdir().unwrap();
    let fixture = crate::test_certificates::revoked_client_certificate_fixture();
    let ca_path = directory.path().join("client-ca.pem");
    let crl_path = directory.path().join("client.crl.pem");
    std::fs::write(&ca_path, &fixture.ca_pem).unwrap();
    let crl_pem = match crl {
        ClientAuthCrl::None | ClientAuthCrl::Revoked => &fixture.crl_pem,
        ClientAuthCrl::Expired => &fixture.expired_crl_pem,
    };
    std::fs::write(&crl_path, crl_pem).unwrap();
    let certificate = StaticCertificateConfig {
        cert_path: PathBuf::from("../../tests/fixtures/tls/localhost-cert.pem"),
        key_path: PathBuf::from("../../tests/fixtures/tls/localhost-key.pem"),
    };
    let tls = TlsConfig {
        enabled: true,
        client_auth: TlsClientAuthConfig {
            mode: TlsClientAuthMode::Required,
            ca_path: Some(ca_path),
            crl_path: (!matches!(crl, ClientAuthCrl::None)).then_some(crl_path),
        },
        ..TlsConfig::default()
    };
    let acceptor = build_openssl_downstream_acceptor(&tls, &certificate).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        acceptor
            .accept(stream)
            .map(|_| ())
            .map_err(|error| error.to_string())
    });

    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    connector
        .set_certificate(&X509::from_pem(fixture.client_pem.as_bytes()).unwrap())
        .unwrap();
    connector
        .set_private_key(&PKey::private_key_from_pem(fixture.client_key_pem.as_bytes()).unwrap())
        .unwrap();
    let client = connector
        .build()
        .connect("localhost", TcpStream::connect(address).unwrap())
        .map(|_| ())
        .map_err(|error| error.to_string());
    let server = server.join().unwrap();
    client.is_ok() && server.is_ok()
}

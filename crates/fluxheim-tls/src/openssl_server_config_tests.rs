use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::thread;

use fluxheim_config::{TlsCipherSuite, TlsClientAuthConfig, TlsClientAuthMode};
use openssl::ssl::{SslConnector, SslVerifyMode};

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

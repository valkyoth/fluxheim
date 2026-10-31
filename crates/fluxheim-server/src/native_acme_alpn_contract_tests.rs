use super::*;
use std::io::Write as _;

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).unwrap().write_all(bytes).unwrap();
}

#[tokio::test]
async fn native_alpn_challenge_currently_serves_ordinary_certificate_even_after_reload() {
    use rustls::pki_types::ServerName;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = tempfile::tempdir_in(fluxheim_common::test_support::test_root()).unwrap();
    let normal = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = root.path().join("normal.pem");
    let key_path = root.path().join("normal-key.pem");
    write_private(&cert_path, normal.cert.pem().as_bytes());
    write_private(&key_path, normal.signing_key.serialize_pem().as_bytes());

    // Stage valid TLS-ALPN challenge material at the same hashed domain layout
    // used by AcmeTlsAlpn01ChallengeStore, distinct from the normal certificate.
    let managed =
        crate::native_http1_acme::native_managed_certificate_config(root.path(), "localhost");
    let segment = managed.cert_path.parent().unwrap().file_name().unwrap();
    let challenge_dir = root.path().join("tls-alpn-01").join(segment);
    std::fs::create_dir_all(&challenge_dir).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params
        .custom_extensions
        .push(rcgen::CustomExtension::new_acme_identifier(&[42; 32]));
    let challenge_key = rcgen::KeyPair::generate().unwrap();
    let challenge = params.self_signed(&challenge_key).unwrap();
    write_private(
        &challenge_dir.join("fullchain.pem"),
        challenge.pem().as_bytes(),
    );
    write_private(
        &challenge_dir.join("privkey.pem"),
        challenge_key.serialize_pem().as_bytes(),
    );

    let mut config = Config::default();
    config.server.listen.clear();
    config.server.tls_listen = vec!["127.0.0.1:0".to_owned()];
    config.tls.enabled = true;
    config.tls.acme.enabled = true;
    config.tls.acme.storage = Some(root.path().to_path_buf());
    config.tls.acme.contact_email = Some("test@example.test".to_owned());
    config.tls.acme.challenge = fluxheim_config::AcmeChallenge::TlsAlpn01;
    config.server.default_vhost = Some("localhost".to_owned());
    config.vhosts = vec![fluxheim_config::VhostConfig {
        name: "localhost".to_owned(),
        hosts: vec!["localhost".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: fluxheim_config::VhostTlsConfig {
            enabled: true,
            acme: fluxheim_config::VhostAcmeConfig {
                enabled: true,
                issuer: None,
                domains: vec!["localhost".to_owned()],
            },
            ..Default::default()
        },
        acme_challenge: Default::default(),
        redirect: Default::default(),
        proxy: Default::default(),
        cache: Default::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: Vec::new(),
    }];
    config.tls.certificates = vec![fluxheim_config::StaticCertificateConfig {
        cert_path,
        key_path,
    }];
    let (server, resolver) = native_rustls_server_config(&config).unwrap();
    // A standalone server-crate build may omit fluxheim-tls/acme; the root
    // application's acme feature enables it. Exercise both feature combinations.
    let advertises_challenge = server
        .alpn_protocols
        .iter()
        .any(|value| value == b"acme-tls/1");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(normal.cert.der().clone()).unwrap();
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client));

    for reload in [false, true] {
        if reload {
            resolver.reload().unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(server.clone());
        let serving = async {
            let (tcp, _) = listener.accept().await.unwrap();
            acceptor.accept(tcp).await
        };
        let connecting = async {
            let tcp = TcpStream::connect(address).await.unwrap();
            connector
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await
        };
        let (accepted, connected) =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(serving, connecting)
            })
            .await
            .unwrap();
        if !advertises_challenge {
            assert!(accepted.is_err() && connected.is_err());
            continue;
        }
        let _accepted = accepted.unwrap();
        let connection = connected.unwrap();
        let tls = connection.get_ref().1;
        assert_eq!(tls.alpn_protocol(), Some(b"acme-tls/1".as_slice()));
        // documented contract: negotiate the protocol but return the wrong certificate.
        assert_eq!(tls.peer_certificates().unwrap()[0], *normal.cert.der());
        assert_ne!(tls.peer_certificates().unwrap()[0], *challenge.der());
    }
}

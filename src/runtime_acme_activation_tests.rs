use super::{Activation, DownstreamCertificateReloader, activate_installed_certificates};
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[test]
fn background_reload_policy_controls_real_tls_handshakes() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(15), check_activation())
            .await
            .unwrap();
    });
}

async fn check_activation() {
    crate::tls::install_rustls_crypto_provider().unwrap();
    let root = tempfile::tempdir().unwrap();
    let files = fluxheim_config::StaticCertificateConfig {
        cert_path: root.path().join("leaf.pem"),
        key_path: root.path().join("key.pem"),
    };
    let pair = || rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let initial = pair();
    let next = pair();
    let install = |cert: &rcgen::CertifiedKey<rcgen::KeyPair>| {
        std::fs::write(&files.cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&files.key_path, cert.signing_key.serialize_pem()).unwrap();
    };
    install(&initial);
    let mut config = fluxheim_config::Config::default();
    config.tls.enabled = true;
    config.tls.certificates.push(files.clone());
    let selector = fluxheim_tls::DownstreamCertificateSelector::from_config(&config).unwrap();
    let resolver =
        Arc::new(fluxheim_tls::RustlsDownstreamCertificateResolver::new(&selector).unwrap());
    let handle = DownstreamCertificateReloader::Rustls(resolver.clone());
    let server = tokio_rustls::TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    ));
    let mut roots = rustls::RootCertStore::empty();
    for cert in [&initial, &next] {
        roots.add(cert.cert.der().clone()).unwrap();
    }
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.resumption = rustls::client::Resumption::disabled();
    let client = tokio_rustls::TlsConnector::from(Arc::new(client));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let handshake = || async {
        let outbound = async {
            let stream = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            client
                .connect("localhost".try_into().unwrap(), stream)
                .await
                .unwrap()
        };
        let inbound = async {
            server
                .accept(listener.accept().await.unwrap().0)
                .await
                .unwrap()
        };
        futures::future::join(outbound, inbound).await
    };
    let (mut established, mut remote) = handshake().await;
    install(&next);
    assert_eq!(
        activate_installed_certificates(false, Some(&handle))
            .await
            .unwrap(),
        Activation::NotRequested
    );
    assert_eq!(
        activate_installed_certificates(true, None).await.unwrap(),
        Activation::Unavailable
    );
    assert_eq!(
        &handshake().await.0.get_ref().1.peer_certificates().unwrap()[0],
        initial.cert.der()
    );
    assert_eq!(
        activate_installed_certificates(true, Some(&handle))
            .await
            .unwrap(),
        Activation::Reloaded
    );
    assert_eq!(
        &handshake().await.0.get_ref().1.peer_certificates().unwrap()[0],
        next.cert.der()
    );
    established.write_all(b"x").await.unwrap();
    established.flush().await.unwrap();
    assert_eq!(remote.read_u8().await.unwrap(), b'x');
    std::fs::write(&files.cert_path, initial.cert.pem()).unwrap();
    assert!(
        activate_installed_certificates(true, Some(&handle))
            .await
            .is_err()
    );
    assert_eq!(
        &handshake().await.0.get_ref().1.peer_certificates().unwrap()[0],
        next.cert.der()
    );
}

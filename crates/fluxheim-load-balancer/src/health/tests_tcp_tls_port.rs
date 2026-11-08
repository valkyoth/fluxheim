use super::*;
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::net::TcpListener;

async fn probe(override_port: bool, trusted: bool, name: &str) {
    crate::install_test_crypto_provider();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = certificate.cert.der().clone();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.clone()],
            PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let readiness = listener.local_addr().unwrap();
    let application = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = if override_port {
        application.local_addr().unwrap()
    } else {
        readiness
    };
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let result = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server))
            .accept(stream)
            .await;
        if let Ok(stream) = &result {
            assert_eq!(stream.get_ref().1.server_name(), Some("localhost"));
        }
    });
    let mut tls = configured_tcp_health_check_tls_inner(
        &ProxyConfig {
            upstream_tls: true,
            upstream_sni: Some(name.to_owned()),
            ..ProxyConfig::default()
        },
        HealthTlsAlpn::None,
    )
    .unwrap();
    // Trust only this ephemeral fixture certificate; never alter the process/OS store.
    #[cfg(feature = "tls-rustls-backend")]
    {
        let mut roots = rustls::RootCertStore::empty();
        if trusted {
            roots.add(cert).unwrap();
        }
        tls.config = std::sync::Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
    }
    #[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
    {
        let mut builder =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
        let mut store = openssl::x509::store::X509StoreBuilder::new().unwrap();
        if trusted {
            store
                .add_cert(openssl::x509::X509::from_der(&cert).unwrap())
                .unwrap();
        }
        builder.set_cert_store(store.build());
        tls.connector = builder.build();
    }
    let check = FluxTcpHealthCheck {
        consecutive_success: 1,
        consecutive_failure: 1,
        connect_timeout: Duration::from_secs(2),
        port_override: override_port.then_some(readiness.port()),
        tls: Some(tls),
    };
    let backend = Backend::new(&address.to_string()).unwrap();
    let result = check.check(&backend).await;
    assert_eq!(backend.addr, address);
    if trusted && name == "localhost" {
        result.unwrap();
    } else {
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("TLS TCP health check handshake failed"),
            "{error}"
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), application.accept())
            .await
            .is_err()
    );
    tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tcp_port_override_tls_verifies_trusted_certificate_and_sni() {
    probe(true, true, "localhost").await;
}

#[tokio::test]
async fn tcp_port_override_tls_rejects_wrong_hostname() {
    probe(true, true, "wrong.example").await;
}

#[tokio::test]
async fn tcp_port_override_tls_rejects_untrusted_certificate() {
    probe(true, false, "localhost").await;
}

#[tokio::test]
async fn tcp_tls_without_override_preserves_verified_handshake() {
    probe(false, true, "localhost").await;
}

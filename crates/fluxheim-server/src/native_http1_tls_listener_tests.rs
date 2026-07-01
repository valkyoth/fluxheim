use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use crate::{DownstreamHttp1Policy, NativeHttp1Request, NativeHttp1Response};

async fn read_response<S>(stream: &mut S) -> String
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "connection closed before response");
        response.extend_from_slice(&chunk[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            let text = String::from_utf8(response.clone()).unwrap();
            let length = text
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap();
            let head_len = response
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;
            if response.len() >= head_len + length {
                return String::from_utf8(response).unwrap();
            }
        }
    }
}

#[cfg(feature = "tls-rustls-backend")]
fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(feature = "tls-rustls-backend")]
#[tokio::test]
async fn native_http1_rustls_listener_serves_request() {
    use crate::serve_native_http1_rustls_listener;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
    use rustls::{ClientConfig, RootCertStore, server::WebPkiClientVerifier};
    use sha2::{Digest, Sha256};
    use tokio_rustls::TlsConnector;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_pem = certificate.pem();
    let key_pem = key.serialize_pem();
    let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let server_private_key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let client_private_key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let expected_client_cert_sha256 = hex_lower(&Sha256::digest(certs[0].as_ref()));
    let mut client_auth_roots = RootCertStore::empty();
    client_auth_roots.add(certs[0].clone()).unwrap();
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
        .build()
        .unwrap();
    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs.clone(), server_private_key)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs.clone(), client_private_key)
        .unwrap();
    let connector = TlsConnector::from(Arc::new(client_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handler = Arc::new(move |request: NativeHttp1Request| {
        let expected_client_cert_sha256 = expected_client_cert_sha256.clone();
        async move {
            assert_eq!(request.target, "/secure");
            assert!(request.downstream_tls);
            let identity = request.tls_identity.expect("TLS identity");
            assert!(identity.version.is_some());
            assert!(identity.cipher.is_some());
            assert_eq!(identity.cert_sha256, Some(expected_client_cert_sha256));
            NativeHttp1Response::new(200, "OK", b"native tls listener".as_slice())
        }
    });
    let join = tokio::spawn(async move {
        serve_native_http1_rustls_listener(
            listener,
            DownstreamHttp1Policy::default(),
            Arc::new(server_config),
            handler,
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
        .unwrap();
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost".to_owned()).unwrap();
    let mut stream = connector.connect(server_name, tcp).await.unwrap();
    stream
        .write_all(b"GET /secure HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("native tls listener"));
    shutdown_tx.send(()).unwrap();
    join.await.unwrap();
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
#[tokio::test]
async fn native_http1_openssl_listener_serves_request() {
    use crate::serve_native_http1_openssl_listener;
    use openssl::pkey::PKey;
    use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
    use openssl::x509::{X509, store::X509StoreBuilder};
    use rcgen::{CertificateParams, KeyPair};
    use tokio_openssl::SslStream;

    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_pem = certificate.pem();
    let key_pem = key.serialize_pem();
    let certs = X509::stack_from_pem(cert_pem.as_bytes()).unwrap();
    let (leaf, intermediates) = certs.split_first().unwrap();
    let private_key = PKey::private_key_from_pem(key_pem.as_bytes()).unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls_server()).unwrap();
    acceptor.set_certificate(leaf).unwrap();
    for certificate in intermediates {
        acceptor.add_extra_chain_cert(certificate.clone()).unwrap();
    }
    acceptor.set_private_key(&private_key).unwrap();

    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(leaf.clone()).unwrap();
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_cert_store(store.build());
    connector.set_verify(SslVerifyMode::PEER);
    let connector = connector.build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handler = Arc::new(|request: NativeHttp1Request| async move {
        assert_eq!(request.target, "/secure");
        assert!(request.downstream_tls);
        let identity = request.tls_identity.expect("TLS identity");
        assert!(identity.version.is_some());
        assert!(identity.cipher.is_some());
        assert_eq!(identity.cert_sha256, None);
        NativeHttp1Response::new(200, "OK", b"native openssl listener".as_slice())
    });
    let join = tokio::spawn(async move {
        serve_native_http1_openssl_listener(
            listener,
            DownstreamHttp1Policy::default(),
            Arc::new(acceptor.build()),
            handler,
            async move {
                let _ = shutdown_rx.await;
            },
        )
        .await
        .unwrap();
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let ssl = connector
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap();
    let mut stream = SslStream::new(ssl, tcp).unwrap();
    std::pin::Pin::new(&mut stream).connect().await.unwrap();
    stream
        .write_all(b"GET /secure HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("native openssl listener"));
    shutdown_tx.send(()).unwrap();
    join.await.unwrap();
}

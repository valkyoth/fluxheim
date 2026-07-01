use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use crate::native_http1_proxy_tls_tests::{downstream_get, native_tls_fixture, proxy_with_native};
use crate::{DownstreamHttp1Policy, NativeHttp1Proxy, native_http1_test_utils::read_request_head};

#[cfg(feature = "tls-rustls-backend")]
async fn mtls_upstream(
    chain_pem: String,
    key_pem: String,
    client_ca_pem: String,
) -> std::net::SocketAddr {
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use rustls::server::WebPkiClientVerifier;
    use tokio_rustls::TlsAcceptor;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let mut client_roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(client_ca_pem.as_bytes()) {
        client_roots.add(cert.unwrap()).unwrap();
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .unwrap();
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return;
        };
        let request = String::from_utf8(read_request_head(&mut stream).await).unwrap();
        assert!(request.starts_with("GET /mtls HTTP/1.1\r\n"));
        assert!(request.contains("host: proxy.test\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 17\r\nx-origin: mtls\r\n\r\nhello mtls native",
            )
            .await
            .unwrap();
    });
    addr
}

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
async fn mtls_upstream(
    chain_pem: String,
    key_pem: String,
    client_ca_pem: String,
) -> std::net::SocketAddr {
    use openssl::pkey::PKey;
    use openssl::ssl::{SslAcceptor, SslMethod, SslVerifyMode};
    use openssl::x509::{X509, store::X509StoreBuilder};
    use tokio_openssl::SslStream;

    let certs = X509::stack_from_pem(chain_pem.as_bytes()).unwrap();
    let (leaf, intermediates) = certs.split_first().unwrap();
    let key = PKey::private_key_from_pem(key_pem.as_bytes()).unwrap();
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls_server()).unwrap();
    builder.set_certificate(leaf).unwrap();
    for cert in intermediates {
        builder.add_extra_chain_cert(cert.clone()).unwrap();
    }
    builder.set_private_key(&key).unwrap();
    let mut store = X509StoreBuilder::new().unwrap();
    for cert in X509::stack_from_pem(client_ca_pem.as_bytes()).unwrap() {
        store.add_cert(cert).unwrap();
    }
    builder.set_cert_store(store.build());
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    let acceptor = Arc::new(builder.build());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let ssl = openssl::ssl::Ssl::new(acceptor.context()).unwrap();
        let mut stream = SslStream::new(ssl, stream).unwrap();
        if std::pin::Pin::new(&mut stream).accept().await.is_err() {
            return;
        }
        let request = String::from_utf8(read_request_head(&mut stream).await).unwrap();
        assert!(request.starts_with("GET /mtls HTTP/1.1\r\n"));
        assert!(request.contains("host: proxy.test\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 17\r\nx-origin: mtls\r\n\r\nhello mtls native",
            )
            .await
            .unwrap();
    });
    addr
}

#[tokio::test]
async fn native_proxy_forwards_to_mtls_upstream_with_client_certificate() {
    let fixture = native_tls_fixture();
    let upstream = mtls_upstream(
        fixture.chain_pem.clone(),
        fixture.key_pem.clone(),
        fixture.ca_pem.clone(),
    )
    .await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        upstream_tls: true,
        upstream_sni: Some("localhost".to_owned()),
        upstream_ca_path: Some(fixture.ca_path.clone()),
        upstream_client_cert_path: Some(fixture.client_cert_path.clone()),
        upstream_client_key_path: Some(fixture.client_key_path.clone()),
        ..Default::default()
    };
    let native =
        NativeHttp1Proxy::from_proxy_config(&proxy_config, DownstreamHttp1Policy::default())
            .unwrap()
            .expect("native mTLS proxy");
    let proxy = proxy_with_native(native).await;

    let response = downstream_get(proxy, "/mtls").await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("x-origin: mtls\r\n"));
    assert!(response.ends_with("hello mtls native"));
}

#[tokio::test]
async fn native_proxy_rejects_mtls_upstream_without_client_certificate() {
    let fixture = native_tls_fixture();
    let upstream = mtls_upstream(
        fixture.chain_pem.clone(),
        fixture.key_pem.clone(),
        fixture.ca_pem.clone(),
    )
    .await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        upstream_tls: true,
        upstream_sni: Some("localhost".to_owned()),
        upstream_ca_path: Some(fixture.ca_path.clone()),
        ..Default::default()
    };
    let native =
        NativeHttp1Proxy::from_proxy_config(&proxy_config, DownstreamHttp1Policy::default())
            .unwrap()
            .expect("native TLS proxy without client cert");
    let proxy = proxy_with_native(native).await;

    let response = downstream_get(proxy, "/mtls").await;

    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.ends_with("bad gateway\n"));
}

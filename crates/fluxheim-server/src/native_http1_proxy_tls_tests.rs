use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    DownstreamHttp1Policy, NativeHttp1Proxy, native_http1_test_utils::read_request_head,
    serve_native_http1_listener,
};

struct NativeTlsFixture {
    ca_path: std::path::PathBuf,
    client_cert_path: std::path::PathBuf,
    client_key_path: std::path::PathBuf,
    directory: std::path::PathBuf,
    ca_pem: String,
    chain_pem: String,
    key_pem: String,
    alternate_chain_pem: String,
    alternate_key_pem: String,
}

fn native_tls_fixture() -> NativeTlsFixture {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_name = DistinguishedName::new();
    ca_name.push(DnType::CommonName, "Fluxheim Native HTTP Test CA");
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = ca_name;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_issuer).unwrap();

    let alternate_leaf_key = KeyPair::generate().unwrap();
    let mut alternate_leaf_params =
        CertificateParams::new(vec!["origin.internal.test".to_owned()]).unwrap();
    alternate_leaf_params.is_ca = IsCa::ExplicitNoCa;
    alternate_leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let alternate_leaf_cert = alternate_leaf_params
        .signed_by(&alternate_leaf_key, &ca_issuer)
        .unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut client_params =
        CertificateParams::new(vec!["fluxheim-native-client".to_owned()]).unwrap();
    client_params.is_ca = IsCa::ExplicitNoCa;
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();

    let directory = unique_temp_dir("native-http1-tls");
    let ca_path = directory.join("ca.pem");
    let client_cert_path = directory.join("client-chain.pem");
    let client_key_path = directory.join("client-key.pem");
    std::fs::write(&ca_path, ca_cert.pem()).unwrap();
    std::fs::write(
        &client_cert_path,
        format!("{}{}", client_cert.pem(), ca_cert.pem()),
    )
    .unwrap();
    std::fs::write(&client_key_path, client_key.serialize_pem()).unwrap();

    NativeTlsFixture {
        ca_path,
        client_cert_path,
        client_key_path,
        directory,
        ca_pem: ca_cert.pem(),
        chain_pem: format!("{}{}", leaf_cert.pem(), ca_cert.pem()),
        key_pem: leaf_key.serialize_pem(),
        alternate_chain_pem: format!("{}{}", alternate_leaf_cert.pem(), ca_cert.pem()),
        alternate_key_pem: alternate_leaf_key.serialize_pem(),
    }
}

static NATIVE_TLS_TEMP_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn unique_temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = NATIVE_TLS_TEMP_DIR_COUNTER.fetch_add(1, Ordering::AcqRel);
    let path = std::env::temp_dir().join(format!(
        "fluxheim-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

#[cfg(feature = "tls-rustls-backend")]
async fn tls_upstream(chain_pem: String, key_pem: String) -> std::net::SocketAddr {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use tokio_rustls::TlsAcceptor;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
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
        assert!(request.starts_with("GET /secure HTTP/1.1\r\n"));
        assert!(request.contains("host: proxy.test\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 16\r\nx-origin: tls\r\n\r\nhello tls native",
            )
            .await
            .unwrap();
    });
    addr
}

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
async fn tls_upstream(chain_pem: String, key_pem: String) -> std::net::SocketAddr {
    use openssl::pkey::PKey;
    use openssl::ssl::{SslAcceptor, SslMethod};
    use openssl::x509::X509;
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
        assert!(request.starts_with("GET /secure HTTP/1.1\r\n"));
        assert!(request.contains("host: proxy.test\r\n"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 16\r\nx-origin: tls\r\n\r\nhello tls native",
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

async fn downstream_get(proxy: std::net::SocketAddr, path: &str) -> String {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: proxy.test\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

async fn proxy_with_native(native: NativeHttp1Proxy) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    tokio::spawn(async move {
        serve_native_http1_listener(
            listener,
            DownstreamHttp1Policy::default(),
            Arc::new(native),
            std::future::pending::<()>(),
        )
        .await
        .unwrap();
    });
    proxy
}

#[tokio::test]
async fn native_proxy_forwards_to_tls_upstream_with_ca_and_sni() {
    let fixture = native_tls_fixture();
    let upstream = tls_upstream(fixture.chain_pem.clone(), fixture.key_pem.clone()).await;
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
            .expect("native TLS proxy");
    let proxy = proxy_with_native(native).await;

    let response = downstream_get(proxy, "/secure").await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("x-origin: tls\r\n"));
    assert!(response.ends_with("hello tls native"));
    std::fs::remove_dir_all(fixture.directory).unwrap();
}

#[tokio::test]
async fn native_proxy_rejects_tls_upstream_hostname_mismatch_by_default() {
    let fixture = native_tls_fixture();
    let upstream = tls_upstream(
        fixture.alternate_chain_pem.clone(),
        fixture.alternate_key_pem.clone(),
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
            .expect("native TLS proxy");
    let proxy = proxy_with_native(native).await;

    let response = downstream_get(proxy, "/secure").await;

    assert!(
        response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.ends_with("bad gateway\n"));
    std::fs::remove_dir_all(fixture.directory).unwrap();
}

#[tokio::test]
async fn native_proxy_accepts_tls_upstream_alternative_name() {
    let fixture = native_tls_fixture();
    let upstream = tls_upstream(
        fixture.alternate_chain_pem.clone(),
        fixture.alternate_key_pem.clone(),
    )
    .await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        upstream_tls: true,
        upstream_sni: Some("localhost".to_owned()),
        upstream_ca_path: Some(fixture.ca_path.clone()),
        upstream_alternative_cn: Some("origin.internal.test".to_owned()),
        ..Default::default()
    };
    let native =
        NativeHttp1Proxy::from_proxy_config(&proxy_config, DownstreamHttp1Policy::default())
            .unwrap()
            .expect("native TLS proxy");
    let proxy = proxy_with_native(native).await;

    let response = downstream_get(proxy, "/secure").await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("x-origin: tls\r\n"));
    assert!(response.ends_with("hello tls native"));
    std::fs::remove_dir_all(fixture.directory).unwrap();
}

#[tokio::test]
async fn native_proxy_accepts_tls_upstream_without_hostname_verification() {
    let fixture = native_tls_fixture();
    let upstream = tls_upstream(
        fixture.alternate_chain_pem.clone(),
        fixture.alternate_key_pem.clone(),
    )
    .await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        upstream_tls: true,
        upstream_sni: Some("localhost".to_owned()),
        upstream_ca_path: Some(fixture.ca_path.clone()),
        upstream_verify_hostname: false,
        ..Default::default()
    };
    let native =
        NativeHttp1Proxy::from_proxy_config(&proxy_config, DownstreamHttp1Policy::default())
            .unwrap()
            .expect("native TLS proxy");
    let proxy = proxy_with_native(native).await;

    let response = downstream_get(proxy, "/secure").await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("x-origin: tls\r\n"));
    assert!(response.ends_with("hello tls native"));
    std::fs::remove_dir_all(fixture.directory).unwrap();
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
    std::fs::remove_dir_all(fixture.directory).unwrap();
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
    std::fs::remove_dir_all(fixture.directory).unwrap();
}

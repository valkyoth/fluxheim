#![cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl"))]

use std::io::Write;
use std::sync::Arc;

use fluxheim_config::{Config, StaticCertificateConfig, TlsAlpnPolicy, TlsConfig};
use fluxheim_server::{
    DownstreamHttp1Policy, NativeHttp1Request, NativeHttp1Response,
    serve_native_http1_openssl_listener,
};
use fluxheim_tls::{DownstreamCertificateSelector, build_openssl_downstream_acceptor};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::{X509, store::X509StoreBuilder};
use rcgen::{CertificateParams, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_openssl::SslStream;

#[tokio::test]
async fn openssl_acceptor_builder_drives_native_http1_listener() {
    let temp = tempfile::tempdir().unwrap();
    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut cert_file = tempfile::Builder::new()
        .prefix("localhost-cert-")
        .suffix(".pem")
        .tempfile_in(temp.path())
        .unwrap();
    let mut key_file = tempfile::Builder::new()
        .prefix("localhost-key-")
        .suffix(".pem")
        .tempfile_in(temp.path())
        .unwrap();
    cert_file.write_all(certificate.pem().as_bytes()).unwrap();
    key_file.write_all(key.serialize_pem().as_bytes()).unwrap();
    cert_file.flush().unwrap();
    key_file.flush().unwrap();
    let cert_path = cert_file.path().to_path_buf();
    let key_path = key_file.path().to_path_buf();

    let config = Config {
        tls: TlsConfig {
            enabled: true,
            alpn: TlsAlpnPolicy::Http1,
            certificates: vec![StaticCertificateConfig {
                cert_path,
                key_path,
            }],
            ..TlsConfig::default()
        },
        ..Config::default()
    };
    let selector = DownstreamCertificateSelector::from_config(&config)
        .expect("configured certificate selector");
    let acceptor = build_openssl_downstream_acceptor(
        &config.tls,
        selector.certificate_for_sni(Some("localhost")),
    )
    .unwrap();

    let certs = X509::stack_from_pem(certificate.pem().as_bytes()).unwrap();
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(certs[0].clone()).unwrap();
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_cert_store(store.build());
    connector.set_verify(SslVerifyMode::PEER);
    let connector = connector.build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handler = Arc::new(|request: NativeHttp1Request| async move {
        assert_eq!(request.target, "/cutover");
        NativeHttp1Response::new(200, "OK", b"native openssl cutover listener".as_slice())
    });
    let join = tokio::spawn(async move {
        serve_native_http1_openssl_listener(
            listener,
            DownstreamHttp1Policy::default(),
            Arc::new(acceptor),
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
        .write_all(b"GET /cutover HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("native openssl cutover listener"));
    shutdown_tx.send(()).unwrap();
    join.await.unwrap();
}

async fn read_response<S>(stream: &mut S) -> String
where
    S: tokio::io::AsyncRead + Unpin,
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

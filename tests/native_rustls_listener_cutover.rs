#![cfg(feature = "tls-rustls-backend")]

use std::io::Write;
use std::sync::Arc;

use fluxheim_config::{Config, StaticCertificateConfig, TlsAlpnPolicy, TlsConfig};
use fluxheim_server::{
    DownstreamHttp1Policy, NativeHttp1Request, NativeHttp1Response,
    serve_native_http1_rustls_listener,
};
use fluxheim_tls::{
    DownstreamCertificateSelector, RustlsDownstreamCertificateResolver,
    build_rustls_downstream_server_config,
};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn rustls_server_config_builder_drives_native_http1_listener() {
    let _ = rustls::crypto::ring::default_provider().install_default();
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
                cert_path: cert_path.clone(),
                key_path,
            }],
            ..TlsConfig::default()
        },
        ..Config::default()
    };
    let selector = DownstreamCertificateSelector::from_config(&config)
        .expect("configured certificate selector");
    let resolver = Arc::new(
        RustlsDownstreamCertificateResolver::new(&selector).expect("rustls certificate resolver"),
    );
    let server_config = build_rustls_downstream_server_config(&config.tls, resolver, None).unwrap();

    let cert_pem = certificate.pem();
    let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handler = Arc::new(|request: NativeHttp1Request| async move {
        assert_eq!(request.target, "/cutover");
        NativeHttp1Response::new(200, "OK", b"native cutover listener".as_slice())
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
        .write_all(b"GET /cutover HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_response(&mut stream).await;

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("native cutover listener"));
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

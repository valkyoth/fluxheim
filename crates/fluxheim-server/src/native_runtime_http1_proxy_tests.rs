use fluxheim_runtime::NativeBackgroundSupervisor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{NativeHttp1ProxyRuntime, ServerPlan};

async fn upstream_response(body: &'static str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    addr
}

async fn downstream_get(proxy: std::net::SocketAddr) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: native.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

#[cfg(feature = "tls-rustls-backend")]
async fn downstream_tls_get(proxy: std::net::SocketAddr, certificate_pem: String) -> String {
    use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
    use rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    let certs = CertificateDer::pem_slice_iter(certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(client_config));

    let tcp = TcpStream::connect(proxy).await.unwrap();
    let server_name = ServerName::try_from("localhost".to_owned()).unwrap();
    let mut stream = connector.connect(server_name, tcp).await.unwrap();
    stream
        .write_all(b"GET /secure HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    read_http_response(&mut stream).await
}

#[cfg(feature = "tls-rustls-backend")]
async fn read_http_response<S>(stream: &mut S) -> String
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
            let header_len = response
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .unwrap()
                + 4;
            while response.len() < header_len + length {
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0, "connection closed before response body");
                response.extend_from_slice(&chunk[..read]);
            }
            return String::from_utf8(response).unwrap();
        }
    }
}

#[tokio::test]
async fn native_http1_proxy_runtime_binds_launch_plan_and_serves_proxy_listener() {
    let upstream = upstream_response("runtime-ok").await;
    let mut config = fluxheim_config::Config::default();
    config.server.listen = vec!["127.0.0.1:0".to_owned()];
    config.proxy.upstream = Some(upstream.to_string());

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.native_runtime_cutover_summary().is_ready());
    let runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
        .await
        .expect("bind native proxy runtime");
    assert_eq!(
        runtime.planned_addrs(),
        [std::net::SocketAddr::from(([127, 0, 0, 1], 0))]
    );
    let local_addr = runtime.local_addrs()[0];

    let supervisor = NativeBackgroundSupervisor::new();
    let handle = runtime.start(&supervisor);
    assert_eq!(handle.local_addrs(), [local_addr]);

    let response = downstream_get(local_addr).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("runtime-ok"));

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("native listener stopped cleanly");
    }
}

#[cfg(feature = "tls-rustls-backend")]
#[tokio::test]
async fn native_http1_proxy_runtime_binds_rustls_launch_plan_and_serves_https_listener() {
    use std::io::Write;

    use fluxheim_config::{StaticCertificateConfig, TlsAlpnPolicy, TlsConfig};
    use rcgen::{CertificateParams, KeyPair};

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

    let upstream = upstream_response("runtime-tls-ok").await;
    let mut config = fluxheim_config::Config::default();
    config.server.listen = Vec::new();
    config.server.tls_listen = vec!["127.0.0.1:0".to_owned()];
    config.proxy.upstream = Some(upstream.to_string());
    config.tls = TlsConfig {
        enabled: true,
        alpn: TlsAlpnPolicy::Http1,
        certificates: vec![StaticCertificateConfig {
            cert_path: cert_file.path().to_path_buf(),
            key_path: key_file.path().to_path_buf(),
        }],
        ..TlsConfig::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.native_runtime_cutover_summary().is_ready());
    let runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
        .await
        .expect("bind native rustls proxy runtime");
    let local_addr = runtime.local_addrs()[0];

    let supervisor = NativeBackgroundSupervisor::new();
    let handle = runtime.start(&supervisor);

    let response = downstream_tls_get(local_addr, certificate.pem()).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("runtime-tls-ok"));

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("native rustls listener stopped cleanly");
    }
}

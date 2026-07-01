use fluxheim_runtime::NativeBackgroundSupervisor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::native_runtime_http1_proxy_tests::upstream_response;
use crate::{NativeHttp1ProxyRuntime, ServerPlan};

struct TemporaryCertificate {
    _temp: tempfile::TempDir,
    _cert_file: tempfile::NamedTempFile,
    _key_file: tempfile::NamedTempFile,
    cert_pem: String,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
}

fn temporary_localhost_certificate() -> TemporaryCertificate {
    use std::io::Write;

    use rcgen::{CertificateParams, KeyPair};

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
    TemporaryCertificate {
        _temp: temp,
        _cert_file: cert_file,
        _key_file: key_file,
        cert_pem: certificate.pem(),
        cert_path,
        key_path,
    }
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
async fn downstream_tls_h2_get(proxy: std::net::SocketAddr, certificate_pem: String) -> String {
    use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
    use rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    let certs = CertificateDer::pem_slice_iter(certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certs[0].clone()).unwrap();
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(std::sync::Arc::new(client_config));

    let tcp = TcpStream::connect(proxy).await.unwrap();
    let server_name = ServerName::try_from("localhost".to_owned()).unwrap();
    let stream = connector.connect(server_name, tcp).await.unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut client, connection) = h2::client::handshake(stream).await.unwrap();
    let driver = tokio::spawn(connection);
    let request = http::Request::builder()
        .method("GET")
        .uri("https://localhost/secure")
        .header("host", "localhost")
        .body(())
        .unwrap();
    let (response, _) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        bytes.extend_from_slice(&chunk.unwrap());
    }
    drop(client);
    driver.abort();
    let _ = driver.await;
    String::from_utf8(bytes).unwrap()
}

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

#[cfg(feature = "tls-rustls-backend")]
#[tokio::test]
async fn native_http1_proxy_runtime_binds_rustls_launch_plan_and_serves_https_listener() {
    use fluxheim_config::{StaticCertificateConfig, TlsAlpnPolicy, TlsConfig};

    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificate = temporary_localhost_certificate();

    let upstream = upstream_response("runtime-tls-ok").await;
    let mut config = fluxheim_config::Config::default();
    config.server.listen = Vec::new();
    config.server.tls_listen = vec!["127.0.0.1:0".to_owned()];
    config.proxy.upstream = Some(upstream.to_string());
    config.tls = TlsConfig {
        enabled: true,
        alpn: TlsAlpnPolicy::Http1,
        certificates: vec![StaticCertificateConfig {
            cert_path: certificate.cert_path.clone(),
            key_path: certificate.key_path.clone(),
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

    let response = downstream_tls_get(local_addr, certificate.cert_pem).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("runtime-tls-ok"));

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("native rustls listener stopped cleanly");
    }
}

#[cfg(all(feature = "tls-rustls-backend", feature = "acme"))]
#[tokio::test]
async fn native_http1_proxy_runtime_accepts_default_vhost_acme_certificate_source() {
    use fluxheim_config::{
        AcmeConfig, ProxyConfig, TlsAlpnPolicy, TlsConfig, VhostAcmeConfig, VhostConfig,
        VhostTlsConfig,
    };

    let _ = rustls::crypto::ring::default_provider().install_default();
    let storage = tempfile::tempdir().unwrap();
    let upstream = upstream_response("unused").await;
    let mut vhost_proxy = ProxyConfig::disabled();
    vhost_proxy.upstream = Some(upstream.to_string());

    let mut config = fluxheim_config::Config::default();
    config.server.listen = Vec::new();
    config.server.tls_listen = vec!["127.0.0.1:0".to_owned()];
    config.server.default_vhost = Some("ulyaoth.eu".to_owned());
    config.proxy.upstream = Some(upstream.to_string());
    config.tls = TlsConfig {
        enabled: true,
        alpn: TlsAlpnPolicy::Http1,
        acme: AcmeConfig {
            enabled: true,
            storage: Some(storage.path().to_path_buf()),
            contact_email: Some("info@example.test".to_owned()),
            ..AcmeConfig::default()
        },
        ..TlsConfig::default()
    };
    config.vhosts = vec![VhostConfig {
        name: "ulyaoth.eu".to_owned(),
        hosts: vec!["ulyaoth.eu".to_owned(), "www.ulyaoth.eu".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: VhostTlsConfig {
            enabled: true,
            acme: VhostAcmeConfig {
                enabled: true,
                issuer: Some("actalis".to_owned()),
                domains: vec!["ulyaoth.eu".to_owned(), "www.ulyaoth.eu".to_owned()],
            },
            ..VhostTlsConfig::default()
        },
        acme_challenge: Default::default(),
        redirect: Default::default(),
        proxy: vhost_proxy,
        cache: Default::default(),
        compression: None,
        headers: Default::default(),
        php: Default::default(),
        web: Default::default(),
        routes: Vec::new(),
    }];

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.native_runtime_cutover_summary().is_ready());
    let runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
        .await
        .expect("bind native rustls proxy runtime with pending ACME fallback");
    let resolver = runtime
        .rustls_certificate_resolver()
        .expect("rustls certificate resolver");
    assert_eq!(resolver.certificate_slot_count(), 1);
    assert_eq!(resolver.loaded_certificate_count(), 0);
}

#[cfg(feature = "tls-rustls-backend")]
#[tokio::test]
async fn native_http1_proxy_runtime_serves_rustls_http2_alpn_listener() {
    use fluxheim_config::{StaticCertificateConfig, TlsAlpnPolicy, TlsConfig};

    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificate = temporary_localhost_certificate();

    let upstream = upstream_response("runtime-h2-ok").await;
    let mut config = fluxheim_config::Config::default();
    config.server.listen = Vec::new();
    config.server.tls_listen = vec!["127.0.0.1:0".to_owned()];
    config.proxy.upstream = Some(upstream.to_string());
    config.tls = TlsConfig {
        enabled: true,
        alpn: TlsAlpnPolicy::Http1AndHttp2,
        certificates: vec![StaticCertificateConfig {
            cert_path: certificate.cert_path.clone(),
            key_path: certificate.key_path.clone(),
        }],
        ..TlsConfig::default()
    };

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.downstream_http2_required());
    assert!(plan.native_runtime_cutover_summary().is_ready());
    let runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
        .await
        .expect("bind native rustls proxy runtime");
    let local_addr = runtime.local_addrs()[0];

    let supervisor = NativeBackgroundSupervisor::new();
    let handle = runtime.start(&supervisor);

    let body = downstream_tls_h2_get(local_addr, certificate.cert_pem).await;
    assert_eq!(body, "runtime-h2-ok");

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("native rustls H2 listener stopped cleanly");
    }
}

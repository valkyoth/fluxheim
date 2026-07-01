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

async fn downstream_tls_get(proxy: std::net::SocketAddr, certificate_pem: String) -> String {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use openssl::x509::{X509, store::X509StoreBuilder};
    use tokio_openssl::SslStream;

    let certs = X509::stack_from_pem(certificate_pem.as_bytes()).unwrap();
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(certs[0].clone()).unwrap();
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_cert_store(store.build());
    connector.set_verify(SslVerifyMode::PEER);
    let connector = connector.build();

    let tcp = TcpStream::connect(proxy).await.unwrap();
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
    read_http_response(&mut stream).await
}

async fn downstream_tls_h2_get(proxy: std::net::SocketAddr, certificate_pem: String) -> String {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use openssl::x509::{X509, store::X509StoreBuilder};
    use tokio_openssl::SslStream;

    let certs = X509::stack_from_pem(certificate_pem.as_bytes()).unwrap();
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(certs[0].clone()).unwrap();
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_cert_store(store.build());
    connector.set_verify(SslVerifyMode::PEER);
    connector.set_alpn_protos(b"\x02h2").unwrap();
    let connector = connector.build();

    let tcp = TcpStream::connect(proxy).await.unwrap();
    let ssl = connector
        .configure()
        .unwrap()
        .into_ssl("localhost")
        .unwrap();
    let mut stream = SslStream::new(ssl, tcp).unwrap();
    std::pin::Pin::new(&mut stream).connect().await.unwrap();
    assert_eq!(
        stream.ssl().selected_alpn_protocol(),
        Some(b"h2".as_slice())
    );

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

#[tokio::test]
async fn native_http1_proxy_runtime_binds_openssl_launch_plan_and_serves_https_listener() {
    use fluxheim_config::{StaticCertificateConfig, TlsAlpnPolicy, TlsConfig};

    let certificate = temporary_localhost_certificate();

    let upstream = upstream_response("runtime-openssl-ok").await;
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
        .expect("bind native OpenSSL proxy runtime");
    let local_addr = runtime.local_addrs()[0];

    let supervisor = NativeBackgroundSupervisor::new();
    let handle = runtime.start(&supervisor);

    let response = downstream_tls_get(local_addr, certificate.cert_pem).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("runtime-openssl-ok"));

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("native OpenSSL listener stopped cleanly");
    }
}

#[tokio::test]
async fn native_http1_proxy_runtime_serves_openssl_http2_alpn_listener() {
    use fluxheim_config::{StaticCertificateConfig, TlsAlpnPolicy, TlsConfig};

    let certificate = temporary_localhost_certificate();

    let upstream = upstream_response("runtime-openssl-h2-ok").await;
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
        .expect("bind native OpenSSL proxy runtime");
    let local_addr = runtime.local_addrs()[0];

    let supervisor = NativeBackgroundSupervisor::new();
    let handle = runtime.start(&supervisor);

    let body = downstream_tls_h2_get(local_addr, certificate.cert_pem).await;
    assert_eq!(body, "runtime-openssl-h2-ok");

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("native OpenSSL H2 listener stopped cleanly");
    }
}

#[tokio::test]
async fn native_http1_proxy_runtime_exposes_openssl_certificate_store_for_sni() {
    use fluxheim_config::{
        ProxyConfig, StaticCertificateConfig, TlsAlpnPolicy, TlsConfig, VhostConfig, VhostTlsConfig,
    };

    let certificate = temporary_localhost_certificate();
    let upstream = upstream_response("unused").await;
    let mut vhost_proxy = ProxyConfig::disabled();
    vhost_proxy.upstream = Some(upstream.to_string());

    let mut config = fluxheim_config::Config::default();
    config.server.listen = Vec::new();
    config.server.tls_listen = vec!["127.0.0.1:0".to_owned()];
    config.server.default_vhost = Some("native".to_owned());
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
    config.vhosts = vec![VhostConfig {
        name: "native".to_owned(),
        hosts: vec!["native.test".to_owned()],
        max_request_body_bytes: None,
        access: Default::default(),
        rate_limit: Default::default(),
        concurrency: Default::default(),
        tls: VhostTlsConfig {
            enabled: true,
            certificate: Some(StaticCertificateConfig {
                cert_path: certificate.cert_path.clone(),
                key_path: certificate.key_path.clone(),
            }),
            acme: Default::default(),
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
    let runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
        .await
        .expect("bind native OpenSSL proxy runtime");
    let store = runtime
        .openssl_certificate_store()
        .expect("SNI certificate store");
    assert_eq!(store.certificate_slot_count(), 1);
    assert_eq!(store.loaded_certificate_count(), 1);
}

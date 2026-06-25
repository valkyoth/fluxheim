use fluxheim_runtime::NativeBackgroundSupervisor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{NativeHttp1ProxyRuntime, ServerPlan};

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
struct TemporaryCertificate {
    _temp: tempfile::TempDir,
    _cert_file: tempfile::NamedTempFile,
    _key_file: tempfile::NamedTempFile,
    cert_pem: String,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
}

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
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

async fn upstream_assert_x_real_ip(expected: &'static str) -> std::net::SocketAddr {
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
        let request = String::from_utf8(request).unwrap();
        assert!(
            request
                .lines()
                .any(|line| line.eq_ignore_ascii_case(&format!("x-real-ip: {expected}"))),
            "missing x-real-ip header in request:\n{request}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\nproxy-ok")
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

async fn downstream_proxy_v1_get(proxy: std::net::SocketAddr, source: &str) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let request = format!(
        "PROXY TCP4 {source} 127.0.0.1 43210 8080\r\n\
         GET / HTTP/1.1\r\nHost: native.test\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

async fn downstream_proxy_v2_get(
    proxy: std::net::SocketAddr,
    source: std::net::SocketAddr,
    destination: std::net::SocketAddr,
) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let mut request = fluxheim_protocol::proxy_protocol_v2_header(Some(source), Some(destination));
    request.extend_from_slice(b"GET / HTTP/1.1\r\nHost: native.test\r\nConnection: close\r\n\r\n");
    stream.write_all(&request).await.unwrap();
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

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
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

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
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

#[tokio::test]
async fn native_http1_proxy_runtime_accepts_trusted_proxy_protocol_v1_listener() {
    let upstream = upstream_assert_x_real_ip("203.0.113.10").await;
    let mut config = fluxheim_config::Config::default();
    config.server.listen = vec!["127.0.0.1:0".to_owned()];
    config.server.proxy_protocol = fluxheim_config::DownstreamProxyProtocol::V1;
    config.server.trusted_proxies = vec!["127.0.0.1".to_owned()];
    config.proxy.upstream = Some(upstream.to_string());

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.native_runtime_cutover_summary().is_ready());
    let runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
        .await
        .expect("bind native proxy runtime");
    let local_addr = runtime.local_addrs()[0];

    let supervisor = NativeBackgroundSupervisor::new();
    let handle = runtime.start(&supervisor);

    let response = downstream_proxy_v1_get(local_addr, "203.0.113.10").await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("proxy-ok"));

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("native PROXY listener stopped cleanly");
    }
}

#[tokio::test]
async fn native_http1_proxy_runtime_accepts_trusted_proxy_protocol_v2_listener() {
    let upstream = upstream_assert_x_real_ip("203.0.113.20").await;
    let mut config = fluxheim_config::Config::default();
    config.server.listen = vec!["127.0.0.1:0".to_owned()];
    config.server.proxy_protocol = fluxheim_config::DownstreamProxyProtocol::V2;
    config.server.trusted_proxies = vec!["127.0.0.1".to_owned()];
    config.proxy.upstream = Some(upstream.to_string());

    let plan = ServerPlan::from_config(&config).expect("valid server plan");
    assert!(plan.native_runtime_cutover_summary().is_ready());
    let runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
        .await
        .expect("bind native proxy runtime");
    let local_addr = runtime.local_addrs()[0];

    let supervisor = NativeBackgroundSupervisor::new();
    let handle = runtime.start(&supervisor);

    let response = downstream_proxy_v2_get(
        local_addr,
        std::net::SocketAddr::from(([203, 0, 113, 20], 43210)),
        std::net::SocketAddr::from(([127, 0, 0, 1], 8080)),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("proxy-ok"));

    assert!(supervisor.shutdown());
    for result in handle.join().await {
        result.expect("native PROXY listener stopped cleanly");
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

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
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

#[cfg(all(not(feature = "tls-rustls-backend"), feature = "tls-openssl-backend"))]
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

use super::*;
use fluxheim_config::{
    CacheConfig, CacheMemoryConfig, CacheStaleErrorKind, ProxyConfig, UpstreamHttpVersion,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio_rustls::TlsAcceptor;

fn acceptor(chain: &str, key: &str) -> TlsAcceptor {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = CertificateDer::pem_slice_iter(chain.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
    TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    ))
}

#[tokio::test]
async fn tls_stale_requires_explicit_permission_and_never_trusts_failed_handshake() {
    for protocol in [
        UpstreamHttpVersion::Http1,
        UpstreamHttpVersion::Http1AndHttp2,
    ] {
        for allowed in [false, true] {
            let fixture = native_tls_fixture();
            let trusted = acceptor(&fixture.chain_pem, &fixture.key_pem);
            let wrong_name = acceptor(&fixture.alternate_chain_pem, &fixture.alternate_key_pem);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let origin = tokio::spawn(async move {
                for step in 0..3 {
                    let (stream, _) = listener.accept().await.unwrap();
                    let acceptor = if step == 1 { &wrong_name } else { &trusted };
                    let result = acceptor.accept(stream).await;
                    if step == 1 {
                        assert!(result.is_err(), "hostname verification must remain enabled");
                        continue;
                    }
                    let mut stream = result.unwrap();
                    read_request_head(&mut stream).await;
                    let body = if step == 0 { "trusted" } else { "renewed" };
                    stream.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: image/png\r\ncache-control: max-age=1\r\ncontent-length: 7\r\nconnection: close\r\n\r\n{body}").as_bytes()).await.unwrap();
                    stream.shutdown().await.unwrap();
                }
            });
            let config = ProxyConfig {
                upstream: Some(address.to_string()),
                upstream_tls: true,
                upstream_sni: Some("localhost".to_owned()),
                upstream_ca_path: Some(fixture.ca_path.clone()),
                upstream_http_version: protocol,
                ..Default::default()
            };
            let cache = CacheConfig {
                enabled: true,
                memory: CacheMemoryConfig {
                    enabled: true,
                    ..Default::default()
                },
                status_header: Some("x-cache-status".to_owned()),
                stale_if_error_secs: Some(60),
                stale_if_error_on: vec![if allowed {
                    CacheStaleErrorKind::Tls
                } else {
                    CacheStaleErrorKind::Protocol
                }],
                ..Default::default()
            };
            let proxy =
                NativeHttp1Proxy::from_proxy_config(&config, DownstreamHttp1Policy::default())
                    .unwrap()
                    .unwrap()
                    .with_proxy_cache_config(&cache);
            let address = proxy_with_native(proxy).await;
            let first = downstream_get(address, "/asset.png").await;
            assert!(first.ends_with("trusted"), "{first}");
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            let failure = downstream_get(address, "/asset.png").await;
            assert_eq!(failure.ends_with("trusted"), allowed, "{failure}");
            if allowed {
                assert!(
                    failure
                        .to_ascii_lowercase()
                        .contains("x-cache-status: stale\r\n")
                );
            } else {
                assert!(failure.starts_with("HTTP/1.1 502"), "{failure}");
            }
            let recovery = downstream_get(address, "/asset.png").await;
            assert!(recovery.ends_with("renewed"), "{recovery}");
            origin.await.unwrap();
        }
    }
}

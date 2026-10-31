use std::{sync::Arc, time::Duration};

use fluxheim_config::{ProxyConfig, UpstreamHttpVersion};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::{net::TcpListener, sync::Barrier, task::JoinSet, time::timeout};
use tokio_rustls::TlsAcceptor;

use crate::{DownstreamHttp1Policy, NativeHttp1Proxy};

#[test]
fn plaintext_mixed_mode_validates_but_native_builder_rejects_it() {
    let config = ProxyConfig {
        upstream_http_version: UpstreamHttpVersion::Http1AndHttp2,
        ..Default::default()
    };
    config.validate().unwrap();
    assert!(
        NativeHttp1Proxy::from_proxy_config(&config, DownstreamHttp1Policy::default()).is_err()
    );
}

#[tokio::test]
async fn mixed_tls_h2_uses_two_connections_despite_one_stream_setting() {
    timeout(Duration::from_secs(10), async {
        let fixture = crate::native_http1_proxy_tls_tests::native_tls_fixture();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certs = CertificateDer::pem_slice_iter(fixture.chain_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(fixture.key_pem.as_bytes()).unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = ProxyConfig {
            upstream: Some(listener.local_addr().unwrap().to_string()),
            upstream_tls: true,
            upstream_sni: Some("localhost".into()),
            upstream_ca_path: Some(fixture.ca_path.clone()),
            upstream_http_version: UpstreamHttpVersion::Http1AndHttp2,
            upstream_h2_max_streams: Some(1),
            ..Default::default()
        };
        let proxy = NativeHttp1Proxy::from_proxy_config(&config, DownstreamHttp1Policy::default())
            .unwrap()
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        // JoinSet aborts remaining work if a bounded assertion fails.
        let mut clients = JoinSet::new();
        let mut origins = JoinSet::new();
        for _ in 0..2 {
            let upstream = proxy.upstream().clone();
            clients.spawn(async move {
                upstream
                    .send(&mut crate::native_http1_client_tests::request())
                    .await
                    .unwrap()
            });
        }
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let barrier = barrier.clone();
            origins.spawn(async move {
                let stream = acceptor.accept(stream).await.unwrap();
                let mut h2 = h2::server::handshake(stream).await.unwrap();
                let (_, mut respond) = h2.accept().await.unwrap().unwrap();
                // Both real origin requests are admitted before either replies.
                barrier.wait().await;
                respond
                    .send_response(
                        http::Response::builder().status(204).body(()).unwrap(),
                        true,
                    )
                    .unwrap();
                h2.graceful_shutdown();
                let _ = timeout(
                    Duration::from_secs(2),
                    std::future::poll_fn(|cx| h2.poll_closed(cx)),
                )
                .await;
            });
        }
        barrier.wait().await;
        while let Some(result) = clients.join_next().await {
            assert_eq!(result.unwrap().status(), 204);
        }
        while let Some(result) = origins.join_next().await {
            result.unwrap();
        }
    })
    .await
    .expect("mixed-mode contract must complete within ten seconds");
}

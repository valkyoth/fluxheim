use super::*;
use crate::{NativeHttp1Upstream, NativeHttp1UpstreamTls};

async fn tls_relay(
    peer: std::net::SocketAddr,
    fixture: &crate::native_http1_proxy_tls_tests::NativeTlsFixture,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificates = CertificateDer::pem_slice_iter(fixture.chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(fixture.key_pem.as_bytes()).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        if let Ok(mut encrypted) = acceptor.accept(stream).await {
            let mut upstream = tokio::net::TcpStream::connect(peer).await.unwrap();
            // The proxy closes this one-shot connection after reading its body.
            let _ = tokio::io::copy_bidirectional(&mut encrypted, &mut upstream).await;
        }
    });
    (address, task)
}

#[tokio::test]
async fn peer_variants_https_binds_context_and_verifies_name_and_ca() {
    for mode in ["trusted", "wrong-name", "wrong-ca"] {
        let fixture = crate::native_http1_proxy_tls_tests::native_tls_fixture();
        let other = crate::native_http1_proxy_tls_tests::native_tls_fixture();
        let root = tempfile::tempdir().unwrap();
        let (origin, calls, origin_task) = variant_origin(true).await;
        let config = policy("memory", root.path(), true);
        let (peer, peer_stop, peer_task) = route_proxy_listener_with_shutdown(
            NativeHttp1RouteProxy::new(Vec::new(), Some(proxy(origin, &config, Some(42)))),
        )
        .await;
        assert!(
            fetch(peer, &["special"], "/asset.png")
                .await
                .ends_with("[\"special\"]")
        );
        let (relay, relay_task) = tls_relay(peer, &fixture).await;
        let mut config = config;
        config.peer_fill.enabled = true;
        config.peer_fill.peers = vec![fluxheim_config::CachePeerConfig {
            name: "tls-peer".into(),
            base_url: format!("https://localhost:{}", relay.port()),
        }];
        let mut front = proxy(origin, &config, Some(42));
        let tls = NativeHttp1UpstreamTls::from_proxy_config(&fluxheim_config::ProxyConfig {
            upstream_tls: true,
            upstream_sni: Some(
                if mode == "wrong-name" {
                    "wrong.invalid"
                } else {
                    "localhost"
                }
                .into(),
            ),
            upstream_ca_path: Some(if mode == "wrong-ca" {
                other.ca_path.clone()
            } else {
                fixture.ca_path.clone()
            }),
            ..Default::default()
        })
        .unwrap()
        .unwrap();
        // Use the fixture CA only for this client; do not modify system trust.
        front.cache.as_mut().unwrap().peer_fill_peers[0].upstream =
            NativeHttp1Upstream::new(relay.to_string()).with_tls(tls);
        let (address, stop, task) =
            route_proxy_listener_with_shutdown(NativeHttp1RouteProxy::new(Vec::new(), Some(front)))
                .await;
        let response = fetch(address, &["special"], "/asset.png").await;
        assert!(response.ends_with("[\"special\"]"), "{response}");
        assert_eq!(
            response_header(&response, "x-cache-status").as_deref(),
            Some(if mode == "trusted" {
                "PEER-HIT"
            } else {
                "MISS"
            }),
            "{response}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if mode == "trusted" { 1 } else { 2 }
        );
        tokio::time::timeout(Duration::from_secs(5), relay_task)
            .await
            .unwrap()
            .unwrap();
        for (stop, task) in [(stop, task), (peer_stop, peer_task)] {
            stop.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap();
        }
        origin_task.abort();
        assert!(origin_task.await.unwrap_err().is_cancelled());
    }
}

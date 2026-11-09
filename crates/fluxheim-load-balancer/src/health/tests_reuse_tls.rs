use super::*;
use crate::backend::FluxHealthCheck;
use crate::health::tests_reuse_fixture::Fixture;

#[tokio::test]
async fn reuse_tls_isolates_policy_and_preserves_verification() {
    crate::install_test_crypto_provider();
    for grpc in [false, true] {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert = certificate.cert.der().clone();
        let mut server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(
                    certificate.signing_key.serialize_der(),
                )
                .into(),
            )
            .unwrap();
        server.alpn_protocols = vec![if grpc {
            b"h2".to_vec()
        } else {
            b"http/1.1".to_vec()
        }];
        let fixture = Fixture::start_with_tls(grpc, Some(Arc::new(server))).await;
        let make_check = |name: &str, trusted: bool| {
            let config = ProxyConfig {
                upstream_tls: true,
                upstream_sni: Some(name.to_owned()),
                ..Default::default()
            };
            let mut check = fixture.check(grpc, true);
            check.upstream_tls = true;
            check.connection_timeout = Duration::from_secs(3);
            check.read_timeout = Duration::from_secs(3);
            let mut tls = configured_tcp_health_check_tls(
                &config,
                if grpc {
                    HealthTlsAlpn::Http2
                } else {
                    HealthTlsAlpn::Http1
                },
            )
            .unwrap()
            .unwrap();
            if trusted {
                tls.trust_fixture_certificate(&cert, grpc);
            }
            check.tls = Some(tls);
            check
        };
        let check = make_check("localhost", true);
        for _ in 0..3 {
            check.check(&fixture.backend).await.unwrap();
        }
        assert_eq!(fixture.count(), 1);
        assert!(
            make_check("wrong.example", true)
                .check(&fixture.backend)
                .await
                .is_err()
        );
        assert!(
            make_check("localhost", false)
                .check(&fixture.backend)
                .await
                .is_err()
        );
        // A different TLS identity/policy cannot borrow the original verified connection.
        assert_eq!(fixture.count(), 3);
        check.check(&fixture.backend).await.unwrap();
        assert_eq!(fixture.count(), 3);
    }
}

use std::time::Duration;

use fluxheim_config::{DownstreamProxyProtocol, StaticCertificateConfig, TlsAlpnPolicy, TlsConfig};

use super::*;

#[tokio::test]
async fn https_proxy_protocol_accepts_untrusted_direct_tls_without_preamble() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certificate = temporary_localhost_certificate();
        let upstream = upstream_response("direct-tls-despite-proxy-policy").await;
        let mut config = fluxheim_config::Config::default();
        config.server.listen.clear();
        config.server.tls_listen = vec!["127.0.0.1:0".into()];
        config.server.proxy_protocol = DownstreamProxyProtocol::V1;
        config.server.trusted_proxies = vec!["192.0.2.10".into()];
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
        let plan = ServerPlan::from_config(&config).unwrap();
        assert!(plan.native_runtime_cutover_summary().is_ready());
        let runtime = NativeHttp1ProxyRuntime::bind_from_config(&config, &plan)
            .await
            .unwrap();
        let address = runtime.local_addrs()[0];
        let supervisor = NativeBackgroundSupervisor::new();
        let handle = runtime.start(&supervisor);
        let response = downstream_tls_get(address, certificate.cert_pem).await;
        // documented contract: trust and required-preamble checks were never applied.
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with("direct-tls-despite-proxy-policy"));
        assert!(supervisor.shutdown());
        for result in handle.join().await {
            result.unwrap();
        }
    })
    .await
    .expect("bounded HTTPS PROXY-policy characterization");
}

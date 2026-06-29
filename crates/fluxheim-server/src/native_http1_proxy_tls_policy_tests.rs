use crate::{DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1ProxyConfigError};

#[test]
fn native_proxy_config_rejects_mixed_static_ip_tls_without_sni() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["localhost:3000".to_owned(), "127.0.0.1:3001".to_owned()],
        upstream_tls: true,
        upstream_verify_cert: true,
        load_balance: static_load_balance_without_health_check(),
        ..Default::default()
    };

    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy)
    );
}

fn static_load_balance_without_health_check() -> fluxheim_config::LoadBalanceConfig {
    fluxheim_config::LoadBalanceConfig {
        health_check: fluxheim_config::LoadBalanceHealthCheckConfig {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn native_proxy_config_rejects_invalid_upstream_tls_material_policy() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("localhost:3000".to_owned()),
        upstream_ca_path: Some(std::path::PathBuf::from("/tmp/upstream-ca.pem")),
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy)
    );

    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("localhost:3000".to_owned()),
        upstream_tls: true,
        upstream_sni: Some("localhost".to_owned()),
        upstream_verify_cert: false,
        upstream_verify_hostname: true,
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy)
    );

    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("localhost:3000".to_owned()),
        upstream_tls: true,
        upstream_sni: Some("localhost".to_owned()),
        upstream_client_cert_path: Some(std::path::PathBuf::from("/tmp/client.pem")),
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy)
    );
}

use crate::{DownstreamHttp1Policy, NativeHttp1Proxy, NativeHttp1ProxyConfigError};

use super::proxy_config_with_error_page;

#[test]
fn native_proxy_config_returns_none_without_upstream() {
    let proxy = fluxheim_config::ProxyConfig::disabled();

    let native =
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).unwrap();

    assert!(native.is_none());
}

#[test]
fn native_proxy_config_rejects_unsupported_upstream_features() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_tls: true,
        ..Default::default()
    };
    #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTls)
    );
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTlsPolicy)
    );

    let proxy = fluxheim_config::ProxyConfig {
        upstreams_file: Some(std::path::PathBuf::from("/tmp/upstreams.txt")),
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::DynamicUpstreamDiscovery)
    );
}

#[cfg(feature = "load-balancer")]
#[test]
fn native_proxy_config_accepts_scoped_dynamic_dns_load_balance_policy() {
    let proxy = fluxheim_config::ProxyConfig {
        upstreams: vec!["localhost:3000".to_owned()],
        upstream_dns_refresh_secs: Some(30),
        upstream_dns_allow_private_backends: true,
        ..Default::default()
    };

    let (native, service) = NativeHttp1Proxy::from_proxy_config_with_native_load_balancer(
        "dynamic-dns",
        "dynamic.test",
        None,
        &proxy,
        DownstreamHttp1Policy::default(),
        0,
    )
    .unwrap()
    .expect("native dynamic proxy");

    assert_eq!(native.upstreams().len(), 1);
    assert!(service.is_some());
}

#[test]
fn native_proxy_config_rejects_unsupported_proxy_policy_layers() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        auth_request: fluxheim_config::AuthRequestConfig {
            enabled: true,
            url: Some("http://127.0.0.1:3001/auth".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    };
    #[cfg(not(feature = "auth-request"))]
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::AuthRequest)
    );
    #[cfg(feature = "auth-request")]
    assert!(NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).is_ok());

    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        mirror: fluxheim_config::TrafficMirrorConfig {
            enabled: true,
            base_url: Some("http://127.0.0.1:3001".to_owned()),
            ..Default::default()
        },
        ..Default::default()
    };
    #[cfg(not(all(feature = "traffic-mirror", not(feature = "privacy-mode"))))]
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::TrafficMirror)
    );
    #[cfg(all(feature = "traffic-mirror", not(feature = "privacy-mode")))]
    assert!(NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).is_ok());

    let errors = tempfile::tempdir().unwrap();
    std::fs::write(errors.path().join("502.html"), "native error page\n").unwrap();
    let proxy = proxy_config_with_error_page(errors.path().to_path_buf());
    assert!(NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).is_ok());
}

#[test]
fn native_proxy_config_keeps_unsupported_upstream_http2_modes_as_explicit_blocker() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http1AndHttp2,
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamHttp2)
    );

    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http1AndHttp2,
        upstream_tls: true,
        upstream_sni: Some("localhost".to_owned()),
        ..Default::default()
    };
    #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamHttp2)
    );
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    assert!(NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).is_ok());

    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        upstream_tls: true,
        upstream_sni: Some("localhost".to_owned()),
        ..Default::default()
    };
    #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend")))]
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTls)
    );
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    assert!(NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).is_ok());

    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        upstream_h2_ping_interval_secs: Some(30),
        ..Default::default()
    };
    assert!(NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).is_ok());
}

#[test]
fn native_proxy_config_rejects_unsupported_transport_and_accepts_downstream_timeout() {
    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_tcp_keepalive_idle_secs: Some(30),
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy)
    );

    #[cfg(not(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    )))]
    {
        let proxy = fluxheim_config::ProxyConfig {
            upstream: Some("127.0.0.1:3000".to_owned()),
            upstream_tcp_keepalive_idle_secs: Some(30),
            upstream_tcp_keepalive_interval_secs: Some(10),
            upstream_tcp_keepalive_count: Some(3),
            upstream_tcp_user_timeout_ms: Some(15000),
            ..Default::default()
        };
        assert_eq!(
            NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
            Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy)
        );
    }

    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        upstream_tcp_keepalive_idle_secs: Some(30),
        upstream_tcp_keepalive_interval_secs: Some(10),
        upstream_tcp_keepalive_count: Some(3),
        upstream_tcp_fast_open: true,
        ..Default::default()
    };
    assert_eq!(
        NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()),
        Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy)
    );

    let proxy = fluxheim_config::ProxyConfig {
        upstream: Some("127.0.0.1:3000".to_owned()),
        downstream_read_timeout_secs: Some(1),
        ..Default::default()
    };
    assert!(NativeHttp1Proxy::from_proxy_config(&proxy, DownstreamHttp1Policy::default()).is_ok());
}

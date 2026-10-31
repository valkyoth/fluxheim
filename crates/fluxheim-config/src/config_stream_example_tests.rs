use crate::{Config, StreamRouteConfig};

#[test]
fn stream_operator_recipes_validate() {
    for source in [
        include_str!("../../../examples/stream/local.toml"),
        include_str!("../../../examples/stream-tcp.toml"),
    ] {
        let config: Config = toml::from_str(source).unwrap();
        // Validate stream policy without depending on machine-specific process paths.
        config.stream.validate().unwrap();
    }
}

#[test]
fn stream_operator_limits_have_documented_boundaries() {
    let base = StreamRouteConfig {
        name: "echo".into(),
        listen: vec!["127.0.0.1:18080".into()],
        upstream: Some("127.0.0.1:19001".into()),
        ..Default::default()
    };
    assert_eq!(base.connect_timeout_secs, 5);
    assert_eq!(base.idle_timeout_secs, 300);
    assert_eq!(base.proxy_header_timeout_secs, 10);
    assert_eq!(base.max_connections, 1024);
    for invalid in [
        StreamRouteConfig {
            connect_timeout_secs: 0,
            ..base.clone()
        },
        StreamRouteConfig {
            idle_timeout_secs: 86_401,
            ..base.clone()
        },
        StreamRouteConfig {
            proxy_header_timeout_secs: 61,
            ..base.clone()
        },
        StreamRouteConfig {
            max_connection_secs: Some(0),
            ..base.clone()
        },
        StreamRouteConfig {
            max_connection_secs: Some(86_401),
            ..base.clone()
        },
        StreamRouteConfig {
            max_connection_bytes: Some(0),
            ..base.clone()
        },
        StreamRouteConfig {
            max_connections: 1_000_001,
            ..base.clone()
        },
    ] {
        assert!(invalid.validate().is_err(), "{invalid:?}");
    }
    StreamRouteConfig {
        connect_timeout_secs: 86_400,
        idle_timeout_secs: 86_400,
        proxy_header_timeout_secs: 60,
        max_connection_secs: Some(86_400),
        max_connection_bytes: Some(1),
        max_connections: 0,
        ..base
    }
    .validate()
    .unwrap();
}

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
#[test]
fn stream_alternative_identity_is_accepted_by_validation() {
    // documented contract: runtime backend parity is covered by the live smoke.
    StreamRouteConfig {
        name: "tls".into(),
        listen: vec!["127.0.0.1:18080".into()],
        upstream: Some("127.0.0.1:19001".into()),
        upstream_tls: true,
        upstream_sni: Some("backend.example.test".into()),
        upstream_alternative_cn: Some("different.example.test".into()),
        ..Default::default()
    }
    .validate()
    .unwrap();
}

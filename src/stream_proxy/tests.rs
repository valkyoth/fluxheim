use super::{StreamProxyApp, proxy_stream_connection, resolve_upstream_socket_addr};
use crate::config::{DownstreamProxyProtocol, StreamRouteConfig, UpstreamProxyProtocol};
use std::io;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn plain_options(
    idle_timeout: std::time::Duration,
    max_connection_bytes: Option<u64>,
) -> super::StreamProxyConnectionOptions {
    plain_options_with_lifetime(idle_timeout, None, max_connection_bytes)
}

fn plain_options_with_lifetime(
    idle_timeout: std::time::Duration,
    max_connection_lifetime: Option<std::time::Duration>,
    max_connection_bytes: Option<u64>,
) -> super::StreamProxyConnectionOptions {
    super::StreamProxyConnectionOptions {
        connect_timeout: std::time::Duration::from_secs(1),
        idle_timeout,
        max_connection_lifetime,
        max_connection_bytes,
        upstream_proxy_protocol: UpstreamProxyProtocol::Off,
        upstream_tls: false,
        upstream_dns_allow_private_addresses: false,
        #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl"))]
        upstream_tls_connector: None,
    }
}

#[test]
fn stream_app_selects_upstreams_round_robin() {
    let app = StreamProxyApp::from_config(&StreamRouteConfig {
        name: "tcp".to_owned(),
        listen: vec!["127.0.0.1:12345".to_owned()],
        upstream: None,
        upstreams: vec!["127.0.0.1:5432".to_owned(), "127.0.0.1:6432".to_owned()],
        upstream_weights: Vec::new(),
        upstream_aliases: Vec::new(),
        backup_upstreams: Vec::new(),
        drain_upstreams: Vec::new(),
        connect_timeout_secs: 1,
        idle_timeout_secs: 1,
        proxy_header_timeout_secs: 10,
        max_connection_secs: None,
        max_connection_bytes: None,
        max_connections: 0,
        downstream_proxy_protocol: DownstreamProxyProtocol::Off,
        trusted_proxies: Vec::new(),
        allow_sources: Vec::new(),
        deny_sources: Vec::new(),
        upstream_proxy_protocol: UpstreamProxyProtocol::Off,
        upstream_tls: false,
        upstream_dns_allow_private_addresses: false,
        upstream_sni: None,
        upstream_verify_cert: true,
        upstream_verify_hostname: true,
        upstream_alternative_cn: None,
        upstream_ca_path: None,
        upstream_client_cert_path: None,
        upstream_client_key_path: None,
    })
    .unwrap();

    assert_eq!(
        app.select_upstream_candidates()[0].authority.as_ref(),
        "127.0.0.1:5432"
    );
    assert_eq!(
        app.select_upstream_candidates()[0].authority.as_ref(),
        "127.0.0.1:6432"
    );
    assert_eq!(
        app.select_upstream_candidates()[0].authority.as_ref(),
        "127.0.0.1:5432"
    );
}

#[test]
fn stream_app_respects_weights_and_drained_upstreams() {
    let app = StreamProxyApp::from_config(&StreamRouteConfig {
        name: "tcp".to_owned(),
        listen: vec!["127.0.0.1:12345".to_owned()],
        upstream: None,
        upstreams: vec![
            "127.0.0.1:5432".to_owned(),
            "127.0.0.1:6432".to_owned(),
            "127.0.0.1:7432".to_owned(),
        ],
        upstream_weights: vec![1, 2, 1],
        upstream_aliases: vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
        backup_upstreams: vec!["127.0.0.1:7432".to_owned()],
        drain_upstreams: vec!["127.0.0.1:5432".to_owned()],
        ..StreamRouteConfig::default()
    })
    .unwrap();

    let first = app.select_upstream_candidates();
    let second = app.select_upstream_candidates();
    let third = app.select_upstream_candidates();

    assert_eq!(first[0].label(), "b");
    assert_eq!(second[0].label(), "b");
    assert_eq!(third[0].label(), "b");
    assert!(first.iter().any(|candidate| candidate.backup));
    assert!(
        first
            .iter()
            .all(|candidate| candidate.authority.as_ref() != "127.0.0.1:5432")
    );
}

#[test]
fn stream_trusted_sources_match_exact_and_cidr() {
    let exact = fluxheim_stream::StreamSourceMatcher::parse("127.0.0.1", "trusted proxy").unwrap();
    assert!(exact.matches("127.0.0.1".parse().unwrap()));
    assert!(!exact.matches("127.0.0.2".parse().unwrap()));

    let cidr = fluxheim_stream::StreamSourceMatcher::parse("10.0.0.0/24", "trusted proxy").unwrap();
    assert!(cidr.matches("10.0.0.42".parse().unwrap()));
    assert!(!cidr.matches("10.0.1.42".parse().unwrap()));

    assert!(fluxheim_stream::StreamSourceMatcher::parse("10.0.0.0/64", "trusted proxy").is_err());
}

#[test]
fn stream_source_policy_denies_before_allowing() {
    let app = StreamProxyApp::from_config(&StreamRouteConfig {
        name: "tcp".to_owned(),
        listen: vec!["127.0.0.1:12345".to_owned()],
        upstream: Some("127.0.0.1:5432".to_owned()),
        allow_sources: vec!["10.0.0.0/8".to_owned()],
        deny_sources: vec!["10.0.0.13".to_owned()],
        ..StreamRouteConfig::default()
    })
    .unwrap();

    assert!(app.source_allowed(Some("10.0.0.12:1234".parse().unwrap())));
    assert!(!app.source_allowed(Some("10.0.0.13:1234".parse().unwrap())));
    assert!(!app.source_allowed(Some("192.0.2.10:1234".parse().unwrap())));
    assert!(!app.source_allowed(None));

    let app = StreamProxyApp::from_config(&StreamRouteConfig {
        name: "tcp".to_owned(),
        listen: vec!["127.0.0.1:12345".to_owned()],
        upstream: Some("127.0.0.1:5432".to_owned()),
        deny_sources: vec!["192.0.2.0/24".to_owned()],
        ..StreamRouteConfig::default()
    })
    .unwrap();
    assert!(app.source_allowed(None));
    assert!(app.source_allowed(Some("10.0.0.12:1234".parse().unwrap())));
    assert!(!app.source_allowed(Some("192.0.2.10:1234".parse().unwrap())));
}

#[test]
fn stream_dns_rebind_guard_rejects_private_resolved_addresses() {
    assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
        "127.0.0.1".parse().unwrap()
    ));
    assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
        "10.0.0.1".parse().unwrap()
    ));
    assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
        "169.254.169.254".parse().unwrap()
    ));
    assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
        "100.64.0.1".parse().unwrap()
    ));
    assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
        "198.18.0.1".parse().unwrap()
    ));
    assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
        "240.0.0.1".parse().unwrap()
    ));
    assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
        "::1".parse().unwrap()
    ));
    assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
        "fc00::1".parse().unwrap()
    ));
    assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
        "2001:db8::1".parse().unwrap()
    ));
    assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
        "64:ff9b:1::1".parse().unwrap()
    ));
    assert!(!fluxheim_stream::stream_dns_resolved_address_allowed(
        "2002::1".parse().unwrap()
    ));
    assert!(fluxheim_stream::stream_dns_resolved_address_allowed(
        "1.1.1.1".parse().unwrap()
    ));
    assert!(fluxheim_stream::stream_dns_resolved_address_allowed(
        "2606:4700:4700::1111".parse().unwrap()
    ));
}

#[test]
fn stream_dns_rebind_guard_allows_explicit_ip_literal_upstreams() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();

    runtime.block_on(async {
        assert_eq!(
            resolve_upstream_socket_addr("127.0.0.1:5432", false)
                .await
                .unwrap(),
            "127.0.0.1:5432".parse().unwrap()
        );
    });
}

#[test]
fn stream_proxy_copies_bytes_bidirectionally() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    runtime.block_on(async {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut input = [0u8; 4];
            stream.read_exact(&mut input).await.unwrap();
            assert_eq!(&input, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let downstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let downstream_addr = downstream_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut downstream, _) = downstream_listener.accept().await.unwrap();
            proxy_stream_connection(
                &mut downstream,
                &upstream_addr.to_string(),
                plain_options(std::time::Duration::from_secs(1), None),
                None,
                None,
            )
            .await
            .unwrap()
        });

        let mut client = tokio::net::TcpStream::connect(downstream_addr)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        client.shutdown().await.unwrap();
        let mut output = Vec::new();
        client.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"pong");

        let copied = proxy_task.await.unwrap();
        assert_eq!(copied, (4, 4));
        upstream_task.await.unwrap();
    });
}

#[test]
fn stream_proxy_rejects_connection_byte_overflow() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    runtime.block_on(async {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut input = Vec::new();
            let _ = stream.read_to_end(&mut input).await;
        });

        let downstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let downstream_addr = downstream_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut downstream, _) = downstream_listener.accept().await.unwrap();
            proxy_stream_connection(
                &mut downstream,
                &upstream_addr.to_string(),
                plain_options(std::time::Duration::from_secs(1), Some(3)),
                None,
                None,
            )
            .await
        });

        let mut client = tokio::net::TcpStream::connect(downstream_addr)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        let _ = client.shutdown().await;

        let error = proxy_task.await.unwrap().unwrap_err();
        assert_eq!(error.into_io().kind(), io::ErrorKind::PermissionDenied);
        upstream_task.await.unwrap();
    });
}

#[test]
fn stream_proxy_times_out_idle_connection_between_reads() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    runtime.block_on(async {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (_stream, _) = upstream_listener.accept().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let downstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let downstream_addr = downstream_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut downstream, _) = downstream_listener.accept().await.unwrap();
            proxy_stream_connection(
                &mut downstream,
                &upstream_addr.to_string(),
                plain_options(std::time::Duration::from_millis(50), None),
                None,
                None,
            )
            .await
        });

        let _client = tokio::net::TcpStream::connect(downstream_addr)
            .await
            .unwrap();

        let error = proxy_task.await.unwrap().unwrap_err();
        assert_eq!(error.into_io().kind(), io::ErrorKind::TimedOut);
        upstream_task.abort();
    });
}

#[test]
fn stream_proxy_enforces_connection_lifetime() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    runtime.block_on(async {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (_stream, _) = upstream_listener.accept().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let downstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let downstream_addr = downstream_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut downstream, _) = downstream_listener.accept().await.unwrap();
            proxy_stream_connection(
                &mut downstream,
                &upstream_addr.to_string(),
                plain_options_with_lifetime(
                    std::time::Duration::from_secs(1),
                    Some(std::time::Duration::from_millis(50)),
                    None,
                ),
                None,
                None,
            )
            .await
        });

        let _client = tokio::net::TcpStream::connect(downstream_addr)
            .await
            .unwrap();

        let error = proxy_task.await.unwrap().unwrap_err();
        assert_eq!(error.into_io().kind(), io::ErrorKind::TimedOut);
        upstream_task.abort();
    });
}

#[test]
fn stream_proxy_writes_upstream_proxy_protocol_v2() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    runtime.block_on(async {
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let mut header = [0u8; 28];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(&header[..12], b"\r\n\r\n\0\r\nQUIT\n");
            assert_eq!(&header[12..16], &[0x21, 0x11, 0x00, 0x0c]);

            let mut input = [0u8; 4];
            stream.read_exact(&mut input).await.unwrap();
            assert_eq!(&input, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let downstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let downstream_addr = downstream_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut downstream, _) = downstream_listener.accept().await.unwrap();
            let mut options = plain_options(std::time::Duration::from_secs(1), None);
            options.upstream_proxy_protocol = UpstreamProxyProtocol::V2;
            proxy_stream_connection(
                &mut downstream,
                &upstream_addr.to_string(),
                options,
                Some("127.0.0.1:50000".parse().unwrap()),
                Some("127.0.0.1:50001".parse().unwrap()),
            )
            .await
            .unwrap()
        });

        let mut client = tokio::net::TcpStream::connect(downstream_addr)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        client.shutdown().await.unwrap();
        let mut output = Vec::new();
        client.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"pong");

        let copied = proxy_task.await.unwrap();
        assert_eq!(copied, (4, 4));
        upstream_task.await.unwrap();
    });
}

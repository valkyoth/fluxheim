use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::native_http1_proxy_tls_tests::{downstream_get, native_tls_fixture, proxy_with_native};
use crate::{DownstreamHttp1Policy, NativeHttp1Proxy};

async fn tls_h2_upstream(chain_pem: String, key_pem: String) -> std::net::SocketAddr {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let Ok(stream) = acceptor.accept(stream).await else {
            return;
        };
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let Some(stream) = connection.accept().await else {
            panic!("expected native TLS H2 upstream request");
        };
        let (request, mut respond) = stream.unwrap();
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.uri().path_and_query().unwrap().as_str(), "/h2tls");
        assert_eq!(request.uri().scheme_str(), Some("https"));
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("x-origin", "tls-h2")
            .body(())
            .unwrap();
        let mut send = respond.send_response(response, false).unwrap();
        send.send_data(bytes::Bytes::from_static(b"hello tls h2 native"), true)
            .unwrap();
        connection.graceful_shutdown();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            std::future::poll_fn(|context| connection.poll_closed(context)),
        )
        .await;
    });
    addr
}

#[tokio::test]
async fn native_proxy_forwards_to_tls_http2_upstream_with_alpn() {
    let fixture = native_tls_fixture();
    let upstream = tls_h2_upstream(fixture.chain_pem.clone(), fixture.key_pem.clone()).await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        upstream_tls: true,
        upstream_sni: Some("localhost".to_owned()),
        upstream_ca_path: Some(fixture.ca_path.clone()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http2,
        ..Default::default()
    };
    let native =
        NativeHttp1Proxy::from_proxy_config(&proxy_config, DownstreamHttp1Policy::default())
            .unwrap()
            .expect("native TLS H2 proxy");
    let proxy = proxy_with_native(native).await;

    let response = downstream_get(proxy, "/h2tls").await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("x-origin: tls-h2\r\n"));
    assert!(response.ends_with("hello tls h2 native"));
}

#[tokio::test]
async fn native_proxy_http1_and_http2_negotiates_tls_http2_upstream() {
    let fixture = native_tls_fixture();
    let upstream = tls_h2_upstream(fixture.chain_pem.clone(), fixture.key_pem.clone()).await;
    let proxy_config = fluxheim_config::ProxyConfig {
        upstream: Some(upstream.to_string()),
        upstream_tls: true,
        upstream_sni: Some("localhost".to_owned()),
        upstream_ca_path: Some(fixture.ca_path.clone()),
        upstream_http_version: fluxheim_config::UpstreamHttpVersion::Http1AndHttp2,
        ..Default::default()
    };
    let native =
        NativeHttp1Proxy::from_proxy_config(&proxy_config, DownstreamHttp1Policy::default())
            .unwrap()
            .expect("native fallback TLS H2 proxy");
    let proxy = proxy_with_native(native).await;

    let response = downstream_get(proxy, "/h2tls").await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {response:?}"
    );
    assert!(response.contains("x-origin: tls-h2\r\n"));
    assert!(response.ends_with("hello tls h2 native"));
}

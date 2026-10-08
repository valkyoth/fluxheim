//! Dependency feasibility only; no public server implementation or runtime wiring.

#[cfg(any(
    all(feature = "ring", feature = "aws-lc"),
    not(any(feature = "ring", feature = "aws-lc"))
))]
compile_error!("select exactly one probe crypto provider");

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, sync::Arc, time::Duration};

    use bytes::{Buf, Bytes};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use tokio::time::timeout;

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        #[cfg(feature = "aws-lc")]
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        #[cfg(not(feature = "aws-lc"))]
        let provider = rustls::crypto::ring::default_provider();
        Arc::new(provider)
    }

    fn endpoints(migration: bool) -> (quinn::Endpoint, quinn::Endpoint) {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert = generated.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()).into();
        let mut tls = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.max_early_data_size = 0;
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.migration(migration);
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(2).try_into().unwrap()));
        transport.datagram_receive_buffer_size(None);
        config.transport_config(Arc::new(transport));
        let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.enable_early_data = false;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        (server, client)
    }

    async fn connect(
        server: &quinn::Endpoint,
        client: &quinn::Endpoint,
    ) -> (quinn::Connection, quinn::Connection) {
        let connecting = client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap();
        let (outgoing, incoming) = tokio::join!(connecting, async {
            server.accept().await.unwrap().await.unwrap()
        });
        let outgoing = outgoing.unwrap();
        let data = outgoing
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .unwrap();
        assert_eq!(data.protocol.as_deref(), Some(b"h3".as_slice()));
        (incoming, outgoing)
    }

    #[tokio::test]
    async fn verified_h3_streams_data_and_trailers_before_completion() {
        timeout(Duration::from_secs(10), async {
            let (server, client) = endpoints(false);
            let (incoming, outgoing) = connect(&server, &client).await;
            let (continue_tx, continue_rx) = tokio::sync::oneshot::channel();
            let server_task = tokio::spawn(async move {
                let mut conn = h3::server::builder()
                    .max_field_section_size(8192)
                    .build::<_, Bytes>(h3_quinn::Connection::new(incoming))
                    .await
                    .unwrap();
                let (request, mut stream) = conn
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                assert_eq!(request.uri().path(), "/probe");
                stream
                    .send_response(http::Response::builder().status(200).body(()).unwrap())
                    .await
                    .unwrap();
                stream
                    .send_data(Bytes::from_static(b"first"))
                    .await
                    .unwrap();
                // The producer cannot finish until the client proves first-byte delivery.
                continue_rx.await.unwrap();
                stream.send_data(Bytes::from_static(b"last")).await.unwrap();
                let mut trailers = http::HeaderMap::new();
                trailers.insert("x-probe", "complete".parse().unwrap());
                stream.send_trailers(trailers).await.unwrap();
                stream.finish().await.unwrap();
                conn.accept().await.ok();
            });
            let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(outgoing))
                .await
                .unwrap();
            let client_task =
                tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
            let request = http::Request::builder()
                .uri("https://localhost/probe")
                .body(())
                .unwrap();
            let mut stream = sender.send_request(request).await.unwrap();
            stream.finish().await.unwrap();
            assert_eq!(stream.recv_response().await.unwrap().status(), 200);
            let mut first = stream.recv_data().await.unwrap().unwrap();
            assert_eq!(first.copy_to_bytes(first.remaining()), b"first".as_slice());
            continue_tx.send(()).unwrap();
            let mut rest = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                rest.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            assert_eq!(rest, b"last");
            assert_eq!(
                stream.recv_trailers().await.unwrap().unwrap()["x-probe"],
                "complete"
            );
            client.close(0u32.into(), b"done");
            server_task.await.unwrap();
            client_task.await.unwrap();
            server.close(0u32.into(), b"done");
        })
        .await
        .expect("bounded H3 feasibility probe");
    }

    async fn echo(server: &quinn::Connection, client: &quinn::Connection) {
        let send = async {
            let mut stream = client.open_uni().await.unwrap();
            stream.write_all(b"probe").await.unwrap();
            stream.finish().unwrap();
        };
        let recv = async {
            let mut stream = server.accept_uni().await.unwrap();
            assert_eq!(stream.read_to_end(16).await.unwrap(), b"probe");
        };
        tokio::join!(send, recv);
    }

    async fn check_rebinding(bind_address: &str) {
        timeout(Duration::from_secs(20), async {
            for migration in [false, true] {
                let (server, client) = endpoints(migration);
                let (incoming, outgoing) = connect(&server, &client).await;
                echo(&incoming, &outgoing).await;
                let original = incoming.remote_address();
                client
                    .rebind(UdpSocket::bind(bind_address).unwrap())
                    .unwrap();
                assert_ne!(original, client.local_addr().unwrap());
                if migration {
                    echo(&incoming, &outgoing).await;
                    assert_eq!(incoming.remote_address(), client.local_addr().unwrap());
                } else {
                    let mut send = outgoing.open_uni().await.unwrap();
                    send.write_all(b"new path").await.unwrap();
                    send.finish().unwrap();
                    assert!(
                        timeout(Duration::from_millis(500), incoming.accept_uni())
                            .await
                            .is_err()
                    );
                    assert_eq!(incoming.remote_address(), original);
                    assert!(matches!(
                        incoming.closed().await,
                        quinn::ConnectionError::TimedOut
                    ));
                    let (fresh_incoming, fresh_outgoing) = connect(&server, &client).await;
                    echo(&fresh_incoming, &fresh_outgoing).await;
                }
                client.close(0u32.into(), b"done");
                server.close(0u32.into(), b"done");
            }
        })
        .await
        .expect("bounded rebind/reconnect feasibility probe");
    }

    #[tokio::test]
    async fn migration_switch_controls_port_rebinding_and_reconnect() {
        check_rebinding("127.0.0.1:0").await;
    }

    // Linux routes 127/8 locally without provisioning additional loopback aliases.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn migration_switch_controls_ip_change_and_reconnect() {
        check_rebinding("127.0.0.2:0").await;
    }
}

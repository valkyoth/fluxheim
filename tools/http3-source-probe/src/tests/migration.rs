//! Characterization, not a Fluxheim authorization implementation.

use super::{connect, endpoints};
use bytes::{Buf, Bytes};
use std::{
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{sync::oneshot, time::timeout};

const DEADLINE: Duration = Duration::from_secs(15);
const CHUNK: usize = 16 * 1024;
const CHUNKS: usize = 32;

async fn ongoing_h3_transfer(bind_address: &str) {
    timeout(DEADLINE, async {
        let (server, client) = endpoints(true);
        let (incoming, outgoing) = connect(&server, &client).await;
        let original_peer = incoming.remote_address();
        let server_id = incoming.stable_id();
        let client_id = outgoing.stable_id();
        let mut session_before = [0; 32];
        outgoing
            .export_keying_material(&mut session_before, b"migration-probe", b"continuity")
            .unwrap();
        let (server_done_tx, server_done_rx) = oneshot::channel();
        let (close_tx, close_rx) = oneshot::channel();
        let server_connection = incoming.clone();
        let server_future = async move {
            let mut conn = h3::server::builder()
                .max_field_section_size(8192)
                .build::<_, Bytes>(h3_quinn::Connection::new(server_connection))
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
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), "/continuity");
            let stream_id = stream.id();
            stream.send_response(http::Response::new(())).await.unwrap();
            let mut bytes = 0;
            while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                let chunk = chunk.copy_to_bytes(chunk.remaining());
                bytes += chunk.len();
                assert!(bytes <= CHUNK * CHUNKS);
                stream.send_data(chunk).await.unwrap();
            }
            assert_eq!(bytes, CHUNK * CHUNKS);
            assert_eq!(stream.id(), stream_id);
            let mut trailers = http::HeaderMap::new();
            trailers.insert("x-probe", "complete".parse().unwrap());
            stream.send_trailers(trailers).await.unwrap();
            stream.finish().await.unwrap();
            server_done_tx.send(stream_id).unwrap();
            // Drive the control stream and reject an unexpected second request.
            tokio::select! {
                biased;
                _ = close_rx => {}
                _ = conn.accept() => panic!("unexpected extra request/closure"),
            }
        };
        let client_future = async {
            let (mut driver, mut sender) =
                h3::client::new(h3_quinn::Connection::new(outgoing.clone()))
                    .await
                    .unwrap();
            let transfer = async {
                let request = http::Request::builder()
                    .method("POST")
                    .uri("https://localhost/continuity")
                    .body(())
                    .unwrap();
                let mut stream = sender.send_request(request).await.unwrap();
                let stream_id = stream.id();
                assert_eq!(stream.recv_response().await.unwrap().status(), 200);
                for index in 0..CHUNKS {
                    if index == CHUNKS / 2 {
                        // Half the same POST has already been uploaded and echoed.
                        client
                            .rebind(UdpSocket::bind(bind_address).unwrap())
                            .unwrap();
                        assert_ne!(client.local_addr().unwrap(), original_peer);
                    }
                    let expected = vec![index as u8; CHUNK];
                    stream
                        .send_data(Bytes::copy_from_slice(&expected))
                        .await
                        .unwrap();
                    let mut echoed = Vec::new();
                    while echoed.len() < expected.len() {
                        let mut data = stream.recv_data().await.unwrap().expect("echo bytes");
                        echoed.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                    }
                    assert_eq!(echoed, expected);
                }
                stream.finish().await.unwrap();
                assert!(stream.recv_data().await.unwrap().is_none());
                assert_eq!(
                    stream.recv_trailers().await.unwrap().unwrap()["x-probe"],
                    "complete"
                );
                assert_eq!(stream.id(), stream_id);
                assert_eq!(server_done_rx.await.unwrap(), stream_id);
                assert_eq!(incoming.remote_address(), client.local_addr().unwrap());
                assert_eq!(incoming.stable_id(), server_id);
                assert_eq!(outgoing.stable_id(), client_id);
                let mut session_after = [0; 32];
                outgoing
                    .export_keying_material(&mut session_after, b"migration-probe", b"continuity")
                    .unwrap();
                assert!(
                    session_before == session_after,
                    "TLS session must not change"
                );
                assert!(incoming.close_reason().is_none());
                assert!(outgoing.close_reason().is_none());
                assert_eq!(server.open_connections(), 1);
                assert_eq!(client.open_connections(), 1);
                close_tx.send(()).unwrap();
            };
            tokio::select! {
                _ = transfer => {}
                error = std::future::poll_fn(|cx| driver.poll_close(cx)) => {
                    panic!("client driver closed during transfer: {error:?}");
                }
            }
        };
        tokio::join!(server_future, client_future);
        client.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
    })
    .await
    .expect("bounded ongoing H3 migration probe");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_post_and_response_continue_on_same_stream_after_port_change() {
    ongoing_h3_transfer("127.0.0.1:0").await;
}

// Linux routes the second loopback IP without changing host network settings.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_post_and_response_continue_on_same_stream_after_ip_change() {
    ongoing_h3_transfer("127.0.0.2:0").await;
}

#[derive(Debug, Default)]
struct ReceiveGate(Mutex<(bool, Option<Waker>)>);

impl ReceiveGate {
    fn pause(&self) {
        self.0.lock().unwrap().0 = true;
    }

    fn resume(&self) {
        let waker = {
            let mut state = self.0.lock().unwrap();
            state.0 = false;
            state.1.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

#[derive(Debug)]
struct PausableSocket {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    gate: Arc<ReceiveGate>,
}

impl PausableSocket {
    fn bind(address: &str, gate: Arc<ReceiveGate>) -> Arc<Self> {
        let inner = quinn::default_runtime()
            .unwrap()
            .wrap_udp_socket(UdpSocket::bind(address).unwrap())
            .unwrap();
        Arc::new(Self { inner, gate })
    }
}

impl quinn::AsyncUdpSocket for PausableSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.gate.0.lock().unwrap();
        if state.0 {
            // Both sockets belong to one endpoint receive driver.
            state.1 = Some(cx.waker().clone());
            return Poll::Pending;
        }
        drop(state);
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

async fn unvalidated_path_visibility(bind_address: &str) {
    timeout(DEADLINE, async {
        let (server, client) = endpoints(true);
        let gate = Arc::new(ReceiveGate::default());
        client
            .rebind_abstract(PausableSocket::bind("127.0.0.1:0", gate.clone()))
            .unwrap();
        let (incoming, outgoing) = connect(&server, &client).await;
        let original = incoming.remote_address();
        let mut send = outgoing.open_uni().await.unwrap();
        send.write_all(b"before").await.unwrap();
        let mut recv = incoming.accept_uni().await.unwrap();
        let mut first = [0; 6];
        recv.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"before");
        let stream_id = recv.id();
        let responses = incoming.stats().frame_rx.path_response;
        assert_eq!(responses, 0);

        // Block receives on both old and new client sockets. The client cannot
        // learn/respond to the server's new-path challenge until resumed.
        gate.pause();
        client
            .rebind_abstract(PausableSocket::bind(bind_address, gate.clone()))
            .unwrap();
        send.write_all(b"after").await.unwrap();
        let mut second = [0; 5];
        recv.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"after");
        assert_eq!(recv.id(), stream_id);
        assert_ne!(incoming.remote_address(), original);
        assert_eq!(incoming.remote_address(), client.local_addr().unwrap());
        let mut new_send = outgoing.open_uni().await.unwrap();
        new_send.write_all(b"new request input").await.unwrap();
        new_send.finish().unwrap();
        let mut new_recv = incoming.accept_uni().await.unwrap();
        assert_eq!(
            new_recv.read_to_end(32).await.unwrap(),
            b"new request input"
        );
        assert_ne!(new_recv.id(), stream_id);
        while incoming.stats().frame_tx.path_challenge == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            incoming.stats().frame_rx.path_response,
            responses,
            "the new peer is exposed without a PATH_RESPONSE"
        );

        // Positive control: re-enable receives and require an actual response.
        gate.resume();
        while incoming.stats().frame_rx.path_response == responses {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(incoming.remote_address(), client.local_addr().unwrap());
        send.finish().unwrap();
        assert!(recv.read_to_end(1).await.unwrap().is_empty());
        client.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
    })
    .await
    .expect("bounded pre-validation visibility probe");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_port_and_stream_bytes_are_visible_before_path_validation() {
    unvalidated_path_visibility("127.0.0.1:0").await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_ip_and_stream_bytes_are_visible_before_path_validation() {
    unvalidated_path_visibility("127.0.0.2:0").await;
}

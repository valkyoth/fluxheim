use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use bytes::Bytes;
use fluxheim_config::{LoadBalanceHealthCheckProtocol, ProxyConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::http::FluxHttpHealthCheck;
use super::reuse_connection::AbortTask;
use super::{Backend, HealthDerivedWeights, configured_http_health_check, grpc_frame};

pub(super) const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

pub(super) struct Fixture {
    pub(super) backend: Backend,
    pub(super) accepted: Arc<AtomicUsize>,
    pub(super) requests: Arc<AtomicUsize>,
    pub(super) active: Arc<AtomicUsize>,
    pub(super) reply: Arc<Mutex<String>>,
    _task: AbortTask,
}

struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Fixture {
    pub(super) async fn start(grpc: bool) -> Self {
        Self::start_with_tls(grpc, None).await
    }

    pub(super) async fn start_with_tls(grpc: bool, tls: Option<Arc<rustls::ServerConfig>>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let live = Arc::clone(&active);
        let reply = Arc::new(Mutex::new(if grpc { "0" } else { OK }.to_owned()));
        let (count, probes, response) = (
            Arc::clone(&accepted),
            Arc::clone(&requests),
            Arc::clone(&reply),
        );
        let task = tokio::spawn(async move {
            let mut jobs = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        count.fetch_add(1, Ordering::SeqCst);
                        let (probes, response) = (Arc::clone(&probes), Arc::clone(&response));
                        let tls = tls.clone();
                        live.fetch_add(1, Ordering::SeqCst);
                        let active = Active(Arc::clone(&live));
                        jobs.spawn(async move {
                            let _active = active;
                            let stream: super::BoxedHealthIo = if let Some(tls) = tls {
                                let Ok(stream) = tokio_rustls::TlsAcceptor::from(tls).accept(stream).await else { return; };
                                Box::new(stream)
                            } else { Box::new(stream) };
                            if grpc { grpc_server(stream, probes, response).await; }
                            else { http_server(stream, probes, response).await; }
                        });
                    }
                    _ = jobs.join_next(), if !jobs.is_empty() => {}
                }
            }
        });
        Self {
            backend: Backend {
                addr: address,
                weight: 1,
            },
            accepted,
            requests,
            active,
            reply,
            _task: AbortTask(task),
        }
    }

    pub(super) fn check(&self, grpc: bool, reuse: bool) -> Box<FluxHttpHealthCheck> {
        check(self.backend.addr, grpc, reuse)
    }

    pub(super) fn count(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    pub(super) fn respond(&self, reply: &str) {
        *self.reply.lock().unwrap() = reply.to_owned();
    }

    pub(super) async fn wait_requests(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.requests.load(Ordering::SeqCst) < count {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }
}

pub(super) fn check(address: SocketAddr, grpc: bool, reuse: bool) -> Box<FluxHttpHealthCheck> {
    let mut config = ProxyConfig {
        upstreams: vec![address.to_string()],
        ..Default::default()
    };
    let health = &mut config.load_balance.health_check;
    health.protocol = if grpc {
        LoadBalanceHealthCheckProtocol::Grpc
    } else {
        LoadBalanceHealthCheckProtocol::Http
    };
    health.reuse_connection = reuse;
    let mut check =
        configured_http_health_check(&config, Arc::new(HealthDerivedWeights::default())).unwrap();
    check.read_timeout = Duration::from_millis(300);
    check.connection_timeout = Duration::from_millis(300);
    check
}

async fn http_server(
    mut stream: super::BoxedHealthIo,
    probes: Arc<AtomicUsize>,
    reply: Arc<Mutex<String>>,
) {
    loop {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            if stream.read_exact(&mut byte).await.is_err() {
                return;
            }
            request.push(byte[0]);
            assert!(request.len() <= 8192);
        }
        probes.fetch_add(1, Ordering::SeqCst);
        let response = reply.lock().unwrap().clone();
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
        if String::from_utf8_lossy(&request)
            .to_ascii_lowercase()
            .contains("connection: close")
            || response.to_ascii_lowercase().contains("connection: close")
        {
            return;
        }
    }
}

async fn grpc_server(
    stream: super::BoxedHealthIo,
    probes: Arc<AtomicUsize>,
    reply: Arc<Mutex<String>>,
) {
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    let mut jobs = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            request = connection.accept() => {
                let Some(Ok((request, mut response))) = request else { return; };
                probes.fetch_add(1, Ordering::SeqCst);
                let status = reply.lock().unwrap().clone();
                if status == "goaway" {
                    connection.abrupt_shutdown(h2::Reason::NO_ERROR);
                    continue;
                }
                jobs.spawn(async move {
                    let mut body = request.into_body();
                    while let Some(Ok(bytes)) = body.data().await {
                        let _ = body.flow_control().release_capacity(bytes.len());
                    }
                    let header = http::Response::builder().header("content-type", "application/grpc").body(()).unwrap();
                    let Ok(mut send) = response.send_response(header, false) else { return; };
                    if status == "hang" { std::future::pending::<()>().await; }
                    let _ = send.send_data(Bytes::from(grpc_frame(&[0x08, 0x01]).unwrap()), false);
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("grpc-status", http::HeaderValue::from_str(&status).unwrap());
                    let _ = send.send_trailers(trailers);
                });
            }
            _ = jobs.join_next(), if !jobs.is_empty() => {}
        }
    }
}

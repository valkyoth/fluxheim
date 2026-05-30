use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::apps::ServerApp;
use pingora::protocols::Stream;
use pingora::server::ShutdownWatch;
use tokio::io::{AsyncWriteExt as _, copy_bidirectional};

use crate::config::{Config, StreamRouteConfig, UpstreamProxyProtocol};
use crate::config_stream::{StreamConnectionSlot, acquire_stream_connection_slot};

pub(crate) type StreamProxyService = pingora::services::listening::Service<StreamProxyApp>;

pub(crate) fn stream_services_from_config(config: &Config) -> io::Result<Vec<StreamProxyService>> {
    if !config.stream.enabled {
        return Ok(Vec::new());
    }

    config
        .stream
        .routes
        .iter()
        .map(stream_service_from_route)
        .collect()
}

fn stream_service_from_route(route: &StreamRouteConfig) -> io::Result<StreamProxyService> {
    let app = StreamProxyApp::from_config(route)?;
    let mut service =
        pingora::services::listening::Service::new(format!("Stream proxy {}", route.name), app);
    for listen in &route.listen {
        service.add_tcp(listen);
    }
    Ok(service)
}

#[derive(Debug)]
pub(crate) struct StreamProxyApp {
    name: Arc<str>,
    upstreams: Arc<[Arc<str>]>,
    connect_timeout: Duration,
    idle_timeout: Duration,
    max_connections: usize,
    active_connections: Arc<AtomicUsize>,
    next_upstream: AtomicUsize,
    upstream_proxy_protocol: UpstreamProxyProtocol,
}

impl StreamProxyApp {
    fn from_config(route: &StreamRouteConfig) -> io::Result<Self> {
        let upstreams = route.upstreams().map(Arc::<str>::from).collect::<Vec<_>>();
        if upstreams.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stream route requires at least one upstream",
            ));
        }

        Ok(Self {
            name: Arc::from(route.name.as_str()),
            upstreams: upstreams.into(),
            connect_timeout: Duration::from_secs(route.connect_timeout_secs),
            idle_timeout: Duration::from_secs(route.idle_timeout_secs),
            max_connections: route.max_connections,
            active_connections: Arc::new(AtomicUsize::new(0)),
            next_upstream: AtomicUsize::new(0),
            upstream_proxy_protocol: route.upstream_proxy_protocol,
        })
    }

    fn acquire_slot(&self) -> Option<StreamConnectionSlot> {
        acquire_stream_connection_slot(&self.active_connections, self.max_connections)
    }

    fn select_upstream(&self) -> &str {
        let index = self.next_upstream.fetch_add(1, Ordering::Relaxed) % self.upstreams.len();
        &self.upstreams[index]
    }
}

#[async_trait]
impl ServerApp for StreamProxyApp {
    async fn process_new(
        self: &Arc<Self>,
        mut downstream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let Some(_slot) = self.acquire_slot() else {
            log::warn!(
                target: "fluxheim::stream",
                "stream route {} rejected connection: max_connections reached",
                self.name
            );
            return None;
        };

        let source = downstream_peer_addr(&downstream);
        let destination = downstream_local_addr(&downstream);
        let upstream_authority = self.select_upstream().to_owned();
        let started = Instant::now();
        let mut shutdown = shutdown.clone();

        let result = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    Err(io::Error::new(io::ErrorKind::Interrupted, "server shutdown requested"))
                } else {
                    proxy_stream_connection(
                        &mut downstream,
                        &upstream_authority,
                        self.connect_timeout,
                        self.idle_timeout,
                        self.upstream_proxy_protocol,
                        source,
                        destination,
                    ).await
                }
            }
            result = proxy_stream_connection(
                &mut downstream,
                &upstream_authority,
                self.connect_timeout,
                self.idle_timeout,
                self.upstream_proxy_protocol,
                source,
                destination,
            ) => result,
        };

        match result {
            Ok((downstream_to_upstream, upstream_to_downstream)) => {
                log::debug!(
                    target: "fluxheim::stream",
                    "stream route {} completed via {}; downstream_to_upstream={} upstream_to_downstream={} duration_ms={}",
                    self.name,
                    upstream_authority,
                    downstream_to_upstream,
                    upstream_to_downstream,
                    started.elapsed().as_millis()
                );
            }
            Err(error) => {
                log::warn!(
                    target: "fluxheim::stream",
                    "stream route {} failed via {} after {}ms: {}",
                    self.name,
                    upstream_authority,
                    started.elapsed().as_millis(),
                    error
                );
            }
        }

        None
    }
}

async fn proxy_stream_connection(
    downstream: &mut Stream,
    upstream_authority: &str,
    connect_timeout: Duration,
    idle_timeout: Duration,
    upstream_proxy_protocol: UpstreamProxyProtocol,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
) -> io::Result<(u64, u64)> {
    let mut upstream = connect_upstream(upstream_authority, connect_timeout).await?;
    write_upstream_proxy_protocol(&mut upstream, upstream_proxy_protocol, source, destination)
        .await?;

    match tokio::time::timeout(idle_timeout, copy_bidirectional(downstream, &mut upstream)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "stream idle timeout elapsed",
        )),
    }
}

async fn connect_upstream(
    upstream_authority: &str,
    connect_timeout: Duration,
) -> io::Result<tokio::net::TcpStream> {
    match tokio::time::timeout(connect_timeout, connect_upstream_inner(upstream_authority)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "stream upstream connect timeout elapsed",
        )),
    }
}

async fn connect_upstream_inner(upstream_authority: &str) -> io::Result<tokio::net::TcpStream> {
    if let Ok(socket_addr) = upstream_authority.parse::<SocketAddr>() {
        return tokio::net::TcpStream::connect(socket_addr).await;
    }

    let mut last_error = None;
    let resolved = tokio::net::lookup_host(upstream_authority).await?;
    for socket_addr in resolved {
        match tokio::net::TcpStream::connect(socket_addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "stream upstream resolved to no socket addresses",
        )
    }))
}

async fn write_upstream_proxy_protocol(
    upstream: &mut tokio::net::TcpStream,
    protocol: UpstreamProxyProtocol,
    source: Option<SocketAddr>,
    destination: Option<SocketAddr>,
) -> io::Result<()> {
    let header = match protocol {
        UpstreamProxyProtocol::Off => return Ok(()),
        UpstreamProxyProtocol::V1 => {
            crate::proxy_protocol::proxy_protocol_v1_header(source, destination)
        }
        UpstreamProxyProtocol::V2 => {
            crate::proxy_protocol::proxy_protocol_v2_header(source, destination)
        }
    };
    upstream.write_all(&header).await
}

fn downstream_peer_addr(downstream: &Stream) -> Option<SocketAddr> {
    downstream
        .get_socket_digest()
        .and_then(|digest| digest.peer_addr().and_then(|addr| addr.as_inet()).copied())
}

fn downstream_local_addr(downstream: &Stream) -> Option<SocketAddr> {
    downstream
        .get_socket_digest()
        .and_then(|digest| digest.local_addr().and_then(|addr| addr.as_inet()).copied())
}

#[cfg(test)]
mod tests {
    use super::{StreamProxyApp, proxy_stream_connection};
    use crate::config::{StreamRouteConfig, UpstreamProxyProtocol};
    use pingora::protocols::Stream as AnyStream;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[test]
    fn stream_app_selects_upstreams_round_robin() {
        let app = StreamProxyApp::from_config(&StreamRouteConfig {
            name: "tcp".to_owned(),
            listen: vec!["127.0.0.1:12345".to_owned()],
            upstream: None,
            upstreams: vec!["127.0.0.1:5432".to_owned(), "127.0.0.1:6432".to_owned()],
            connect_timeout_secs: 1,
            idle_timeout_secs: 1,
            max_connections: 0,
            upstream_proxy_protocol: UpstreamProxyProtocol::Off,
        })
        .unwrap();

        assert_eq!(app.select_upstream(), "127.0.0.1:5432");
        assert_eq!(app.select_upstream(), "127.0.0.1:6432");
        assert_eq!(app.select_upstream(), "127.0.0.1:5432");
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
                let (stream, _) = downstream_listener.accept().await.unwrap();
                let mut downstream: AnyStream =
                    Box::new(pingora::protocols::l4::stream::Stream::from(stream));
                proxy_stream_connection(
                    &mut downstream,
                    &upstream_addr.to_string(),
                    std::time::Duration::from_secs(1),
                    std::time::Duration::from_secs(1),
                    UpstreamProxyProtocol::Off,
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
}

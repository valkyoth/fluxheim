use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fluxheim_config::{PhpConfig, PhpFpmConfig};

use crate::policy::{
    PhpFpmEndpoint, PhpFpmTimeoutKind, php_fpm_endpoints_from_config, php_fpm_timeout_error,
};
use crate::request_body::PhpRequestBody;
use crate::response_stream::collect_php_fpm_response_stream;

#[derive(Clone, Default)]
pub struct PhpFpmPoolMetrics {
    event: Option<Arc<PhpFpmPoolEventRecorder>>,
    idle: Option<Arc<PhpFpmPoolIdleRecorder>>,
}

type PhpFpmPoolEventRecorder = dyn Fn(&str, &str, &str) + Send + Sync;
type PhpFpmPoolIdleRecorder = dyn Fn(&str, &str, usize) + Send + Sync;

pub struct PhpFpmPool {
    endpoint: PhpFpmEndpoint,
    metric_vhost: String,
    metric_pool: String,
    max_idle: usize,
    idle_timeout: Duration,
    max_response_bytes: u64,
    metrics: PhpFpmPoolMetrics,
    idle: tokio::sync::Mutex<Vec<PhpFpmPoolEntry>>,
}

struct PhpFpmPoolEntry {
    client: PhpFpmPooledClient,
    last_used: Instant,
}

enum PhpFpmPooledClient {
    Tcp(
        fastcgi_client::Client<
            fastcgi_client::io::TokioCompat<tokio::net::TcpStream>,
            fastcgi_client::conn::KeepAlive,
        >,
    ),
    #[cfg(unix)]
    Unix(
        fastcgi_client::Client<
            fastcgi_client::io::TokioCompat<tokio::net::UnixStream>,
            fastcgi_client::conn::KeepAlive,
        >,
    ),
}

impl std::fmt::Debug for PhpFpmPoolMetrics {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PhpFpmPoolMetrics")
            .field("event", &self.event.is_some())
            .field("idle", &self.idle.is_some())
            .finish()
    }
}

impl PhpFpmPoolMetrics {
    pub fn new<E, I>(event: E, idle: I) -> Self
    where
        E: Fn(&str, &str, &str) + Send + Sync + 'static,
        I: Fn(&str, &str, usize) + Send + Sync + 'static,
    {
        Self {
            event: Some(Arc::new(event)),
            idle: Some(Arc::new(idle)),
        }
    }

    fn record_event(&self, vhost: &str, pool: &str, event: &str) {
        if let Some(recorder) = &self.event {
            recorder(vhost, pool, event);
        }
    }

    fn record_idle(&self, vhost: &str, pool: &str, idle_connections: usize) {
        if let Some(recorder) = &self.idle {
            recorder(vhost, pool, idle_connections);
        }
    }
}

impl std::fmt::Debug for PhpFpmPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PhpFpmPool")
            .field("endpoint", &self.endpoint)
            .field("metric_vhost", &self.metric_vhost)
            .field("metric_pool", &self.metric_pool)
            .field("max_idle", &self.max_idle)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

pub fn php_fpm_keepalive_pools_from_config(
    config: &PhpConfig,
    metric_vhost: &str,
    metric_pool: &str,
    metrics: PhpFpmPoolMetrics,
) -> Vec<Arc<PhpFpmPool>> {
    if !config.fpm.keepalive {
        return Vec::new();
    }
    let endpoints = php_fpm_endpoints_from_config(&config.fpm);
    let multiple_endpoints = endpoints.len() > 1;
    endpoints
        .into_iter()
        .enumerate()
        .map(|(index, endpoint)| {
            let pool_label = if multiple_endpoints {
                format!("{metric_pool}-{index}")
            } else {
                metric_pool.to_owned()
            };
            Arc::new(PhpFpmPool::from_endpoint(
                endpoint,
                &config.fpm,
                metric_vhost,
                &pool_label,
                config.max_response_bytes.as_u64(),
                metrics.clone(),
            ))
        })
        .collect()
}

impl PhpFpmPool {
    pub fn metric_pool(&self) -> &str {
        &self.metric_pool
    }

    fn from_endpoint(
        endpoint: PhpFpmEndpoint,
        config: &PhpFpmConfig,
        metric_vhost: &str,
        metric_pool: &str,
        max_response_bytes: u64,
        metrics: PhpFpmPoolMetrics,
    ) -> Self {
        Self {
            endpoint,
            metric_vhost: metric_vhost.to_owned(),
            metric_pool: metric_pool.to_owned(),
            max_idle: config.pool_max_idle,
            idle_timeout: Duration::from_secs(config.idle_timeout_secs),
            max_response_bytes,
            metrics,
            idle: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    fn record_pool_event(&self, event: &str) {
        self.metrics
            .record_event(&self.metric_vhost, &self.metric_pool, event);
    }

    fn record_pool_idle(&self, idle_connections: usize) {
        self.metrics
            .record_idle(&self.metric_vhost, &self.metric_pool, idle_connections);
    }

    pub async fn execute(
        &self,
        params: fastcgi_client::Params<'_>,
        body: &PhpRequestBody,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> io::Result<fastcgi_client::Response> {
        let mut entry = self.checkout(connect_timeout).await?;
        let result = entry
            .execute(params, body, request_timeout, self.max_response_bytes)
            .await;
        if result.is_ok() {
            self.checkin(entry).await;
        }
        result
    }

    async fn checkout(&self, connect_timeout: Duration) -> io::Result<PhpFpmPoolEntry> {
        let now = Instant::now();
        {
            let mut idle = self.idle.lock().await;
            let before_retain = idle.len();
            idle.retain(|entry| now.duration_since(entry.last_used) <= self.idle_timeout);
            if before_retain > idle.len() {
                self.record_pool_event("drop_stale");
            }
            if let Some(entry) = idle.pop() {
                self.record_pool_event("reuse");
                self.record_pool_idle(idle.len());
                return Ok(entry);
            }
            self.record_pool_idle(idle.len());
        }
        let client = self.connect_client(connect_timeout).await?;
        self.record_pool_event("connect");
        Ok(PhpFpmPoolEntry {
            client,
            last_used: now,
        })
    }

    async fn checkin(&self, mut entry: PhpFpmPoolEntry) {
        entry.last_used = Instant::now();
        let mut idle = self.idle.lock().await;
        let before_retain = idle.len();
        idle.retain(|entry| entry.last_used.elapsed() <= self.idle_timeout);
        if before_retain > idle.len() {
            self.record_pool_event("drop_stale");
        }
        if idle.len() < self.max_idle {
            idle.push(entry);
            self.record_pool_event("return");
        } else {
            self.record_pool_event("discard_full");
        }
        self.record_pool_idle(idle.len());
    }

    async fn connect_client(&self, timeout: Duration) -> io::Result<PhpFpmPooledClient> {
        match &self.endpoint {
            PhpFpmEndpoint::Tcp(address) => {
                let stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address))
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Connect))??;
                Ok(PhpFpmPooledClient::Tcp(
                    fastcgi_client::Client::new_keep_alive_tokio(stream),
                ))
            }
            #[cfg(unix)]
            PhpFpmEndpoint::Unix(socket) => {
                let stream = tokio::time::timeout(timeout, tokio::net::UnixStream::connect(socket))
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Connect))??;
                Ok(PhpFpmPooledClient::Unix(
                    fastcgi_client::Client::new_keep_alive_tokio(stream),
                ))
            }
        }
    }
}

pub async fn execute_php_fpm_once(
    pool: Option<&PhpFpmPool>,
    endpoint: &PhpFpmEndpoint,
    params: fastcgi_client::Params<'_>,
    body: &PhpRequestBody,
    connect_timeout: Duration,
    timeout: Duration,
    max_response_bytes: u64,
) -> io::Result<fastcgi_client::Response> {
    if let Some(pool) = pool {
        return pool.execute(params, body, connect_timeout, timeout).await;
    }

    match endpoint {
        PhpFpmEndpoint::Tcp(address) => {
            let stream =
                tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(address))
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Connect))??;
            execute_php_fpm_stream(stream, params, body, timeout, max_response_bytes).await
        }
        #[cfg(unix)]
        PhpFpmEndpoint::Unix(socket) => {
            let stream =
                tokio::time::timeout(connect_timeout, tokio::net::UnixStream::connect(socket))
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Connect))??;
            execute_php_fpm_stream(stream, params, body, timeout, max_response_bytes).await
        }
    }
}

impl PhpFpmPoolEntry {
    async fn execute(
        &mut self,
        params: fastcgi_client::Params<'_>,
        body: &PhpRequestBody,
        timeout: Duration,
        max_response_bytes: u64,
    ) -> io::Result<fastcgi_client::Response> {
        self.client
            .execute(params, body, timeout, max_response_bytes)
            .await
    }
}

async fn execute_php_fpm_stream<S>(
    stream: S,
    params: fastcgi_client::Params<'_>,
    body: &PhpRequestBody,
    timeout: Duration,
    max_response_bytes: u64,
) -> io::Result<fastcgi_client::Response>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let operation = async {
        let client = fastcgi_client::Client::new_tokio(stream);
        let request = fastcgi_client::Request::new(params, body.reader().await?);
        let stream = client
            .execute_once_stream(request)
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        collect_php_fpm_response_stream(stream, max_response_bytes).await
    };
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Request))?
}

impl PhpFpmPooledClient {
    async fn execute(
        &mut self,
        params: fastcgi_client::Params<'_>,
        body: &PhpRequestBody,
        timeout: Duration,
        max_response_bytes: u64,
    ) -> io::Result<fastcgi_client::Response> {
        match self {
            Self::Tcp(client) => {
                let operation = async {
                    let request = fastcgi_client::Request::new(params, body.reader().await?);
                    let stream = client
                        .execute_stream(request)
                        .await
                        .map_err(|error| io::Error::other(error.to_string()))?;
                    collect_php_fpm_response_stream(stream, max_response_bytes).await
                };
                tokio::time::timeout(timeout, operation)
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Request))?
            }
            #[cfg(unix)]
            Self::Unix(client) => {
                let operation = async {
                    let request = fastcgi_client::Request::new(params, body.reader().await?);
                    let stream = client
                        .execute_stream(request)
                        .await
                        .map_err(|error| io::Error::other(error.to_string()))?;
                    collect_php_fpm_response_stream(stream, max_response_bytes).await
                };
                tokio::time::timeout(timeout, operation)
                    .await
                    .map_err(|_| php_fpm_timeout_error(PhpFpmTimeoutKind::Request))?
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PhpFpmPooledClient, execute_php_fpm_stream};
    use crate::{PhpFpmTimeoutKind, PhpRequestBody, php_fpm_timeout_kind};
    use std::time::Duration;
    use tokio::io::AsyncReadExt as _;

    #[test]
    fn request_timeout_covers_stalled_fastcgi_response_reads() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("test runtime");

        runtime.block_on(async {
            let (client, mut backend) = tokio::io::duplex(16 * 1024);
            let backend_task = tokio::spawn(async move {
                let mut buffer = [0_u8; 1024];
                while backend.read(&mut buffer).await.unwrap_or(0) != 0 {}
            });
            let error = execute_php_fpm_stream(
                client,
                fastcgi_client::Params::default(),
                &PhpRequestBody::memory(Vec::new()),
                Duration::from_millis(25),
                1024,
            )
            .await
            .expect_err("stalled FastCGI response must time out");

            assert_eq!(
                php_fpm_timeout_kind(&error),
                Some(PhpFpmTimeoutKind::Request)
            );
            backend_task.abort();
        });
    }

    #[test]
    fn pooled_request_timeout_covers_stalled_fastcgi_response_reads() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("test runtime");

        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind backend");
            let address = listener.local_addr().expect("backend address");
            let backend_task = tokio::spawn(async move {
                let (mut backend, _) = listener.accept().await.expect("accept backend");
                let mut buffer = [0_u8; 1024];
                while backend.read(&mut buffer).await.unwrap_or(0) != 0 {}
            });
            let client_stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("connect backend");
            let mut client = PhpFpmPooledClient::Tcp(fastcgi_client::Client::new_keep_alive_tokio(
                client_stream,
            ));
            let error = client
                .execute(
                    fastcgi_client::Params::default(),
                    &PhpRequestBody::memory(Vec::new()),
                    Duration::from_millis(25),
                    1024,
                )
                .await
                .expect_err("stalled pooled FastCGI response must time out");

            assert_eq!(
                php_fpm_timeout_kind(&error),
                Some(PhpFpmTimeoutKind::Request)
            );
            backend_task.abort();
        });
    }
}

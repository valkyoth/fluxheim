use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::FutureExt;
use serde::Deserialize;
use zeroize::Zeroizing;

#[cfg(unix)]
use pingora::server::ListenFds;
use pingora::server::ShutdownWatch;
use pingora::services::{ServiceReadyNotifier, ServiceWithDependents};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::config::ProxyConfig;
use crate::flux_error::{FluxError, FluxResult};

use super::backend::{FluxBackend, FluxBackendDiscovery, FluxBackendSet, FluxLoadBalancerRuntime};
use super::health::configured_health_check;
use super::policy::BackendSelectionPolicy;
use super::selection::MaglevTable;
use super::{UpstreamLoadBalancer, UpstreamLoadBalancerInner, UpstreamLoadBalancerService};

const MAX_HTTP_DISCOVERY_RESPONSE_BYTES: u64 = 64 * 1024;
const MAX_HTTP_DISCOVERY_BEARER_TOKEN_BYTES: u64 = 4096;

#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NOFOLLOW: i32 = 0o400000;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NOFOLLOW: i32 = 0x0100;

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit symlink-safe load-balancer discovery token loading before building Fluxheim"
);

pub(super) fn configured_load_balancer(
    config: &ProxyConfig,
    backend_policy: &BackendSelectionPolicy,
) -> io::Result<Option<FluxLoadBalancerRuntime>> {
    if config.upstreams.len() < 2
        && config.upstreams_file.is_none()
        && config.upstreams_http_url.is_none()
        && config.upstream_dns_refresh_secs.is_none()
    {
        return Ok(None);
    }

    let mut load_balancer = FluxLoadBalancerRuntime::new(configured_backend_discovery(config)?);
    if config.upstreams_file.is_some() {
        load_balancer.set_update_frequency(Some(Duration::from_secs(
            config.upstreams_file_refresh_secs.clamp(1, 300),
        )));
    } else if config.upstreams_http_url.is_some() {
        load_balancer.set_update_frequency(Some(Duration::from_secs(
            config.upstreams_http_refresh_secs.clamp(1, 300),
        )));
    } else if let Some(refresh_secs) = config.upstream_dns_refresh_secs {
        load_balancer.set_update_frequency(Some(Duration::from_secs(refresh_secs.clamp(1, 300))));
    }
    load_balancer
        .update()
        .now_or_never()
        .ok_or_else(|| io::Error::other("static load balancer update blocked unexpectedly"))?
        .map_err(FluxError::into_io)?;
    apply_disabled_backend_enablement(&load_balancer, config);
    if config.load_balance.health_check.enabled {
        let health_check = configured_health_check(config, backend_policy.health_weights())?;
        load_balancer.set_health_check(health_check);
        load_balancer.set_health_check_frequency(Some(Duration::from_secs(
            config.load_balance.health_check.interval_secs,
        )));
        load_balancer.set_parallel_health_check(config.load_balance.health_check.parallel);
    }

    Ok(Some(load_balancer))
}

fn apply_disabled_backend_enablement(
    load_balancer: &FluxLoadBalancerRuntime,
    config: &ProxyConfig,
) {
    for upstream in &config.disabled_upstreams {
        if let Ok(backend) =
            FluxBackend::new(upstream).and_then(|backend| backend.to_pingora_backend())
        {
            load_balancer.set_enable(&backend, false);
        }
    }
}

struct FileUpstreamDiscovery {
    path: PathBuf,
}

struct HttpUpstreamDiscovery {
    url: String,
    bearer_token_file: Option<PathBuf>,
}

struct StaticUpstreamDiscovery {
    backends: FluxBackendSet,
}

#[async_trait]
impl FluxBackendDiscovery for StaticUpstreamDiscovery {
    async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet> {
        Ok(self.backends.clone())
    }
}

#[async_trait]
impl FluxBackendDiscovery for FileUpstreamDiscovery {
    async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet> {
        let upstreams = read_proxy_upstreams_file_for_discovery(self.path.clone()).await?;
        let mut backends = FluxBackendSet::default();
        for upstream in upstreams {
            let backend = FluxBackend::new(&upstream)?;
            backends.insert(backend);
        }
        Ok(backends)
    }
}

#[async_trait]
impl FluxBackendDiscovery for HttpUpstreamDiscovery {
    async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet> {
        let upstreams = fetch_proxy_upstreams_http_for_discovery(
            self.url.clone(),
            self.bearer_token_file.clone(),
        )
        .await?;
        let mut backends = FluxBackendSet::default();
        for upstream in upstreams {
            let backend = FluxBackend::new(&upstream)?;
            backends.insert(backend);
        }
        Ok(backends)
    }
}

async fn read_proxy_upstreams_file_for_discovery(path: PathBuf) -> FluxResult<Vec<String>> {
    let result = if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::spawn_blocking(move || crate::config::read_proxy_upstreams_file(&path))
            .await
            .map_err(|error| {
                FluxError::io(
                    "proxy upstreams file discovery task failed",
                    io::Error::other(error.to_string()),
                )
            })?
    } else {
        // Pingora performs the initial load-balancer update synchronously during
        // construction. There is no Tokio reactor yet in that path, so this
        // bootstrap read must stay immediately ready for now_or_never().
        crate::config::read_proxy_upstreams_file(&path)
    };

    result.map_err(|error| FluxError::io("failed to read proxy upstreams file", error))
}

async fn fetch_proxy_upstreams_http_for_discovery(
    url: String,
    bearer_token_file: Option<PathBuf>,
) -> FluxResult<Vec<String>> {
    let result = if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::spawn_blocking(move || fetch_proxy_upstreams_http(&url, bearer_token_file))
            .await
            .map_err(|error| {
                FluxError::io(
                    "proxy upstreams HTTP discovery task failed",
                    io::Error::other(error.to_string()),
                )
            })?
    } else {
        // The construction-time update is synchronously polled before a Tokio
        // reactor exists. Keep the bootstrap fetch immediately ready; later
        // refreshes run through spawn_blocking().
        fetch_proxy_upstreams_http(&url, bearer_token_file)
    };

    result.map_err(|error| FluxError::io("failed to fetch proxy upstreams HTTP discovery", error))
}

fn fetch_proxy_upstreams_http(
    url: &str,
    bearer_token_file: Option<PathBuf>,
) -> io::Result<Vec<String>> {
    let timeout = Duration::from_secs(5);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into();
    let mut request = agent.get(url).header("cache-control", "no-store");
    let bearer_token = if let Some(path) = bearer_token_file {
        Some(read_http_discovery_bearer_token(&path)?)
    } else {
        None
    };
    if let Some(token) = bearer_token.as_ref() {
        request = request.header("authorization", format!("Bearer {}", token.trim()));
    }
    let mut response = request
        .call()
        .map_err(|error| io::Error::other(error.to_string()))?;
    if response.status().as_u16() != 200 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "HTTP discovery endpoint returned status {}",
                response.status().as_u16()
            ),
        ));
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_HTTP_DISCOVERY_RESPONSE_BYTES.saturating_add(1))
        .read_to_vec()
        .map_err(|error| io::Error::other(error.to_string()))?;
    if body.len() as u64 > MAX_HTTP_DISCOVERY_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP discovery response is too large",
        ));
    }
    parse_proxy_upstreams_http_body(&body)
}

fn read_http_discovery_bearer_token(path: &Path) -> io::Result<Zeroizing<String>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTP discovery bearer token file must be a regular file",
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTP discovery bearer token file must be a regular file",
        ));
    }
    if metadata.len() > MAX_HTTP_DISCOVERY_BEARER_TOKEN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP discovery bearer token file is too large",
        ));
    }

    let mut token = Zeroizing::new(String::new());
    let mut limited = file.take(MAX_HTTP_DISCOVERY_BEARER_TOKEN_BYTES.saturating_add(1));
    limited.read_to_string(&mut token)?;
    if token.len() as u64 > MAX_HTTP_DISCOVERY_BEARER_TOKEN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP discovery bearer token file changed while reading and became too large",
        ));
    }
    Ok(token)
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HttpDiscoveryPayload {
    List(Vec<String>),
    Object { upstreams: Vec<String> },
}

fn parse_proxy_upstreams_http_body(body: &[u8]) -> io::Result<Vec<String>> {
    let payload: HttpDiscoveryPayload = serde_json::from_slice(body).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("HTTP discovery response is not a valid upstream JSON payload: {error}"),
        )
    })?;
    let upstreams = match payload {
        HttpDiscoveryPayload::List(upstreams) | HttpDiscoveryPayload::Object { upstreams } => {
            upstreams
        }
    };
    validate_http_discovery_upstreams(upstreams)
}

fn validate_http_discovery_upstreams(upstreams: Vec<String>) -> io::Result<Vec<String>> {
    let mut validated = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for upstream in upstreams {
        let value = upstream.trim();
        if !crate::config_net::valid_authority(value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP discovery upstream is not a host:port or ip:port authority",
            ));
        }
        if !seen.insert(value.to_ascii_lowercase()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP discovery response repeats an upstream",
            ));
        }
        validated.push(value.to_owned());
        if validated.len() > crate::config_proxy::MAX_PROXY_UPSTREAMS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP discovery response contains too many upstreams",
            ));
        }
    }
    if validated.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP discovery response must contain at least two upstreams",
        ));
    }
    Ok(validated)
}

struct DnsUpstreamDiscovery {
    upstreams: Arc<[String]>,
}

#[async_trait]
impl FluxBackendDiscovery for DnsUpstreamDiscovery {
    async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet> {
        let mut backends = FluxBackendSet::default();
        for upstream in self.upstreams.iter() {
            let resolved = resolve_proxy_upstream_for_discovery(upstream).await?;
            for address in resolved {
                let backend = FluxBackend::new(&address.to_string())?;
                backends.insert(backend);
            }
        }
        if backends.is_empty() {
            return Err(FluxError::InvalidInput(
                "DNS discovery resolved no proxy upstreams",
            ));
        }
        Ok(backends)
    }
}

async fn resolve_proxy_upstream_for_discovery(upstream: &str) -> FluxResult<Vec<SocketAddr>> {
    let result = if tokio::runtime::Handle::try_current().is_ok() {
        tokio::net::lookup_host(upstream)
            .await
            .map(|resolved| resolved.collect())
    } else {
        // See read_proxy_upstreams_file_for_discovery(): construction-time
        // update is polled synchronously before a reactor is available. Later
        // refreshes run under Tokio and use lookup_host().
        upstream
            .to_socket_addrs()
            .map(|resolved| resolved.collect::<Vec<_>>())
    };

    result.map_err(|error| FluxError::io("failed to resolve proxy upstream", error))
}

pub(super) fn background_service_for<F>(
    name: &str,
    config: &ProxyConfig,
    wrap: F,
) -> io::Result<Option<(UpstreamLoadBalancer, UpstreamLoadBalancerService)>>
where
    F: FnOnce(Arc<FluxLoadBalancerRuntime>) -> UpstreamLoadBalancerInner,
{
    let backend_policy = BackendSelectionPolicy::from_config(config);
    let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
        return Ok(None);
    };

    let service = FluxLoadBalancerBackgroundService::new(format!("LB {name}"), inner);
    let load_balancer =
        UpstreamLoadBalancer::from_inner(wrap(service.task()), config, backend_policy);
    Ok(Some((load_balancer, Box::new(service))))
}

pub(super) fn background_maglev_service_for(
    name: &str,
    config: &ProxyConfig,
) -> io::Result<Option<(UpstreamLoadBalancer, UpstreamLoadBalancerService)>> {
    let backend_policy = BackendSelectionPolicy::from_config(config);
    let Some(inner) = configured_load_balancer(config, &backend_policy)? else {
        return Ok(None);
    };
    let table = Arc::new(configured_maglev_table(config)?);
    let service = FluxLoadBalancerBackgroundService::new(format!("LB {name}"), inner);
    let load_balancer = UpstreamLoadBalancer::from_inner(
        UpstreamLoadBalancerInner::MaglevHash {
            inner: service.task(),
            table,
        },
        config,
        backend_policy,
    );
    Ok(Some((load_balancer, Box::new(service))))
}

struct FluxLoadBalancerBackgroundService {
    name: String,
    task: Arc<FluxLoadBalancerRuntime>,
}

impl FluxLoadBalancerBackgroundService {
    fn new(name: String, task: FluxLoadBalancerRuntime) -> Self {
        Self {
            name,
            task: Arc::new(task),
        }
    }

    fn task(&self) -> Arc<FluxLoadBalancerRuntime> {
        self.task.clone()
    }
}

#[async_trait]
impl ServiceWithDependents for FluxLoadBalancerBackgroundService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<ListenFds>,
        shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
        ready: ServiceReadyNotifier,
    ) {
        self.task.run(shutdown, Some(ready)).await;
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

fn configured_backends(config: &ProxyConfig) -> FluxResult<FluxBackendSet> {
    let mut backends = FluxBackendSet::default();
    for (index, upstream) in config.upstreams.iter().enumerate() {
        let weight = config.upstream_weights.get(index).copied().unwrap_or(1);
        let backend = FluxBackend::new_with_weight(upstream, weight)?;
        backends.insert(backend);
    }
    Ok(backends)
}

pub(super) fn configured_maglev_table(config: &ProxyConfig) -> io::Result<MaglevTable> {
    let backends = configured_backends(config).map_err(FluxError::into_io)?;
    MaglevTable::from_backend_identities(backends.iter()).map_err(FluxError::into_io)
}

fn configured_backend_discovery(config: &ProxyConfig) -> io::Result<Box<dyn FluxBackendDiscovery>> {
    if let Some(path) = &config.upstreams_file {
        return Ok(Box::new(FileUpstreamDiscovery { path: path.clone() }));
    }
    if let Some(url) = &config.upstreams_http_url {
        return Ok(Box::new(HttpUpstreamDiscovery {
            url: url.clone(),
            bearer_token_file: config.upstreams_http_bearer_token_file.clone(),
        }));
    }
    if config.upstream_dns_refresh_secs.is_some() {
        return Ok(Box::new(DnsUpstreamDiscovery {
            upstreams: config.upstreams.clone().into(),
        }));
    }

    Ok(Box::new(StaticUpstreamDiscovery {
        backends: configured_backends(config).map_err(FluxError::into_io)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::parse_proxy_upstreams_http_body;

    #[test]
    fn parses_http_discovery_list_payload() {
        let upstreams =
            parse_proxy_upstreams_http_body(br#"["127.0.0.1:3001","backend.example.test:443"]"#)
                .unwrap();

        assert_eq!(upstreams, ["127.0.0.1:3001", "backend.example.test:443"]);
    }

    #[test]
    fn parses_http_discovery_object_payload() {
        let upstreams = parse_proxy_upstreams_http_body(
            br#"{"upstreams":["127.0.0.1:3001","127.0.0.1:3002"]}"#,
        )
        .unwrap();

        assert_eq!(upstreams, ["127.0.0.1:3001", "127.0.0.1:3002"]);
    }

    #[test]
    fn rejects_http_discovery_duplicate_and_short_payloads() {
        assert!(
            parse_proxy_upstreams_http_body(br#"["127.0.0.1:3001","127.0.0.1:3001"]"#)
                .unwrap_err()
                .to_string()
                .contains("repeats")
        );
        assert!(
            parse_proxy_upstreams_http_body(br#"["127.0.0.1:3001"]"#)
                .unwrap_err()
                .to_string()
                .contains("at least two")
        );
    }

    #[test]
    fn rejects_http_discovery_invalid_authority() {
        assert!(
            parse_proxy_upstreams_http_body(br#"["http://127.0.0.1:3001","127.0.0.1:3002"]"#)
                .unwrap_err()
                .to_string()
                .contains("authority")
        );
    }
}

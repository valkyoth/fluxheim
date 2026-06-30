use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::FutureExt;
use sanitization::SecretString;
use serde::Deserialize;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use fluxheim_common::{FluxError, FluxResult};
use fluxheim_config::ProxyConfig;

use super::backend::{FluxBackend, FluxBackendDiscovery, FluxBackendSet, FluxLoadBalancerRuntime};
use super::health::configured_health_check;
use super::policy::BackendSelectionPolicy;
use super::selection::MaglevTable;
use super::selection_ketama::NginxKetamaTable;
use super::{
    LoadBalancerMetricLabels, UpstreamLoadBalancer, UpstreamLoadBalancerInner,
    UpstreamLoadBalancerService,
};

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
    #[cfg(test)]
    crate::install_test_crypto_provider();

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
        if let Ok(backend) = FluxBackend::new(upstream) {
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
    allow_private_backends: bool,
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
            self.allow_private_backends,
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
        tokio::task::spawn_blocking(move || fluxheim_config::read_proxy_upstreams_file(&path))
            .await
            .map_err(|error| {
                FluxError::io(
                    "proxy upstreams file discovery task failed",
                    io::Error::other(error.to_string()),
                )
            })?
    } else {
        // Some bootstrap callers perform the initial load-balancer update
        // synchronously before a Tokio reactor is available, so this read must
        // stay immediately ready for now_or_never().
        fluxheim_config::read_proxy_upstreams_file(&path)
    };

    result.map_err(|error| FluxError::io("failed to read proxy upstreams file", error))
}

async fn fetch_proxy_upstreams_http_for_discovery(
    url: String,
    bearer_token_file: Option<PathBuf>,
    allow_private_backends: bool,
) -> FluxResult<Vec<String>> {
    let result = if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::spawn_blocking(move || {
            fetch_proxy_upstreams_http(&url, bearer_token_file, allow_private_backends)
        })
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
        fetch_proxy_upstreams_http(&url, bearer_token_file, allow_private_backends)
    };

    result.map_err(|error| FluxError::io("failed to fetch proxy upstreams HTTP discovery", error))
}

fn fetch_proxy_upstreams_http(
    url: &str,
    bearer_token_file: Option<PathBuf>,
    allow_private_backends: bool,
) -> io::Result<Vec<String>> {
    let timeout = Duration::from_secs(5);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into();
    let mut request = agent
        .get(url)
        .header("accept", "application/json")
        .header("cache-control", "no-store");
    let bearer_token = if let Some(path) = bearer_token_file {
        Some(read_http_discovery_bearer_token(&path)?)
    } else {
        None
    };
    if let Some(token) = bearer_token.as_ref() {
        let header_value = http_discovery_bearer_authorization_value(token)?;
        request = header_value
            .try_with_secret(|value| request.header("authorization", value))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
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
    validate_http_discovery_content_type(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
    )?;
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
    parse_proxy_upstreams_http_body(&body, allow_private_backends)
}

fn read_http_discovery_bearer_token(path: &Path) -> io::Result<SecretString> {
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
    validate_http_discovery_bearer_token(&token)?;
    Ok(SecretString::from_secret_str(token.trim()))
}

fn http_discovery_bearer_authorization_value(token: &SecretString) -> io::Result<SecretString> {
    token
        .try_with_secret(|token| {
            let token = token.trim();
            let mut header_value = SecretString::with_capacity("Bearer ".len() + token.len());
            header_value.push_str("Bearer ");
            header_value.push_str(token);
            header_value
        })
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn validate_http_discovery_bearer_token(token: &str) -> io::Result<()> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP discovery bearer token file is empty",
        ));
    }
    if trimmed.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP discovery bearer token contains whitespace",
        ));
    }
    Ok(())
}

fn validate_http_discovery_content_type(content_type: Option<&str>) -> io::Result<()> {
    let Some(content_type) = content_type else {
        return Ok(());
    };
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media_type == "application/json" || media_type.ends_with("+json") {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "HTTP discovery response content-type is not JSON",
    ))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HttpDiscoveryPayload {
    List(Vec<String>),
    Object { upstreams: Vec<String> },
}

fn parse_proxy_upstreams_http_body(
    body: &[u8],
    allow_private_backends: bool,
) -> io::Result<Vec<String>> {
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
    validate_http_discovery_upstreams(upstreams, allow_private_backends)
}

fn validate_http_discovery_upstreams(
    upstreams: Vec<String>,
    allow_private_backends: bool,
) -> io::Result<Vec<String>> {
    let mut validated = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for upstream in upstreams {
        let value = upstream.trim();
        if !fluxheim_config::config_net::valid_authority(value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP discovery upstream is not a host:port or ip:port authority",
            ));
        }
        if !allow_private_backends && http_discovery_upstream_uses_restricted_ip_literal(value) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP discovery upstream uses a private, loopback, link-local, multicast, reserved, or documentation IP address without proxy.upstreams_http_allow_private_backends",
            ));
        }
        if !seen.insert(value.to_ascii_lowercase()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP discovery response repeats an upstream",
            ));
        }
        if validated.len() >= fluxheim_config::config_proxy::MAX_PROXY_UPSTREAMS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP discovery response contains too many upstreams",
            ));
        }
        validated.push(value.to_owned());
    }
    if validated.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP discovery response must contain at least two upstreams",
        ));
    }
    Ok(validated)
}

fn http_discovery_upstream_uses_restricted_ip_literal(upstream: &str) -> bool {
    upstream
        .parse::<SocketAddr>()
        .is_ok_and(|socket| restricted_http_discovery_ip(socket.ip()))
}

fn restricted_http_discovery_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => restricted_http_discovery_ipv4(ip),
        IpAddr::V6(ip) => restricted_http_discovery_ipv6(ip),
    }
}

fn restricted_http_discovery_ipv4(ip: Ipv4Addr) -> bool {
    let [first, second, third, _fourth] = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || first == 0
        || first >= 240
        || (first == 100 && (64..=127).contains(&second))
        || (first == 192 && second == 0 && third == 0)
        || (first == 192 && second == 0 && third == 2)
        || (first == 198 && matches!(second, 18 | 19))
        || (first == 198 && second == 51 && third == 100)
        || (first == 203 && second == 0 && third == 113)
}

fn restricted_http_discovery_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return restricted_http_discovery_ipv4(mapped);
    }
    if let Some(compatible) = ip.to_ipv4()
        && !ip.is_loopback()
        && !ip.is_unspecified()
    {
        return restricted_http_discovery_ipv4(compatible);
    }
    let segments = ip.segments();
    if segments[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            (segments[1] & 0xff) as u8,
            (segments[2] >> 8) as u8,
            (segments[2] & 0xff) as u8,
        );
        if restricted_http_discovery_ipv4(embedded) {
            return true;
        }
    }
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        let raw = ((segments[6] as u32) << 16) | u32::from(segments[7]);
        let embedded = Ipv4Addr::from(!raw);
        if restricted_http_discovery_ipv4(embedded) {
            return true;
        }
    }
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0)
}

struct DnsUpstreamDiscovery {
    upstreams: Arc<[String]>,
    allow_private_backends: bool,
}

#[async_trait]
impl FluxBackendDiscovery for DnsUpstreamDiscovery {
    async fn discover_flux_backends(&self) -> FluxResult<FluxBackendSet> {
        let mut backends = FluxBackendSet::default();
        for upstream in self.upstreams.iter() {
            let resolved = resolve_proxy_upstream_for_discovery(upstream).await?;
            for address in resolved {
                if !self.allow_private_backends && restricted_http_discovery_ip(address.ip()) {
                    return Err(FluxError::InvalidInput(
                        "DNS discovery resolved a private, loopback, link-local, multicast, reserved, or documentation IP address without proxy.upstream_dns_allow_private_backends",
                    ));
                }
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
    metric_labels: LoadBalancerMetricLabels,
    config: &ProxyConfig,
    wrap: F,
) -> io::Result<Option<(UpstreamLoadBalancer, UpstreamLoadBalancerService)>>
where
    F: FnOnce(Arc<FluxLoadBalancerRuntime>) -> UpstreamLoadBalancerInner,
{
    let backend_policy = BackendSelectionPolicy::from_config(config);
    let Some(mut inner) = configured_load_balancer(config, &backend_policy)? else {
        return Ok(None);
    };
    inner.set_metric_labels(metric_labels);

    let inner_service = crate::background::background_service_with_kind(
        format!("LB {name}"),
        crate::background::BackgroundTaskKind::LoadBalancerRefresh,
        inner,
    );
    let load_balancer =
        UpstreamLoadBalancer::from_inner(wrap(inner_service.task()), config, backend_policy);
    let service = UpstreamLoadBalancerService::new(inner_service, load_balancer.clone());
    Ok(Some((load_balancer, service)))
}

pub(super) fn background_maglev_service_for(
    name: &str,
    metric_labels: LoadBalancerMetricLabels,
    config: &ProxyConfig,
) -> io::Result<Option<(UpstreamLoadBalancer, UpstreamLoadBalancerService)>> {
    let backend_policy = BackendSelectionPolicy::from_config(config);
    let Some(mut inner) = configured_load_balancer(config, &backend_policy)? else {
        return Ok(None);
    };
    inner.set_metric_labels(metric_labels);
    let table = Arc::new(configured_maglev_table(config)?);
    let inner_service = crate::background::background_service_with_kind(
        format!("LB {name}"),
        crate::background::BackgroundTaskKind::LoadBalancerRefresh,
        inner,
    );
    let load_balancer = UpstreamLoadBalancer::from_inner(
        UpstreamLoadBalancerInner::MaglevHash {
            inner: inner_service.task(),
            table,
        },
        config,
        backend_policy,
    );
    let service = UpstreamLoadBalancerService::new(inner_service, load_balancer.clone());
    Ok(Some((load_balancer, service)))
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

pub(super) fn configured_nginx_ketama_table(config: &ProxyConfig) -> io::Result<NginxKetamaTable> {
    if config.upstreams_file.is_some()
        || config.upstreams_http_url.is_some()
        || config.upstream_dns_refresh_secs.is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nginx-compatible Ketama selections require static proxy.upstreams; dynamic discovery would make the compatibility ring stale",
        ));
    }
    let backends = configured_backends(config).map_err(FluxError::into_io)?;
    NginxKetamaTable::from_backend_identities(backends.iter()).map_err(FluxError::into_io)
}

fn configured_backend_discovery(config: &ProxyConfig) -> io::Result<Box<dyn FluxBackendDiscovery>> {
    if let Some(path) = &config.upstreams_file {
        return Ok(Box::new(FileUpstreamDiscovery { path: path.clone() }));
    }
    if let Some(url) = &config.upstreams_http_url {
        return Ok(Box::new(HttpUpstreamDiscovery {
            url: url.clone(),
            bearer_token_file: config.upstreams_http_bearer_token_file.clone(),
            allow_private_backends: config.upstreams_http_allow_private_backends,
        }));
    }
    if config.upstream_dns_refresh_secs.is_some() {
        return Ok(Box::new(DnsUpstreamDiscovery {
            upstreams: config.upstreams.clone().into(),
            allow_private_backends: config.upstream_dns_allow_private_backends,
        }));
    }

    Ok(Box::new(StaticUpstreamDiscovery {
        backends: configured_backends(config).map_err(FluxError::into_io)?,
    }))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::{Arc, mpsc};

    use fluxheim_common::test_support::{safe_child_path, unique_temp_path};

    use super::{
        DnsUpstreamDiscovery, fetch_proxy_upstreams_http, parse_proxy_upstreams_http_body,
        validate_http_discovery_bearer_token, validate_http_discovery_content_type,
    };
    use crate::backend::FluxBackendDiscovery;

    #[test]
    fn parses_http_discovery_list_payload() {
        let upstreams = parse_proxy_upstreams_http_body(
            br#"["8.8.8.8:3001","backend.example.test:443"]"#,
            false,
        )
        .unwrap();

        assert_eq!(upstreams, ["8.8.8.8:3001", "backend.example.test:443"]);
    }

    #[test]
    fn parses_http_discovery_object_payload() {
        let upstreams = parse_proxy_upstreams_http_body(
            br#"{"upstreams":["8.8.8.8:3001","1.1.1.1:3002"]}"#,
            false,
        )
        .unwrap();

        assert_eq!(upstreams, ["8.8.8.8:3001", "1.1.1.1:3002"]);
    }

    #[test]
    fn rejects_http_discovery_duplicate_and_short_payloads() {
        assert!(
            parse_proxy_upstreams_http_body(br#"["8.8.8.8:3001","8.8.8.8:3001"]"#, false)
                .unwrap_err()
                .to_string()
                .contains("repeats")
        );
        assert!(
            parse_proxy_upstreams_http_body(br#"["8.8.8.8:3001"]"#, false)
                .unwrap_err()
                .to_string()
                .contains("at least two")
        );
    }

    #[test]
    fn rejects_http_discovery_invalid_authority() {
        assert!(
            parse_proxy_upstreams_http_body(br#"["http://127.0.0.1:3001","1.1.1.1:3002"]"#, false)
                .unwrap_err()
                .to_string()
                .contains("authority")
        );
    }

    #[test]
    fn rejects_http_discovery_private_backends_without_opt_in() {
        assert!(
            parse_proxy_upstreams_http_body(br#"["169.254.169.254:80","8.8.8.8:3002"]"#, false)
                .unwrap_err()
                .to_string()
                .contains("private")
        );
        assert!(
            parse_proxy_upstreams_http_body(br#"["127.0.0.1:3001","8.8.8.8:3002"]"#, false)
                .unwrap_err()
                .to_string()
                .contains("private")
        );
        assert!(
            parse_proxy_upstreams_http_body(br#"["[::1]:3001","8.8.8.8:3002"]"#, false)
                .unwrap_err()
                .to_string()
                .contains("private")
        );

        let upstreams =
            parse_proxy_upstreams_http_body(br#"["169.254.169.254:80","127.0.0.1:3001"]"#, true)
                .unwrap();
        assert_eq!(upstreams, ["169.254.169.254:80", "127.0.0.1:3001"]);
    }

    #[test]
    fn rejects_http_discovery_ipv4_encoded_ipv6_literals_without_opt_in() {
        for upstream in [
            "[::ffff:169.254.169.254]:80",
            "[::ffff:127.0.0.1]:3001",
            "[::ffff:10.0.0.1]:3001",
            "[::169.254.169.254]:80",
            "[2002:7f00:1::1]:3001",
            "[2002:a00:1::1]:3001",
            "[2001:0000::ffff:80ff:fffe]:3001",
        ] {
            let body = format!(r#"["{upstream}","8.8.8.8:3002"]"#);
            assert!(
                parse_proxy_upstreams_http_body(body.as_bytes(), false)
                    .unwrap_err()
                    .to_string()
                    .contains("private"),
                "{upstream}"
            );
        }

        let upstreams = parse_proxy_upstreams_http_body(
            br#"["[::ffff:169.254.169.254]:80","[::ffff:127.0.0.1]:3001"]"#,
            true,
        )
        .unwrap();
        assert_eq!(
            upstreams,
            ["[::ffff:169.254.169.254]:80", "[::ffff:127.0.0.1]:3001"]
        );
    }

    #[tokio::test]
    async fn rejects_dns_discovery_private_backends_without_opt_in() {
        let discovery = DnsUpstreamDiscovery {
            upstreams: Arc::from(["127.0.0.1:3001".to_owned()]),
            allow_private_backends: false,
        };

        let error = discovery
            .discover_flux_backends()
            .await
            .expect_err("restricted DNS backend");
        assert!(error.to_string().contains("private"));

        let discovery = DnsUpstreamDiscovery {
            upstreams: Arc::from(["127.0.0.1:3001".to_owned()]),
            allow_private_backends: true,
        };
        assert!(discovery.discover_flux_backends().await.is_ok());
    }

    #[test]
    fn rejects_http_discovery_payload_over_upstream_cap() {
        let upstreams = (0..=fluxheim_config::config_proxy::MAX_PROXY_UPSTREAMS)
            .map(|index| format!("\"8.8.8.8:{}\"", 3000 + index))
            .collect::<Vec<_>>()
            .join(",");
        let body = format!("[{upstreams}]");

        assert!(
            parse_proxy_upstreams_http_body(body.as_bytes(), false)
                .unwrap_err()
                .to_string()
                .contains("too many")
        );
    }

    #[test]
    fn validates_http_discovery_json_content_types() {
        validate_http_discovery_content_type(None).unwrap();
        validate_http_discovery_content_type(Some("application/json")).unwrap();
        validate_http_discovery_content_type(Some("application/json; charset=utf-8")).unwrap();
        validate_http_discovery_content_type(Some("application/vnd.fluxheim.upstreams+json"))
            .unwrap();

        assert!(
            validate_http_discovery_content_type(Some("text/plain"))
                .unwrap_err()
                .to_string()
                .contains("content-type")
        );
    }

    #[test]
    fn rejects_empty_or_control_character_http_discovery_bearer_token() {
        validate_http_discovery_bearer_token("secret-token\n").unwrap();
        assert!(
            validate_http_discovery_bearer_token(" \n\t ")
                .unwrap_err()
                .to_string()
                .contains("empty")
        );
        assert!(
            validate_http_discovery_bearer_token("secret\r\nother")
                .unwrap_err()
                .to_string()
                .contains("whitespace")
        );
        assert!(
            validate_http_discovery_bearer_token("secret other")
                .unwrap_err()
                .to_string()
                .contains("whitespace")
        );
    }

    #[test]
    fn fetches_http_discovery_with_json_accept_and_bearer_token() {
        let root = unique_temp_path("lb-http-discovery-token");
        std::fs::create_dir_all(&root).unwrap();
        let token_path = safe_child_path(&root, "token.txt");
        std::fs::write(&token_path, "secret-token\n").unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            sender.send(request).unwrap();
            let body = br#"["127.0.0.1:3001","127.0.0.1:3002"]"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });

        let upstreams = fetch_proxy_upstreams_http(
            &format!("http://{address}/v1/upstreams"),
            Some(token_path),
            true,
        )
        .unwrap();
        handle.join().unwrap();
        let request = receiver.recv().unwrap();

        assert_eq!(upstreams, ["127.0.0.1:3001", "127.0.0.1:3002"]);
        let lower_request = request.to_ascii_lowercase();
        assert!(request.contains("GET /v1/upstreams HTTP/1.1"));
        assert!(lower_request.contains("accept: application/json"));
        assert!(lower_request.contains("cache-control: no-store"));
        assert!(lower_request.contains("authorization: bearer secret-token"));
    }
}

use std::time::Duration;

#[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
use crate::NativeHttp1UpstreamTls;
use crate::NativeTcpKeepalivePolicy;
use crate::native_http1_proxy::NativeHttp1ProxyConfigError;
use crate::{DownstreamHttp1Policy, DownstreamHttp2Policy, NativeHttp1Upstream};

const MAX_NATIVE_UPSTREAM_H2_STREAMS: usize = 1024;

pub(crate) fn native_upstream_from_proxy_config(
    authority: impl Into<String>,
    proxy: &fluxheim_config::ProxyConfig,
    policy: DownstreamHttp1Policy,
    pool_max_idle: usize,
) -> Result<NativeHttp1Upstream, NativeHttp1ProxyConfigError> {
    let mut native_upstream = NativeHttp1Upstream::from_policy(authority, policy);
    #[cfg(any(feature = "tls-rustls-backend", feature = "tls-openssl-backend"))]
    if let Some(tls) = NativeHttp1UpstreamTls::from_proxy_config(proxy)? {
        native_upstream = native_upstream.with_tls(tls);
    }
    if let Some(timeout) = proxy.connect_timeout_secs {
        native_upstream = native_upstream.with_connect_timeout(Duration::from_secs(timeout));
    }
    native_upstream = native_upstream.with_total_connection_timeout(
        proxy
            .upstream_total_connection_timeout_secs
            .map(Duration::from_secs),
    );
    if let Some(timeout) = proxy.read_timeout_secs {
        native_upstream = native_upstream.with_read_timeout(Duration::from_secs(timeout));
    }
    if let Some(timeout) = proxy.send_timeout_secs {
        native_upstream = native_upstream.with_write_timeout(Duration::from_secs(timeout));
    }
    native_upstream = native_upstream.with_proxy_protocol(proxy.upstream_proxy_protocol);
    if matches!(
        proxy.upstream_http_version,
        fluxheim_config::UpstreamHttpVersion::Http2
            | fluxheim_config::UpstreamHttpVersion::Http1AndHttp2
    ) {
        let http2_policy = native_http2_policy_from_config(proxy)?;
        native_upstream =
            if proxy.upstream_http_version == fluxheim_config::UpstreamHttpVersion::Http2 {
                native_upstream.with_http2_policy(http2_policy)
            } else {
                native_upstream
                    .with_http1_and_http2_policy(http2_policy)
                    .with_h2c_upgrade(proxy.upstream_h2c_upgrade)
            };
        native_upstream = native_upstream.with_http2_keepalive_interval(
            proxy
                .upstream_h2_ping_interval_secs
                .map(Duration::from_secs),
        );
    }
    let recv_buffer_size = match proxy
        .upstream_tcp_recv_buffer_bytes
        .map(fluxheim_config::ByteSize::as_u64)
        .map(u32::try_from)
    {
        Some(Ok(bytes)) => Some(bytes),
        Some(Err(_)) => return Err(NativeHttp1ProxyConfigError::RecvBufferTooLarge),
        None => None,
    };
    native_upstream = native_upstream.with_recv_buffer_size(recv_buffer_size);
    native_upstream = native_upstream.with_dscp(proxy.upstream_dscp);
    native_upstream = native_upstream.with_tcp_keepalive(native_tcp_keepalive(proxy)?);
    native_upstream = native_upstream.with_tcp_user_timeout(native_tcp_user_timeout(proxy)?);
    native_upstream = native_upstream
        .with_pool_idle_timeout(proxy.upstream_idle_timeout_secs.map(Duration::from_secs));
    let pool_max_idle =
        if proxy.upstream_proxy_protocol == fluxheim_config::UpstreamProxyProtocol::Off {
            pool_max_idle
        } else {
            0
        };
    Ok(native_upstream.with_pool_max_idle(pool_max_idle))
}

pub(crate) fn configured_native_upstreams(
    proxy: &fluxheim_config::ProxyConfig,
) -> Option<Vec<String>> {
    if !proxy.upstreams.is_empty() {
        return Some(proxy.upstreams.clone());
    }
    proxy
        .configured_primary_upstream()
        .map(|upstream| vec![upstream.to_owned()])
}

#[cfg(feature = "load-balancer")]
pub(crate) fn native_load_balancer_from_config(
    proxy: &fluxheim_config::ProxyConfig,
    scope: Option<(&str, &str, Option<&str>)>,
) -> Result<
    Option<(
        fluxheim_load_balancer::UpstreamLoadBalancer,
        Option<fluxheim_load_balancer::UpstreamLoadBalancerService>,
    )>,
    NativeHttp1ProxyConfigError,
> {
    let Some((name, vhost, route)) = scope else {
        return Ok(None);
    };
    if !native_load_balancer_pool_configured(proxy) {
        return Ok(None);
    }
    if proxy.load_balance.health_check.enabled || proxy_uses_dynamic_upstream_discovery(proxy) {
        return fluxheim_load_balancer::UpstreamLoadBalancer::background_service_from_proxy_config(
            name, vhost, route, proxy,
        )
        .map(|result| result.map(|(load_balancer, service)| (load_balancer, Some(service))))
        .map_err(|_| NativeHttp1ProxyConfigError::LoadBalancing);
    }
    fluxheim_load_balancer::UpstreamLoadBalancer::from_proxy_config(proxy)
        .map(|result| result.map(|load_balancer| (load_balancer, None)))
        .map_err(|_| NativeHttp1ProxyConfigError::LoadBalancing)
}

pub(crate) fn proxy_requires_advanced_load_balancer(
    proxy: &fluxheim_config::ProxyConfig,
    native_load_balancer_enabled: bool,
) -> bool {
    if !native_load_balancer_pool_configured(proxy) {
        return false;
    }
    if native_load_balancer_enabled {
        return false;
    }
    if !native_load_balancer_enabled
        && !native_static_load_balance_config_supported(&proxy.load_balance)
    {
        return true;
    }
    !proxy.upstream_priority_groups.is_empty()
        || !proxy.upstream_localities.is_empty()
        || !proxy.preferred_upstream_localities.is_empty()
        || !proxy.upstream_max_in_flight.is_empty()
        || !proxy.upstream_aliases.is_empty()
        || !proxy.upstream_tags.is_empty()
        || !proxy.backup_upstreams.is_empty()
        || !proxy.drain_upstreams.is_empty()
        || !proxy.disabled_upstreams.is_empty()
}

pub(crate) fn proxy_uses_dynamic_upstream_discovery(proxy: &fluxheim_config::ProxyConfig) -> bool {
    proxy.upstreams_file.is_some()
        || proxy.upstreams_http_url.is_some()
        || proxy.upstream_dns_refresh_secs.is_some()
}

#[cfg(not(feature = "auth-request"))]
pub(crate) fn proxy_requires_auth_request(proxy: &fluxheim_config::ProxyConfig) -> bool {
    proxy.auth_request.enabled
        || proxy.auth_request.url.is_some()
        || !proxy.auth_request.forward_headers.is_empty()
        || !proxy.auth_request.allow_response_headers.is_empty()
}

pub(crate) fn proxy_requires_advanced_upstream_transport(
    proxy: &fluxheim_config::ProxyConfig,
) -> bool {
    proxy.upstream_tcp_user_timeout_ms.is_some() && !native_tcp_user_timeout_supported()
        || proxy.upstream_tcp_fast_open
}

pub(crate) fn native_http1_static_failover_method_allowed(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

fn native_load_balancer_pool_configured(proxy: &fluxheim_config::ProxyConfig) -> bool {
    proxy.upstreams.len() >= 2
        || proxy.upstreams_file.is_some()
        || proxy.upstreams_http_url.is_some()
        || proxy.upstream_dns_refresh_secs.is_some()
}

fn native_static_load_balance_config_supported(
    load_balance: &fluxheim_config::LoadBalanceConfig,
) -> bool {
    let mut disabled_health = fluxheim_config::LoadBalanceConfig::default();
    disabled_health.health_check.enabled = false;
    load_balance == &disabled_health
}

fn native_http2_policy_from_config(
    proxy: &fluxheim_config::ProxyConfig,
) -> Result<DownstreamHttp2Policy, NativeHttp1ProxyConfigError> {
    let mut policy = DownstreamHttp2Policy::default();
    if let Some(read_timeout_secs) = proxy.read_timeout_secs {
        let timeout = Duration::from_secs(read_timeout_secs);
        policy = policy
            .with_response_body_timeout(timeout)
            .with_handler_timeout(timeout);
    }
    if let Some(write_timeout_secs) = proxy.send_timeout_secs {
        policy = policy.with_response_write_lifetime(Duration::from_secs(write_timeout_secs));
    }
    if let Some(max_streams) = proxy.upstream_h2_max_streams {
        let max_streams = u32::try_from(max_streams)
            .ok()
            .filter(|max_streams| {
                *max_streams > 0 && (*max_streams as usize) <= MAX_NATIVE_UPSTREAM_H2_STREAMS
            })
            .ok_or(NativeHttp1ProxyConfigError::UpstreamHttp2)?;
        policy = policy.with_max_concurrent_streams(max_streams);
    }
    Ok(policy)
}

const fn native_tcp_user_timeout_supported() -> bool {
    cfg!(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    ))
}

fn native_tcp_keepalive(
    proxy: &fluxheim_config::ProxyConfig,
) -> Result<Option<NativeTcpKeepalivePolicy>, NativeHttp1ProxyConfigError> {
    match (
        proxy.upstream_tcp_keepalive_idle_secs,
        proxy.upstream_tcp_keepalive_interval_secs,
        proxy.upstream_tcp_keepalive_count,
    ) {
        (None, None, None) => Ok(None),
        (Some(idle_secs), Some(interval_secs), Some(count)) => {
            let count = u32::try_from(count)
                .map_err(|_| NativeHttp1ProxyConfigError::UpstreamTransportPolicy)?;
            Ok(Some(NativeTcpKeepalivePolicy::new(
                Duration::from_secs(idle_secs),
                Duration::from_secs(interval_secs),
                count,
            )))
        }
        _ => Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy),
    }
}

fn native_tcp_user_timeout(
    proxy: &fluxheim_config::ProxyConfig,
) -> Result<Option<Duration>, NativeHttp1ProxyConfigError> {
    let Some(timeout_ms) = proxy.upstream_tcp_user_timeout_ms else {
        return Ok(None);
    };
    if !native_tcp_user_timeout_supported() {
        return Err(NativeHttp1ProxyConfigError::UpstreamTransportPolicy);
    }
    Ok(Some(Duration::from_millis(timeout_ms)))
}

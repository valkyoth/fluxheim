use crate::config::{ConfigError, validate_optional_timeout_secs};
use crate::config_net::normalize_host;
use crate::config_path::{validate_non_world_writable_parent, validate_path};
use crate::config_proxy::{ProxyConfig, UpstreamHttpVersion, UpstreamProxyProtocol};
use crate::config_proxy_upstream_policy::static_upstreams_include_ip_address;

const MAX_PROXY_UPSTREAM_H2_STREAMS: usize = 1024;
const MAX_PROXY_UPSTREAM_TCP_KEEPALIVE_COUNT: usize = 128;
const MAX_PROXY_UPSTREAM_TCP_RECV_BUFFER_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PROXY_UPSTREAM_DSCP: u8 = 63;

pub(crate) fn validate_proxy_upstream_transport(
    proxy: &ProxyConfig,
    default_upstream: &str,
) -> Result<(), ConfigError> {
    validate_proxy_upstream_tls_policy(proxy, default_upstream)?;
    validate_proxy_upstream_protocol_policy(proxy)?;
    validate_proxy_upstream_h2_policy(proxy)?;
    validate_proxy_upstream_timeouts(proxy)?;
    validate_proxy_upstream_tcp_policy(proxy)
}

fn validate_proxy_upstream_tls_policy(
    proxy: &ProxyConfig,
    default_upstream: &str,
) -> Result<(), ConfigError> {
    if let Some(sni) = &proxy.upstream_sni
        && sni.trim().is_empty()
    {
        return Err(ConfigError::EmptyUpstreamSni);
    }
    if proxy.upstream_tls
        && proxy.upstream_verify_cert
        && proxy.upstream_sni.is_none()
        && static_upstreams_include_ip_address(proxy, default_upstream)
    {
        return Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "IP-addressed upstreams with upstream_tls and upstream_verify_cert require explicit upstream_sni",
        });
    }
    if !proxy.upstream_verify_cert && proxy.upstream_verify_hostname {
        return Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "upstream_verify_hostname must be false when upstream_verify_cert = false",
        });
    }
    if !proxy.upstream_tls
        && (proxy.upstream_ca_path.is_some()
            || proxy.upstream_client_cert_path.is_some()
            || proxy.upstream_client_key_path.is_some())
    {
        return Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "upstream TLS trust roots or client certificates require upstream_tls = true",
        });
    }
    if !proxy.upstream_verify_cert && proxy.upstream_ca_path.is_some() {
        return Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "upstream_ca_path requires upstream_verify_cert = true",
        });
    }
    match (
        &proxy.upstream_client_cert_path,
        &proxy.upstream_client_key_path,
    ) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => {
            return Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream_client_cert_path and upstream_client_key_path must be configured together",
            });
        }
    }
    for (field, path) in [
        ("proxy.upstream_ca_path", proxy.upstream_ca_path.as_deref()),
        (
            "proxy.upstream_client_cert_path",
            proxy.upstream_client_cert_path.as_deref(),
        ),
        (
            "proxy.upstream_client_key_path",
            proxy.upstream_client_key_path.as_deref(),
        ),
    ] {
        validate_path(field, path)?;
        validate_non_world_writable_parent(field, path)?;
    }
    if let Some(alternative_cn) = &proxy.upstream_alternative_cn {
        if alternative_cn.contains('*') {
            return Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream_alternative_cn must not contain wildcards",
            });
        }
        if normalize_host(alternative_cn).is_none() {
            return Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream_alternative_cn must be a valid hostname",
            });
        }
    }
    Ok(())
}

fn validate_proxy_upstream_protocol_policy(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    if proxy.upstream_proxy_protocol != UpstreamProxyProtocol::Off
        && !proxy.has_configured_upstream()
    {
        return Err(ConfigError::InvalidProxyTlsPolicy {
            reason: "upstream_proxy_protocol requires a configured proxy upstream",
        });
    }
    if proxy.upstream_http_version != UpstreamHttpVersion::Http1 && !proxy.has_configured_upstream()
    {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_http_version",
            reason: "requires a configured proxy upstream",
        });
    }
    if proxy.upstream_h2c_upgrade {
        if !proxy.has_configured_upstream() {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_h2c_upgrade",
                reason: "requires a configured proxy upstream",
            });
        }
        if proxy.upstream_tls {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_h2c_upgrade",
                reason: "is only valid for plaintext upstreams",
            });
        }
        if proxy.upstream_http_version != UpstreamHttpVersion::Http1AndHttp2 {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_h2c_upgrade",
                reason: "requires upstream_http_version = \"http1-and-http2\"",
            });
        }
    }
    if proxy.websocket && proxy.upstream_http_version != UpstreamHttpVersion::Http1 {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.websocket",
            reason: "HTTP/1.1 upgrade proxying requires upstream_http_version = \"http1\"",
        });
    }
    Ok(())
}

fn validate_proxy_upstream_h2_policy(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    if proxy.upstream_h2_max_streams.is_some()
        && proxy.upstream_http_version == UpstreamHttpVersion::Http1
    {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_h2_max_streams",
            reason: "requires upstream_http_version to allow http2",
        });
    }
    if proxy.upstream_h2_ping_interval_secs.is_some()
        && proxy.upstream_http_version == UpstreamHttpVersion::Http1
    {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_h2_ping_interval_secs",
            reason: "requires upstream_http_version to allow http2",
        });
    }
    if proxy
        .upstream_h2_max_streams
        .is_some_and(|streams| streams == 0 || streams > MAX_PROXY_UPSTREAM_H2_STREAMS)
    {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_h2_max_streams",
            reason: "must be between 1 and 1024",
        });
    }
    validate_optional_timeout_secs(
        "proxy.upstream_h2_ping_interval_secs",
        proxy.upstream_h2_ping_interval_secs,
    )
}

fn validate_proxy_upstream_timeouts(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    validate_optional_timeout_secs("proxy.connect_timeout_secs", proxy.connect_timeout_secs)?;
    validate_optional_timeout_secs(
        "proxy.upstream_total_connection_timeout_secs",
        proxy.upstream_total_connection_timeout_secs,
    )?;
    validate_optional_timeout_secs(
        "proxy.upstream_idle_timeout_secs",
        proxy.upstream_idle_timeout_secs,
    )
}

fn validate_proxy_upstream_tcp_policy(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    validate_optional_timeout_secs(
        "proxy.upstream_tcp_keepalive_idle_secs",
        proxy.upstream_tcp_keepalive_idle_secs,
    )?;
    validate_optional_timeout_secs(
        "proxy.upstream_tcp_keepalive_interval_secs",
        proxy.upstream_tcp_keepalive_interval_secs,
    )?;
    if proxy.upstream_tcp_keepalive_count.is_some()
        || proxy.upstream_tcp_keepalive_idle_secs.is_some()
        || proxy.upstream_tcp_keepalive_interval_secs.is_some()
        || proxy.upstream_tcp_user_timeout_ms.is_some()
    {
        match (
            proxy.upstream_tcp_keepalive_idle_secs,
            proxy.upstream_tcp_keepalive_interval_secs,
            proxy.upstream_tcp_keepalive_count,
        ) {
            (Some(_), Some(_), Some(count))
                if (1..=MAX_PROXY_UPSTREAM_TCP_KEEPALIVE_COUNT).contains(&count) => {}
            _ => {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_tcp_keepalive_count",
                    reason: "TCP keepalive requires idle_secs, interval_secs, and count, with count between 1 and 128",
                });
            }
        }
    }
    if proxy
        .upstream_tcp_user_timeout_ms
        .is_some_and(|milliseconds| milliseconds == 0)
    {
        return Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.upstream_tcp_user_timeout_ms",
        });
    }
    if proxy.upstream_tcp_recv_buffer_bytes.is_some_and(|bytes| {
        bytes.as_u64() == 0 || bytes.as_u64() > MAX_PROXY_UPSTREAM_TCP_RECV_BUFFER_BYTES
    }) {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_tcp_recv_buffer_bytes",
            reason: "must be between 1 byte and 256MiB",
        });
    }
    if proxy
        .upstream_dscp
        .is_some_and(|dscp| dscp > MAX_PROXY_UPSTREAM_DSCP)
    {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_dscp",
            reason: "must be a DSCP value between 0 and 63",
        });
    }
    Ok(())
}

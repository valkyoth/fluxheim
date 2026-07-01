use crate::config::ConfigError;
#[cfg(feature = "load-balancer")]
use crate::config_http::valid_http_endpoint_url;
#[cfg(feature = "load-balancer")]
use crate::config_loader::read_proxy_upstreams_file;
#[cfg(feature = "load-balancer")]
use crate::config_net::http_authority_is_numeric_loopback;
#[cfg(feature = "load-balancer")]
use crate::config_path::{validate_non_world_writable_parent, validate_path};
use crate::config_proxy::ProxyConfig;

const MIN_PROXY_UPSTREAMS_FILE_REFRESH_SECS: u64 = 1;
const MAX_PROXY_UPSTREAMS_FILE_REFRESH_SECS: u64 = 300;
#[cfg(feature = "load-balancer")]
const MIN_PROXY_UPSTREAM_DNS_REFRESH_SECS: u64 = 1;
#[cfg(feature = "load-balancer")]
const MAX_PROXY_UPSTREAM_DNS_REFRESH_SECS: u64 = 300;

pub(crate) fn default_proxy_upstreams_file_refresh_secs() -> u64 {
    5
}

pub(crate) fn default_proxy_upstreams_http_refresh_secs() -> u64 {
    5
}

pub(crate) fn validate_proxy_upstream_discovery(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    let dynamic_discovery_count = usize::from(proxy.upstreams_file.is_some())
        + usize::from(proxy.upstreams_http_url.is_some());
    if proxy.upstream.is_some()
        && (!proxy.upstreams.is_empty()
            || proxy.upstreams_file.is_some()
            || proxy.upstreams_http_url.is_some())
        || !proxy.upstreams.is_empty()
            && (proxy.upstreams_file.is_some() || proxy.upstreams_http_url.is_some())
        || dynamic_discovery_count > 1
    {
        return Err(ConfigError::ConflictingProxyUpstreams);
    }
    validate_proxy_upstreams_file_discovery(proxy)?;
    validate_proxy_upstreams_http_discovery(proxy)?;
    validate_proxy_upstream_dns_discovery(proxy)
}

fn validate_proxy_upstreams_file_discovery(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    if let Some(path) = &proxy.upstreams_file {
        #[cfg(not(feature = "load-balancer"))]
        {
            let _ = path;
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstreams_file",
                reason: "requires the load-balancer feature",
            });
        }
        #[cfg(feature = "load-balancer")]
        {
            validate_path("proxy.upstreams_file", Some(path))?;
            validate_non_world_writable_parent("proxy.upstreams_file", Some(path))?;
            let upstreams = read_proxy_upstreams_file(path).map_err(|_| {
                ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstreams_file",
                    reason: "must be a readable regular file containing 2-64 unique host:port entries",
                }
            })?;
            if upstreams.len() < 2 {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstreams_file",
                    reason: "must contain at least two upstreams",
                });
            }
            reject_static_upstream_attributes_with_discovery(proxy, "proxy.upstreams_file")?;
            if proxy.upstream_tls && proxy.upstream_sni.is_none() {
                return Err(ConfigError::InvalidProxyTlsPolicy {
                    reason: "upstreams_file with upstream_tls requires explicit upstream_sni",
                });
            }
        }
    }
    if proxy.upstreams_file.is_some()
        && !(MIN_PROXY_UPSTREAMS_FILE_REFRESH_SECS..=MAX_PROXY_UPSTREAMS_FILE_REFRESH_SECS)
            .contains(&proxy.upstreams_file_refresh_secs)
    {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstreams_file_refresh_secs",
            reason: "must be between 1 and 300 seconds",
        });
    }
    Ok(())
}

fn validate_proxy_upstreams_http_discovery(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    if let Some(url) = &proxy.upstreams_http_url {
        #[cfg(not(feature = "load-balancer"))]
        {
            let _ = url;
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstreams_http_url",
                reason: "requires the load-balancer feature",
            });
        }
        #[cfg(feature = "load-balancer")]
        {
            if !valid_http_endpoint_url(url) {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstreams_http_url",
                    reason: "must be an http:// or https:// endpoint URL without credentials, query, or fragment",
                });
            }
            if let Some(rest) = url.strip_prefix("http://") {
                let authority = rest.split('/').next().unwrap_or_default();
                if !http_authority_is_numeric_loopback(authority) {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstreams_http_url",
                        reason: "must use https:// unless the endpoint is numeric loopback http://",
                    });
                }
            }
            if !(MIN_PROXY_UPSTREAMS_FILE_REFRESH_SECS..=MAX_PROXY_UPSTREAMS_FILE_REFRESH_SECS)
                .contains(&proxy.upstreams_http_refresh_secs)
            {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstreams_http_refresh_secs",
                    reason: "must be between 1 and 300 seconds",
                });
            }
            if let Some(path) = &proxy.upstreams_http_bearer_token_file {
                validate_path("proxy.upstreams_http_bearer_token_file", Some(path))?;
                validate_non_world_writable_parent(
                    "proxy.upstreams_http_bearer_token_file",
                    Some(path),
                )?;
            }
            reject_static_upstream_attributes_with_discovery(proxy, "proxy.upstreams_http_url")?;
            if proxy.upstream_tls && proxy.upstream_sni.is_none() {
                return Err(ConfigError::InvalidProxyTlsPolicy {
                    reason: "upstreams_http_url with upstream_tls requires explicit upstream_sni",
                });
            }
        }
    } else if proxy.upstreams_http_bearer_token_file.is_some() {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstreams_http_bearer_token_file",
            reason: "requires proxy.upstreams_http_url",
        });
    }
    Ok(())
}

fn validate_proxy_upstream_dns_discovery(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    if let Some(refresh_secs) = proxy.upstream_dns_refresh_secs {
        #[cfg(not(feature = "load-balancer"))]
        {
            let _ = refresh_secs;
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_dns_refresh_secs",
                reason: "requires the load-balancer feature",
            });
        }
        #[cfg(feature = "load-balancer")]
        {
            if !(MIN_PROXY_UPSTREAM_DNS_REFRESH_SECS..=MAX_PROXY_UPSTREAM_DNS_REFRESH_SECS)
                .contains(&refresh_secs)
            {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_dns_refresh_secs",
                    reason: "must be between 1 and 300 seconds",
                });
            }
            if proxy.upstream.is_some()
                || proxy.upstreams.is_empty()
                || proxy.upstreams_file.is_some()
                || proxy.upstreams_http_url.is_some()
            {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_dns_refresh_secs",
                    reason: "requires proxy.upstreams and cannot be used with proxy.upstream, proxy.upstreams_file, or proxy.upstreams_http_url",
                });
            }
            reject_static_upstream_attributes_with_discovery(
                proxy,
                "proxy.upstream_dns_refresh_secs",
            )?;
        }
    } else if proxy.upstream_dns_allow_private_backends {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_dns_allow_private_backends",
            reason: "requires proxy.upstream_dns_refresh_secs",
        });
    }
    Ok(())
}

#[cfg(feature = "load-balancer")]
fn reject_static_upstream_attributes_with_discovery(
    proxy: &ProxyConfig,
    field: &'static str,
) -> Result<(), ConfigError> {
    if !proxy.upstream_weights.is_empty()
        || !proxy.upstream_priority_groups.is_empty()
        || proxy.upstream_priority_group_min_active
            != crate::config_proxy::default_upstream_priority_group_min_active()
        || !proxy.upstream_localities.is_empty()
        || !proxy.preferred_upstream_localities.is_empty()
        || !proxy.upstream_max_in_flight.is_empty()
        || !proxy.upstream_aliases.is_empty()
        || !proxy.upstream_tags.is_empty()
        || !proxy.backup_upstreams.is_empty()
        || !proxy.drain_upstreams.is_empty()
        || !proxy.disabled_upstreams.is_empty()
    {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field,
            reason: "cannot be combined with upstream_weights, upstream_priority_groups, upstream_priority_group_min_active, upstream_localities, preferred_upstream_localities, upstream_max_in_flight, upstream_aliases, upstream_tags, backup_upstreams, drain_upstreams, or disabled_upstreams in this release",
        });
    }
    Ok(())
}

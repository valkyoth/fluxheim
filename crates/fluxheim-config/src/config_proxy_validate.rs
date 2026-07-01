use crate::config::{ConfigError, validate_optional_timeout_secs};
use crate::config_net::valid_authority;
use crate::config_proxy::{MAX_PROXY_ERROR_PAGES, MAX_PROXY_UPSTREAMS, ProxyConfig};
use crate::config_proxy_discovery::validate_proxy_upstream_discovery;
use crate::config_proxy_transport::validate_proxy_upstream_transport;
use crate::config_proxy_upstream_attributes::validate_static_upstream_attributes;
#[cfg(feature = "load-balancer")]
use crate::config_proxy_upstream_policy::validate_load_balancer_backend_keys;
use crate::config_proxy_upstream_policy::validate_upstream_policy;

pub(crate) fn validate_proxy_config(
    proxy: &ProxyConfig,
    default_upstream: &str,
) -> Result<(), ConfigError> {
    validate_proxy_upstream_discovery(proxy)?;
    if proxy.upstreams.len() > MAX_PROXY_UPSTREAMS {
        return Err(ConfigError::TooManyProxyUpstreams {
            max: MAX_PROXY_UPSTREAMS,
        });
    }
    validate_static_upstream_attributes(proxy)?;
    if proxy.error_pages.len() > MAX_PROXY_ERROR_PAGES {
        return Err(ConfigError::TooManyProxyErrorPages {
            max: MAX_PROXY_ERROR_PAGES,
        });
    }
    validate_proxy_upstream_authorities(proxy)?;
    #[cfg(feature = "load-balancer")]
    validate_load_balancer_backend_keys(&proxy.upstreams)?;
    validate_upstream_policy(proxy)?;
    validate_proxy_upstream_transport(proxy, default_upstream)?;
    proxy.auth_request.validate("proxy.auth_request")?;
    proxy.mirror.validate("proxy.mirror")?;
    validate_proxy_downstream_policy(proxy)?;
    validate_proxy_error_pages(proxy)?;
    validate_proxy_load_balance_policy(proxy)
}

fn validate_proxy_upstream_authorities(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    if let Some(upstream) = &proxy.upstream
        && !valid_authority(upstream)
    {
        return Err(ConfigError::InvalidUpstream {
            address: upstream.clone(),
        });
    }

    let mut seen_upstreams = std::collections::HashSet::new();
    for upstream in &proxy.upstreams {
        if !valid_authority(upstream) {
            return Err(ConfigError::InvalidUpstream {
                address: upstream.clone(),
            });
        }
        if !seen_upstreams.insert(upstream.to_ascii_lowercase()) {
            return Err(ConfigError::DuplicateProxyUpstream {
                upstream: upstream.clone(),
            });
        }
    }
    Ok(())
}

fn validate_proxy_downstream_policy(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    validate_optional_timeout_secs("proxy.read_timeout_secs", proxy.read_timeout_secs)?;
    validate_optional_timeout_secs("proxy.send_timeout_secs", proxy.send_timeout_secs)?;
    validate_optional_timeout_secs(
        "proxy.downstream_read_timeout_secs",
        proxy.downstream_read_timeout_secs,
    )?;
    validate_optional_timeout_secs(
        "proxy.downstream_write_timeout_secs",
        proxy.downstream_write_timeout_secs,
    )?;
    validate_optional_timeout_secs(
        "proxy.downstream_total_response_timeout_secs",
        proxy.downstream_total_response_timeout_secs,
    )?;
    if proxy
        .downstream_min_send_rate_bytes_per_sec
        .is_some_and(|rate| rate == 0)
    {
        return Err(ConfigError::InvalidProxyTimeout {
            field: "proxy.downstream_min_send_rate_bytes_per_sec",
        });
    }
    Ok(())
}

fn validate_proxy_error_pages(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    let mut statuses = std::collections::HashSet::new();
    for error_page in &proxy.error_pages {
        error_page.validate()?;
        if !statuses.insert(error_page.status) {
            return Err(ConfigError::DuplicateProxyErrorPageStatus {
                status: error_page.status,
            });
        }
    }
    Ok(())
}

fn validate_proxy_load_balance_policy(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    proxy.load_balance.validate()?;
    if proxy.load_balance.selection.uses_static_ring()
        && (proxy.upstreams_file.is_some()
            || proxy.upstreams_http_url.is_some()
            || proxy.upstream_dns_refresh_secs.is_some())
    {
        return Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "static-ring selections require a static proxy.upstreams pool; file, HTTP, and DNS discovery pools rebuild membership dynamically",
        });
    }
    Ok(())
}

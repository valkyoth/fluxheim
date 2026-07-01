use std::collections::HashSet;
#[cfg(feature = "load-balancer")]
use std::hash::Hasher;
use std::net::IpAddr;

use crate::config::ConfigError;
use crate::config_net::{upstream_host, valid_authority};
use crate::config_proxy::ProxyConfig;

pub(crate) fn static_upstreams_include_ip_address(
    config: &ProxyConfig,
    default_upstream: &str,
) -> bool {
    let mut upstreams = config.upstreams.iter().map(String::as_str);
    if let Some(upstream) = config.upstream.as_deref() {
        return upstream_authority_host_is_ip(upstream);
    }
    if config.upstreams.is_empty()
        && config.upstreams_file.is_none()
        && config.upstreams_http_url.is_none()
    {
        return upstream_authority_host_is_ip(default_upstream);
    }
    upstreams.any(upstream_authority_host_is_ip)
}

pub(crate) fn validate_upstream_policy(config: &ProxyConfig) -> Result<(), ConfigError> {
    if config.backup_upstreams.is_empty()
        && config.drain_upstreams.is_empty()
        && config.disabled_upstreams.is_empty()
    {
        return Ok(());
    }
    if config.upstreams.len() < 2 || config.upstream.is_some() {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstreams",
            reason: "backup_upstreams, drain_upstreams, and disabled_upstreams require proxy.upstreams with at least two entries",
        });
    }
    let configured = config
        .upstreams
        .iter()
        .map(|upstream| upstream.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let backup = validate_proxy_upstream_subset(
        "proxy.backup_upstreams",
        &config.backup_upstreams,
        &configured,
    )?;
    let drain = validate_proxy_upstream_subset(
        "proxy.drain_upstreams",
        &config.drain_upstreams,
        &configured,
    )?;
    let disabled = validate_proxy_upstream_subset(
        "proxy.disabled_upstreams",
        &config.disabled_upstreams,
        &configured,
    )?;
    if !backup.is_disjoint(&drain)
        || !backup.is_disjoint(&disabled)
        || !drain.is_disjoint(&disabled)
    {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.backup_upstreams",
            reason: "backup_upstreams, drain_upstreams, and disabled_upstreams must not overlap",
        });
    }
    let primary_count = configured
        .len()
        .saturating_sub(backup.len() + drain.len() + disabled.len());
    if primary_count == 0 {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstreams",
            reason: "at least one upstream must remain primary and selectable",
        });
    }
    Ok(())
}

fn validate_proxy_upstream_subset(
    field: &'static str,
    values: &[String],
    configured: &HashSet<String>,
) -> Result<HashSet<String>, ConfigError> {
    let mut seen = HashSet::new();
    for upstream in values {
        if !valid_authority(upstream) {
            return Err(ConfigError::InvalidUpstream {
                address: upstream.clone(),
            });
        }
        let normalized = upstream.to_ascii_lowercase();
        if !configured.contains(&normalized) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field,
                reason: "each entry must also be present in proxy.upstreams",
            });
        }
        if !seen.insert(normalized) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field,
                reason: "duplicate upstream policy entries are not allowed",
            });
        }
    }
    Ok(seen)
}

fn upstream_authority_host_is_ip(upstream: &str) -> bool {
    upstream_host(upstream).is_some_and(|host| host.parse::<IpAddr>().is_ok())
}

#[cfg(feature = "load-balancer")]
pub(crate) fn validate_load_balancer_backend_keys(upstreams: &[String]) -> Result<(), ConfigError> {
    let mut seen = HashSet::new();
    for upstream in upstreams {
        let normalized = upstream.to_ascii_lowercase();
        if !seen.insert(backend_authority_key(&normalized)) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstreams",
                reason: "load-balancer backend key collision detected; use distinct upstream addresses",
            });
        }
    }
    Ok(())
}

#[cfg(feature = "load-balancer")]
fn backend_authority_key(authority: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    struct Fnv1a64(u64);

    impl Hasher for Fnv1a64 {
        fn finish(&self) -> u64 {
            self.0
        }

        fn write(&mut self, bytes: &[u8]) {
            for byte in bytes {
                self.0 ^= u64::from(*byte);
                self.0 = self.0.wrapping_mul(FNV_PRIME);
            }
        }
    }

    let mut hasher = Fnv1a64(FNV_OFFSET);
    hasher.write(authority.as_bytes());
    hasher.finish()
}

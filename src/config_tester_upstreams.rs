use std::error::Error;
use std::net::ToSocketAddrs;

use crate::config::{Config, ProxyConfig};

pub(crate) fn resolve_upstreams(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut failed = 0usize;
    for upstream in configured_upstreams(config) {
        match upstream.authority.to_socket_addrs() {
            Ok(addresses) => {
                let addresses = addresses
                    .map(|address| address.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "upstream: {} {} -> {}",
                    upstream.scope, upstream.authority, addresses
                );
            }
            Err(error) => {
                failed = failed.saturating_add(1);
                println!(
                    "upstream: {} {} -> error: {}",
                    upstream.scope, upstream.authority, error
                );
            }
        }
    }
    if failed > 0 {
        return Err(format!("failed to resolve {failed} upstream target(s)").into());
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct UpstreamTarget {
    pub(crate) authority: String,
    scope: String,
}

pub(crate) fn configured_upstreams(config: &Config) -> Vec<UpstreamTarget> {
    let mut targets = Vec::new();
    if config.vhosts.is_empty() && config.proxy.has_configured_upstream() {
        push_proxy_upstreams("proxy", &config.proxy, &mut targets);
    }
    for vhost in &config.vhosts {
        push_proxy_upstreams(
            &format!("vhost {:?}", vhost.name),
            &vhost.proxy,
            &mut targets,
        );
        if vhost.acme_challenge.enabled {
            if let Some(upstream) = &vhost.acme_challenge.upstream {
                targets.push(UpstreamTarget {
                    scope: format!("vhost {:?} acme_challenge", vhost.name),
                    authority: upstream.clone(),
                });
            }
            for upstream in &vhost.acme_challenge.upstreams {
                targets.push(UpstreamTarget {
                    scope: format!("vhost {:?} acme_challenge", vhost.name),
                    authority: upstream.clone(),
                });
            }
        }
        for route in &vhost.routes {
            if let Some(proxy) = &route.proxy {
                push_proxy_upstreams(
                    &format!("vhost {:?} route {:?}", vhost.name, route.name),
                    proxy,
                    &mut targets,
                );
            }
        }
    }
    targets
}

fn push_proxy_upstreams(scope: &str, proxy: &ProxyConfig, targets: &mut Vec<UpstreamTarget>) {
    if let Some(upstream) = &proxy.upstream {
        targets.push(UpstreamTarget {
            scope: scope.to_owned(),
            authority: upstream.clone(),
        });
    }
    for upstream in &proxy.upstreams {
        targets.push(UpstreamTarget {
            scope: scope.to_owned(),
            authority: upstream.clone(),
        });
    }
}

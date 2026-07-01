use fluxheim_config::{AcmeChallenge, Config, HeaderPolicyConfig};

use crate::native_http1_route_proxy::{
    NativeHttp1RouteProxyConfigError, NativeHttp1RouteProxyRoute,
};

pub(crate) fn native_managed_http_01_route(
    config: &Config,
    vhost: &fluxheim_config::VhostConfig,
    base_headers: &HeaderPolicyConfig,
) -> Result<Option<NativeHttp1RouteProxyRoute>, NativeHttp1RouteProxyConfigError> {
    if vhost.acme_challenge.enabled
        || !config.tls.acme.enabled
        || config.tls.acme.challenge != AcmeChallenge::Http01
    {
        return Ok(None);
    }

    let Some(storage) = config.tls.acme.storage.as_deref() else {
        return Err(NativeHttp1RouteProxyConfigError::AcmeStorage);
    };
    let Some(owner) = native_managed_http_01_owner_vhost(config, vhost) else {
        return Ok(None);
    };

    Ok(Some(NativeHttp1RouteProxyRoute::acme_http_01(
        owner,
        storage,
        base_headers,
    )))
}

fn native_managed_http_01_owner_vhost<'a>(
    config: &'a Config,
    request_vhost: &'a fluxheim_config::VhostConfig,
) -> Option<&'a str> {
    if request_vhost.tls.enabled && request_vhost.tls.acme.enabled {
        return Some(&request_vhost.name);
    }

    let request_hosts: std::collections::HashSet<String> = request_vhost
        .hosts
        .iter()
        .filter_map(|host| fluxheim_config::config_net::normalize_host(host))
        .collect();
    if request_hosts.is_empty() {
        return None;
    }

    config.vhosts.iter().find_map(|candidate| {
        if !candidate.tls.enabled || !candidate.tls.acme.enabled {
            return None;
        }

        let domains: Box<dyn Iterator<Item = &str> + '_> = if candidate.tls.acme.domains.is_empty()
        {
            Box::new(candidate.hosts.iter().map(String::as_str))
        } else {
            Box::new(candidate.tls.acme.domains.iter().map(String::as_str))
        };

        for domain in domains {
            let Some(domain) = fluxheim_config::config_net::normalize_host(domain) else {
                continue;
            };
            if request_hosts.contains(&domain) {
                return Some(candidate.name.as_str());
            }
        }

        None
    })
}

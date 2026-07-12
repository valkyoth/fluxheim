use super::*;

pub fn renewal_targets(config: &Config) -> Vec<AcmeRenewalTarget> {
    if !config.tls.acme.renewal.enabled {
        return Vec::new();
    }
    managed_acme_targets(config)
}

pub fn managed_acme_targets(config: &Config) -> Vec<AcmeRenewalTarget> {
    if !config.tls.enabled || !config.tls.acme.enabled {
        return Vec::new();
    }
    let Some(storage) = &config.tls.acme.storage else {
        return Vec::new();
    };

    config
        .vhosts
        .iter()
        .filter(|vhost| vhost.tls.enabled && vhost.tls.acme.enabled)
        .map(|vhost| {
            let issuer = vhost
                .tls
                .acme
                .issuer
                .clone()
                .unwrap_or_else(|| config.tls.acme.default_issuer.clone());
            let configured_domains = &vhost.tls.acme.domains;
            let domains = if configured_domains.is_empty() {
                vhost
                    .hosts
                    .iter()
                    .filter(|host| !host.starts_with("*."))
                    .map(|host| normalized_domain(host))
                    .collect()
            } else {
                configured_domains
                    .iter()
                    .map(|domain| normalized_domain(domain))
                    .collect()
            };
            AcmeRenewalTarget {
                vhost_name: vhost.name.clone(),
                issuer,
                domains,
                challenge: config.tls.acme.challenge,
                certificate: managed_certificate_paths(storage, &vhost.name),
            }
        })
        .collect()
}

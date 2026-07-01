use std::sync::Arc;

use fluxheim_config::ProxyConfig;

use super::backend::FluxBackend;
use super::key::backend_key;

pub(super) fn backend_priority_groups(config: &ProxyConfig) -> std::collections::HashMap<u64, u16> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_priority_groups)
        .filter_map(|(upstream, priority)| {
            let backend = FluxBackend::new(upstream).ok()?;
            Some((backend_key(&backend), *priority))
        })
        .collect()
}

pub(super) fn backend_max_in_flight(config: &ProxyConfig) -> std::collections::HashMap<u64, usize> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_max_in_flight)
        .filter_map(|(upstream, max_in_flight)| {
            let backend = FluxBackend::new(upstream).ok()?;
            Some((backend_key(&backend), *max_in_flight))
        })
        .collect()
}

pub(super) fn backend_localities(config: &ProxyConfig) -> std::collections::HashMap<u64, Arc<str>> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_localities)
        .filter_map(|(upstream, locality)| {
            let backend = FluxBackend::new(upstream).ok()?;
            Some((
                backend_key(&backend),
                Arc::<str>::from(locality.to_ascii_lowercase()),
            ))
        })
        .collect()
}

pub(super) fn backend_tags(config: &ProxyConfig) -> std::collections::HashMap<u64, Arc<[String]>> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_tags)
        .filter_map(|(upstream, tags)| {
            let backend = FluxBackend::new(upstream).ok()?;
            Some((backend_key(&backend), Arc::<[String]>::from(tags.clone())))
        })
        .collect()
}

pub(super) fn sorted_priority_groups(priority: &std::collections::HashMap<u64, u16>) -> Vec<u16> {
    let mut groups = priority
        .values()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    groups.reverse();
    groups
}

pub(super) fn backend_aliases(config: &ProxyConfig) -> std::collections::HashMap<u64, Arc<str>> {
    config
        .upstreams
        .iter()
        .zip(&config.upstream_aliases)
        .filter_map(|(upstream, alias)| {
            let backend = FluxBackend::new(upstream).ok()?;
            Some((backend_key(&backend), Arc::<str>::from(alias.as_str())))
        })
        .collect()
}

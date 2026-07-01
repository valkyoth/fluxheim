use crate::config::ConfigError;
use crate::config_net::valid_upstream_alias;
use crate::config_proxy::ProxyConfig;

const MAX_PROXY_UPSTREAM_WEIGHT: usize = 1000;
const MAX_PROXY_UPSTREAM_TOTAL_WEIGHT: usize = u16::MAX as usize;
const MAX_PROXY_UPSTREAM_PRIORITY_GROUP: u16 = 1000;
const MAX_PROXY_UPSTREAM_MAX_IN_FLIGHT: usize = 1_000_000;
const MAX_PROXY_UPSTREAM_TAGS_PER_BACKEND: usize = 16;

pub(crate) fn validate_static_upstream_attributes(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    validate_upstream_weights(proxy)?;
    validate_upstream_priority_groups(proxy)?;
    validate_upstream_localities(proxy)?;
    validate_upstream_max_in_flight(proxy)?;
    validate_upstream_aliases(proxy)?;
    validate_upstream_tags(proxy)
}

fn validate_upstream_weights(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    if proxy.upstream_weights.is_empty() {
        return Ok(());
    }
    if proxy.upstream.is_some() || proxy.upstream_weights.len() != proxy.upstreams.len() {
        return Err(ConfigError::InvalidProxyUpstreamWeights {
            reason: "upstream_weights must match proxy.upstreams and cannot be used with proxy.upstream",
        });
    }
    let mut total_weight = 0usize;
    for weight in &proxy.upstream_weights {
        if *weight == 0 {
            return Err(ConfigError::InvalidProxyUpstreamWeights {
                reason: "weights must be greater than zero",
            });
        }
        if *weight > MAX_PROXY_UPSTREAM_WEIGHT {
            return Err(ConfigError::InvalidProxyUpstreamWeights {
                reason: "each weight must be at most 1000",
            });
        }
        total_weight = total_weight.saturating_add(*weight);
    }
    if total_weight > MAX_PROXY_UPSTREAM_TOTAL_WEIGHT {
        return Err(ConfigError::InvalidProxyUpstreamWeights {
            reason: "total upstream weight is too large",
        });
    }
    Ok(())
}

fn validate_upstream_priority_groups(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    if !proxy.upstream_priority_groups.is_empty() {
        if proxy.upstream.is_some() || proxy.upstream_priority_groups.len() != proxy.upstreams.len()
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_priority_groups",
                reason: "upstream_priority_groups must match proxy.upstreams and cannot be used with proxy.upstream",
            });
        }
        if proxy.upstream_priority_group_min_active == 0
            || proxy.upstream_priority_group_min_active > proxy.upstreams.len()
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_priority_group_min_active",
                reason: "priority group activation threshold must be between 1 and the number of upstreams",
            });
        }
        for priority in &proxy.upstream_priority_groups {
            if *priority > MAX_PROXY_UPSTREAM_PRIORITY_GROUP {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_priority_groups",
                    reason: "priority groups must be at most 1000",
                });
            }
        }
    } else if proxy.upstream_priority_group_min_active
        != crate::config_proxy::default_upstream_priority_group_min_active()
    {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_priority_group_min_active",
            reason: "requires proxy.upstream_priority_groups",
        });
    }
    Ok(())
}

fn validate_upstream_localities(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    if proxy.upstream_localities.is_empty() {
        if !proxy.preferred_upstream_localities.is_empty() {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.preferred_upstream_localities",
                reason: "requires proxy.upstream_localities",
            });
        }
        return Ok(());
    }
    if proxy.upstream.is_some() || proxy.upstream_localities.len() != proxy.upstreams.len() {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_localities",
            reason: "upstream_localities must match proxy.upstreams and cannot be used with proxy.upstream",
        });
    }
    let mut configured_localities = std::collections::HashSet::new();
    for locality in &proxy.upstream_localities {
        if !valid_upstream_alias(locality) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_localities",
                reason: "localities must be 1-64 ASCII letters, digits, dots, dashes, or underscores",
            });
        }
        configured_localities.insert(locality.to_ascii_lowercase());
    }
    let mut seen_preferred = std::collections::HashSet::new();
    for locality in &proxy.preferred_upstream_localities {
        if !valid_upstream_alias(locality) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.preferred_upstream_localities",
                reason: "preferred localities must be 1-64 ASCII letters, digits, dots, dashes, or underscores",
            });
        }
        let normalized = locality.to_ascii_lowercase();
        if !configured_localities.contains(&normalized) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.preferred_upstream_localities",
                reason: "preferred localities must be present in proxy.upstream_localities",
            });
        }
        if !seen_preferred.insert(normalized) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.preferred_upstream_localities",
                reason: "preferred localities must be unique case-insensitively",
            });
        }
    }
    Ok(())
}

fn validate_upstream_max_in_flight(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    if proxy.upstream_max_in_flight.is_empty() {
        return Ok(());
    }
    if proxy.upstream.is_some() || proxy.upstream_max_in_flight.len() != proxy.upstreams.len() {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_max_in_flight",
            reason: "upstream_max_in_flight must match proxy.upstreams and cannot be used with proxy.upstream",
        });
    }
    for max_in_flight in &proxy.upstream_max_in_flight {
        if *max_in_flight == 0 || *max_in_flight > MAX_PROXY_UPSTREAM_MAX_IN_FLIGHT {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_max_in_flight",
                reason: "max in-flight values must be between 1 and 1000000",
            });
        }
    }
    Ok(())
}

fn validate_upstream_aliases(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    if proxy.upstream_aliases.is_empty() {
        return Ok(());
    }
    if proxy.upstream.is_some() || proxy.upstream_aliases.len() != proxy.upstreams.len() {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_aliases",
            reason: "upstream_aliases must match proxy.upstreams and cannot be used with proxy.upstream",
        });
    }
    let mut seen_aliases = std::collections::HashSet::new();
    for alias in &proxy.upstream_aliases {
        if !valid_upstream_alias(alias) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_aliases",
                reason: "aliases must be 1-64 ASCII letters, digits, dots, dashes, or underscores",
            });
        }
        if !seen_aliases.insert(alias.to_ascii_lowercase()) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_aliases",
                reason: "aliases must be unique case-insensitively",
            });
        }
    }
    Ok(())
}

fn validate_upstream_tags(proxy: &ProxyConfig) -> Result<(), ConfigError> {
    if proxy.upstream_tags.is_empty() {
        return Ok(());
    }
    if proxy.upstream.is_some() || proxy.upstream_tags.len() != proxy.upstreams.len() {
        return Err(ConfigError::InvalidProxyUpstreamPolicy {
            field: "proxy.upstream_tags",
            reason: "upstream_tags must match proxy.upstreams and cannot be used with proxy.upstream",
        });
    }
    for tags in &proxy.upstream_tags {
        if tags.len() > MAX_PROXY_UPSTREAM_TAGS_PER_BACKEND {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_tags",
                reason: "each upstream may have at most 16 tags",
            });
        }
        let mut seen_tags = std::collections::HashSet::new();
        for tag in tags {
            if !valid_upstream_alias(tag) {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_tags",
                    reason: "tags must be 1-64 ASCII letters, digits, dots, dashes, or underscores",
                });
            }
            if !seen_tags.insert(tag.to_ascii_lowercase()) {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_tags",
                    reason: "tags must be unique per upstream case-insensitively",
                });
            }
        }
    }
    Ok(())
}

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use fluxheim_config::{Config, DownstreamProxyProtocol};

use crate::ServerPlanError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProtocolTrustedSource {
    Cidr { network: IpAddr, prefix: u8 },
    Ip(IpAddr),
}

impl ProxyProtocolTrustedSource {
    pub fn contains(self, address: IpAddr) -> bool {
        let address = normalize_ipv4_mapped_ip(address);
        match (self, address) {
            (Self::Ip(trusted), address) => normalize_ipv4_mapped_ip(trusted) == address,
            (
                Self::Cidr {
                    network: IpAddr::V4(network),
                    prefix,
                },
                IpAddr::V4(address),
            ) => ipv4_prefix_match(network, address, prefix),
            (
                Self::Cidr {
                    network: IpAddr::V6(network),
                    prefix,
                },
                IpAddr::V6(address),
            ) => ipv6_prefix_match(network, address, prefix),
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyProtocolPolicy {
    Off,
    V1 {
        trusted_sources: Vec<ProxyProtocolTrustedSource>,
    },
    V2 {
        trusted_sources: Vec<ProxyProtocolTrustedSource>,
    },
}

fn normalize_ipv4_mapped_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        IpAddr::V4(_) => address,
    }
}

fn ipv4_prefix_match(network: Ipv4Addr, address: Ipv4Addr, prefix: u8) -> bool {
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32u32 - u32::from(prefix))
    };
    u32::from(network) & mask == u32::from(address) & mask
}

fn ipv6_prefix_match(network: Ipv6Addr, address: Ipv6Addr, prefix: u8) -> bool {
    if prefix > 128 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128u32 - u32::from(prefix))
    };
    u128::from(network) & mask == u128::from(address) & mask
}

impl ProxyProtocolPolicy {
    pub const fn enabled(&self) -> bool {
        !matches!(self, Self::Off)
    }
}

pub(crate) fn proxy_protocol_policy_from_config(
    config: &Config,
) -> Result<ProxyProtocolPolicy, ServerPlanError> {
    let trusted_sources = config
        .server
        .trusted_proxies
        .iter()
        .map(|source| parse_proxy_protocol_trusted_source(source))
        .collect::<Result<Vec<_>, _>>()?;

    match config.server.proxy_protocol {
        DownstreamProxyProtocol::Off => Ok(ProxyProtocolPolicy::Off),
        DownstreamProxyProtocol::V1 => Ok(ProxyProtocolPolicy::V1 { trusted_sources }),
        DownstreamProxyProtocol::V2 => Ok(ProxyProtocolPolicy::V2 { trusted_sources }),
    }
}

fn parse_proxy_protocol_trusted_source(
    value: &str,
) -> Result<ProxyProtocolTrustedSource, ServerPlanError> {
    match fluxheim_protocol::parse_proxy_protocol_trusted_source(value).map_err(|error| {
        ServerPlanError::InvalidProxyProtocolTrustedSource {
            source: value.to_owned(),
            reason: error.to_string(),
        }
    })? {
        fluxheim_protocol::ProxyProtocolTrustedSource::Ip(address) => {
            Ok(ProxyProtocolTrustedSource::Ip(address))
        }
        fluxheim_protocol::ProxyProtocolTrustedSource::Cidr { network, prefix } => {
            Ok(ProxyProtocolTrustedSource::Cidr { network, prefix })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_source_contains_exact_and_cidr_matches() {
        let exact = ProxyProtocolTrustedSource::Ip("203.0.113.10".parse().unwrap());
        assert!(exact.contains("203.0.113.10".parse().unwrap()));
        assert!(!exact.contains("203.0.113.11".parse().unwrap()));

        let v4_cidr = ProxyProtocolTrustedSource::Cidr {
            network: "198.51.100.0".parse().unwrap(),
            prefix: 24,
        };
        assert!(v4_cidr.contains("198.51.100.42".parse().unwrap()));
        assert!(!v4_cidr.contains("198.51.101.42".parse().unwrap()));

        let v6_cidr = ProxyProtocolTrustedSource::Cidr {
            network: "2001:db8:abcd::".parse().unwrap(),
            prefix: 48,
        };
        assert!(v6_cidr.contains("2001:db8:abcd::42".parse().unwrap()));
        assert!(!v6_cidr.contains("2001:db8:abce::42".parse().unwrap()));
    }

    #[test]
    fn trusted_source_matches_ipv4_mapped_ipv6_literals() {
        let exact = ProxyProtocolTrustedSource::Ip("203.0.113.10".parse().unwrap());
        assert!(exact.contains("::ffff:203.0.113.10".parse().unwrap()));

        let v4_cidr = ProxyProtocolTrustedSource::Cidr {
            network: "198.51.100.0".parse().unwrap(),
            prefix: 24,
        };
        assert!(v4_cidr.contains("::ffff:198.51.100.42".parse().unwrap()));
        assert!(!v4_cidr.contains("::ffff:198.51.101.42".parse().unwrap()));
    }

    #[test]
    fn trusted_source_rejects_directly_constructed_invalid_prefixes() {
        let invalid_v4 = ProxyProtocolTrustedSource::Cidr {
            network: "198.51.100.0".parse().unwrap(),
            prefix: 33,
        };
        assert!(!invalid_v4.contains("198.51.100.42".parse().unwrap()));

        let invalid_v6 = ProxyProtocolTrustedSource::Cidr {
            network: "2001:db8::".parse().unwrap(),
            prefix: 129,
        };
        assert!(!invalid_v6.contains("2001:db8::42".parse().unwrap()));
    }
}

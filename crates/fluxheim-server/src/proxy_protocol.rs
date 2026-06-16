use fluxheim_config::{Config, DownstreamProxyProtocol};

use crate::ServerPlanError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyProtocolTrustedSource {
    Cidr {
        network: std::net::IpAddr,
        prefix: u8,
    },
    Ip(std::net::IpAddr),
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

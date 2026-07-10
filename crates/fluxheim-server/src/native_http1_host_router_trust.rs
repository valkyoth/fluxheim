use fluxheim_config::Config;

use super::NativeHttp1HostRouterConfigError;
use crate::ProxyProtocolTrustedSource;

pub(super) fn trusted_sources_from_config(
    config: &Config,
) -> Result<Vec<ProxyProtocolTrustedSource>, NativeHttp1HostRouterConfigError> {
    config
        .server
        .trusted_proxies
        .iter()
        .map(
            |source| match fluxheim_protocol::parse_proxy_protocol_trusted_source(source) {
                Ok(fluxheim_protocol::ProxyProtocolTrustedSource::Ip(address)) => {
                    Ok(ProxyProtocolTrustedSource::Ip(address))
                }
                Ok(fluxheim_protocol::ProxyProtocolTrustedSource::Cidr { network, prefix }) => {
                    Ok(ProxyProtocolTrustedSource::Cidr { network, prefix })
                }
                Err(error) => Err(NativeHttp1HostRouterConfigError::TrustedProxy {
                    source: source.clone(),
                    reason: error.to_string(),
                }),
            },
        )
        .collect()
}

use std::net::IpAddr;

use fluxheim_config::AccessPolicyConfig;

use crate::ProxyProtocolTrustedSource;
use crate::native_http1_route_proxy::NativeHttp1RouteProxyConfigError;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeIpAccessPolicy {
    enabled: bool,
    allow: Vec<ProxyProtocolTrustedSource>,
    deny: Vec<ProxyProtocolTrustedSource>,
    require_client_cert: bool,
    allow_client_cert_sha256: Vec<String>,
    deny_client_cert_sha256: Vec<String>,
    allow_countries: Vec<String>,
    deny_countries: Vec<String>,
    allow_asns: Vec<u32>,
    deny_asns: Vec<u32>,
}

impl NativeIpAccessPolicy {
    pub(crate) fn from_config(
        access: &AccessPolicyConfig,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        if !access.enabled {
            return Ok(Self::default());
        }
        Ok(Self {
            enabled: true,
            allow: parse_native_access_sources(&access.allow)?,
            deny: parse_native_access_sources(&access.deny)?,
            require_client_cert: access.require_client_cert,
            allow_client_cert_sha256: normalized_access_strings(&access.allow_client_cert_sha256),
            deny_client_cert_sha256: normalized_access_strings(&access.deny_client_cert_sha256),
            allow_countries: normalized_access_strings(&access.allow_countries),
            deny_countries: normalized_access_strings(&access.deny_countries),
            allow_asns: access.allow_asns.clone(),
            deny_asns: access.deny_asns.clone(),
        })
    }

    pub(crate) fn allows(
        &self,
        client_ip: Option<IpAddr>,
        tls_identity: Option<&crate::NativeHttp1TlsClientIdentity>,
        geo_context: Option<&crate::NativeHttp1GeoContext>,
    ) -> bool {
        if !self.enabled {
            return true;
        }
        let ip_restrictive = !self.allow.is_empty() || !self.deny.is_empty();
        if let Some(client_ip) = client_ip {
            if self.deny.iter().any(|source| source.contains(client_ip)) {
                return false;
            }
            if !self.allow.is_empty() && !self.allow.iter().any(|source| source.contains(client_ip))
            {
                return false;
            }
        } else if ip_restrictive {
            return false;
        }
        self.allows_client_certificate(tls_identity) && self.allows_geo(geo_context)
    }

    fn allows_client_certificate(
        &self,
        tls_identity: Option<&crate::NativeHttp1TlsClientIdentity>,
    ) -> bool {
        let cert_sha256 = tls_identity
            .and_then(|identity| identity.cert_sha256.as_deref())
            .map(str::to_ascii_lowercase);
        if self.require_client_cert && cert_sha256.is_none() {
            return false;
        }
        let Some(cert_sha256) = cert_sha256.as_deref() else {
            return self.allow_client_cert_sha256.is_empty();
        };
        if self
            .deny_client_cert_sha256
            .iter()
            .any(|denied| denied == cert_sha256)
        {
            return false;
        }
        self.allow_client_cert_sha256.is_empty()
            || self
                .allow_client_cert_sha256
                .iter()
                .any(|allowed| allowed == cert_sha256)
    }

    fn allows_geo(&self, geo_context: Option<&crate::NativeHttp1GeoContext>) -> bool {
        let has_allow = !self.allow_countries.is_empty() || !self.allow_asns.is_empty();
        let has_deny = !self.deny_countries.is_empty() || !self.deny_asns.is_empty();
        if !has_allow && !has_deny {
            return true;
        }
        let Some(geo_context) = geo_context else {
            return !has_allow;
        };
        let country = geo_context
            .country_iso
            .as_deref()
            .map(str::to_ascii_lowercase);
        if country
            .as_deref()
            .is_some_and(|country| self.deny_countries.iter().any(|denied| denied == country))
        {
            return false;
        }
        if !self.allow_countries.is_empty()
            && !country.as_deref().is_some_and(|country| {
                self.allow_countries
                    .iter()
                    .any(|allowed| allowed == country)
            })
        {
            return false;
        }
        if geo_context
            .asn
            .is_some_and(|asn| self.deny_asns.contains(&asn))
        {
            return false;
        }
        self.allow_asns.is_empty()
            || geo_context
                .asn
                .is_some_and(|asn| self.allow_asns.contains(&asn))
    }
}

fn normalized_access_strings(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn parse_native_access_sources(
    values: &[String],
) -> Result<Vec<ProxyProtocolTrustedSource>, NativeHttp1RouteProxyConfigError> {
    values
        .iter()
        .map(
            |value| match fluxheim_protocol::parse_proxy_protocol_trusted_source(value) {
                Ok(fluxheim_protocol::ProxyProtocolTrustedSource::Ip(address)) => {
                    Ok(ProxyProtocolTrustedSource::Ip(address))
                }
                Ok(fluxheim_protocol::ProxyProtocolTrustedSource::Cidr { network, prefix }) => {
                    Ok(ProxyProtocolTrustedSource::Cidr { network, prefix })
                }
                Err(_) => Err(NativeHttp1RouteProxyConfigError::AccessPolicy),
            },
        )
        .collect()
}

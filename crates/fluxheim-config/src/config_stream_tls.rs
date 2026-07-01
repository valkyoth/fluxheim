use std::net::IpAddr;

use crate::config::{ConfigError, UpstreamProxyProtocol};
use crate::config_net::{normalize_host, upstream_host};
use crate::config_path::{validate_non_world_writable_parent, validate_path};
use crate::config_stream::StreamRouteConfig;

impl StreamRouteConfig {
    pub(crate) fn validate_upstream_tls_policy(&self) -> Result<(), ConfigError> {
        if let Some(sni) = &self.upstream_sni
            && sni.trim().is_empty()
        {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.upstream_sni",
                reason: "must not be empty",
            });
        }
        if self.upstream_tls
            && self.upstream_verify_cert
            && self.upstream_sni.is_none()
            && self.upstreams().any(stream_upstream_authority_host_is_ip)
        {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.upstream_sni",
                reason: "IP-addressed upstreams with upstream_tls and upstream_verify_cert require explicit upstream_sni",
            });
        }
        if !self.upstream_verify_cert && self.upstream_verify_hostname {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.upstream_verify_hostname",
                reason: "must be false when upstream_verify_cert = false",
            });
        }
        if !self.upstream_tls
            && (self.upstream_ca_path.is_some()
                || self.upstream_client_cert_path.is_some()
                || self.upstream_client_key_path.is_some())
        {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.upstream_tls",
                reason: "upstream TLS trust roots or client certificates require upstream_tls = true",
            });
        }
        if self.upstream_tls && self.upstream_proxy_protocol != UpstreamProxyProtocol::Off {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.upstream_proxy_protocol",
                reason: "stream upstream PROXY protocol cannot be combined with upstream_tls yet because PROXY must be written before the TLS handshake",
            });
        }
        if !self.upstream_verify_cert && self.upstream_ca_path.is_some() {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.upstream_ca_path",
                reason: "requires upstream_verify_cert = true",
            });
        }
        match (
            &self.upstream_client_cert_path,
            &self.upstream_client_key_path,
        ) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => {
                return Err(ConfigError::InvalidStreamProxyPolicy {
                    field: "stream.routes.upstream_client_cert_path",
                    reason: "upstream_client_cert_path and upstream_client_key_path must be configured together",
                });
            }
        }
        for (field, path) in [
            (
                "stream.routes.upstream_ca_path",
                self.upstream_ca_path.as_deref(),
            ),
            (
                "stream.routes.upstream_client_cert_path",
                self.upstream_client_cert_path.as_deref(),
            ),
            (
                "stream.routes.upstream_client_key_path",
                self.upstream_client_key_path.as_deref(),
            ),
        ] {
            validate_path(field, path)?;
            validate_non_world_writable_parent(field, path)?;
        }
        if let Some(alternative_cn) = &self.upstream_alternative_cn {
            if alternative_cn.contains('*') {
                return Err(ConfigError::InvalidStreamProxyPolicy {
                    field: "stream.routes.upstream_alternative_cn",
                    reason: "must not contain wildcards",
                });
            }
            if normalize_host(alternative_cn).is_none() {
                return Err(ConfigError::InvalidStreamProxyPolicy {
                    field: "stream.routes.upstream_alternative_cn",
                    reason: "must be a valid hostname",
                });
            }
        }
        #[cfg(not(any(feature = "tls-rustls-backend", feature = "tls-openssl")))]
        if self.upstream_tls {
            return Err(ConfigError::InvalidStreamProxyPolicy {
                field: "stream.routes.upstream_tls",
                reason: "requires a TLS backend feature",
            });
        }
        Ok(())
    }
}

fn stream_upstream_authority_host_is_ip(upstream: &str) -> bool {
    upstream_host(upstream).is_some_and(|host| host.parse::<IpAddr>().is_ok())
}

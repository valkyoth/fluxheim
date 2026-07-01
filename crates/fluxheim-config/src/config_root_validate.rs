use crate::config::{
    AcmeChallenge, Config, ConfigError, MAX_VHOSTS, ProxyConfig, TlsBackend, VhostConfig,
    normalize_host_pattern, validate_config_list_len,
};
use crate::config_cache::validate_cache_compliance_internal_crypto;
use crate::config_http::{
    fips_allowed_local_auth_request_endpoint, fips_allowed_local_mirror_endpoint,
    fips_allowed_local_otlp_endpoint,
};

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_with_runtime_path_validation(true)
    }

    pub(crate) fn validate_with_runtime_path_validation(
        &self,
        validate_runtime_paths: bool,
    ) -> Result<(), ConfigError> {
        self.server.validate_with_runtime_path_validation(
            validate_runtime_paths,
            self.stream.enabled || self.udp.enabled,
        )?;
        self.admin.validate()?;
        self.metrics.validate()?;
        self.tracing.validate()?;
        self.logging.validate()?;
        self.headers.validate()?;
        self.tls.validate()?;
        self.validate_acme_challenge_runtime()?;
        self.validate_tls_listeners()?;
        self.proxy.validate()?;
        self.compression.validate()?;
        self.cache.validate("cache")?;
        self.cache_purger.validate()?;
        self.web.validate()?;
        self.geoip.validate()?;
        self.stream.validate()?;
        self.udp.validate()?;
        self.validate_vhosts()?;
        self.validate_geoip_policy()?;
        self.validate_compliance_internal_crypto()?;
        Ok(())
    }

    fn validate_acme_challenge_runtime(&self) -> Result<(), ConfigError> {
        if !self.tls.acme.enabled || self.tls.acme.challenge != AcmeChallenge::TlsAlpn01 {
            return Ok(());
        }
        if self.tls.backend != TlsBackend::Rustls {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.acme.challenge",
                reason: "tls-alpn-01 managed ACME is currently supported only by the rustls backend",
            });
        }
        if self.server.tls_listen.is_empty() {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.acme.challenge",
                reason: "tls-alpn-01 managed ACME requires at least one server.tls_listen address",
            });
        }

        Ok(())
    }

    fn validate_tls_listeners(&self) -> Result<(), ConfigError> {
        if self.server.tls_listen.is_empty() {
            return Ok(());
        }
        if !self.tls.enabled {
            return Err(ConfigError::TlsListenerWithoutTls);
        }
        if !self.has_tls_listener_fallback_certificate() {
            return Err(ConfigError::TlsListenerWithoutStaticCertificate);
        }

        Ok(())
    }

    fn validate_compliance_internal_crypto(&self) -> Result<(), ConfigError> {
        let compliance_mode = self.tls.compliance_mode();
        if !compliance_mode.required() {
            return Ok(());
        }

        if self.admin.enabled && !crate::internal_crypto::admin_mac_is_compliance_capable() {
            return Err(ConfigError::InvalidCompliancePolicy {
                field: "admin.enabled",
                reason: "FIPS/ISO-required mode allows the admin API only when bearer-token verification is routed through a validated provider; rebuild with tls-openssl-fips or tls-rustls-fips, or disable admin.enabled",
            });
        }

        if self.tls.acme.enabled {
            return Err(ConfigError::InvalidCompliancePolicy {
                field: "tls.acme.enabled",
                reason: "FIPS/ISO-required mode currently rejects managed ACME because account key generation, JWS account signing, EAB handling, outbound ACME HTTPS transport, and TLS-ALPN challenge certificate generation are not fully routed through the selected validated provider; use externally issued static certificates or an externally evidenced renewal process for the FIPS evidence boundary",
            });
        }

        if self.metrics.otlp.enabled
            && !fips_allowed_local_otlp_endpoint(&self.metrics.otlp.endpoint)
        {
            return Err(ConfigError::InvalidCompliancePolicy {
                field: "metrics.otlp.endpoint",
                reason: "FIPS/ISO-required mode allows OTLP metrics export only to a numeric local http://127.0.0.1 or http://[::1] loopback collector; remote, localhost, or HTTPS OTLP export needs provider-aligned outbound TLS evidence first",
            });
        }

        if self.tracing.otlp.enabled
            && !fips_allowed_local_otlp_endpoint(&self.tracing.otlp.endpoint)
        {
            return Err(ConfigError::InvalidCompliancePolicy {
                field: "tracing.otlp.endpoint",
                reason: "FIPS/ISO-required mode allows OTLP trace export only to a numeric local http://127.0.0.1 or http://[::1] loopback collector; remote, localhost, or HTTPS OTLP export needs provider-aligned outbound TLS evidence first",
            });
        }
        validate_auth_request_compliance_internal_crypto(&self.proxy, "proxy.auth_request")?;
        validate_traffic_mirror_compliance_internal_crypto(&self.proxy, "proxy.mirror")?;

        let require_disk_cache_encryption = self.tls.fips.require_disk_cache_encryption
            || self.tls.iso19790.require_disk_cache_encryption;

        validate_cache_compliance_internal_crypto(
            &self.cache,
            "cache",
            require_disk_cache_encryption,
        )?;
        for vhost in &self.vhosts {
            validate_cache_compliance_internal_crypto(
                &vhost.cache,
                "vhosts.cache",
                require_disk_cache_encryption,
            )
            .map_err(|source| ConfigError::VhostSection {
                vhost: vhost.name.clone(),
                section: "cache",
                source: Box::new(source),
            })?;
            validate_auth_request_compliance_internal_crypto(
                &vhost.proxy,
                "vhosts.proxy.auth_request",
            )
            .map_err(|source| ConfigError::VhostSection {
                vhost: vhost.name.clone(),
                section: "proxy",
                source: Box::new(source),
            })?;
            validate_traffic_mirror_compliance_internal_crypto(&vhost.proxy, "vhosts.proxy.mirror")
                .map_err(|source| ConfigError::VhostSection {
                    vhost: vhost.name.clone(),
                    section: "proxy",
                    source: Box::new(source),
                })?;
            for route in &vhost.routes {
                if let Some(cache) = &route.cache {
                    validate_cache_compliance_internal_crypto(
                        cache,
                        "vhosts.routes.cache",
                        require_disk_cache_encryption,
                    )
                    .map_err(|source| ConfigError::RouteSection {
                        vhost: vhost.name.clone(),
                        route: route.name.clone(),
                        section: "cache",
                        source: Box::new(source),
                    })?;
                }
                if let Some(proxy) = &route.proxy {
                    validate_auth_request_compliance_internal_crypto(
                        proxy,
                        "vhosts.routes.proxy.auth_request",
                    )
                    .map_err(|source| ConfigError::RouteSection {
                        vhost: vhost.name.clone(),
                        route: route.name.clone(),
                        section: "proxy",
                        source: Box::new(source),
                    })?;
                    validate_traffic_mirror_compliance_internal_crypto(
                        proxy,
                        "vhosts.routes.proxy.mirror",
                    )
                    .map_err(|source| ConfigError::RouteSection {
                        vhost: vhost.name.clone(),
                        route: route.name.clone(),
                        section: "proxy",
                        source: Box::new(source),
                    })?;
                }
            }
        }

        Ok(())
    }

    fn has_tls_listener_fallback_certificate(&self) -> bool {
        if !self.tls.certificates.is_empty() {
            return true;
        }

        let Some(default_vhost) = &self.server.default_vhost else {
            return false;
        };

        self.vhosts.iter().any(|vhost| {
            &vhost.name == default_vhost
                && vhost.tls.enabled
                && (vhost.tls.certificate.is_some() || self.vhost_has_managed_acme_source(vhost))
        })
    }

    #[cfg(feature = "acme")]
    fn vhost_has_managed_acme_source(&self, vhost: &VhostConfig) -> bool {
        self.tls.acme.enabled && self.tls.acme.storage.is_some() && vhost.tls.acme.enabled
    }

    #[cfg(not(feature = "acme"))]
    fn vhost_has_managed_acme_source(&self, _vhost: &VhostConfig) -> bool {
        false
    }

    fn validate_vhosts(&self) -> Result<(), ConfigError> {
        validate_config_list_len("vhosts", self.vhosts.len(), MAX_VHOSTS)?;

        let mut seen_names = std::collections::HashSet::new();
        let mut seen_hosts = std::collections::HashSet::new();

        for vhost in &self.vhosts {
            vhost.validate(self.server.regex_enabled)?;
            vhost
                .validate_tls(&self.tls, self.vhost_has_shared_managed_acme_source(vhost))
                .map_err(|source| ConfigError::VhostSection {
                    vhost: vhost.name.clone(),
                    section: "tls",
                    source: Box::new(source),
                })?;

            if !seen_names.insert(vhost.name.clone()) {
                return Err(ConfigError::DuplicateVhostName {
                    name: vhost.name.clone(),
                });
            }

            for host in &vhost.hosts {
                let normalized_host =
                    normalize_host_pattern(host).ok_or_else(|| ConfigError::InvalidVhostHost {
                        vhost: vhost.name.clone(),
                        host: host.clone(),
                    })?;
                if !seen_hosts.insert(normalized_host.clone()) {
                    return Err(ConfigError::DuplicateVhostHost {
                        host: normalized_host,
                    });
                }
            }
        }

        if let Some(default_vhost) = &self.server.default_vhost
            && !self.vhosts.iter().any(|vhost| &vhost.name == default_vhost)
        {
            return Err(ConfigError::UnknownDefaultVhost {
                name: default_vhost.clone(),
            });
        }

        Ok(())
    }

    fn validate_geoip_policy(&self) -> Result<(), ConfigError> {
        if self.geoip.enabled {
            return Ok(());
        }
        for vhost in &self.vhosts {
            if vhost.access.requires_geoip() {
                return Err(ConfigError::InvalidGeoIpPolicy {
                    field: "vhosts.access",
                    reason: "GeoIP access rules require geoip.enabled = true",
                });
            }
            for route in &vhost.routes {
                if route.access.requires_geoip() {
                    return Err(ConfigError::InvalidGeoIpPolicy {
                        field: "vhosts.routes.access",
                        reason: "GeoIP access rules require geoip.enabled = true",
                    });
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "acme")]
    fn vhost_has_shared_managed_acme_source(&self, vhost: &VhostConfig) -> bool {
        if !self.tls.acme.enabled || self.tls.acme.storage.is_none() {
            return false;
        }
        if vhost.tls.certificate.is_some() || vhost.tls.acme.enabled {
            return false;
        }
        let hosts = vhost
            .hosts
            .iter()
            .filter(|host| !host.starts_with("*."))
            .filter_map(|host| crate::config::normalize_host(host))
            .collect::<Vec<_>>();
        if hosts.is_empty() {
            return false;
        }

        self.vhosts.iter().any(|candidate| {
            candidate.name != vhost.name
                && candidate.tls.enabled
                && candidate.tls.acme.enabled
                && managed_acme_domains_for_vhost(candidate)
                    .is_some_and(|domains| hosts.iter().all(|host| domains.contains(host)))
        })
    }

    #[cfg(not(feature = "acme"))]
    fn vhost_has_shared_managed_acme_source(&self, _vhost: &VhostConfig) -> bool {
        false
    }
}

#[cfg(feature = "acme")]
fn managed_acme_domains_for_vhost(
    vhost: &VhostConfig,
) -> Option<std::collections::HashSet<String>> {
    let domains = if vhost.tls.acme.domains.is_empty() {
        &vhost.hosts
    } else {
        &vhost.tls.acme.domains
    };
    let domains = domains
        .iter()
        .filter(|domain| !domain.starts_with("*."))
        .filter_map(|domain| crate::config::normalize_host(domain))
        .collect::<std::collections::HashSet<_>>();
    (!domains.is_empty()).then_some(domains)
}

fn validate_auth_request_compliance_internal_crypto(
    proxy: &ProxyConfig,
    scope: &'static str,
) -> Result<(), ConfigError> {
    if !proxy.auth_request.enabled {
        return Ok(());
    }
    let Some(url) = proxy.auth_request.url.as_deref() else {
        return Ok(());
    };
    if fips_allowed_local_auth_request_endpoint(url) {
        return Ok(());
    }
    Err(ConfigError::InvalidCompliancePolicy {
        field: scope,
        reason: "FIPS/ISO-required mode allows auth_request only to a numeric local http://127.0.0.1 or http://[::1] loopback endpoint; remote or HTTPS auth subrequests need provider-aligned outbound TLS evidence first",
    })
}

fn validate_traffic_mirror_compliance_internal_crypto(
    proxy: &ProxyConfig,
    scope: &'static str,
) -> Result<(), ConfigError> {
    if !proxy.mirror.enabled {
        return Ok(());
    }
    let Some(base_url) = proxy.mirror.base_url.as_deref() else {
        return Ok(());
    };
    if fips_allowed_local_mirror_endpoint(base_url) {
        return Ok(());
    }
    Err(ConfigError::InvalidCompliancePolicy {
        field: scope,
        reason: "FIPS/ISO-required mode allows traffic mirroring only to a numeric local http://127.0.0.1 or http://[::1] loopback endpoint; remote or HTTPS mirror export needs provider-aligned outbound TLS evidence first",
    })
}

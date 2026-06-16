use std::collections::{HashMap, HashSet};

use fluxheim_config::{Config, StaticCertificateConfig, VhostConfig, normalize_host};
use thiserror::Error;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DownstreamTlsListenerPlan {
    listens: Vec<String>,
    selector: DownstreamCertificateSelector,
    requires_certificate_resolver: bool,
    acme_tls_alpn_enabled: bool,
}

impl DownstreamTlsListenerPlan {
    pub fn from_config_with_acme_resolver(
        config: &Config,
        resolver: impl Fn(&Config, &VhostConfig) -> Option<DownstreamCertificateSource>,
    ) -> Result<Option<Self>, DownstreamTlsPlanError> {
        if config.server.tls_listen.is_empty() {
            return Ok(None);
        }
        if !config.tls.enabled {
            return Err(DownstreamTlsPlanError::TlsDisabled);
        }

        let selector =
            DownstreamCertificateSelector::from_config_with_acme_resolver(config, resolver)
                .ok_or(DownstreamTlsPlanError::MissingFallbackCertificate)?;
        let acme_tls_alpn_enabled = acme_tls_alpn_enabled(config);
        let requires_certificate_resolver =
            selector.has_sni_certificates() || acme_tls_alpn_enabled;

        Ok(Some(Self {
            listens: config.server.tls_listen.clone(),
            selector,
            requires_certificate_resolver,
            acme_tls_alpn_enabled,
        }))
    }

    pub fn from_config(config: &Config) -> Result<Option<Self>, DownstreamTlsPlanError> {
        Self::from_config_with_acme_resolver(config, |_config, _vhost| None)
    }

    pub fn listens(&self) -> &[String] {
        &self.listens
    }

    pub fn selector(&self) -> &DownstreamCertificateSelector {
        &self.selector
    }

    pub fn requires_certificate_resolver(&self) -> bool {
        self.requires_certificate_resolver
    }

    pub fn acme_tls_alpn_enabled(&self) -> bool {
        self.acme_tls_alpn_enabled
    }
}

#[derive(Debug, Error)]
pub enum DownstreamTlsPlanError {
    #[error("server.tls_listen requires tls.enabled = true")]
    TlsDisabled,
    #[error(
        "server.tls_listen requires a global certificate or a static/ACME certificate source on server.default_vhost"
    )]
    MissingFallbackCertificate,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DownstreamCertificateSelector {
    certificates: Vec<StaticCertificateConfig>,
    fallback_certificate: StaticCertificateConfig,
    managed_acme: Vec<bool>,
    default_index: usize,
    exact_hosts: HashMap<String, usize>,
    wildcard_hosts: Vec<WildcardCertificate>,
}

impl DownstreamCertificateSelector {
    pub fn from_config_with_acme_resolver(
        config: &Config,
        resolver: impl Fn(&Config, &VhostConfig) -> Option<DownstreamCertificateSource>,
    ) -> Option<Self> {
        let default = default_downstream_certificate(config, &resolver)?;
        let mut selector = Self {
            certificates: vec![default.certificate.clone()],
            fallback_certificate: default.certificate,
            managed_acme: vec![default.managed_acme],
            default_index: 0,
            exact_hosts: HashMap::new(),
            wildcard_hosts: Vec::new(),
        };

        for vhost in &config.vhosts {
            if !vhost.tls.enabled {
                continue;
            }
            let Some(certificate) = vhost_certificate_source(config, vhost, &resolver) else {
                continue;
            };
            let certificate_index = selector
                .certificates
                .iter()
                .position(|existing| existing == &certificate.certificate)
                .unwrap_or_else(|| {
                    let index = selector.certificates.len();
                    selector.certificates.push(certificate.certificate.clone());
                    selector.managed_acme.push(certificate.managed_acme);
                    index
                });
            if !certificate.managed_acme {
                selector.managed_acme[certificate_index] = false;
            }

            for host in vhost.normalized_hosts() {
                if let Some(suffix) = host.strip_prefix("*.") {
                    selector.wildcard_hosts.push(WildcardCertificate {
                        suffix: suffix.to_owned(),
                        certificate_index,
                    });
                } else {
                    selector.exact_hosts.insert(host, certificate_index);
                }
            }
        }

        selector
            .wildcard_hosts
            .sort_by_key(|wildcard| std::cmp::Reverse(wildcard.suffix.len()));

        Some(selector)
    }

    pub fn from_config(config: &Config) -> Option<Self> {
        Self::from_config_with_acme_resolver(config, |_config, _vhost| None)
    }

    pub fn has_sni_certificates(&self) -> bool {
        !self.exact_hosts.is_empty() || !self.wildcard_hosts.is_empty()
    }

    pub fn certificates(&self) -> &[StaticCertificateConfig] {
        &self.certificates
    }

    pub fn certificate_is_managed_acme(&self, index: usize) -> bool {
        self.managed_acme.get(index).copied().unwrap_or(false)
    }

    pub fn default_certificate_index(&self) -> usize {
        self.default_index
    }

    pub fn certificate_index_for_sni(&self, sni: Option<&str>) -> usize {
        let Some(host) = sni.and_then(normalize_host) else {
            return self.default_index;
        };

        if let Some(index) = self.exact_hosts.get(&host) {
            return *index;
        }

        self.wildcard_hosts
            .iter()
            .find(|wildcard| wildcard.matches(&host))
            .map(|wildcard| wildcard.certificate_index)
            .unwrap_or(self.default_index)
    }

    pub fn certificate_for_sni(&self, sni: Option<&str>) -> &StaticCertificateConfig {
        let index = self.certificate_index_for_sni(sni);
        self.certificates
            .get(index)
            .or_else(|| self.certificates.get(self.default_index))
            .unwrap_or(&self.fallback_certificate)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DownstreamCertificateSource {
    pub certificate: StaticCertificateConfig,
    pub managed_acme: bool,
}

fn default_downstream_certificate(
    config: &Config,
    resolver: &impl Fn(&Config, &VhostConfig) -> Option<DownstreamCertificateSource>,
) -> Option<DownstreamCertificateSource> {
    config
        .tls
        .certificates
        .first()
        .cloned()
        .map(|certificate| DownstreamCertificateSource {
            certificate,
            managed_acme: false,
        })
        .or_else(|| default_vhost_certificate_source(config, resolver))
}

fn default_vhost_certificate_source(
    config: &Config,
    resolver: &impl Fn(&Config, &VhostConfig) -> Option<DownstreamCertificateSource>,
) -> Option<DownstreamCertificateSource> {
    let default_vhost = config.server.default_vhost.as_ref()?;
    config
        .vhosts
        .iter()
        .find(|vhost| &vhost.name == default_vhost && vhost.tls.enabled)
        .and_then(|vhost| vhost_certificate_source(config, vhost, resolver))
}

fn vhost_certificate_source(
    config: &Config,
    vhost: &VhostConfig,
    resolver: &impl Fn(&Config, &VhostConfig) -> Option<DownstreamCertificateSource>,
) -> Option<DownstreamCertificateSource> {
    if let Some(certificate) = vhost.tls.certificate.clone() {
        return Some(DownstreamCertificateSource {
            certificate,
            managed_acme: false,
        });
    }
    resolver(config, vhost)
}

pub fn shared_managed_acme_certificate_owner<'a>(
    config: &'a Config,
    vhost: &VhostConfig,
) -> Option<&'a str> {
    let hosts = vhost
        .hosts
        .iter()
        .filter(|host| !host.starts_with("*."))
        .filter_map(|host| normalize_host(host))
        .collect::<Vec<_>>();
    if hosts.is_empty() {
        return None;
    }

    config
        .vhosts
        .iter()
        .find(|candidate| {
            candidate.name != vhost.name
                && candidate.tls.enabled
                && candidate.tls.acme.enabled
                && managed_acme_domains_for_vhost(candidate)
                    .is_some_and(|domains| hosts.iter().all(|host| domains.contains(host)))
        })
        .map(|candidate| candidate.name.as_str())
}

fn managed_acme_domains_for_vhost(vhost: &VhostConfig) -> Option<HashSet<String>> {
    let domains = if vhost.tls.acme.domains.is_empty() {
        &vhost.hosts
    } else {
        &vhost.tls.acme.domains
    };
    let domains = domains
        .iter()
        .filter(|domain| !domain.starts_with("*."))
        .filter_map(|domain| normalize_host(domain))
        .collect::<HashSet<_>>();
    (!domains.is_empty()).then_some(domains)
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct WildcardCertificate {
    suffix: String,
    certificate_index: usize,
}

impl WildcardCertificate {
    fn matches(&self, host: &str) -> bool {
        let Some(prefix) = host.strip_suffix(self.suffix.as_str()) else {
            return false;
        };

        prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
    }
}

fn acme_tls_alpn_enabled(config: &Config) -> bool {
    #[cfg(feature = "acme")]
    {
        config.tls.acme.enabled
            && config.tls.acme.challenge == fluxheim_config::AcmeChallenge::TlsAlpn01
    }
    #[cfg(not(feature = "acme"))]
    {
        let _ = config;
        false
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use fluxheim_config::{
        CacheConfig, Config, ProxyConfig, ServerConfig, StaticCertificateConfig, TlsConfig,
        VhostConfig, VhostHeaderPolicyConfig, VhostTlsConfig, WebConfig,
    };

    use super::*;

    fn vhost(
        name: &str,
        hosts: Vec<&str>,
        certificate: Option<StaticCertificateConfig>,
    ) -> VhostConfig {
        VhostConfig {
            name: name.to_owned(),
            hosts: hosts.into_iter().map(str::to_owned).collect(),
            max_request_body_bytes: None,
            access: Default::default(),
            rate_limit: Default::default(),
            concurrency: Default::default(),
            acme_challenge: Default::default(),
            redirect: Default::default(),
            tls: VhostTlsConfig {
                enabled: true,
                certificate,
                ..VhostTlsConfig::default()
            },
            proxy: ProxyConfig::default(),
            cache: CacheConfig::default(),
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
            php: Default::default(),
            web: WebConfig::default(),
            routes: Vec::new(),
        }
    }

    #[test]
    fn downstream_certificate_selector_matches_exact_and_wildcard_sni() {
        let default_cert = StaticCertificateConfig {
            cert_path: PathBuf::from("/tls/default.pem"),
            key_path: PathBuf::from("/tls/default.key"),
        };
        let exact_cert = StaticCertificateConfig {
            cert_path: PathBuf::from("/tls/exact.pem"),
            key_path: PathBuf::from("/tls/exact.key"),
        };
        let wildcard_cert = StaticCertificateConfig {
            cert_path: PathBuf::from("/tls/wildcard.pem"),
            key_path: PathBuf::from("/tls/wildcard.key"),
        };
        let config = Config {
            tls: TlsConfig {
                enabled: true,
                certificates: vec![default_cert.clone()],
                ..TlsConfig::default()
            },
            vhosts: vec![
                vhost("exact", vec!["Example.TEST"], Some(exact_cert.clone())),
                vhost(
                    "wildcard",
                    vec!["*.api.example.test"],
                    Some(wildcard_cert.clone()),
                ),
            ],
            ..Config::default()
        };

        let selector = DownstreamCertificateSelector::from_config(&config).unwrap();

        assert!(selector.has_sni_certificates());
        assert_eq!(
            selector.certificate_for_sni(Some("example.test")),
            &exact_cert
        );
        assert_eq!(
            selector.certificate_for_sni(Some("service.api.example.test")),
            &wildcard_cert
        );
        assert_eq!(
            selector.certificate_for_sni(Some("deep.service.api.example.test")),
            &default_cert
        );
        assert_eq!(selector.certificate_for_sni(None), &default_cert);
    }

    #[test]
    fn listener_plan_requires_resolver_for_sni_or_acme_alpn() {
        let default_cert = StaticCertificateConfig {
            cert_path: PathBuf::from("/tls/default.pem"),
            key_path: PathBuf::from("/tls/default.key"),
        };
        let exact_cert = StaticCertificateConfig {
            cert_path: PathBuf::from("/tls/exact.pem"),
            key_path: PathBuf::from("/tls/exact.key"),
        };
        let config = Config {
            server: ServerConfig {
                tls_listen: vec!["127.0.0.1:8443".to_owned()],
                ..ServerConfig::default()
            },
            tls: TlsConfig {
                enabled: true,
                certificates: vec![default_cert],
                ..TlsConfig::default()
            },
            vhosts: vec![vhost("exact", vec!["example.test"], Some(exact_cert))],
            ..Config::default()
        };

        let plan = DownstreamTlsListenerPlan::from_config(&config)
            .unwrap()
            .unwrap();

        assert_eq!(plan.listens(), ["127.0.0.1:8443"]);
        assert!(plan.requires_certificate_resolver());
        assert!(!plan.acme_tls_alpn_enabled());
    }

    #[test]
    fn listener_plan_rejects_tls_listen_without_tls_enabled() {
        let config = Config {
            server: ServerConfig {
                tls_listen: vec!["127.0.0.1:8443".to_owned()],
                ..ServerConfig::default()
            },
            ..Config::default()
        };

        assert!(matches!(
            DownstreamTlsListenerPlan::from_config(&config),
            Err(DownstreamTlsPlanError::TlsDisabled)
        ));
    }

    #[test]
    fn listener_plan_rejects_tls_listen_without_fallback_certificate() {
        let config = Config {
            server: ServerConfig {
                tls_listen: vec!["127.0.0.1:8443".to_owned()],
                ..ServerConfig::default()
            },
            tls: TlsConfig {
                enabled: true,
                ..TlsConfig::default()
            },
            ..Config::default()
        };

        assert!(matches!(
            DownstreamTlsListenerPlan::from_config(&config),
            Err(DownstreamTlsPlanError::MissingFallbackCertificate)
        ));
    }
}

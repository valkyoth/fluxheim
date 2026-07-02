use crate::config::Config;

pub const PRIVATE_KEY_MODE: u32 = 0o600;
pub const ACME_STORAGE_MODE: u32 = 0o700;

#[path = "tls_storage_issue.rs"]
mod tls_storage_issue;
pub use tls_storage_issue::{TlsStorageCheck, TlsStorageIssue};

#[path = "tls_storage_validation.rs"]
mod tls_storage_validation;
pub use tls_storage_validation::{
    recommended_acme_storage_mode, recommended_private_key_mode, secure_acme_storage_mode,
    secure_private_key_mode, validate_tls_storage,
};

#[cfg(feature = "tls-rustls-backend")]
pub fn install_rustls_crypto_provider() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fluxheim_tls::install_rustls_crypto_provider().map_err(Into::into)
}

#[cfg(feature = "tls-rustls-backend")]
pub fn rustls_crypto_provider() -> rustls::crypto::CryptoProvider {
    fluxheim_tls::rustls_crypto_provider()
}

#[cfg(feature = "tls-rustls-fips")]
pub use fluxheim_tls::RustlsFipsStatus;

#[cfg(feature = "tls-rustls-fips")]
pub fn probe_rustls_fips_provider() -> Result<RustlsFipsStatus, String> {
    fluxheim_tls::probe_rustls_fips_provider()
}

#[cfg(feature = "tls-openssl-fips")]
pub use fluxheim_tls::OpenSslFipsStatus;

#[cfg(feature = "tls-openssl-fips")]
pub fn probe_openssl_fips_provider() -> Result<OpenSslFipsStatus, String> {
    fluxheim_tls::probe_openssl_fips_provider()
}

#[cfg(feature = "tls-openssl-fips")]
pub fn activate_openssl_fips_provider() -> Result<OpenSslFipsStatus, String> {
    fluxheim_tls::activate_openssl_fips_provider()
}

pub fn validate_fips_runtime_config(
    config: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fluxheim_tls::validate_fips_runtime_config(config).map_err(Into::into)
}

pub fn downstream_tls_listener_plan(
    config: &Config,
) -> Result<Option<fluxheim_tls::DownstreamTlsListenerPlan>, Box<dyn std::error::Error + Send + Sync>>
{
    fluxheim_tls::DownstreamTlsListenerPlan::from_config_with_acme_resolver(
        config,
        managed_acme_certificate_source,
    )
    .map_err(Into::into)
}

pub type DownstreamCertificateSelector = fluxheim_tls::DownstreamCertificateSelector;
pub type DownstreamCertificateSource = fluxheim_tls::DownstreamCertificateSource;

pub fn downstream_certificate_selector(config: &Config) -> Option<DownstreamCertificateSelector> {
    DownstreamCertificateSelector::from_config_with_acme_resolver(
        config,
        managed_acme_certificate_source,
    )
}

#[cfg(feature = "acme")]
fn managed_acme_certificate_source(
    config: &Config,
    vhost: &crate::config::VhostConfig,
) -> Option<DownstreamCertificateSource> {
    if !config.tls.acme.enabled {
        return None;
    }

    let storage = config.tls.acme.storage.as_ref()?;
    let owner = if vhost.tls.acme.enabled {
        vhost.name.as_str()
    } else {
        fluxheim_tls::shared_managed_acme_certificate_owner(config, vhost)?
    };
    let paths = crate::acme::managed_certificate_paths(storage, owner);
    Some(DownstreamCertificateSource {
        certificate: crate::config::StaticCertificateConfig {
            cert_path: paths.cert_path,
            key_path: paths.key_path,
        },
        managed_acme: true,
    })
}

#[cfg(not(feature = "acme"))]
fn managed_acme_certificate_source(
    _config: &Config,
    _vhost: &crate::config::VhostConfig,
) -> Option<DownstreamCertificateSource> {
    None
}

#[cfg(test)]
#[path = "tls_selector_tests.rs"]
mod selector_tests;

#[cfg(test)]
#[path = "tls_storage_tests.rs"]
mod storage_tests;

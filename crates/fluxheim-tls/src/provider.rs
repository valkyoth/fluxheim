use fluxheim_config::Config;
use thiserror::Error;

#[cfg(feature = "tls-rustls-backend")]
pub fn install_rustls_crypto_provider() -> Result<(), TlsRuntimeError> {
    ensure_rustls_crypto_provider_installed().map_err(TlsRuntimeError::RustlsProvider)
}

#[cfg(feature = "tls-rustls-backend")]
pub fn rustls_crypto_provider() -> rustls::crypto::CryptoProvider {
    #[cfg(feature = "tls-rustls-fips")]
    {
        rustls::crypto::default_fips_provider()
    }
    #[cfg(not(feature = "tls-rustls-fips"))]
    {
        rustls::crypto::ring::default_provider()
    }
}

#[cfg(feature = "tls-rustls-backend")]
fn ensure_rustls_crypto_provider_installed() -> Result<(), String> {
    match rustls_crypto_provider().install_default() {
        Ok(()) => Ok(()),
        Err(candidate) => {
            let installed = rustls::crypto::CryptoProvider::get_default().ok_or_else(|| {
                format!(
                    "rustls rejected candidate CryptoProvider but no installed provider is visible; candidate_fips={}",
                    candidate.fips()
                )
            })?;
            #[cfg(feature = "tls-rustls-fips")]
            {
                if !installed.fips() {
                    return Err(format!(
                        "non-FIPS process-default CryptoProvider is already installed; installed_provider_fips={}, candidate_provider_fips={}",
                        installed.fips(),
                        candidate.fips()
                    ));
                }
                log::debug!(
                    "rustls process-default CryptoProvider is already installed and reports FIPS mode"
                );
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                log::debug!(
                    "rustls process-default CryptoProvider is already installed; installed_provider_fips={}, candidate_provider_fips={}",
                    installed.fips(),
                    candidate.fips()
                );
            }
            Ok(())
        }
    }
}

#[cfg(feature = "tls-rustls-fips")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RustlsFipsStatus {
    pub provider_fips: bool,
}

#[cfg(feature = "tls-rustls-fips")]
pub fn probe_rustls_fips_provider() -> Result<RustlsFipsStatus, String> {
    ensure_rustls_crypto_provider_installed()?;
    let provider = rustls::crypto::CryptoProvider::get_default()
        .ok_or_else(|| "no process-default rustls CryptoProvider is installed".to_owned())?;
    let provider_fips = provider.fips();
    if !provider_fips {
        return Err("installed rustls CryptoProvider does not report FIPS mode".to_owned());
    }
    Ok(RustlsFipsStatus { provider_fips })
}

#[cfg(feature = "tls-openssl-fips")]
static OPENSSL_FIPS_PROVIDER_RESULT: std::sync::OnceLock<Result<(), String>> =
    std::sync::OnceLock::new();

#[cfg(feature = "tls-openssl-fips")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OpenSslFipsStatus {
    pub openssl_version: String,
    pub default_properties_fips_enabled: bool,
}

#[cfg(feature = "tls-openssl-fips")]
pub fn probe_openssl_fips_provider() -> Result<OpenSslFipsStatus, String> {
    let openssl_version = openssl::version::version().to_owned();
    load_openssl_fips_providers_once()?;
    openssl_fips_property_query_check()?;

    Ok(OpenSslFipsStatus {
        openssl_version,
        default_properties_fips_enabled:
            fluxheim_openssl_fips_support::default_properties_fips_enabled(),
    })
}

#[cfg(feature = "tls-openssl-fips")]
pub fn activate_openssl_fips_provider() -> Result<OpenSslFipsStatus, String> {
    let openssl_version = openssl::version::version().to_owned();
    load_openssl_fips_providers_once()?;

    fluxheim_openssl_fips_support::enable_default_properties_fips()
        .map_err(|error| format!("OpenSSL FIPS default-property enable failed: {error}"))?;
    let default_properties_fips_enabled =
        fluxheim_openssl_fips_support::default_properties_fips_enabled();
    if !default_properties_fips_enabled {
        return Err("OpenSSL FIPS default properties are not enabled".to_owned());
    }

    openssl_fips_property_query_check()?;
    openssl_fips_default_fetch_check()?;
    openssl_non_fips_default_fetch_rejected()?;
    Ok(OpenSslFipsStatus {
        openssl_version,
        default_properties_fips_enabled,
    })
}

#[cfg(feature = "tls-openssl-fips")]
fn load_openssl_fips_providers_once() -> Result<(), String> {
    OPENSSL_FIPS_PROVIDER_RESULT
        .get_or_init(|| {
            let fips_provider = openssl::provider::Provider::try_load(None, "fips", true)
                .map_err(|error| format!("OpenSSL FIPS provider could not be loaded: {error}"))?;
            let base_provider = openssl::provider::Provider::try_load(None, "base", true).ok();
            let _ = Box::leak(Box::new(fips_provider));
            if let Some(base_provider) = base_provider {
                let _ = Box::leak(Box::new(base_provider));
            }
            Ok(())
        })
        .clone()
}

#[cfg(feature = "tls-openssl-fips")]
fn openssl_fips_property_query_check() -> Result<(), String> {
    openssl::cipher::Cipher::fetch(None, "AES-256-GCM", Some("fips=yes"))
        .map(|_| ())
        .map_err(|error| {
            format!("OpenSSL FIPS property query failed for AES-256-GCM with fips=yes: {error}")
        })
}

#[cfg(feature = "tls-openssl-fips")]
fn openssl_fips_default_fetch_check() -> Result<(), String> {
    openssl::cipher::Cipher::fetch(None, "AES-256-GCM", None)
        .map(|_| ())
        .map_err(|error| {
            format!("OpenSSL FIPS default-property fetch failed for AES-256-GCM: {error}")
        })
}

#[cfg(feature = "tls-openssl-fips")]
fn openssl_non_fips_default_fetch_rejected() -> Result<(), String> {
    match openssl::cipher::Cipher::fetch(None, "CHACHA20-POLY1305", None) {
        Ok(_) => Err(
            "OpenSSL FIPS default properties still allow CHACHA20-POLY1305 without an explicit property query"
                .to_owned(),
        ),
        Err(error) => {
            log::debug!(
                "OpenSSL FIPS default properties rejected CHACHA20-POLY1305 as expected: {error}"
            );
            Ok(())
        }
    }
}

pub fn validate_fips_runtime_config(config: &Config) -> Result<(), TlsRuntimeError> {
    let compliance_mode = config.tls.compliance_mode();
    if !compliance_mode.required() {
        return Ok(());
    }

    #[cfg(feature = "tls-rustls-fips")]
    if config.tls.backend == fluxheim_config::TlsBackend::Rustls {
        let status = probe_rustls_fips_provider().map_err(|error| {
            TlsRuntimeError::Compliance(format!(
                "{} required mode rustls/AWS-LC provider check failed: {error}",
                compliance_mode.label()
            ))
        })?;
        log::info!(
            "{} required mode rustls/AWS-LC provider check passed; provider_fips={}",
            compliance_mode.label(),
            status.provider_fips
        );
        return Ok(());
    }

    #[cfg(feature = "tls-openssl-fips")]
    if config.tls.backend == fluxheim_config::TlsBackend::Openssl {
        let status = activate_openssl_fips_provider().map_err(|error| {
            TlsRuntimeError::Compliance(format!(
                "{} required mode OpenSSL provider check failed: {error}",
                compliance_mode.label()
            ))
        })?;
        log::info!(
            "{} required mode OpenSSL provider check passed using {}; default_properties_fips_enabled={}",
            compliance_mode.label(),
            status.openssl_version,
            status.default_properties_fips_enabled
        );
        return Ok(());
    }

    #[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
    {
        Err(TlsRuntimeError::Compliance(format!(
            "{} required mode is not supported by the configured TLS backend in this build",
            compliance_mode.label()
        )))
    }

    #[cfg(not(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips")))]
    {
        Err(TlsRuntimeError::Compliance(format!(
            "{} required mode requires a FIPS/ISO-capable TLS backend feature such as tls-rustls-fips, tls-openssl-fips, or tls-openssl-iso19790",
            compliance_mode.label()
        )))
    }
}

#[derive(Debug, Error)]
pub enum TlsRuntimeError {
    #[error("rustls CryptoProvider installation failed: {0}")]
    RustlsProvider(String),
    #[error("{0}")]
    Compliance(String),
}

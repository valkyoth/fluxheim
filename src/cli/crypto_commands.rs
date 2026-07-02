use std::error::Error;

use crate::config::Config;

pub(super) fn run_crypto_diagnostics_command(
    config_path: Option<&std::path::Path>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = match config_path {
        Some(path) => Some(Config::load_without_runtime_paths(Some(path))?),
        None => None,
    };
    print_crypto_diagnostics(config.as_ref(), config_path);
    Ok(())
}

pub fn print_crypto_diagnostics(config: Option<&Config>, config_path: Option<&std::path::Path>) {
    println!("crypto diagnostics:");
    println!("  version: {}", env!("FLUXHEIM_VERSION"));
    println!("  tls compiled: {}", cfg!(feature = "tls"));
    println!("  tls backends:");
    println!("    rustls: {}", cfg!(feature = "tls-rustls-backend"));
    println!("    openssl: {}", cfg!(feature = "tls-openssl"));
    println!("  fips-capable features:");
    println!("    tls-rustls-fips: {}", cfg!(feature = "tls-rustls-fips"));
    println!(
        "    tls-rustls-iso19790: {}",
        cfg!(feature = "tls-rustls-iso19790")
    );
    println!(
        "    tls-openssl-fips: {}",
        cfg!(feature = "tls-openssl-fips")
    );
    println!(
        "    tls-openssl-iso19790: {}",
        cfg!(feature = "tls-openssl-iso19790")
    );
    println!(
        "    admin_auth_hmac_provider: {}",
        crate::internal_crypto::admin_mac_provider_label()
    );
    println!(
        "    admin_auth_hmac_fips_capable: {}",
        crate::internal_crypto::admin_mac_is_compliance_capable()
    );
    println!(
        "    acme_client_compiled: {}",
        cfg!(feature = "acme-client")
    );
    println!("    managed_acme_fips_capable: false");
    #[cfg(feature = "tls-openssl-fips")]
    match crate::tls::probe_openssl_fips_provider() {
        Ok(status) => println!(
            "    openssl_fips_provider: available ({}; default_properties_fips_enabled={})",
            status.openssl_version, status.default_properties_fips_enabled
        ),
        Err(error) => println!("    openssl_fips_provider: unavailable ({error})"),
    }
    #[cfg(not(feature = "tls-openssl-fips"))]
    println!("    openssl_fips_provider: unavailable (build lacks tls-openssl-fips)");
    #[cfg(feature = "tls-rustls-fips")]
    match crate::tls::probe_rustls_fips_provider() {
        Ok(status) => println!(
            "    rustls_fips_provider: available (provider_fips={})",
            status.provider_fips
        ),
        Err(error) => println!("    rustls_fips_provider: unavailable ({error})"),
    }
    #[cfg(not(feature = "tls-rustls-fips"))]
    println!("    rustls_fips_provider: unavailable (build lacks tls-rustls-fips)");
    print_openssl_environment_diagnostics();
    println!("  notes:");
    println!(
        "    FIPS/ISO-required mode fails closed unless a configured backend can prove provider status."
    );
    println!("    See docs/fips.md for the validated-module and operator-evidence model.");

    if let Some(config) = config {
        println!("  config:");
        if let Some(path) = config_path {
            println!("    path: {}", path.display());
        }
        println!("    tls.enabled: {}", config.tls.enabled);
        println!("    tls.backend: {}", tls_backend_name(config.tls.backend));
        println!("    tls.profile: {}", tls_profile_name(config.tls.profile));
        println!(
            "    tls.min_protocol: {}",
            tls_protocol_name(config.tls.effective_min_protocol())
        );
        println!(
            "    tls.compliance_mode: {}",
            config.tls.compliance_mode().label()
        );
        println!(
            "    admin_auth_hmac_effective_provider: {}",
            crate::internal_crypto::admin_mac_provider_for_compliance_required(
                config.tls.compliance_mode().required()
            )
            .label()
        );
        println!("    tls.fips.required: {}", config.tls.fips.required);
        println!(
            "    tls.iso19790.required: {}",
            config.tls.iso19790.required
        );
    }
}

fn print_openssl_environment_diagnostics() {
    println!("  openssl environment:");
    println!("    OPENSSL_CONF: {}", diagnostic_env_value("OPENSSL_CONF"));
    println!(
        "    OPENSSL_MODULES: {}",
        diagnostic_env_value("OPENSSL_MODULES")
    );
}

fn diagnostic_env_value(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        Ok(_) => "<empty>".to_owned(),
        Err(std::env::VarError::NotPresent) => "<unset>".to_owned(),
        Err(std::env::VarError::NotUnicode(_)) => "<non-unicode>".to_owned(),
    }
}

fn tls_backend_name(backend: crate::config::TlsBackend) -> &'static str {
    match backend {
        crate::config::TlsBackend::Rustls => "rustls",
        crate::config::TlsBackend::Openssl => "openssl",
    }
}

fn tls_profile_name(profile: crate::config::TlsPolicyProfile) -> &'static str {
    match profile {
        crate::config::TlsPolicyProfile::Modern => "modern",
        crate::config::TlsPolicyProfile::Intermediate => "intermediate",
        crate::config::TlsPolicyProfile::Compat => "compat",
    }
}

fn tls_protocol_name(protocol: crate::config::TlsProtocolVersion) -> &'static str {
    match protocol {
        crate::config::TlsProtocolVersion::Tls12 => "tls1.2",
        crate::config::TlsProtocolVersion::Tls13 => "tls1.3",
    }
}

pub(super) fn run_cache_keygen_command() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key)?;
    println!("{}", hex_encode_lower(&key));
    Ok(())
}

pub(super) fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    encoded
}

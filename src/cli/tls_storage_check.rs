use std::error::Error;

use crate::config::Config;

#[cfg(any(
    feature = "tls",
    feature = "tls-rustls-backend",
    feature = "tls-openssl"
))]
pub fn check_tls_storage(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let check = crate::tls::validate_tls_storage(config);
    if check.is_secure() {
        println!("TLS storage check passed");
        return Ok(());
    }

    for issue in &check.issues {
        eprintln!("TLS storage issue: {issue}");
    }

    Err(format!(
        "TLS storage check failed with {} issue(s)",
        check.issues.len()
    )
    .into())
}

#[cfg(not(any(
    feature = "tls",
    feature = "tls-rustls-backend",
    feature = "tls-openssl"
)))]
pub fn check_tls_storage(_config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("TLS storage checks require a TLS feature".into())
}

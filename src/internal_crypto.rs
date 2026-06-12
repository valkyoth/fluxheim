pub use fluxheim_config::internal_crypto::{
    AdminMacProvider, admin_mac_is_compliance_capable, admin_mac_provider,
    admin_mac_provider_for_compliance_required, admin_mac_provider_label,
};

#[cfg(all(feature = "proxy", feature = "tls-openssl-fips"))]
static OPENSSL_ADMIN_HMAC_READY: std::sync::OnceLock<Result<(), String>> =
    std::sync::OnceLock::new();

#[cfg(feature = "proxy")]
pub fn admin_hmac_sha256_or_abort(
    provider: AdminMacProvider,
    context: &'static str,
    key: &[u8],
    message: &[u8],
) -> [u8; 32] {
    match admin_hmac_sha256(provider, key, message) {
        Ok(digest) => digest,
        Err(error) => {
            log::error!(
                "fatal: {context} HMAC failed through {}: {error}",
                provider.label()
            );
            std::process::abort();
        }
    }
}

#[cfg(feature = "proxy")]
fn admin_hmac_sha256(
    provider: AdminMacProvider,
    key: &[u8],
    message: &[u8],
) -> Result<[u8; 32], String> {
    match provider {
        AdminMacProvider::Ring => Ok(ring_admin_hmac_sha256(key, message)),
        AdminMacProvider::OpenSslFips => openssl_fips_admin_hmac_sha256(key, message),
        AdminMacProvider::AwsLcFips => aws_lc_fips_admin_hmac_sha256(key, message),
    }
}

#[cfg(feature = "proxy")]
fn ring_admin_hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let tag = ring::hmac::sign(&key, message);
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(tag.as_ref());
    digest
}

#[cfg(all(feature = "proxy", feature = "tls-openssl-fips"))]
fn openssl_fips_admin_hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; 32], String> {
    ensure_openssl_fips_admin_hmac_ready()?;
    let key = openssl::pkey::PKey::hmac(key)
        .map_err(|error| format!("OpenSSL HMAC key creation failed: {error}"))?;
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key)
        .map_err(|error| format!("OpenSSL HMAC signer creation failed: {error}"))?;
    signer
        .update(message)
        .map_err(|error| format!("OpenSSL HMAC update failed: {error}"))?;
    let digest = signer
        .sign_to_vec()
        .map_err(|error| format!("OpenSSL HMAC finalization failed: {error}"))?;
    digest_vec_to_array(digest, "OpenSSL")
}

#[cfg(all(feature = "proxy", feature = "tls-openssl-fips"))]
fn ensure_openssl_fips_admin_hmac_ready() -> Result<(), String> {
    OPENSSL_ADMIN_HMAC_READY
        .get_or_init(|| {
            crate::tls::activate_openssl_fips_provider()
                .map(|_| ())
                .map_err(|error| format!("OpenSSL FIPS provider activation failed: {error}"))
        })
        .clone()
}

#[cfg(all(feature = "proxy", not(feature = "tls-openssl-fips")))]
fn openssl_fips_admin_hmac_sha256(_key: &[u8], _message: &[u8]) -> Result<[u8; 32], String> {
    Err("build lacks tls-openssl-fips".to_owned())
}

#[cfg(all(feature = "proxy", feature = "tls-rustls-fips"))]
fn aws_lc_fips_admin_hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; 32], String> {
    crate::tls::probe_rustls_fips_provider()
        .map_err(|error| format!("rustls FIPS provider check failed: {error}"))?;
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
    let tag = aws_lc_rs::hmac::sign(&key, message);
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(tag.as_ref());
    Ok(digest)
}

#[cfg(all(feature = "proxy", not(feature = "tls-rustls-fips")))]
fn aws_lc_fips_admin_hmac_sha256(_key: &[u8], _message: &[u8]) -> Result<[u8; 32], String> {
    Err("build lacks tls-rustls-fips".to_owned())
}

#[cfg(all(feature = "proxy", feature = "tls-openssl-fips"))]
fn digest_vec_to_array(mut digest: Vec<u8>, provider: &'static str) -> Result<[u8; 32], String> {
    use zeroize::Zeroize;

    if digest.len() != 32 {
        let len = digest.len();
        digest.zeroize();
        return Err(format!(
            "{provider} HMAC-SHA256 returned {len} bytes instead of 32"
        ));
    }
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    digest.zeroize();
    Ok(output)
}

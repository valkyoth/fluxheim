pub use fluxheim_config::internal_crypto::{
    AdminMacProvider, admin_mac_is_compliance_capable, admin_mac_provider,
    admin_mac_provider_for_compliance_required, admin_mac_provider_label,
};

#[cfg(feature = "proxy")]
#[derive(Debug, Clone, Copy)]
pub struct FluxheimSnapshotCryptoProvider(pub AdminMacProvider);

#[cfg(feature = "proxy")]
impl fluxheim_snapshot::SnapshotCryptoProvider for FluxheimSnapshotCryptoProvider {
    fn label(&self) -> &'static str {
        self.0.label()
    }

    fn compliance_capable(&self) -> bool {
        self.0.compliance_capable()
    }

    fn sha256(&self, chunks: &[&[u8]]) -> Result<[u8; 32], String> {
        admin_sha256_chunks(self.0, chunks)
    }

    fn hmac_sha256(&self, key: &[u8], chunks: &[&[u8]]) -> Result<[u8; 32], String> {
        admin_hmac_sha256_chunks(self.0, key, chunks)
    }
}

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
    admin_hmac_sha256_chunks(provider, key, &[message])
}

#[cfg(feature = "proxy")]
fn admin_hmac_sha256_chunks(
    provider: AdminMacProvider,
    key: &[u8],
    chunks: &[&[u8]],
) -> Result<[u8; 32], String> {
    match provider {
        AdminMacProvider::Ring => Ok(ring_admin_hmac_sha256(key, chunks)),
        AdminMacProvider::OpenSslFips => openssl_fips_admin_hmac_sha256(key, chunks),
        AdminMacProvider::AwsLcFips => aws_lc_fips_admin_hmac_sha256(key, chunks),
    }
}

#[cfg(feature = "proxy")]
fn ring_admin_hmac_sha256(key: &[u8], chunks: &[&[u8]]) -> [u8; 32] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let mut context = ring::hmac::Context::with_key(&key);
    for chunk in chunks {
        context.update(chunk);
    }
    let tag = context.sign();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(tag.as_ref());
    digest
}

#[cfg(all(feature = "proxy", feature = "tls-openssl-fips"))]
fn openssl_fips_admin_hmac_sha256(key: &[u8], chunks: &[&[u8]]) -> Result<[u8; 32], String> {
    ensure_openssl_fips_admin_hmac_ready()?;
    let key = openssl::pkey::PKey::hmac(key)
        .map_err(|error| format!("OpenSSL HMAC key creation failed: {error}"))?;
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key)
        .map_err(|error| format!("OpenSSL HMAC signer creation failed: {error}"))?;
    for chunk in chunks {
        signer
            .update(chunk)
            .map_err(|error| format!("OpenSSL HMAC update failed: {error}"))?;
    }
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
fn openssl_fips_admin_hmac_sha256(_key: &[u8], _chunks: &[&[u8]]) -> Result<[u8; 32], String> {
    Err("build lacks tls-openssl-fips".to_owned())
}

#[cfg(all(feature = "proxy", feature = "tls-rustls-fips"))]
fn aws_lc_fips_admin_hmac_sha256(key: &[u8], chunks: &[&[u8]]) -> Result<[u8; 32], String> {
    crate::tls::probe_rustls_fips_provider()
        .map_err(|error| format!("rustls FIPS provider check failed: {error}"))?;
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
    let mut context = aws_lc_rs::hmac::Context::with_key(&key);
    for chunk in chunks {
        context.update(chunk);
    }
    let tag = context.sign();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(tag.as_ref());
    Ok(digest)
}

#[cfg(all(feature = "proxy", not(feature = "tls-rustls-fips")))]
fn aws_lc_fips_admin_hmac_sha256(_key: &[u8], _chunks: &[&[u8]]) -> Result<[u8; 32], String> {
    Err("build lacks tls-rustls-fips".to_owned())
}

#[cfg(feature = "proxy")]
fn admin_sha256_chunks(provider: AdminMacProvider, chunks: &[&[u8]]) -> Result<[u8; 32], String> {
    match provider {
        AdminMacProvider::Ring => {
            let mut context = ring::digest::Context::new(&ring::digest::SHA256);
            for chunk in chunks {
                context.update(chunk);
            }
            let digest = context.finish();
            let mut output = [0_u8; 32];
            output.copy_from_slice(digest.as_ref());
            Ok(output)
        }
        AdminMacProvider::OpenSslFips => {
            #[cfg(feature = "tls-openssl-fips")]
            {
                ensure_openssl_fips_admin_hmac_ready()?;
                let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())
                    .map_err(|error| format!("OpenSSL SHA-256 initialization failed: {error}"))?;
                for chunk in chunks {
                    hasher
                        .update(chunk)
                        .map_err(|error| format!("OpenSSL SHA-256 update failed: {error}"))?;
                }
                let digest = hasher
                    .finish()
                    .map_err(|error| format!("OpenSSL SHA-256 finalization failed: {error}"))?;
                let mut output = [0_u8; 32];
                output.copy_from_slice(digest.as_ref());
                Ok(output)
            }
            #[cfg(not(feature = "tls-openssl-fips"))]
            Err("build lacks tls-openssl-fips".to_owned())
        }
        AdminMacProvider::AwsLcFips => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                crate::tls::probe_rustls_fips_provider()
                    .map_err(|error| format!("rustls FIPS provider check failed: {error}"))?;
                let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
                for chunk in chunks {
                    context.update(chunk);
                }
                let digest = context.finish();
                let mut output = [0_u8; 32];
                output.copy_from_slice(digest.as_ref());
                Ok(output)
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            Err("build lacks tls-rustls-fips".to_owned())
        }
    }
}

#[cfg(all(feature = "proxy", feature = "tls-openssl-fips"))]
fn digest_vec_to_array(mut digest: Vec<u8>, provider: &'static str) -> Result<[u8; 32], String> {
    use sanitization::SecureSanitize;

    if digest.len() != 32 {
        let len = digest.len();
        digest.secure_sanitize();
        return Err(format!(
            "{provider} HMAC-SHA256 returned {len} bytes instead of 32"
        ));
    }
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    digest.secure_sanitize();
    Ok(output)
}

#[cfg(all(test, feature = "proxy"))]
mod tests {
    use super::*;

    #[test]
    fn selected_snapshot_crypto_provider_streams_sha256_and_hmac() {
        let provider = admin_mac_provider();
        let snapshot = FluxheimSnapshotCryptoProvider(provider);
        let digest =
            fluxheim_snapshot::SnapshotCryptoProvider::sha256(&snapshot, &[b"a", b"b", b"c"])
                .unwrap();
        assert_eq!(
            digest,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        let streamed = fluxheim_snapshot::SnapshotCryptoProvider::hmac_sha256(
            &snapshot,
            b"snapshot-test-key",
            &[b"first", b"second"],
        )
        .unwrap();
        let contiguous = admin_hmac_sha256(provider, b"snapshot-test-key", b"firstsecond").unwrap();
        assert_eq!(streamed, contiguous);
    }
}

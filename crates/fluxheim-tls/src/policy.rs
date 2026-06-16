use fluxheim_config::{TlsAlpnPolicy, TlsCipherSuite, TlsConfig, TlsCurvePreference};

#[cfg(feature = "tls-rustls-backend")]
use crate::TlsRuntimeError;

pub fn rustls_alpn_protocols(
    tls: &TlsConfig,
    acme_tls_alpn_protocol: Option<&[u8]>,
) -> Vec<Vec<u8>> {
    let mut protocols = match tls.effective_alpn() {
        TlsAlpnPolicy::Http1 => vec![b"http/1.1".to_vec()],
        TlsAlpnPolicy::Http2 => vec![b"h2".to_vec()],
        TlsAlpnPolicy::Http1AndHttp2 => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    };
    if let Some(protocol) = acme_tls_alpn_protocol {
        protocols.insert(0, protocol.to_vec());
    }
    protocols
}

#[cfg(feature = "tls-rustls-backend")]
pub fn rustls_cipher_suite(
    cipher: TlsCipherSuite,
    fips_required: bool,
) -> Result<rustls::SupportedCipherSuite, TlsRuntimeError> {
    #[cfg(not(feature = "tls-rustls-fips"))]
    let _ = fips_required;

    match cipher {
        TlsCipherSuite::Tls13Aes256GcmSha384 => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                Ok(rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384)
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                Ok(rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384)
            }
        }
        TlsCipherSuite::Tls13Chacha20Poly1305Sha256 => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                if fips_required {
                    Err(TlsRuntimeError::Compliance(
                        "TLS_CHACHA20_POLY1305_SHA256 is not allowed when rustls FIPS/ISO mode is required"
                            .to_owned(),
                    ))
                } else {
                    Ok(rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256)
                }
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                Ok(rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256)
            }
        }
        TlsCipherSuite::Tls13Aes128GcmSha256 => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                Ok(rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256)
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                Ok(rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256)
            }
        }
        TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256 => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                Ok(rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                Ok(rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
            }
        }
        TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256 => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                Ok(rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                Ok(rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            }
        }
        TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384 => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                Ok(rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                Ok(rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
            }
        }
        TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384 => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                Ok(rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                Ok(rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
            }
        }
        TlsCipherSuite::TlsEcdheEcdsaWithChacha20Poly1305Sha256 => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                if fips_required {
                    Err(TlsRuntimeError::Compliance(
                        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 is not allowed when rustls FIPS/ISO mode is required"
                            .to_owned(),
                    ))
                } else {
                    Ok(rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
                }
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                Ok(rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
            }
        }
        TlsCipherSuite::TlsEcdheRsaWithChacha20Poly1305Sha256 => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                if fips_required {
                    Err(TlsRuntimeError::Compliance(
                        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 is not allowed when rustls FIPS/ISO mode is required"
                            .to_owned(),
                    ))
                } else {
                    Ok(rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
                }
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                Ok(rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
            }
        }
    }
}

#[cfg(feature = "tls-rustls-backend")]
pub fn rustls_kx_group(
    curve: TlsCurvePreference,
    fips_required: bool,
) -> Result<&'static dyn rustls::crypto::SupportedKxGroup, TlsRuntimeError> {
    #[cfg(not(feature = "tls-rustls-fips"))]
    let _ = fips_required;

    match curve {
        TlsCurvePreference::X25519 => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                if fips_required {
                    Err(TlsRuntimeError::Compliance(
                        "X25519 is not allowed when rustls FIPS/ISO mode is required".to_owned(),
                    ))
                } else {
                    Ok(rustls::crypto::aws_lc_rs::kx_group::X25519)
                }
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                Ok(rustls::crypto::ring::kx_group::X25519)
            }
        }
        TlsCurvePreference::P256 => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                Ok(rustls::crypto::aws_lc_rs::kx_group::SECP256R1)
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                Ok(rustls::crypto::ring::kx_group::SECP256R1)
            }
        }
        TlsCurvePreference::P384 => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                Ok(rustls::crypto::aws_lc_rs::kx_group::SECP384R1)
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                Ok(rustls::crypto::ring::kx_group::SECP384R1)
            }
        }
        TlsCurvePreference::X25519MlKem768 => {
            #[cfg(feature = "tls-rustls-fips")]
            {
                if fips_required {
                    Err(TlsRuntimeError::Compliance(
                        "X25519MLKEM768 is not allowed when rustls FIPS/ISO mode is required"
                            .to_owned(),
                    ))
                } else {
                    Ok(rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768)
                }
            }
            #[cfg(not(feature = "tls-rustls-fips"))]
            {
                Err(TlsRuntimeError::Compliance(
                    "X25519MLKEM768 is not available with the default rustls/ring backend"
                        .to_owned(),
                ))
            }
        }
    }
}

pub fn openssl_curve_list(curves: &[TlsCurvePreference]) -> String {
    curves
        .iter()
        .map(|curve| match curve {
            TlsCurvePreference::X25519 => "X25519",
            TlsCurvePreference::P256 => "P-256",
            TlsCurvePreference::P384 => "P-384",
            TlsCurvePreference::X25519MlKem768 => "X25519MLKEM768",
        })
        .collect::<Vec<_>>()
        .join(":")
}

pub fn openssl_cipher_lists(ciphers: &[TlsCipherSuite]) -> (String, String) {
    let mut tls12 = Vec::new();
    let mut tls13 = Vec::new();
    for cipher in ciphers {
        match cipher {
            TlsCipherSuite::Tls13Aes256GcmSha384 => tls13.push("TLS_AES_256_GCM_SHA384"),
            TlsCipherSuite::Tls13Chacha20Poly1305Sha256 => {
                tls13.push("TLS_CHACHA20_POLY1305_SHA256");
            }
            TlsCipherSuite::Tls13Aes128GcmSha256 => tls13.push("TLS_AES_128_GCM_SHA256"),
            TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256 => {
                tls12.push("ECDHE-ECDSA-AES128-GCM-SHA256");
            }
            TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256 => {
                tls12.push("ECDHE-RSA-AES128-GCM-SHA256");
            }
            TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384 => {
                tls12.push("ECDHE-ECDSA-AES256-GCM-SHA384");
            }
            TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384 => {
                tls12.push("ECDHE-RSA-AES256-GCM-SHA384");
            }
            TlsCipherSuite::TlsEcdheEcdsaWithChacha20Poly1305Sha256 => {
                tls12.push("ECDHE-ECDSA-CHACHA20-POLY1305");
            }
            TlsCipherSuite::TlsEcdheRsaWithChacha20Poly1305Sha256 => {
                tls12.push("ECDHE-RSA-CHACHA20-POLY1305");
            }
        }
    }
    (tls12.join(":"), tls13.join(":"))
}

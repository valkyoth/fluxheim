use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsBackend {
    #[default]
    Rustls,
    Openssl,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsPolicyProfile {
    Modern,
    #[default]
    Intermediate,
    Compat,
}

impl TlsPolicyProfile {
    pub(super) const fn default_min_protocol(self) -> TlsProtocolVersion {
        match self {
            Self::Modern => TlsProtocolVersion::Tls13,
            Self::Intermediate | Self::Compat => TlsProtocolVersion::Tls12,
        }
    }

    pub(super) fn default_curve_preferences(self) -> Vec<TlsCurvePreference> {
        vec![
            TlsCurvePreference::X25519,
            TlsCurvePreference::P256,
            TlsCurvePreference::P384,
        ]
    }

    pub(super) fn default_cipher_suites(self) -> Vec<TlsCipherSuite> {
        match self {
            Self::Modern => vec![
                TlsCipherSuite::Tls13Aes256GcmSha384,
                TlsCipherSuite::Tls13Chacha20Poly1305Sha256,
                TlsCipherSuite::Tls13Aes128GcmSha256,
            ],
            Self::Intermediate | Self::Compat => vec![
                TlsCipherSuite::Tls13Aes256GcmSha384,
                TlsCipherSuite::Tls13Chacha20Poly1305Sha256,
                TlsCipherSuite::Tls13Aes128GcmSha256,
                TlsCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256,
                TlsCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
                TlsCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384,
                TlsCipherSuite::TlsEcdheRsaWithAes256GcmSha384,
                TlsCipherSuite::TlsEcdheEcdsaWithChacha20Poly1305Sha256,
                TlsCipherSuite::TlsEcdheRsaWithChacha20Poly1305Sha256,
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum TlsProtocolVersion {
    #[serde(rename = "tls1.2", alias = "TLS1.2", alias = "VersionTLS12")]
    Tls12,
    #[serde(rename = "tls1.3", alias = "TLS1.3", alias = "VersionTLS13")]
    Tls13,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsAlpnPolicy {
    Http1,
    Http2,
    #[default]
    Http1AndHttp2,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum TlsCurvePreference {
    #[serde(rename = "x25519", alias = "X25519")]
    X25519,
    #[serde(rename = "p256", alias = "P-256", alias = "CurveP256")]
    P256,
    #[serde(rename = "p384", alias = "P-384", alias = "CurveP384")]
    P384,
    #[serde(
        rename = "x25519-mlkem768",
        alias = "X25519MLKEM768",
        alias = "X25519-MLKEM768"
    )]
    X25519MlKem768,
}

impl TlsCurvePreference {
    pub(super) const fn is_fips_approved(self) -> bool {
        matches!(self, Self::P256 | Self::P384)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub enum TlsCipherSuite {
    #[serde(rename = "TLS_AES_256_GCM_SHA384")]
    Tls13Aes256GcmSha384,
    #[serde(rename = "TLS_CHACHA20_POLY1305_SHA256")]
    Tls13Chacha20Poly1305Sha256,
    #[serde(rename = "TLS_AES_128_GCM_SHA256")]
    Tls13Aes128GcmSha256,
    #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")]
    TlsEcdheEcdsaWithAes128GcmSha256,
    #[serde(rename = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")]
    TlsEcdheRsaWithAes128GcmSha256,
    #[serde(rename = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")]
    TlsEcdheEcdsaWithAes256GcmSha384,
    #[serde(rename = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")]
    TlsEcdheRsaWithAes256GcmSha384,
    #[serde(rename = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")]
    TlsEcdheEcdsaWithChacha20Poly1305Sha256,
    #[serde(rename = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")]
    TlsEcdheRsaWithChacha20Poly1305Sha256,
}

impl TlsCipherSuite {
    pub(super) const fn is_tls12(&self) -> bool {
        !matches!(
            self,
            Self::Tls13Aes256GcmSha384
                | Self::Tls13Chacha20Poly1305Sha256
                | Self::Tls13Aes128GcmSha256
        )
    }

    pub(super) const fn is_fips_approved(self) -> bool {
        matches!(
            self,
            Self::Tls13Aes256GcmSha384
                | Self::Tls13Aes128GcmSha256
                | Self::TlsEcdheEcdsaWithAes128GcmSha256
                | Self::TlsEcdheRsaWithAes128GcmSha256
                | Self::TlsEcdheEcdsaWithAes256GcmSha384
                | Self::TlsEcdheRsaWithAes256GcmSha384
        )
    }
}

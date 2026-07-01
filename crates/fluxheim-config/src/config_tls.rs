use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{ConfigError, validate_config_list_len};
use crate::config_acme::{AcmeConfig, AcmeConfigFragment, VhostAcmeConfig};

#[path = "config_tls_certificate.rs"]
mod config_tls_certificate;
#[path = "config_tls_client_auth.rs"]
mod config_tls_client_auth;
#[path = "config_tls_policy.rs"]
mod config_tls_policy;

pub use config_tls_certificate::StaticCertificateConfig;
use config_tls_client_auth::TlsClientAuthConfigFragment;
pub use config_tls_client_auth::{TlsClientAuthConfig, TlsClientAuthMode};
pub use config_tls_policy::{
    TlsAlpnPolicy, TlsBackend, TlsCipherSuite, TlsCurvePreference, TlsPolicyProfile,
    TlsProtocolVersion,
};

pub const MAX_TLS_CURVE_PREFERENCES: usize = 16;
pub const MAX_TLS_CIPHER_SUITES: usize = 32;
pub const MAX_TLS_CERTIFICATES: usize = 1024;

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub certificate: Option<StaticCertificateConfig>,
    #[serde(default)]
    pub acme: VhostAcmeConfig,
}

impl VhostTlsConfig {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(certificate) = &mut self.certificate {
            certificate.resolve_relative_paths(base_dir);
        }
    }

    pub fn validate(
        &self,
        scope: &'static str,
        vhost_hosts: &[String],
        global_tls: &TlsConfig,
        has_shared_certificate_source: bool,
    ) -> Result<(), ConfigError> {
        if let Some(certificate) = &self.certificate {
            certificate.validate(scope)?;
        }

        if self.enabled
            && self.certificate.is_none()
            && !self.acme.enabled
            && !has_shared_certificate_source
        {
            return Err(ConfigError::TlsEnabledWithoutCertificateSource { scope });
        }

        self.acme.validate(scope, vhost_hosts, global_tls)
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub backend: TlsBackend,
    #[serde(default)]
    pub profile: TlsPolicyProfile,
    #[serde(default)]
    pub min_protocol: Option<TlsProtocolVersion>,
    #[serde(default)]
    pub alpn: TlsAlpnPolicy,
    #[serde(default)]
    pub curve_preferences: Vec<TlsCurvePreference>,
    #[serde(default)]
    pub cipher_suites: Vec<TlsCipherSuite>,
    #[serde(default)]
    pub client_auth: TlsClientAuthConfig,
    #[serde(default)]
    pub certificates: Vec<StaticCertificateConfig>,
    #[serde(default)]
    pub fips: TlsFipsConfig,
    #[serde(default)]
    pub iso19790: TlsIso19790Config,
    #[serde(default)]
    pub acme: AcmeConfig,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfigFragment {
    enabled: Option<bool>,
    backend: Option<TlsBackend>,
    profile: Option<TlsPolicyProfile>,
    min_protocol: Option<TlsProtocolVersion>,
    alpn: Option<TlsAlpnPolicy>,
    curve_preferences: Option<Vec<TlsCurvePreference>>,
    cipher_suites: Option<Vec<TlsCipherSuite>>,
    client_auth: Option<TlsClientAuthConfigFragment>,
    certificates: Option<Vec<StaticCertificateConfig>>,
    fips: Option<TlsFipsConfigFragment>,
    iso19790: Option<TlsIso19790ConfigFragment>,
    acme: Option<AcmeConfigFragment>,
}

impl TlsConfig {
    pub fn merge(&mut self, fragment: TlsConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(backend) = fragment.backend {
            self.backend = backend;
        }
        if let Some(profile) = fragment.profile {
            self.profile = profile;
        }
        if let Some(min_protocol) = fragment.min_protocol {
            self.min_protocol = Some(min_protocol);
        }
        if let Some(alpn) = fragment.alpn {
            self.alpn = alpn;
        }
        if let Some(curve_preferences) = fragment.curve_preferences {
            self.curve_preferences = curve_preferences;
        }
        if let Some(cipher_suites) = fragment.cipher_suites {
            self.cipher_suites = cipher_suites;
        }
        if let Some(client_auth) = fragment.client_auth {
            self.client_auth.merge(client_auth);
        }
        if let Some(certificates) = fragment.certificates {
            self.certificates = certificates;
        }
        if let Some(fips) = fragment.fips {
            self.fips.merge(fips);
        }
        if let Some(iso19790) = fragment.iso19790 {
            self.iso19790.merge(iso19790);
        }
        if let Some(acme) = fragment.acme {
            self.acme.merge(acme);
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_config_list_len(
            "tls.curve_preferences",
            self.curve_preferences.len(),
            MAX_TLS_CURVE_PREFERENCES,
        )?;
        validate_config_list_len(
            "tls.cipher_suites",
            self.cipher_suites.len(),
            MAX_TLS_CIPHER_SUITES,
        )?;
        validate_config_list_len(
            "tls.certificates",
            self.certificates.len(),
            MAX_TLS_CERTIFICATES,
        )?;

        let effective_min_protocol = self.effective_min_protocol();
        if self.profile == TlsPolicyProfile::Modern
            && effective_min_protocol != TlsProtocolVersion::Tls13
        {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.min_protocol",
                reason: "tls.profile = \"modern\" requires min_protocol = \"tls1.3\"",
            });
        }
        if effective_min_protocol == TlsProtocolVersion::Tls13
            && !self.cipher_suites.is_empty()
            && self.cipher_suites.iter().any(|cipher| cipher.is_tls12())
        {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.cipher_suites",
                reason: "TLS 1.2 cipher suites cannot be used when min_protocol = \"tls1.3\"",
            });
        }
        #[cfg(not(feature = "tls-rustls-fips"))]
        if self.backend == TlsBackend::Rustls
            && self
                .effective_curve_preferences()
                .contains(&TlsCurvePreference::X25519MlKem768)
        {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.curve_preferences",
                reason: "X25519MLKEM768 needs a rustls crypto provider with post-quantum key exchange support; the default rustls backend currently uses ring",
            });
        }
        self.validate_fips_policy()?;
        self.client_auth.validate()?;

        for certificate in &self.certificates {
            certificate.validate("tls.certificates")?;
        }
        self.acme.validate()
    }

    fn validate_fips_policy(&self) -> Result<(), ConfigError> {
        let compliance_mode = self.compliance_mode();
        if !compliance_mode.required() {
            return Ok(());
        }
        if self
            .effective_curve_preferences()
            .iter()
            .any(|curve| !curve.is_fips_approved())
        {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.curve_preferences",
                reason: compliance_mode.non_nist_group_reason(),
            });
        }
        if self
            .effective_cipher_suites()
            .iter()
            .any(|cipher| !cipher.is_fips_approved())
        {
            return Err(ConfigError::InvalidTlsPolicy {
                field: "tls.cipher_suites",
                reason: compliance_mode.non_approved_cipher_reason(),
            });
        }

        #[cfg(not(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips")))]
        {
            Err(ConfigError::InvalidTlsPolicy {
                field: compliance_mode.config_field(),
                reason: compliance_mode.missing_feature_reason(),
            })
        }

        #[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
        {
            #[cfg(feature = "tls-rustls-fips")]
            if self.backend == TlsBackend::Rustls {
                return Ok(());
            }
            #[cfg(feature = "tls-openssl-fips")]
            if self.backend == TlsBackend::Openssl {
                return Ok(());
            }
            Err(ConfigError::InvalidTlsPolicy {
                field: "tls.backend",
                reason: compliance_mode.backend_reason(),
            })
        }
    }

    pub fn compliance_mode(&self) -> TlsComplianceMode {
        match (self.fips.required, self.iso19790.required) {
            (false, false) => TlsComplianceMode::None,
            (true, false) => TlsComplianceMode::Fips1403,
            (false, true) => TlsComplianceMode::Iso19790,
            (true, true) => TlsComplianceMode::Fips1403AndIso19790,
        }
    }

    pub fn effective_min_protocol(&self) -> TlsProtocolVersion {
        self.min_protocol
            .unwrap_or_else(|| self.profile.default_min_protocol())
    }

    pub fn effective_alpn(&self) -> TlsAlpnPolicy {
        self.alpn
    }

    pub fn effective_curve_preferences(&self) -> Vec<TlsCurvePreference> {
        if self.curve_preferences.is_empty() {
            self.profile.default_curve_preferences()
        } else {
            self.curve_preferences.clone()
        }
    }

    pub fn effective_cipher_suites(&self) -> Vec<TlsCipherSuite> {
        if self.cipher_suites.is_empty() {
            self.profile.default_cipher_suites()
        } else {
            self.cipher_suites.clone()
        }
    }

    pub fn acme_issuer_exists(&self, issuer: &str) -> bool {
        self.acme
            .issuers
            .iter()
            .any(|candidate| candidate.name == issuer)
    }
}

impl TlsConfigFragment {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(client_auth) = &mut self.client_auth {
            client_auth.resolve_relative_paths(base_dir);
        }
        if let Some(certificates) = &mut self.certificates {
            for certificate in certificates {
                certificate.resolve_relative_paths(base_dir);
            }
        }
        if let Some(acme) = &mut self.acme {
            acme.resolve_relative_paths(base_dir);
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFipsConfig {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub require_disk_cache_encryption: bool,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsIso19790Config {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub require_disk_cache_encryption: bool,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TlsFipsConfigFragment {
    required: Option<bool>,
    require_disk_cache_encryption: Option<bool>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TlsIso19790ConfigFragment {
    required: Option<bool>,
    require_disk_cache_encryption: Option<bool>,
}

impl TlsFipsConfig {
    fn merge(&mut self, fragment: TlsFipsConfigFragment) {
        if let Some(required) = fragment.required {
            self.required = required;
        }
        if let Some(require_disk_cache_encryption) = fragment.require_disk_cache_encryption {
            self.require_disk_cache_encryption = require_disk_cache_encryption;
        }
    }
}

impl TlsIso19790Config {
    fn merge(&mut self, fragment: TlsIso19790ConfigFragment) {
        if let Some(required) = fragment.required {
            self.required = required;
        }
        if let Some(require_disk_cache_encryption) = fragment.require_disk_cache_encryption {
            self.require_disk_cache_encryption = require_disk_cache_encryption;
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TlsComplianceMode {
    None,
    Fips1403,
    Iso19790,
    Fips1403AndIso19790,
}

impl TlsComplianceMode {
    pub fn required(self) -> bool {
        !matches!(self, Self::None)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Fips1403 => "FIPS 140-3",
            Self::Iso19790 => "ISO/IEC 19790",
            Self::Fips1403AndIso19790 => "FIPS 140-3 / ISO/IEC 19790",
        }
    }

    pub fn config_field(self) -> &'static str {
        match self {
            Self::None | Self::Fips1403 | Self::Fips1403AndIso19790 => "tls.fips.required",
            Self::Iso19790 => "tls.iso19790.required",
        }
    }

    fn non_nist_group_reason(self) -> &'static str {
        match self {
            Self::Iso19790 => {
                "tls.iso19790.required rejects non-NIST or unproven hybrid groups; use CurveP256 and/or CurveP384 until a validated provider supports more"
            }
            Self::None | Self::Fips1403 | Self::Fips1403AndIso19790 => {
                "tls.fips.required rejects non-NIST or unproven hybrid groups; use CurveP256 and/or CurveP384 until a validated provider supports more"
            }
        }
    }

    fn non_approved_cipher_reason(self) -> &'static str {
        match self {
            Self::Iso19790 => {
                "tls.iso19790.required rejects non-approved cipher suites such as ChaCha20; use AES-GCM/SHA-2 suites from the selected validated provider"
            }
            Self::None | Self::Fips1403 | Self::Fips1403AndIso19790 => {
                "tls.fips.required rejects non-FIPS cipher suites such as ChaCha20; use AES-GCM/SHA-2 suites from the selected validated provider"
            }
        }
    }

    #[cfg(not(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips")))]
    fn missing_feature_reason(self) -> &'static str {
        match self {
            Self::Iso19790 => {
                "ISO/IEC 19790-required mode requires a FIPS/ISO-capable TLS backend feature such as tls-rustls-fips, tls-openssl-fips, or tls-openssl-iso19790; see docs/fips.md"
            }
            Self::None | Self::Fips1403 | Self::Fips1403AndIso19790 => {
                "FIPS-required mode requires a FIPS-capable TLS backend feature such as tls-rustls-fips or tls-openssl-fips; see docs/fips.md"
            }
        }
    }

    #[cfg(any(feature = "tls-rustls-fips", feature = "tls-openssl-fips"))]
    fn backend_reason(self) -> &'static str {
        match self {
            Self::Iso19790 => {
                "tls.iso19790.required requires a configured backend supported by this FIPS/ISO-capable build"
            }
            Self::None | Self::Fips1403 | Self::Fips1403AndIso19790 => {
                "tls.fips.required requires a configured backend supported by this FIPS-capable build"
            }
        }
    }
}

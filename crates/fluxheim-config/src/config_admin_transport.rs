use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_access::validate_client_cert_sha256_list;
use crate::config_header::validate_header_name;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminTransportConfig {
    #[serde(default)]
    pub mode: AdminRemoteTransportMode,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminTransportConfigFragment {
    mode: Option<AdminRemoteTransportMode>,
}

impl AdminTransportConfig {
    pub(crate) fn merge(&mut self, fragment: AdminTransportConfigFragment) {
        if let Some(mode) = fragment.mode {
            self.mode = mode;
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminRemoteTransportMode {
    #[default]
    LocalOnly,
    TrustedTlsTerminator,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminClientCertificateConfig {
    #[serde(default)]
    pub required: bool,
    #[serde(default = "default_admin_client_certificate_sha256_header")]
    pub sha256_header: String,
    #[serde(default)]
    pub allow_sha256: Vec<String>,
    #[serde(default)]
    pub deny_sha256: Vec<String>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminClientCertificateConfigFragment {
    required: Option<bool>,
    sha256_header: Option<String>,
    allow_sha256: Option<Vec<String>>,
    deny_sha256: Option<Vec<String>>,
}

impl Default for AdminClientCertificateConfig {
    fn default() -> Self {
        Self {
            required: false,
            sha256_header: default_admin_client_certificate_sha256_header(),
            allow_sha256: Vec::new(),
            deny_sha256: Vec::new(),
        }
    }
}

impl AdminClientCertificateConfig {
    pub(crate) fn merge(&mut self, fragment: AdminClientCertificateConfigFragment) {
        if let Some(required) = fragment.required {
            self.required = required;
        }
        if let Some(header) = fragment.sha256_header {
            self.sha256_header = header;
        }
        if let Some(allow_sha256) = fragment.allow_sha256 {
            self.allow_sha256 = allow_sha256;
        }
        if let Some(deny_sha256) = fragment.deny_sha256 {
            self.deny_sha256 = deny_sha256;
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        validate_header_name(
            "admin.client_certificate.sha256_header",
            &self.sha256_header,
        )?;
        validate_client_cert_sha256_list(
            "admin.client_certificate",
            "allow_sha256",
            &self.allow_sha256,
        )?;
        validate_client_cert_sha256_list(
            "admin.client_certificate",
            "deny_sha256",
            &self.deny_sha256,
        )?;
        Ok(())
    }
}

fn default_admin_client_certificate_sha256_header() -> String {
    "x-client-cert-sha256".to_owned()
}

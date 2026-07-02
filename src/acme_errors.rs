use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::config::AcmeChallenge;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AcmeSecretLoadError {
    UnknownIssuer {
        issuer: String,
    },
    MissingExternalAccountBinding {
        issuer: String,
    },
    InvalidSecretSource {
        issuer: String,
        field: &'static str,
    },
    EnvRead {
        issuer: String,
        field: &'static str,
        env: String,
        message: String,
    },
    FileRead {
        issuer: String,
        field: &'static str,
        path: PathBuf,
        message: String,
    },
    EmptySecret {
        issuer: String,
        field: &'static str,
    },
    OversizedSecret {
        issuer: String,
        field: &'static str,
        max_bytes: u64,
    },
}

impl fmt::Display for AcmeSecretLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownIssuer { issuer } => {
                write!(formatter, "unknown ACME issuer {issuer:?}")
            }
            Self::MissingExternalAccountBinding { issuer } => {
                write!(formatter, "ACME issuer {issuer:?} has no EAB configuration")
            }
            Self::InvalidSecretSource { issuer, field } => write!(
                formatter,
                "ACME issuer {issuer:?} EAB {field} must be read from exactly one env var or file"
            ),
            Self::EnvRead {
                issuer,
                field,
                env,
                message,
            } => write!(
                formatter,
                "failed to read ACME issuer {issuer:?} EAB {field} env {env:?}: {message}"
            ),
            Self::FileRead {
                issuer,
                field,
                path,
                message,
            } => write!(
                formatter,
                "failed to read ACME issuer {issuer:?} EAB {field} file {}: {message}",
                path.display()
            ),
            Self::EmptySecret { issuer, field } => {
                write!(formatter, "ACME issuer {issuer:?} EAB {field} is empty")
            }
            Self::OversizedSecret {
                issuer,
                field,
                max_bytes,
            } => write!(
                formatter,
                "ACME issuer {issuer:?} EAB {field} exceeds {max_bytes} bytes"
            ),
        }
    }
}

impl std::error::Error for AcmeSecretLoadError {}

#[derive(Debug)]
pub enum AcmeCertificateInstallError {
    InvalidCertificatePem(&'static str),
    InvalidPrivateKeyPem(&'static str),
    UnsafePath { path: PathBuf, message: String },
    Io { path: PathBuf, error: io::Error },
}

impl fmt::Display for AcmeCertificateInstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCertificatePem(message) => {
                write!(formatter, "invalid ACME certificate PEM: {message}")
            }
            Self::InvalidPrivateKeyPem(message) => {
                write!(formatter, "invalid ACME private key PEM: {message}")
            }
            Self::UnsafePath { path, message } => {
                write!(
                    formatter,
                    "unsafe ACME certificate path {}: {message}",
                    path.display()
                )
            }
            Self::Io { path, error } => {
                write!(
                    formatter,
                    "failed to install ACME certificate at {}: {error}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for AcmeCertificateInstallError {}

#[derive(Debug)]
pub enum AcmeAccountStoreError {
    UnsafePath { path: PathBuf, message: String },
    Io { path: PathBuf, error: io::Error },
    Serialize { message: String },
    Deserialize { path: PathBuf, message: String },
    Oversized { path: PathBuf, max_bytes: u64 },
}

impl fmt::Display for AcmeAccountStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafePath { path, message } => write!(
                formatter,
                "unsafe ACME account credential path {}: {message}",
                path.display()
            ),
            Self::Io { path, error } => {
                write!(
                    formatter,
                    "failed to access ACME account credentials at {}: {error}",
                    path.display()
                )
            }
            Self::Serialize { message } => {
                write!(
                    formatter,
                    "failed to serialize ACME account credentials: {message}"
                )
            }
            Self::Deserialize { path, message } => write!(
                formatter,
                "failed to parse ACME account credentials at {}: {message}",
                path.display()
            ),
            Self::Oversized { path, max_bytes } => write!(
                formatter,
                "ACME account credentials at {} exceed {max_bytes} bytes",
                path.display()
            ),
        }
    }
}

impl std::error::Error for AcmeAccountStoreError {}

#[cfg(feature = "acme-client")]
#[derive(Debug)]
pub enum AcmeInstantClientError {
    MissingStorage,
    UnknownIssuer { issuer: String },
    AccountStore(AcmeAccountStoreError),
    ExternalAccountBinding(AcmeSecretLoadError),
    InvalidExternalAccountBindingHmacKey { issuer: String, message: String },
    Account { issuer: String, message: String },
}

#[cfg(feature = "acme-client")]
impl fmt::Display for AcmeInstantClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingStorage => write!(formatter, "tls.acme.storage is required"),
            Self::UnknownIssuer { issuer } => write!(formatter, "unknown ACME issuer {issuer:?}"),
            Self::AccountStore(error) => write!(formatter, "{error}"),
            Self::ExternalAccountBinding(error) => write!(formatter, "{error}"),
            Self::InvalidExternalAccountBindingHmacKey { issuer, message } => write!(
                formatter,
                "ACME issuer {issuer:?} EAB hmac_key is not valid base64: {message}"
            ),
            Self::Account { issuer, message } => {
                write!(
                    formatter,
                    "ACME issuer {issuer:?} account operation failed: {message}"
                )
            }
        }
    }
}

#[cfg(feature = "acme-client")]
impl std::error::Error for AcmeInstantClientError {}

#[derive(Debug)]
pub enum AcmeRenewalError {
    MissingStorage,
    UnknownIssuer { issuer: String },
    UnsupportedChallenge { challenge: AcmeChallenge },
    ExternalAccountBinding(AcmeSecretLoadError),
    Client { issuer: String, message: String },
    Challenge { token: String, error: io::Error },
    TlsAlpnCertificate { domain: String, message: String },
    CertificateInstall(AcmeCertificateInstallError),
}

impl fmt::Display for AcmeRenewalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingStorage => write!(formatter, "tls.acme.storage is required"),
            Self::UnknownIssuer { issuer } => write!(formatter, "unknown ACME issuer {issuer:?}"),
            Self::UnsupportedChallenge { challenge } => {
                write!(
                    formatter,
                    "unsupported ACME challenge for runtime renewal: {challenge:?}"
                )
            }
            Self::ExternalAccountBinding(error) => write!(formatter, "{error}"),
            Self::Client { issuer, message } => {
                write!(formatter, "ACME issuer {issuer:?} failed: {message}")
            }
            Self::Challenge { token, error } => {
                write!(
                    formatter,
                    "ACME HTTP-01 challenge {token:?} failed: {error}"
                )
            }
            Self::TlsAlpnCertificate { domain, message } => write!(
                formatter,
                "ACME TLS-ALPN-01 certificate for {domain:?} failed: {message}"
            ),
            Self::CertificateInstall(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for AcmeRenewalError {}

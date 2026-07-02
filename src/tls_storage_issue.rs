use std::fmt::{Display, Formatter};
use std::path::PathBuf;

use super::{ACME_STORAGE_MODE, PRIVATE_KEY_MODE};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TlsStorageCheck {
    pub issues: Vec<TlsStorageIssue>,
}

impl TlsStorageCheck {
    pub fn is_secure(&self) -> bool {
        self.issues.is_empty()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TlsStorageIssue {
    CertificateReadFailed {
        scope: String,
        path: PathBuf,
        message: String,
    },
    CertificatePathIsNotFile {
        scope: String,
        path: PathBuf,
    },
    CertificatePathHasWorldWritableParent {
        scope: String,
        path: PathBuf,
    },
    PrivateKeyReadFailed {
        scope: String,
        path: PathBuf,
        message: String,
    },
    PrivateKeyPathIsNotFile {
        scope: String,
        path: PathBuf,
    },
    PrivateKeyPathHasWorldWritableParent {
        scope: String,
        path: PathBuf,
    },
    InsecurePrivateKeyPermissions {
        scope: String,
        path: PathBuf,
        mode: u32,
    },
    PrivateKeyOwnerMismatch {
        scope: String,
        path: PathBuf,
        owner_uid: u32,
        process_uid: u32,
    },
    AcmeEabSecretReadFailed {
        issuer: String,
        field: &'static str,
        path: PathBuf,
        message: String,
    },
    AcmeEabSecretPathIsNotFile {
        issuer: String,
        field: &'static str,
        path: PathBuf,
    },
    AcmeEabSecretPathHasWorldWritableParent {
        issuer: String,
        field: &'static str,
        path: PathBuf,
    },
    InsecureAcmeEabSecretPermissions {
        issuer: String,
        field: &'static str,
        path: PathBuf,
        mode: u32,
    },
    AcmeEabSecretOwnerMismatch {
        issuer: String,
        field: &'static str,
        path: PathBuf,
        owner_uid: u32,
        process_uid: u32,
    },
    AcmeStorageReadFailed {
        path: PathBuf,
        message: String,
    },
    AcmeStoragePathIsNotDirectory {
        path: PathBuf,
    },
    AcmeStoragePathHasWorldWritableParent {
        path: PathBuf,
    },
    InsecureAcmeStoragePermissions {
        path: PathBuf,
        mode: u32,
    },
    AcmeStorageOwnerMismatch {
        path: PathBuf,
        owner_uid: u32,
        process_uid: u32,
    },
}

impl Display for TlsStorageIssue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertificateReadFailed {
                scope,
                path,
                message,
            } => write!(
                formatter,
                "{scope}.cert_path {} cannot be read: {message}",
                path.display()
            ),
            Self::CertificatePathIsNotFile { scope, path } => write!(
                formatter,
                "{scope}.cert_path {} is not a regular file",
                path.display()
            ),
            Self::CertificatePathHasWorldWritableParent { scope, path } => write!(
                formatter,
                "{scope}.cert_path {} uses a group- or world-writable parent directory",
                path.display()
            ),
            Self::PrivateKeyReadFailed {
                scope,
                path,
                message,
            } => write!(
                formatter,
                "{scope}.key_path {} cannot be read: {message}",
                path.display()
            ),
            Self::PrivateKeyPathIsNotFile { scope, path } => write!(
                formatter,
                "{scope}.key_path {} is not a regular file",
                path.display()
            ),
            Self::PrivateKeyPathHasWorldWritableParent { scope, path } => write!(
                formatter,
                "{scope}.key_path {} uses a group- or world-writable parent directory",
                path.display()
            ),
            Self::InsecurePrivateKeyPermissions { scope, path, mode } => write!(
                formatter,
                "{scope}.key_path {} has insecure mode {mode:o}; use {:o}",
                path.display(),
                PRIVATE_KEY_MODE
            ),
            Self::PrivateKeyOwnerMismatch {
                scope,
                path,
                owner_uid,
                process_uid,
            } => write!(
                formatter,
                "{scope}.key_path {} is owned by uid {owner_uid}; expected process uid {process_uid}",
                path.display()
            ),
            Self::AcmeEabSecretReadFailed {
                issuer,
                field,
                path,
                message,
            } => write!(
                formatter,
                "tls.acme.issuers.{issuer}.eab.{field}_file {} cannot be read: {message}",
                path.display()
            ),
            Self::AcmeEabSecretPathIsNotFile {
                issuer,
                field,
                path,
            } => write!(
                formatter,
                "tls.acme.issuers.{issuer}.eab.{field}_file {} is not a regular file",
                path.display()
            ),
            Self::AcmeEabSecretPathHasWorldWritableParent {
                issuer,
                field,
                path,
            } => write!(
                formatter,
                "tls.acme.issuers.{issuer}.eab.{field}_file {} uses a group- or world-writable parent directory",
                path.display()
            ),
            Self::InsecureAcmeEabSecretPermissions {
                issuer,
                field,
                path,
                mode,
            } => write!(
                formatter,
                "tls.acme.issuers.{issuer}.eab.{field}_file {} has insecure mode {mode:o}; use {:o}",
                path.display(),
                PRIVATE_KEY_MODE
            ),
            Self::AcmeEabSecretOwnerMismatch {
                issuer,
                field,
                path,
                owner_uid,
                process_uid,
            } => write!(
                formatter,
                "tls.acme.issuers.{issuer}.eab.{field}_file {} is owned by uid {owner_uid}; expected process uid {process_uid}",
                path.display()
            ),
            Self::AcmeStorageReadFailed { path, message } => write!(
                formatter,
                "tls.acme.storage {} cannot be read: {message}",
                path.display()
            ),
            Self::AcmeStoragePathIsNotDirectory { path } => write!(
                formatter,
                "tls.acme.storage {} is not a directory",
                path.display()
            ),
            Self::AcmeStoragePathHasWorldWritableParent { path } => write!(
                formatter,
                "tls.acme.storage {} uses a group- or world-writable parent directory",
                path.display()
            ),
            Self::InsecureAcmeStoragePermissions { path, mode } => write!(
                formatter,
                "tls.acme.storage {} has insecure mode {mode:o}; use {:o}",
                path.display(),
                ACME_STORAGE_MODE
            ),
            Self::AcmeStorageOwnerMismatch {
                path,
                owner_uid,
                process_uid,
            } => write!(
                formatter,
                "tls.acme.storage {} is owned by uid {owner_uid}; expected process uid {process_uid}",
                path.display()
            ),
        }
    }
}

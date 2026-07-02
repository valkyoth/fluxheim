use std::fmt::{Display, Formatter};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::config::{AcmeConfig, Config, StaticCertificateConfig};

pub const PRIVATE_KEY_MODE: u32 = 0o600;
pub const ACME_STORAGE_MODE: u32 = 0o700;

#[cfg(feature = "tls-rustls-backend")]
pub fn install_rustls_crypto_provider() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fluxheim_tls::install_rustls_crypto_provider().map_err(Into::into)
}

#[cfg(feature = "tls-rustls-backend")]
pub fn rustls_crypto_provider() -> rustls::crypto::CryptoProvider {
    fluxheim_tls::rustls_crypto_provider()
}

#[cfg(feature = "tls-rustls-fips")]
pub use fluxheim_tls::RustlsFipsStatus;

#[cfg(feature = "tls-rustls-fips")]
pub fn probe_rustls_fips_provider() -> Result<RustlsFipsStatus, String> {
    fluxheim_tls::probe_rustls_fips_provider()
}

#[cfg(feature = "tls-openssl-fips")]
pub use fluxheim_tls::OpenSslFipsStatus;

#[cfg(feature = "tls-openssl-fips")]
pub fn probe_openssl_fips_provider() -> Result<OpenSslFipsStatus, String> {
    fluxheim_tls::probe_openssl_fips_provider()
}

#[cfg(feature = "tls-openssl-fips")]
pub fn activate_openssl_fips_provider() -> Result<OpenSslFipsStatus, String> {
    fluxheim_tls::activate_openssl_fips_provider()
}

pub fn validate_fips_runtime_config(
    config: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fluxheim_tls::validate_fips_runtime_config(config).map_err(Into::into)
}

pub fn downstream_tls_listener_plan(
    config: &Config,
) -> Result<Option<fluxheim_tls::DownstreamTlsListenerPlan>, Box<dyn std::error::Error + Send + Sync>>
{
    fluxheim_tls::DownstreamTlsListenerPlan::from_config_with_acme_resolver(
        config,
        managed_acme_certificate_source,
    )
    .map_err(Into::into)
}

pub type DownstreamCertificateSelector = fluxheim_tls::DownstreamCertificateSelector;
pub type DownstreamCertificateSource = fluxheim_tls::DownstreamCertificateSource;

pub fn downstream_certificate_selector(config: &Config) -> Option<DownstreamCertificateSelector> {
    DownstreamCertificateSelector::from_config_with_acme_resolver(
        config,
        managed_acme_certificate_source,
    )
}

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

pub fn validate_tls_storage(config: &Config) -> TlsStorageCheck {
    let mut issues = Vec::new();

    for (index, certificate) in config.tls.certificates.iter().enumerate() {
        validate_static_certificate_storage(
            &format!("tls.certificates[{index}]"),
            certificate,
            &mut issues,
        );
    }

    for vhost in &config.vhosts {
        if let Some(certificate) = &vhost.tls.certificate {
            validate_static_certificate_storage(
                &format!("vhosts.{}.tls.certificate", vhost.name),
                certificate,
                &mut issues,
            );
        }
    }

    validate_acme_storage(&config.tls.acme, &mut issues);
    validate_acme_eab_secret_storage(&config.tls.acme, &mut issues);

    TlsStorageCheck { issues }
}

pub fn secure_private_key_mode(mode: u32) -> bool {
    mode & 0o077 == 0
}

pub fn secure_acme_storage_mode(mode: u32) -> bool {
    mode & 0o077 == 0
}

pub fn recommended_private_key_mode() -> u32 {
    PRIVATE_KEY_MODE
}

pub fn recommended_acme_storage_mode() -> u32 {
    ACME_STORAGE_MODE
}

#[cfg(feature = "acme")]
fn managed_acme_certificate_source(
    config: &Config,
    vhost: &crate::config::VhostConfig,
) -> Option<DownstreamCertificateSource> {
    if !config.tls.acme.enabled {
        return None;
    }

    let storage = config.tls.acme.storage.as_ref()?;
    let owner = if vhost.tls.acme.enabled {
        vhost.name.as_str()
    } else {
        fluxheim_tls::shared_managed_acme_certificate_owner(config, vhost)?
    };
    let paths = crate::acme::managed_certificate_paths(storage, owner);
    Some(DownstreamCertificateSource {
        certificate: StaticCertificateConfig {
            cert_path: paths.cert_path,
            key_path: paths.key_path,
        },
        managed_acme: true,
    })
}

#[cfg(not(feature = "acme"))]
fn managed_acme_certificate_source(
    _config: &Config,
    _vhost: &crate::config::VhostConfig,
) -> Option<DownstreamCertificateSource> {
    None
}

fn validate_static_certificate_storage(
    scope: &str,
    certificate: &StaticCertificateConfig,
    issues: &mut Vec<TlsStorageIssue>,
) {
    // These storage checks are an operator-facing preflight, not the final
    // file open used by the TLS backend. Parent writability and symlink
    // rejection make local replacement races require control of already
    // untrusted paths; Unix deployments that need a stricter descriptor-bound
    // check should keep keys below root-owned, non-writable parents.
    if !push_certificate_world_writable_parent_issue(scope, &certificate.cert_path, issues) {
        match path_contains_symlink(&certificate.cert_path) {
            Ok(true) => issues.push(TlsStorageIssue::CertificatePathIsNotFile {
                scope: scope.to_owned(),
                path: certificate.cert_path.clone(),
            }),
            Ok(false) => match fs::symlink_metadata(&certificate.cert_path) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    issues.push(TlsStorageIssue::CertificatePathIsNotFile {
                        scope: scope.to_owned(),
                        path: certificate.cert_path.clone(),
                    });
                }
                Ok(_) => {}
                Err(error) => issues.push(TlsStorageIssue::CertificateReadFailed {
                    scope: scope.to_owned(),
                    path: certificate.cert_path.clone(),
                    message: error_message(error),
                }),
            },
            Err(error) => issues.push(TlsStorageIssue::CertificateReadFailed {
                scope: scope.to_owned(),
                path: certificate.cert_path.clone(),
                message: symlink_inspection_error(error),
            }),
        }
    }

    if !push_private_key_world_writable_parent_issue(scope, &certificate.key_path, issues) {
        match path_contains_symlink(&certificate.key_path) {
            Ok(true) => issues.push(TlsStorageIssue::PrivateKeyPathIsNotFile {
                scope: scope.to_owned(),
                path: certificate.key_path.clone(),
            }),
            Ok(false) => match fs::symlink_metadata(&certificate.key_path) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    issues.push(TlsStorageIssue::PrivateKeyPathIsNotFile {
                        scope: scope.to_owned(),
                        path: certificate.key_path.clone(),
                    });
                }
                Ok(metadata) => {
                    validate_key_permissions(scope, &certificate.key_path, &metadata, issues)
                }
                Err(error) => issues.push(TlsStorageIssue::PrivateKeyReadFailed {
                    scope: scope.to_owned(),
                    path: certificate.key_path.clone(),
                    message: error_message(error),
                }),
            },
            Err(error) => issues.push(TlsStorageIssue::PrivateKeyReadFailed {
                scope: scope.to_owned(),
                path: certificate.key_path.clone(),
                message: symlink_inspection_error(error),
            }),
        }
    }
}

fn validate_acme_storage(acme: &AcmeConfig, issues: &mut Vec<TlsStorageIssue>) {
    if !acme.enabled {
        return;
    }

    let Some(path) = &acme.storage else {
        return;
    };

    if push_acme_storage_world_writable_parent_issue(path, issues) {
        return;
    }

    match path_contains_symlink(path) {
        Ok(true) => {
            issues.push(TlsStorageIssue::AcmeStoragePathIsNotDirectory { path: path.clone() })
        }
        Ok(false) => match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                issues.push(TlsStorageIssue::AcmeStoragePathIsNotDirectory { path: path.clone() })
            }
            Ok(metadata) => validate_acme_storage_permissions(path, &metadata, issues),
            Err(error) => issues.push(TlsStorageIssue::AcmeStorageReadFailed {
                path: path.clone(),
                message: error_message(error),
            }),
        },
        Err(error) => issues.push(TlsStorageIssue::AcmeStorageReadFailed {
            path: path.clone(),
            message: symlink_inspection_error(error),
        }),
    }
}

fn validate_acme_eab_secret_storage(acme: &AcmeConfig, issues: &mut Vec<TlsStorageIssue>) {
    if !acme.enabled {
        return;
    }

    for issuer in &acme.issuers {
        let Some(eab) = &issuer.eab else {
            continue;
        };

        if let Some(path) = &eab.key_id_file {
            validate_acme_eab_secret_file(&issuer.name, "key_id", path, issues);
        }
        if let Some(path) = &eab.hmac_key_file {
            validate_acme_eab_secret_file(&issuer.name, "hmac_key", path, issues);
        }
    }
}

fn validate_acme_eab_secret_file(
    issuer: &str,
    field: &'static str,
    path: &Path,
    issues: &mut Vec<TlsStorageIssue>,
) {
    if push_acme_eab_world_writable_parent_issue(issuer, field, path, issues) {
        return;
    }

    match path_contains_symlink(path) {
        Ok(true) => issues.push(TlsStorageIssue::AcmeEabSecretPathIsNotFile {
            issuer: issuer.to_owned(),
            field,
            path: path.to_path_buf(),
        }),
        Ok(false) => match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                issues.push(TlsStorageIssue::AcmeEabSecretPathIsNotFile {
                    issuer: issuer.to_owned(),
                    field,
                    path: path.to_path_buf(),
                });
            }
            Ok(metadata) => {
                validate_acme_eab_secret_permissions(issuer, field, path, &metadata, issues)
            }
            Err(error) => issues.push(TlsStorageIssue::AcmeEabSecretReadFailed {
                issuer: issuer.to_owned(),
                field,
                path: path.to_path_buf(),
                message: error_message(error),
            }),
        },
        Err(error) => issues.push(TlsStorageIssue::AcmeEabSecretReadFailed {
            issuer: issuer.to_owned(),
            field,
            path: path.to_path_buf(),
            message: symlink_inspection_error(error),
        }),
    }
}

fn path_contains_symlink(path: &Path) -> io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

fn push_certificate_world_writable_parent_issue(
    scope: &str,
    path: &Path,
    issues: &mut Vec<TlsStorageIssue>,
) -> bool {
    match path_has_insecure_writable_parent(path) {
        Ok(true) => {
            issues.push(TlsStorageIssue::CertificatePathHasWorldWritableParent {
                scope: scope.to_owned(),
                path: path.to_path_buf(),
            });
            true
        }
        Ok(false) => false,
        Err(error) => {
            issues.push(TlsStorageIssue::CertificateReadFailed {
                scope: scope.to_owned(),
                path: path.to_path_buf(),
                message: error_message(error),
            });
            true
        }
    }
}

fn push_private_key_world_writable_parent_issue(
    scope: &str,
    path: &Path,
    issues: &mut Vec<TlsStorageIssue>,
) -> bool {
    match path_has_insecure_writable_parent(path) {
        Ok(true) => {
            issues.push(TlsStorageIssue::PrivateKeyPathHasWorldWritableParent {
                scope: scope.to_owned(),
                path: path.to_path_buf(),
            });
            true
        }
        Ok(false) => false,
        Err(error) => {
            issues.push(TlsStorageIssue::PrivateKeyReadFailed {
                scope: scope.to_owned(),
                path: path.to_path_buf(),
                message: error_message(error),
            });
            true
        }
    }
}

fn push_acme_storage_world_writable_parent_issue(
    path: &Path,
    issues: &mut Vec<TlsStorageIssue>,
) -> bool {
    match path_has_insecure_writable_parent(path) {
        Ok(true) => {
            issues.push(TlsStorageIssue::AcmeStoragePathHasWorldWritableParent {
                path: path.to_path_buf(),
            });
            true
        }
        Ok(false) => false,
        Err(error) => {
            issues.push(TlsStorageIssue::AcmeStorageReadFailed {
                path: path.to_path_buf(),
                message: error_message(error),
            });
            true
        }
    }
}

fn push_acme_eab_world_writable_parent_issue(
    issuer: &str,
    field: &'static str,
    path: &Path,
    issues: &mut Vec<TlsStorageIssue>,
) -> bool {
    match path_has_insecure_writable_parent(path) {
        Ok(true) => {
            issues.push(TlsStorageIssue::AcmeEabSecretPathHasWorldWritableParent {
                issuer: issuer.to_owned(),
                field,
                path: path.to_path_buf(),
            });
            true
        }
        Ok(false) => false,
        Err(error) => {
            issues.push(TlsStorageIssue::AcmeEabSecretReadFailed {
                issuer: issuer.to_owned(),
                field,
                path: path.to_path_buf(),
                message: error_message(error),
            });
            true
        }
    }
}

fn path_has_insecure_writable_parent(path: &Path) -> io::Result<bool> {
    fluxheim_config::fs_trust::existing_parent_has_insecure_write_permissions(path)
}

fn symlink_inspection_error(error: io::Error) -> String {
    format!(
        "failed to inspect path for symlinks: {}",
        error_message(error)
    )
}

#[cfg(unix)]
fn validate_key_permissions(
    scope: &str,
    path: &Path,
    metadata: &fs::Metadata,
    issues: &mut Vec<TlsStorageIssue>,
) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = metadata.permissions().mode() & 0o777;
    if !secure_private_key_mode(mode) {
        issues.push(TlsStorageIssue::InsecurePrivateKeyPermissions {
            scope: scope.to_owned(),
            path: path.to_path_buf(),
            mode,
        });
    }

    let owner_uid = metadata.uid();
    let process_uid = current_effective_uid();
    if owner_uid != process_uid {
        issues.push(TlsStorageIssue::PrivateKeyOwnerMismatch {
            scope: scope.to_owned(),
            path: path.to_path_buf(),
            owner_uid,
            process_uid,
        });
    }
}

#[cfg(unix)]
fn validate_acme_storage_permissions(
    path: &Path,
    metadata: &fs::Metadata,
    issues: &mut Vec<TlsStorageIssue>,
) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = metadata.permissions().mode() & 0o777;
    if !secure_acme_storage_mode(mode) {
        issues.push(TlsStorageIssue::InsecureAcmeStoragePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }

    let owner_uid = metadata.uid();
    let process_uid = current_effective_uid();
    if owner_uid != process_uid {
        issues.push(TlsStorageIssue::AcmeStorageOwnerMismatch {
            path: path.to_path_buf(),
            owner_uid,
            process_uid,
        });
    }
}

#[cfg(unix)]
fn validate_acme_eab_secret_permissions(
    issuer: &str,
    field: &'static str,
    path: &Path,
    metadata: &fs::Metadata,
    issues: &mut Vec<TlsStorageIssue>,
) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mode = metadata.permissions().mode() & 0o777;
    if !secure_private_key_mode(mode) {
        issues.push(TlsStorageIssue::InsecureAcmeEabSecretPermissions {
            issuer: issuer.to_owned(),
            field,
            path: path.to_path_buf(),
            mode,
        });
    }

    let owner_uid = metadata.uid();
    let process_uid = current_effective_uid();
    if owner_uid != process_uid {
        issues.push(TlsStorageIssue::AcmeEabSecretOwnerMismatch {
            issuer: issuer.to_owned(),
            field,
            path: path.to_path_buf(),
            owner_uid,
            process_uid,
        });
    }
}

#[cfg(unix)]
fn current_effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn error_message(error: io::Error) -> String {
    error.to_string()
}

#[cfg(test)]
#[path = "tls_selector_tests.rs"]
mod selector_tests;

#[cfg(test)]
#[path = "tls_storage_tests.rs"]
mod storage_tests;

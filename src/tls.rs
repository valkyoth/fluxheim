use std::fmt::{Display, Formatter};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::config::{AcmeConfig, Config, StaticCertificateConfig};

pub const PRIVATE_KEY_MODE: u32 = 0o600;
pub const ACME_STORAGE_MODE: u32 = 0o700;

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
                "{scope}.cert_path {} uses a world-writable parent directory",
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
                "{scope}.key_path {} uses a world-writable parent directory",
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
                "tls.acme.issuers.{issuer}.eab.{field}_file {} uses a world-writable parent directory",
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
                "tls.acme.storage {} uses a world-writable parent directory",
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

pub fn default_downstream_certificate(config: &Config) -> Option<&StaticCertificateConfig> {
    config.tls.certificates.first()
}

fn validate_static_certificate_storage(
    scope: &str,
    certificate: &StaticCertificateConfig,
    issues: &mut Vec<TlsStorageIssue>,
) {
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
    match path_has_world_writable_parent(path) {
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
    match path_has_world_writable_parent(path) {
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
    match path_has_world_writable_parent(path) {
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
    match path_has_world_writable_parent(path) {
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

#[cfg(unix)]
fn path_has_world_writable_parent(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    let mut current = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    loop {
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(false),
            Ok(metadata) => return Ok(metadata.permissions().mode() & 0o002 != 0),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !current.pop() {
                    return Ok(false);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(not(unix))]
fn path_has_world_writable_parent(_path: &Path) -> io::Result<bool> {
    Ok(false)
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

#[cfg(not(unix))]
fn validate_key_permissions(
    _scope: &str,
    _path: &Path,
    _metadata: &fs::Metadata,
    _issues: &mut Vec<TlsStorageIssue>,
) {
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

#[cfg(not(unix))]
fn validate_acme_eab_secret_permissions(
    _issuer: &str,
    _field: &'static str,
    _path: &Path,
    _metadata: &fs::Metadata,
    _issues: &mut Vec<TlsStorageIssue>,
) {
}

#[cfg(unix)]
fn current_effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }

    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    unsafe { geteuid() }
}

#[cfg(not(unix))]
fn validate_acme_storage_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
    _issues: &mut Vec<TlsStorageIssue>,
) {
}

fn error_message(error: io::Error) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use crate::config::{
        AcmeConfig, AcmeExternalAccountBindingConfig, AcmeIssuerConfig, Config,
        StaticCertificateConfig, TlsConfig,
    };
    #[cfg(unix)]
    use crate::test_support::unique_world_writable_child;
    use crate::test_support::{safe_child_path, unique_temp_path};

    use super::{
        TlsStorageIssue, recommended_acme_storage_mode, recommended_private_key_mode,
        secure_acme_storage_mode, secure_private_key_mode, validate_tls_storage,
    };

    #[test]
    fn accepts_owner_only_private_key_and_acme_storage() {
        let dir = TestDir::new("tls-storage-secure");
        let cert = dir.file("fullchain.pem", 0o644);
        let key = dir.file("key.pem", recommended_private_key_mode());
        let acme = dir.dir("acme", recommended_acme_storage_mode());
        let config = tls_config(cert, key, acme);

        let check = validate_tls_storage(&config);

        assert_eq!(check.issues, Vec::new());
        assert!(check.is_secure());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_readable_private_key() {
        let dir = TestDir::new("tls-storage-key-mode");
        let cert = dir.file("fullchain.pem", 0o644);
        let key = dir.file("key.pem", 0o640);
        let acme = dir.dir("acme", recommended_acme_storage_mode());
        let config = tls_config(cert, key.clone(), acme);

        let check = validate_tls_storage(&config);

        assert_eq!(
            check.issues,
            vec![TlsStorageIssue::InsecurePrivateKeyPermissions {
                scope: "tls.certificates[0]".to_owned(),
                path: key,
                mode: 0o640
            }]
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_accessible_acme_storage() {
        let dir = TestDir::new("tls-storage-acme-mode");
        let cert = dir.file("fullchain.pem", 0o644);
        let key = dir.file("key.pem", recommended_private_key_mode());
        let acme = dir.dir("acme", 0o755);
        let config = tls_config(cert, key, acme.clone());

        let check = validate_tls_storage(&config);

        assert_eq!(
            check.issues,
            vec![TlsStorageIssue::InsecureAcmeStoragePermissions {
                path: acme,
                mode: 0o755
            }]
        );
    }

    #[test]
    fn reports_missing_certificate_files() {
        let dir = TestDir::new("tls-storage-missing");
        let cert = dir.path().join("missing-fullchain.pem");
        let key = dir.path().join("missing-key.pem");
        let acme = dir.dir("acme", recommended_acme_storage_mode());
        let config = tls_config(cert.clone(), key.clone(), acme);

        let check = validate_tls_storage(&config);

        assert!(matches!(
            &check.issues[0],
            TlsStorageIssue::CertificateReadFailed { path, .. } if path == &cert
        ));
        assert!(matches!(
            &check.issues[1],
            TlsStorageIssue::PrivateKeyReadFailed { path, .. } if path == &key
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_certificate_files_and_acme_storage() {
        let dir = TestDir::new("tls-storage-symlink");
        let real_cert = dir.file("real-fullchain.pem", 0o644);
        let real_key = dir.file("real-key.pem", recommended_private_key_mode());
        let real_acme = dir.dir("real-acme", recommended_acme_storage_mode());
        let cert = dir.path().join("fullchain.pem");
        let key = dir.path().join("key.pem");
        let acme = dir.path().join("acme");
        std::os::unix::fs::symlink(&real_cert, &cert).unwrap();
        std::os::unix::fs::symlink(&real_key, &key).unwrap();
        std::os::unix::fs::symlink(&real_acme, &acme).unwrap();
        let config = tls_config(cert.clone(), key.clone(), acme.clone());

        let check = validate_tls_storage(&config);

        assert_eq!(
            check.issues,
            vec![
                TlsStorageIssue::CertificatePathIsNotFile {
                    scope: "tls.certificates[0]".to_owned(),
                    path: cert,
                },
                TlsStorageIssue::PrivateKeyPathIsNotFile {
                    scope: "tls.certificates[0]".to_owned(),
                    path: key,
                },
                TlsStorageIssue::AcmeStoragePathIsNotDirectory { path: acme },
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_tls_storage_below_symlinked_directory() {
        let dir = TestDir::new("tls-storage-parent-symlink");
        let real_dir = dir.dir("real", 0o700);
        let linked_dir = dir.path().join("linked");
        std::os::unix::fs::symlink(&real_dir, &linked_dir).unwrap();
        let cert = linked_dir.join("fullchain.pem");
        let key = linked_dir.join("key.pem");
        let acme = linked_dir.join("acme");
        fs::write(real_dir.join("fullchain.pem"), "test").unwrap();
        fs::write(real_dir.join("key.pem"), "test").unwrap();
        fs::create_dir(real_dir.join("acme")).unwrap();
        set_mode(&real_dir.join("key.pem"), recommended_private_key_mode());
        set_mode(&real_dir.join("acme"), recommended_acme_storage_mode());
        let config = tls_config(cert.clone(), key.clone(), acme.clone());

        let check = validate_tls_storage(&config);

        assert_eq!(
            check.issues,
            vec![
                TlsStorageIssue::CertificatePathIsNotFile {
                    scope: "tls.certificates[0]".to_owned(),
                    path: cert,
                },
                TlsStorageIssue::PrivateKeyPathIsNotFile {
                    scope: "tls.certificates[0]".to_owned(),
                    path: key,
                },
                TlsStorageIssue::AcmeStoragePathIsNotDirectory { path: acme },
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_tls_storage_below_world_writable_parent() {
        let cert = unique_world_writable_child("tls-world-writable-parent", "fullchain.pem");
        let key = unique_world_writable_child("tls-world-writable-parent-key", "key.pem");
        let acme = unique_world_writable_child("tls-world-writable-parent-acme", "acme");
        let config = tls_config(cert.clone(), key.clone(), acme.clone());

        let check = validate_tls_storage(&config);

        assert_eq!(
            check.issues,
            vec![
                TlsStorageIssue::CertificatePathHasWorldWritableParent {
                    scope: "tls.certificates[0]".to_owned(),
                    path: cert,
                },
                TlsStorageIssue::PrivateKeyPathHasWorldWritableParent {
                    scope: "tls.certificates[0]".to_owned(),
                    path: key,
                },
                TlsStorageIssue::AcmeStoragePathHasWorldWritableParent { path: acme },
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn validates_acme_eab_secret_files() {
        let dir = TestDir::new("tls-storage-eab");
        let cert = dir.file("fullchain.pem", 0o644);
        let key = dir.file("key.pem", recommended_private_key_mode());
        let acme = dir.dir("acme", recommended_acme_storage_mode());
        let key_id = dir.file("key-id", 0o640);
        let real_hmac = dir.file("real-hmac", recommended_private_key_mode());
        let hmac = dir.path().join("hmac");
        std::os::unix::fs::symlink(&real_hmac, &hmac).unwrap();
        let mut config = tls_config(cert, key, acme);
        config.tls.acme.issuers = vec![AcmeIssuerConfig {
            name: "actalis".to_owned(),
            directory_url: "https://acme-api.actalis.com/acme/directory".to_owned(),
            eab: Some(AcmeExternalAccountBindingConfig {
                key_id_env: None,
                key_id_file: Some(key_id.clone()),
                hmac_key_env: None,
                hmac_key_file: Some(hmac.clone()),
            }),
        }];

        let check = validate_tls_storage(&config);

        assert_eq!(
            check.issues,
            vec![
                TlsStorageIssue::InsecureAcmeEabSecretPermissions {
                    issuer: "actalis".to_owned(),
                    field: "key_id",
                    path: key_id,
                    mode: 0o640,
                },
                TlsStorageIssue::AcmeEabSecretPathIsNotFile {
                    issuer: "actalis".to_owned(),
                    field: "hmac_key",
                    path: hmac,
                },
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_acme_eab_secret_below_world_writable_parent() {
        let dir = TestDir::new("tls-storage-eab-world-writable");
        let cert = dir.file("fullchain.pem", 0o644);
        let key = dir.file("key.pem", recommended_private_key_mode());
        let acme = dir.dir("acme", recommended_acme_storage_mode());
        let key_id = unique_world_writable_child("tls-eab-kid", "key-id");
        let mut config = tls_config(cert, key, acme);
        config.tls.acme.issuers = vec![AcmeIssuerConfig {
            name: "actalis".to_owned(),
            directory_url: "https://acme-api.actalis.com/acme/directory".to_owned(),
            eab: Some(AcmeExternalAccountBindingConfig {
                key_id_env: None,
                key_id_file: Some(key_id.clone()),
                hmac_key_env: Some("FLUXHEIM_ACTALIS_EAB_HMAC_KEY".to_owned()),
                hmac_key_file: None,
            }),
        }];

        let check = validate_tls_storage(&config);

        assert_eq!(
            check.issues,
            vec![TlsStorageIssue::AcmeEabSecretPathHasWorldWritableParent {
                issuer: "actalis".to_owned(),
                field: "key_id",
                path: key_id,
            }]
        );
    }

    #[test]
    fn permission_predicates_allow_only_owner_access() {
        assert!(secure_private_key_mode(0o600));
        assert!(secure_private_key_mode(0o400));
        assert!(!secure_private_key_mode(0o640));
        assert!(secure_acme_storage_mode(0o700));
        assert!(secure_acme_storage_mode(0o500));
        assert!(!secure_acme_storage_mode(0o750));
    }

    #[test]
    fn formats_storage_issues_for_cli_output() {
        let path = PathBuf::from("target/fluxheim-test-tmp/key.pem");
        let issue = TlsStorageIssue::InsecurePrivateKeyPermissions {
            scope: "tls.certificates[0]".to_owned(),
            path: path.clone(),
            mode: 0o640,
        };

        assert_eq!(
            issue.to_string(),
            format!(
                "tls.certificates[0].key_path {} has insecure mode 640; use 600",
                path.display()
            )
        );
    }

    fn tls_config(cert_path: PathBuf, key_path: PathBuf, acme_storage: PathBuf) -> Config {
        Config {
            tls: TlsConfig {
                enabled: true,
                certificates: vec![StaticCertificateConfig {
                    cert_path,
                    key_path,
                }],
                acme: AcmeConfig {
                    enabled: true,
                    storage: Some(acme_storage),
                    ..AcmeConfig::default()
                },
                ..TlsConfig::default()
            },
            ..Config::default()
        }
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            let path = unique_temp_path(name);
            fs::create_dir(&path).expect("create test directory");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn file(&self, name: &str, mode: u32) -> PathBuf {
            let path = safe_child_path(&self.path, name);
            fs::write(&path, "test").expect("write test file");
            set_mode(&path, mode);
            path
        }

        fn dir(&self, name: &str, mode: u32) -> PathBuf {
            let path = safe_child_path(&self.path, name);
            fs::create_dir(&path).expect("create child directory");
            set_mode(&path, mode);
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
    }

    #[cfg(not(unix))]
    fn set_mode(_path: &Path, _mode: u32) {}
}

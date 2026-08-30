use std::fs;
use std::io;
use std::path::Path;

use crate::config::{AcmeConfig, Config, StaticCertificateConfig};

use super::{ACME_STORAGE_MODE, PRIVATE_KEY_MODE, TlsStorageCheck, TlsStorageIssue};

#[path = "tls_storage_permissions.rs"]
mod permissions;
use permissions::{
    validate_acme_eab_secret_permissions, validate_acme_storage_permissions,
    validate_certificate_permissions, validate_key_permissions,
};

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
                Ok(_) => validate_certificate_permissions(scope, &certificate.cert_path, issues),
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
    fluxheim_config::config_path::path_existing_prefix_contains_symlink(path)
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
    // Preserve the more precise symlink diagnostic below; the full-chain
    // permission helper also treats symlink components as untrusted.
    if path_contains_symlink(path)? {
        return Ok(false);
    }
    fluxheim_config::fs_trust::existing_parent_has_insecure_write_permissions(path)
}

fn symlink_inspection_error(error: io::Error) -> String {
    format!(
        "failed to inspect path for symlinks: {}",
        error_message(error)
    )
}

fn error_message(error: io::Error) -> String {
    error.to_string()
}

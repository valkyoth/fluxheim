use std::fs;
#[cfg(windows)]
use std::io;
use std::path::Path;

use super::TlsStorageIssue;
#[cfg(windows)]
use super::error_message;
#[cfg(unix)]
use super::{secure_acme_storage_mode, secure_private_key_mode};

#[cfg(unix)]
pub(super) fn validate_certificate_permissions(
    _scope: &str,
    _path: &Path,
    _issues: &mut Vec<TlsStorageIssue>,
) {
}

#[cfg(windows)]
pub(super) fn validate_certificate_permissions(
    scope: &str,
    path: &Path,
    issues: &mut Vec<TlsStorageIssue>,
) {
    match fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(path) {
        Ok(true) => issues.push(TlsStorageIssue::CertificatePathHasUntrustedWindowsAcl {
            scope: scope.to_owned(),
            path: path.to_path_buf(),
        }),
        Ok(false) => {}
        Err(error) => issues.push(TlsStorageIssue::CertificateReadFailed {
            scope: scope.to_owned(),
            path: path.to_path_buf(),
            message: error_message(error),
        }),
    }
}

#[cfg(unix)]
pub(super) fn validate_key_permissions(
    scope: &str,
    path: &Path,
    metadata: &fs::Metadata,
    issues: &mut Vec<TlsStorageIssue>,
) {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
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

#[cfg(windows)]
pub(super) fn validate_key_permissions(
    scope: &str,
    path: &Path,
    _metadata: &fs::Metadata,
    issues: &mut Vec<TlsStorageIssue>,
) {
    match windows_confidential_file_is_insecure(path) {
        Ok(true) => issues.push(TlsStorageIssue::PrivateKeyPathHasUntrustedWindowsAcl {
            scope: scope.to_owned(),
            path: path.to_path_buf(),
        }),
        Ok(false) => {}
        Err(error) => issues.push(TlsStorageIssue::PrivateKeyReadFailed {
            scope: scope.to_owned(),
            path: path.to_path_buf(),
            message: error_message(error),
        }),
    }
}

#[cfg(unix)]
pub(super) fn validate_acme_storage_permissions(
    path: &Path,
    metadata: &fs::Metadata,
    issues: &mut Vec<TlsStorageIssue>,
) {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
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

#[cfg(windows)]
pub(super) fn validate_acme_storage_permissions(
    path: &Path,
    _metadata: &fs::Metadata,
    issues: &mut Vec<TlsStorageIssue>,
) {
    match fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(path) {
        Ok(true) => issues.push(TlsStorageIssue::AcmeStoragePathHasUntrustedWindowsAcl {
            path: path.to_path_buf(),
        }),
        Ok(false) => {}
        Err(error) => issues.push(TlsStorageIssue::AcmeStorageReadFailed {
            path: path.to_path_buf(),
            message: error_message(error),
        }),
    }
}

#[cfg(unix)]
pub(super) fn validate_acme_eab_secret_permissions(
    issuer: &str,
    field: &'static str,
    path: &Path,
    metadata: &fs::Metadata,
    issues: &mut Vec<TlsStorageIssue>,
) {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
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

#[cfg(windows)]
pub(super) fn validate_acme_eab_secret_permissions(
    issuer: &str,
    field: &'static str,
    path: &Path,
    _metadata: &fs::Metadata,
    issues: &mut Vec<TlsStorageIssue>,
) {
    match windows_confidential_file_is_insecure(path) {
        Ok(true) => issues.push(TlsStorageIssue::AcmeEabSecretPathHasUntrustedWindowsAcl {
            issuer: issuer.to_owned(),
            field,
            path: path.to_path_buf(),
        }),
        Ok(false) => {}
        Err(error) => issues.push(TlsStorageIssue::AcmeEabSecretReadFailed {
            issuer: issuer.to_owned(),
            field,
            path: path.to_path_buf(),
            message: error_message(error),
        }),
    }
}

#[cfg(windows)]
fn windows_confidential_file_is_insecure(path: &Path) -> io::Result<bool> {
    if fluxheim_config::fs_trust::existing_path_or_parent_has_insecure_write_permissions(path)? {
        return Ok(true);
    }
    match fluxheim_config::fs_trust::open_confidential_file(path) {
        Ok(file) => {
            drop(file);
            Ok(false)
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(true),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn current_effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

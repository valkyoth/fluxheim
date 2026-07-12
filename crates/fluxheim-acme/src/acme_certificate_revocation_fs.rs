use super::fs_ops::{CertificateDirectoryFd, certificate_file_name_in_directory};
use super::*;

pub(super) fn ensure_existing_regular_file(
    directory: &Path,
    path: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    if certificate_file_exists_regular(directory, path, directory_fd)? {
        Ok(())
    } else {
        Err(AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error: io::Error::new(io::ErrorKind::NotFound, "managed certificate is missing"),
        })
    }
}

pub(super) fn certificate_file_exists_regular(
    directory: &Path,
    path: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<bool, AcmeCertificateInstallError> {
    #[cfg(unix)]
    if let Some(directory_fd) = directory_fd {
        let name = certificate_file_name_in_directory(directory, path)?;
        return match rustix::fs::statat(directory_fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() => Ok(true),
            Ok(_) => Err(AcmeCertificateInstallError::UnsafePath {
                path: path.to_path_buf(),
                message: "managed certificate path is not a regular file".to_owned(),
            }),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(false),
            Err(error) => Err(AcmeCertificateInstallError::Io {
                path: path.to_path_buf(),
                error: error.into(),
            }),
        };
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: "managed certificate path is not a regular file".to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        }),
    }
}

pub(super) fn ensure_certificate_slot_absent(
    directory: &Path,
    path: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    if certificate_file_exists_regular(directory, path, directory_fd)? {
        Err(AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: "managed certificate destination unexpectedly exists".to_owned(),
        })
    } else {
        Ok(())
    }
}

pub(crate) fn revocation_file_names_valid(
    transaction: &str,
    certificate_name: &str,
    private_key_name: &str,
) -> bool {
    transaction.len() == 32
        && transaction.bytes().all(|byte| byte.is_ascii_hexdigit())
        && certificate_name == format!(".revoked-{transaction}-fullchain.pem")
        && private_key_name == format!(".revoked-{transaction}-privkey.pem")
}

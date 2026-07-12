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

#[cfg(feature = "acme-client")]
pub(super) fn read_bounded_regular_file(
    directory: &Path,
    path: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
    max_bytes: usize,
) -> Result<Vec<u8>, AcmeCertificateInstallError> {
    #[cfg(unix)]
    let mut file = {
        let directory_fd = directory_fd.ok_or_else(|| AcmeCertificateInstallError::UnsafePath {
            path: directory.to_path_buf(),
            message: "managed certificate directory fd is unavailable".to_owned(),
        })?;
        let name = certificate_file_name_in_directory(directory, path)?;
        let fd = rustix::fs::openat(
            directory_fd,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error: error.into(),
        })?;
        fs::File::from(fd)
    };
    #[cfg(not(unix))]
    let mut file = {
        ensure_existing_regular_file(directory, path, directory_fd)?;
        fs::OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|error| AcmeCertificateInstallError::Io {
                path: path.to_path_buf(),
                error,
            })?
    };
    let metadata = file
        .metadata()
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        })?;
    if !metadata.is_file() {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: "managed certificate is not a regular file".to_owned(),
        });
    }
    if metadata.len() > max_bytes as u64 {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: format!("managed certificate exceeds {max_bytes} bytes"),
        });
    }
    let admitted =
        usize::try_from(metadata.len()).map_err(|_| AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: format!("managed certificate exceeds {max_bytes} bytes"),
        })?;
    let mut bytes = vec![0_u8; admitted];
    file.read_exact(&mut bytes)
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        })?;
    let mut growth_probe = [0_u8; 1];
    if file
        .read(&mut growth_probe)
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        })?
        != 0
    {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: format!("managed certificate exceeds {max_bytes} bytes"),
        });
    }
    Ok(bytes)
}

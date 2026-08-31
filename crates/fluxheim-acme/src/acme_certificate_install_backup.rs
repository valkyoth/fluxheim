use super::super::*;
use super::fs_ops::CertificateDirectoryFd;
#[cfg(unix)]
use super::fs_ops::certificate_file_name_in_directory;
#[cfg(not(windows))]
use super::fs_ops::certificate_metadata_is_link;

pub(super) fn backup_existing_file(
    directory: &Path,
    path: &Path,
    backup: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<bool, AcmeCertificateInstallError> {
    #[cfg(not(unix))]
    let _ = (directory, directory_fd);
    #[cfg(unix)]
    if let Some(directory_fd) = directory_fd {
        let path_name = certificate_file_name_in_directory(directory, path)?;
        let backup_name = certificate_file_name_in_directory(directory, backup)?;
        match rustix::fs::statat(
            directory_fd,
            path_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() => {
                return Err(AcmeCertificateInstallError::UnsafePath {
                    path: path.to_path_buf(),
                    message: "destination is not a real file".to_owned(),
                });
            }
            Ok(_) => {
                ensure_backup_slot_is_empty(directory, backup, Some(directory_fd))?;
                rustix::fs::linkat(
                    directory_fd,
                    path_name,
                    directory_fd,
                    backup_name,
                    rustix::fs::AtFlags::empty(),
                )
                .map_err(|error| AcmeCertificateInstallError::Io {
                    path: backup.to_path_buf(),
                    error: error.into(),
                })?;
                return Ok(true);
            }
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(false),
            Err(error) => {
                return Err(AcmeCertificateInstallError::Io {
                    path: path.to_path_buf(),
                    error: error.into(),
                });
            }
        }
    }

    #[cfg(windows)]
    {
        match fluxheim_windows_security::open_existing_regular_file(path, false) {
            Ok(file) => drop(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(AcmeCertificateInstallError::Io {
                    path: path.to_path_buf(),
                    error,
                });
            }
        }
        fluxheim_windows_security::create_hard_link_regular_file(path, backup).map_err(
            |error| AcmeCertificateInstallError::Io {
                path: backup.to_path_buf(),
                error,
            },
        )?;
        Ok(true)
    }

    #[cfg(not(windows))]
    match fs::symlink_metadata(path) {
        Ok(metadata) if certificate_metadata_is_link(&metadata) || !metadata.is_file() => {
            Err(AcmeCertificateInstallError::UnsafePath {
                path: path.to_path_buf(),
                message: "destination is not a real file".to_owned(),
            })
        }
        Ok(_) => {
            ensure_backup_slot_is_empty(directory, backup, None)?;
            fs::hard_link(path, backup).map_err(|error| AcmeCertificateInstallError::Io {
                path: backup.to_path_buf(),
                error,
            })?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        }),
    }
}

#[cfg(not(windows))]
fn ensure_backup_slot_is_empty(
    directory: &Path,
    path: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    #[cfg(not(unix))]
    let _ = (directory, directory_fd);
    #[cfg(unix)]
    if let Some(directory_fd) = directory_fd {
        let name = certificate_file_name_in_directory(directory, path)?;
        return match rustix::fs::statat(directory_fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Err(AcmeCertificateInstallError::UnsafePath {
                path: path.to_path_buf(),
                message: "backup path already exists".to_owned(),
            }),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(error) => Err(AcmeCertificateInstallError::Io {
                path: path.to_path_buf(),
                error: error.into(),
            }),
        };
    }

    #[cfg(windows)]
    return match fluxheim_windows_security::open_existing_regular_file(path, false) {
        Ok(file) => {
            drop(file);
            Err(AcmeCertificateInstallError::UnsafePath {
                path: path.to_path_buf(),
                message: "backup path already exists".to_owned(),
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        }),
    };

    #[cfg(not(windows))]
    match fs::symlink_metadata(path) {
        Ok(_) => Err(AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: "backup path already exists".to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        }),
    }
}

pub(super) fn cleanup_backup(
    directory: &Path,
    path: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    #[cfg(not(unix))]
    let _ = (directory, directory_fd);
    #[cfg(unix)]
    if let Some(directory_fd) = directory_fd {
        let name = certificate_file_name_in_directory(directory, path)?;
        return match rustix::fs::unlinkat(directory_fd, name, rustix::fs::AtFlags::empty()) {
            Ok(()) => Ok(()),
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(error) => Err(AcmeCertificateInstallError::Io {
                path: path.to_path_buf(),
                error: error.into(),
            }),
        };
    }

    #[cfg(windows)]
    return match fluxheim_windows_security::remove_regular_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        }),
    };

    #[cfg(not(windows))]
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        }),
    }
}

pub(super) fn restore_backup(
    directory: &Path,
    backup: &Path,
    destination: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> io::Result<()> {
    #[cfg(not(unix))]
    let _ = (directory, directory_fd);
    #[cfg(unix)]
    if let Some(directory_fd) = directory_fd {
        let backup_name = certificate_file_name_in_directory(directory, backup)
            .map_err(acme_install_error_to_io_error)?;
        let destination_name = certificate_file_name_in_directory(directory, destination)
            .map_err(acme_install_error_to_io_error)?;
        return match rustix::fs::statat(
            directory_fd,
            backup_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(stat) if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file() => Err(
                io::Error::new(io::ErrorKind::InvalidData, "backup is not a regular file"),
            ),
            Ok(_) => {
                rustix::fs::renameat(directory_fd, backup_name, directory_fd, destination_name)
                    .map_err(Into::into)
            }
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(error) => Err(error.into()),
        };
    }

    #[cfg(windows)]
    return match fluxheim_windows_security::rename_regular_file(backup, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    };

    #[cfg(not(windows))]
    match fs::symlink_metadata(backup) {
        Ok(metadata) if certificate_metadata_is_link(&metadata) || !metadata.is_file() => Err(
            io::Error::new(io::ErrorKind::InvalidData, "backup is not a regular file"),
        ),
        Ok(_) => fs::rename(backup, destination),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn acme_install_error_to_io_error(error: AcmeCertificateInstallError) -> io::Error {
    match error {
        AcmeCertificateInstallError::Io { error, .. } => error,
        other => io::Error::new(io::ErrorKind::InvalidInput, other.to_string()),
    }
}

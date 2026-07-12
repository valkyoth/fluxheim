use super::super::*;

#[cfg(unix)]
pub(super) type CertificateDirectoryFd = rustix::fd::OwnedFd;

#[cfg(not(unix))]
pub(super) type CertificateDirectoryFd = ();

pub(super) fn certificate_directory(
    paths: &AcmeCertificatePaths,
) -> Result<PathBuf, AcmeCertificateInstallError> {
    let Some(cert_parent) = paths.cert_path.parent() else {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: paths.cert_path.clone(),
            message: "certificate path has no parent directory".to_owned(),
        });
    };
    let Some(key_parent) = paths.key_path.parent() else {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: paths.key_path.clone(),
            message: "private-key path has no parent directory".to_owned(),
        });
    };
    if cert_parent != key_parent {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: paths.key_path.clone(),
            message: "certificate and private key must share a directory".to_owned(),
        });
    }

    Ok(cert_parent.to_path_buf())
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnixFileOwner {
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
pub(crate) type ManagedCertificateOwner = Option<UnixFileOwner>;

#[cfg(not(unix))]
pub(crate) type ManagedCertificateOwner = ();

#[derive(Debug)]
pub(crate) struct ManagedCertificateOwnership {
    #[cfg(unix)]
    owner: ManagedCertificateOwner,
    #[cfg(unix)]
    boundary: Option<PathBuf>,
    #[cfg(unix)]
    boundary_directory: Option<rustix::fd::OwnedFd>,
}

impl ManagedCertificateOwnership {
    pub(crate) fn file_owner(&self) -> ManagedCertificateOwner {
        #[cfg(unix)]
        {
            self.owner
        }
        #[cfg(not(unix))]
        {}
    }
}

#[cfg(unix)]
pub(crate) fn managed_certificate_ownership(
    storage: &Path,
) -> Result<ManagedCertificateOwnership, AcmeCertificateInstallError> {
    if !rustix::process::geteuid().is_root() {
        return Ok(ManagedCertificateOwnership {
            owner: None,
            boundary: None,
            boundary_directory: None,
        });
    }

    let mut current = storage;
    loop {
        match fs::symlink_metadata(current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AcmeCertificateInstallError::UnsafePath {
                    path: current.to_path_buf(),
                    message: "path contains a symlink".to_owned(),
                });
            }
            Ok(_) => {
                let boundary_directory = crate::acme_directory::open_directory_no_symlinks(current)
                    .map_err(|error| AcmeCertificateInstallError::Io {
                        path: current.to_path_buf(),
                        error,
                    })?;
                let metadata = rustix::fs::fstat(&boundary_directory).map_err(|error| {
                    AcmeCertificateInstallError::Io {
                        path: current.to_path_buf(),
                        error: error.into(),
                    }
                })?;
                return Ok(ManagedCertificateOwnership {
                    owner: Some(UnixFileOwner {
                        uid: metadata.st_uid,
                        gid: metadata.st_gid,
                    }),
                    boundary: Some(current.to_path_buf()),
                    boundary_directory: Some(boundary_directory),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let Some(parent) = current.parent() else {
                    return Ok(ManagedCertificateOwnership {
                        owner: None,
                        boundary: None,
                        boundary_directory: None,
                    });
                };
                current = parent;
            }
            Err(error) => {
                return Err(AcmeCertificateInstallError::Io {
                    path: current.to_path_buf(),
                    error,
                });
            }
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn managed_certificate_ownership(
    _storage: &Path,
) -> Result<ManagedCertificateOwnership, AcmeCertificateInstallError> {
    Ok(ManagedCertificateOwnership {})
}

#[cfg(feature = "acme-client")]
pub(crate) fn managed_certificate_owner(
    storage: &Path,
) -> Result<ManagedCertificateOwner, AcmeCertificateInstallError> {
    managed_certificate_ownership(storage).map(|ownership| ownership.file_owner())
}

pub(super) fn ensure_safe_directory(
    directory: &Path,
    ownership: &ManagedCertificateOwnership,
) -> Result<(), AcmeCertificateInstallError> {
    #[cfg(unix)]
    {
        let directory_fd = match (
            ownership.owner,
            ownership.boundary.as_deref(),
            ownership.boundary_directory.as_ref(),
        ) {
            (Some(owner), Some(boundary), Some(boundary_directory)) => {
                crate::acme_directory::reconcile_private_directory_subtree(
                    boundary,
                    boundary_directory,
                    directory,
                    (owner.uid, owner.gid),
                )
            }
            (None, None, None) => crate::acme_directory::create_private_directory_all(directory),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ACME managed directory ownership plan is incomplete",
            )),
        }
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: directory.to_path_buf(),
            error,
        })?;
        rustix::fs::fchmod(
            &directory_fd,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
        )
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: directory.to_path_buf(),
            error: error.into(),
        })?;
        let directory_file = fs::File::from(directory_fd);
        apply_owner_to_file(&directory_file, directory, ownership.file_owner())?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        reject_existing_symlink_in_path(directory)?;
        fs::create_dir_all(directory).map_err(|error| AcmeCertificateInstallError::Io {
            path: directory.to_path_buf(),
            error,
        })?;
        apply_owner_to_path(directory, ownership.file_owner())?;
        reject_existing_symlink_in_path(directory)?;
        let metadata =
            fs::symlink_metadata(directory).map_err(|error| AcmeCertificateInstallError::Io {
                path: directory.to_path_buf(),
                error,
            })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AcmeCertificateInstallError::UnsafePath {
                path: directory.to_path_buf(),
                message: "path is not a real directory".to_owned(),
            });
        }

        Ok(())
    }
}

#[cfg(not(unix))]
fn apply_owner_to_path(
    _path: &Path,
    _owner: ManagedCertificateOwner,
) -> Result<(), AcmeCertificateInstallError> {
    Ok(())
}

#[cfg(unix)]
fn apply_owner_to_file(
    file: &fs::File,
    path: &Path,
    owner: ManagedCertificateOwner,
) -> Result<(), AcmeCertificateInstallError> {
    let Some(owner) = owner else {
        return Ok(());
    };

    rustix::fs::fchown(
        file,
        Some(rustix::fs::Uid::from_raw(owner.uid)),
        Some(rustix::fs::Gid::from_raw(owner.gid)),
    )
    .map_err(|error| AcmeCertificateInstallError::Io {
        path: path.to_path_buf(),
        error: error.into(),
    })
}

#[cfg(not(unix))]
fn apply_owner_to_file(
    _file: &fs::File,
    _path: &Path,
    _owner: ManagedCertificateOwner,
) -> Result<(), AcmeCertificateInstallError> {
    Ok(())
}

pub(super) fn ensure_safe_destination(path: &Path) -> Result<(), AcmeCertificateInstallError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(AcmeCertificateInstallError::UnsafePath {
                path: path.to_path_buf(),
                message: "destination is not a real file".to_owned(),
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        }),
    }
}

#[cfg(not(unix))]
pub(crate) fn reject_existing_symlink_in_path(
    path: &Path,
) -> Result<(), AcmeCertificateInstallError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AcmeCertificateInstallError::UnsafePath {
                    path: current,
                    message: "path contains a symlink".to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(AcmeCertificateInstallError::Io {
                    path: current,
                    error,
                });
            }
        }
    }

    Ok(())
}

pub(super) fn write_new_file(
    directory: &Path,
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: ManagedCertificateOwner,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    #[cfg(unix)]
    if let Some(directory_fd) = directory_fd {
        let name = certificate_file_name_in_directory(directory, path)?;
        let raw_mode = certificate_file_raw_mode(path, mode)?;
        let fd = rustix::fs::openat(
            directory_fd,
            name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(raw_mode),
        )
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error: error.into(),
        })?;
        let mut file = fs::File::from(fd);
        apply_owner_to_file(&file, path, owner)?;
        file.write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(|error| AcmeCertificateInstallError::Io {
                path: path.to_path_buf(),
                error,
            })?;
        return Ok(());
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
        options.custom_flags(UNIX_O_NOFOLLOW);
    }

    let mut file = options
        .open(path)
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        })?;
    apply_owner_to_file(&file, path, owner)?;
    file.write_all(contents)
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        })?;
    file.sync_all()
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        })
}

#[cfg(all(unix, target_os = "macos"))]
fn certificate_file_raw_mode(
    path: &Path,
    mode: u32,
) -> Result<rustix::fs::RawMode, AcmeCertificateInstallError> {
    mode.try_into()
        .map_err(|_| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error: io::Error::new(
                io::ErrorKind::InvalidInput,
                "certificate file mode is unsupported on this platform",
            ),
        })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn certificate_file_raw_mode(
    _path: &Path,
    mode: u32,
) -> Result<rustix::fs::RawMode, AcmeCertificateInstallError> {
    Ok(mode)
}

#[cfg(unix)]
pub(super) fn open_safe_certificate_directory(
    directory: &Path,
) -> Result<rustix::fd::OwnedFd, AcmeCertificateInstallError> {
    crate::acme_directory::open_directory_no_symlinks(directory).map_err(|error| {
        AcmeCertificateInstallError::Io {
            path: directory.to_path_buf(),
            error,
        }
    })
}

#[cfg(unix)]
pub(super) fn certificate_file_name_in_directory<'a>(
    directory: &Path,
    path: &'a Path,
) -> Result<&'a str, AcmeCertificateInstallError> {
    if path.parent() != Some(directory) {
        return Err(AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: "certificate file operation must stay within managed directory".to_owned(),
        });
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .ok_or_else(|| AcmeCertificateInstallError::UnsafePath {
            path: path.to_path_buf(),
            message: "certificate path must end in a safe file name".to_owned(),
        })
}

pub(super) fn rename_certificate_file(
    directory: &Path,
    source: &Path,
    destination: &Path,
    #[cfg_attr(not(unix), allow(unused_variables))] directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    #[cfg(unix)]
    {
        let directory_fd = directory_fd.ok_or_else(|| AcmeCertificateInstallError::UnsafePath {
            path: directory.to_path_buf(),
            message: "managed certificate directory fd is unavailable".to_owned(),
        })?;
        let source_name = certificate_file_name_in_directory(directory, source)?;
        let destination_name = certificate_file_name_in_directory(directory, destination)?;
        rustix::fs::renameat(directory_fd, source_name, directory_fd, destination_name).map_err(
            |error| AcmeCertificateInstallError::Io {
                path: destination.to_path_buf(),
                error: error.into(),
            },
        )
    }

    #[cfg(not(unix))]
    {
        fs::rename(source, destination).map_err(|error| AcmeCertificateInstallError::Io {
            path: destination.to_path_buf(),
            error,
        })
    }
}

pub(super) fn sync_directory(
    path: &Path,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    #[cfg(unix)]
    if let Some(directory_fd) = directory_fd {
        return rustix::fs::fsync(directory_fd).map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error: error.into(),
        });
    }

    let directory = fs::File::open(path).map_err(|error| AcmeCertificateInstallError::Io {
        path: path.to_path_buf(),
        error,
    })?;
    directory
        .sync_all()
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        })
}

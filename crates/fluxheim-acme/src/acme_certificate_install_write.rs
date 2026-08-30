use super::super::*;
#[cfg(unix)]
use super::certificate_file_name_in_directory;
use super::{CertificateDirectoryFd, ManagedCertificateOwner, apply_owner_to_file};

#[cfg(windows)]
pub(crate) fn certificate_metadata_is_link(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
}

#[cfg(not(windows))]
pub(crate) fn certificate_metadata_is_link(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

pub(crate) fn write_new_file(
    directory: &Path,
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: ManagedCertificateOwner,
    directory_fd: Option<&CertificateDirectoryFd>,
) -> Result<(), AcmeCertificateInstallError> {
    #[cfg(not(unix))]
    let _ = (directory, mode, directory_fd);
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
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
        options.custom_flags(UNIX_O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|error| AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        })?;
    #[cfg(windows)]
    fluxheim_config::fs_trust::harden_confidential_file(&mut file).map_err(|error| {
        AcmeCertificateInstallError::Io {
            path: path.to_path_buf(),
            error,
        }
    })?;
    apply_owner_to_file(&file, path, owner)?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
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

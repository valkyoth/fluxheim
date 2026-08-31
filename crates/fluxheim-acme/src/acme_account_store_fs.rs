use std::fs;
use std::io::{self, Write as _};
use std::path::Path;
#[cfg(not(unix))]
use std::path::PathBuf;

use super::AcmeAccountStoreError;
#[cfg(target_os = "linux")]
use super::UNIX_O_NOFOLLOW;

#[cfg(not(unix))]
pub(super) fn reject_existing_symlink_in_account_path(
    path: &Path,
) -> Result<(), AcmeAccountStoreError> {
    use std::path::Component;

    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::CurDir
        ) {
            continue;
        }
        if matches!(component, Component::ParentDir) {
            return Err(AcmeAccountStoreError::UnsafePath {
                path: current,
                message: "path contains parent traversal".to_owned(),
            });
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if account_metadata_is_link(&metadata) => {
                return Err(AcmeAccountStoreError::UnsafePath {
                    path: current,
                    message: "path contains a link or reparse point".to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(account_store_io_error(&current, error)),
        }
    }
    Ok(())
}

#[cfg(all(not(unix), windows))]
fn account_metadata_is_link(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
}

#[cfg(all(not(unix), not(windows)))]
fn account_metadata_is_link(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

pub(super) fn write_account_credentials_file(
    path: &Path,
    contents: &[u8],
) -> Result<(), AcmeAccountStoreError> {
    #[cfg(windows)]
    let mut file = fluxheim_config::fs_trust::create_confidential_file(path)
        .map_err(|error| account_store_io_error(path, error))?;
    #[cfg(not(windows))]
    let mut file = {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options
            .open(path)
            .map_err(|error| account_store_io_error(path, error))?
    };
    file.write_all(contents)
        .map_err(|error| account_store_io_error(path, error))?;
    file.sync_all()
        .map_err(|error| account_store_io_error(path, error))
}

pub(super) fn sync_account_directory(path: &Path) -> Result<(), AcmeAccountStoreError> {
    crate::sync_directory_io(path).map_err(|error| account_store_io_error(path, error))
}

#[cfg(target_os = "linux")]
pub(super) fn open_regular_account_credentials_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(UNIX_O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
pub(super) fn open_regular_account_credentials_file(path: &Path) -> io::Result<std::fs::File> {
    fluxheim_config::fs_trust::open_confidential_file(path)
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
pub(super) fn open_regular_account_credentials_file(path: &Path) -> io::Result<std::fs::File> {
    std::fs::File::open(path)
}

pub(super) fn account_store_io_error(path: &Path, error: io::Error) -> AcmeAccountStoreError {
    AcmeAccountStoreError::Io {
        path: path.to_path_buf(),
        error,
    }
}

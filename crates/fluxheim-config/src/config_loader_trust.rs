use std::fs::Metadata;
use std::path::Path;

use super::ConfigLoadError;

pub(super) fn ensure_trusted_config_path(path: &Path) -> Result<(), ConfigLoadError> {
    match crate::fs_trust::existing_path_or_parent_has_insecure_write_permissions(path) {
        Ok(false) => Ok(()),
        Ok(true) => Err(ConfigLoadError::Read(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "config source has an untrusted owner, symlink, or writable component: {}",
                path.display()
            ),
        ))),
        Err(error) => Err(ConfigLoadError::Read(error)),
    }
}

pub(super) fn ensure_trusted_opened_config_file(
    metadata: &Metadata,
    path: &Path,
) -> Result<(), ConfigLoadError> {
    if crate::fs_trust::metadata_has_insecure_owner_or_write_permissions(metadata)
        .map_err(ConfigLoadError::Read)?
    {
        return Err(ConfigLoadError::Read(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("opened config file is not trusted: {}", path.display()),
        )));
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn same_config_file(path_metadata: &Metadata, opened_metadata: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    path_metadata.dev() == opened_metadata.dev() && path_metadata.ino() == opened_metadata.ino()
}

#[cfg(not(unix))]
pub(super) fn same_config_file(path_metadata: &Metadata, opened_metadata: &Metadata) -> bool {
    path_metadata.len() == opened_metadata.len()
        && path_metadata.modified().ok() == opened_metadata.modified().ok()
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ConfigFileState {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    change_seconds: i64,
    #[cfg(unix)]
    change_nanoseconds: i64,
}

impl ConfigFileState {
    pub(super) fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;

        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            change_seconds: metadata.ctime(),
            #[cfg(unix)]
            change_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::same_config_file;

    #[test]
    fn descriptor_identity_rejects_replaced_config_file() {
        let first = fluxheim_common::test_support::unique_temp_path("config-identity-first");
        let second = fluxheim_common::test_support::unique_temp_path("config-identity-second");
        std::fs::write(&first, "[server]\n").unwrap();
        std::fs::write(&second, "[server]\n").unwrap();

        let first_metadata = std::fs::symlink_metadata(&first).unwrap();
        let second_metadata = std::fs::File::open(&second).unwrap().metadata().unwrap();

        assert!(!same_config_file(&first_metadata, &second_metadata));
    }
}

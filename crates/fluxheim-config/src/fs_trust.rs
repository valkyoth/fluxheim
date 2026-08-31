#[cfg(not(windows))]
use std::path::Path;

#[cfg(unix)]
const MAX_PERMISSION_INSPECTION_DEPTH: usize = 256;

#[cfg(windows)]
#[path = "fs_trust_windows.rs"]
mod windows;
#[cfg(windows)]
pub use windows::{
    create_confidential_file, create_private_directory_all, harden_confidential_file,
    harden_private_directory, open_confidential_file, open_or_create_confidential_file,
    open_regular_file, opened_file_has_insecure_confidential_permissions,
    opened_file_has_insecure_owner_or_write_permissions, sync_directory,
};
#[cfg(windows)]
pub use windows::{
    existing_parent_has_insecure_write_permissions,
    existing_path_or_parent_has_insecure_write_permissions,
};

#[cfg(unix)]
pub fn existing_parent_has_insecure_write_permissions(path: &Path) -> std::io::Result<bool> {
    let current = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    existing_path_has_insecure_write_permissions(&current)
}

#[cfg(not(any(unix, windows)))]
pub fn existing_parent_has_insecure_write_permissions(_path: &Path) -> std::io::Result<bool> {
    Err(unsupported_filesystem_trust_error())
}

#[cfg(unix)]
pub fn existing_path_or_parent_has_insecure_write_permissions(
    path: &Path,
) -> std::io::Result<bool> {
    existing_path_has_insecure_write_permissions(path)
}

#[cfg(not(any(unix, windows)))]
pub fn existing_path_or_parent_has_insecure_write_permissions(
    _path: &Path,
) -> std::io::Result<bool> {
    Err(unsupported_filesystem_trust_error())
}

#[cfg(unix)]
fn existing_path_has_insecure_write_permissions(current: &Path) -> std::io::Result<bool> {
    let mut current = if current.is_absolute() {
        current.to_path_buf()
    } else {
        std::env::current_dir()?.join(current)
    };

    let mut inspected_depth = 0usize;
    loop {
        check_inspection_depth(&mut inspected_depth)?;
        match path_stat_no_follow(&current) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !current.pop() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "path has no existing ancestor",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }

    let process_uid = rustix::process::geteuid().as_raw();
    let root_uid = path_stat_no_follow(Path::new("/"))?.st_uid;
    loop {
        check_inspection_depth(&mut inspected_depth)?;
        let stat = path_stat_no_follow(&current)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_symlink()
            || stat_has_insecure_owner_or_write_permissions(&stat, process_uid, root_uid)
        {
            return Ok(true);
        }
        if !current.pop() {
            return Ok(false);
        }
    }
}

#[cfg(unix)]
fn path_stat_no_follow(path: &Path) -> std::io::Result<rustix::fs::Stat> {
    rustix::fs::statat(rustix::fs::CWD, path, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(std::io::Error::from)
}

#[cfg(unix)]
fn stat_has_insecure_owner_or_write_permissions(
    stat: &rustix::fs::Stat,
    process_uid: u32,
    root_uid: u32,
) -> bool {
    (stat.st_uid != 0 && stat.st_uid != process_uid && stat.st_uid != root_uid)
        || stat.st_mode & 0o022 != 0
}

#[cfg(unix)]
pub fn opened_file_has_insecure_owner_or_write_permissions(
    file: &std::fs::File,
) -> std::io::Result<bool> {
    let metadata = file.metadata()?;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let process_uid = rustix::process::geteuid().as_raw();
    let root_uid = path_stat_no_follow(Path::new("/"))?.st_uid;
    Ok(
        (metadata.uid() != 0 && metadata.uid() != process_uid && metadata.uid() != root_uid)
            || metadata.permissions().mode() & 0o022 != 0,
    )
}

#[cfg(unix)]
pub fn opened_file_has_insecure_confidential_permissions(
    file: &std::fs::File,
) -> std::io::Result<bool> {
    let metadata = file.metadata()?;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let process_uid = rustix::process::geteuid().as_raw();
    let root_uid = path_stat_no_follow(Path::new("/"))?.st_uid;
    Ok(
        (metadata.uid() != 0 && metadata.uid() != process_uid && metadata.uid() != root_uid)
            || metadata.permissions().mode() & 0o077 != 0,
    )
}

#[cfg(not(any(unix, windows)))]
pub fn opened_file_has_insecure_owner_or_write_permissions(
    _file: &std::fs::File,
) -> std::io::Result<bool> {
    Err(unsupported_filesystem_trust_error())
}

#[cfg(not(any(unix, windows)))]
pub fn opened_file_has_insecure_confidential_permissions(
    _file: &std::fs::File,
) -> std::io::Result<bool> {
    Err(unsupported_filesystem_trust_error())
}

#[cfg(not(any(unix, windows)))]
fn unsupported_filesystem_trust_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "filesystem ownership and ACL trust checks are not implemented for this platform",
    )
}

#[cfg(unix)]
fn check_inspection_depth(inspected_depth: &mut usize) -> std::io::Result<()> {
    *inspected_depth = inspected_depth.saturating_add(1);
    if *inspected_depth > MAX_PERMISSION_INSPECTION_DEPTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path exceeds maximum depth for permission inspection",
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::existing_path_has_insecure_write_permissions;
    use fluxheim_common::test_support::unique_temp_path;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    #[test]
    fn follows_symlinked_path_for_permission_checks() {
        let target = unique_temp_path("fs-trust-world-writable-target");
        let link = unique_temp_path("fs-trust-world-writable-link");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o777)).unwrap();
        symlink(&target, &link).unwrap();

        assert!(existing_path_has_insecure_write_permissions(&link).unwrap());
    }

    #[test]
    fn rejects_writable_higher_ancestor() {
        let ancestor = unique_temp_path("fs-trust-writable-higher-ancestor");
        let leaf = fluxheim_common::test_support::safe_child_path(&ancestor, "safe");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o777)).unwrap();

        assert!(existing_path_has_insecure_write_permissions(&leaf).unwrap());
    }

    #[test]
    fn rejects_excessive_path_depth_for_permission_checks() {
        let mut current = PathBuf::from("missing-root");
        for _ in 0..=super::MAX_PERMISSION_INSPECTION_DEPTH {
            current.push("missing");
        }

        let error = existing_path_has_insecure_write_permissions(&current).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}

#[cfg(all(test, not(any(unix, windows))))]
mod non_unix_tests {
    use super::{
        existing_parent_has_insecure_write_permissions,
        existing_path_or_parent_has_insecure_write_permissions,
    };
    use std::path::Path;

    #[test]
    fn filesystem_trust_checks_fail_closed_when_platform_support_is_absent() {
        let path = Path::new("fluxheim.toml");

        for error in [
            existing_parent_has_insecure_write_permissions(path).unwrap_err(),
            existing_path_or_parent_has_insecure_write_permissions(path).unwrap_err(),
        ] {
            assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
            assert!(
                error
                    .to_string()
                    .contains("filesystem ownership and ACL trust checks")
            );
        }
    }
}

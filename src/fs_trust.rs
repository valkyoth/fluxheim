use std::path::Path;

#[cfg(unix)]
const MAX_PERMISSION_INSPECTION_DEPTH: usize = 256;

#[cfg(not(unix))]
compile_error!(
    "Fluxheim filesystem trust checks require a Unix target; implement platform ACL and ownership checks before enabling non-Unix builds"
);

#[cfg(unix)]
pub(crate) fn existing_parent_has_insecure_write_permissions(path: &Path) -> std::io::Result<bool> {
    let mut current = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    existing_path_has_insecure_write_permissions(&mut current)
}

#[cfg(unix)]
pub(crate) fn existing_path_or_parent_has_insecure_write_permissions(
    path: &Path,
) -> std::io::Result<bool> {
    let mut current = path.to_path_buf();
    existing_path_has_insecure_write_permissions(&mut current)
}

#[cfg(unix)]
fn existing_path_has_insecure_write_permissions(
    current: &mut std::path::PathBuf,
) -> std::io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    let mut inspected_depth = 0usize;
    loop {
        inspected_depth = inspected_depth.saturating_add(1);
        if inspected_depth > MAX_PERMISSION_INSPECTION_DEPTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path exceeds maximum depth for permission inspection",
            ));
        }
        match std::fs::metadata(&current) {
            Ok(metadata) => return Ok(metadata.permissions().mode() & 0o022 != 0),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !current.pop() {
                    return Ok(false);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::existing_path_has_insecure_write_permissions;
    use crate::test_support::unique_temp_path;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    #[test]
    fn follows_symlinked_path_for_permission_checks() {
        let target = unique_temp_path("fs-trust-world-writable-target");
        let link = unique_temp_path("fs-trust-world-writable-link");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o777)).unwrap();
        symlink(&target, &link).unwrap();

        let mut current = link;
        assert!(existing_path_has_insecure_write_permissions(&mut current).unwrap());
    }

    #[test]
    fn rejects_excessive_path_depth_for_permission_checks() {
        let mut current = PathBuf::new();
        for _ in 0..=super::MAX_PERMISSION_INSPECTION_DEPTH {
            current.push("missing");
        }

        let error = existing_path_has_insecure_write_permissions(&mut current).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}

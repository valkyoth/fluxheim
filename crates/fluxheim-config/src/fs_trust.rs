use std::path::Path;

#[cfg(unix)]
const MAX_PERMISSION_INSPECTION_DEPTH: usize = 256;

#[cfg(not(unix))]
compile_error!(
    "Fluxheim filesystem trust checks require a Unix target; implement platform ACL and ownership checks before enabling non-Unix builds"
);

#[cfg(unix)]
pub fn existing_parent_has_insecure_write_permissions(path: &Path) -> std::io::Result<bool> {
    let mut current = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    existing_path_has_insecure_write_permissions(&mut current)
}

#[cfg(unix)]
pub fn existing_path_or_parent_has_insecure_write_permissions(
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

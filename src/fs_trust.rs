use std::path::Path;

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

    loop {
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(false),
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

#[cfg(not(unix))]
pub(crate) fn existing_parent_has_insecure_write_permissions(
    _path: &Path,
) -> std::io::Result<bool> {
    Ok(false)
}

#[cfg(not(unix))]
pub(crate) fn existing_path_or_parent_has_insecure_write_permissions(
    _path: &Path,
) -> std::io::Result<bool> {
    Ok(false)
}

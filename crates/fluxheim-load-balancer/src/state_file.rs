use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use super::LoadBalancerRuntimeStateSnapshot;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NOFOLLOW: i32 = 0o400000;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NOFOLLOW: i32 = 0x0100;

const MAX_RUNTIME_STATE_FILE_BYTES: u64 = 16 * 1024 * 1024;
#[cfg(unix)]
const RUNTIME_STATE_FILE_MODE: u32 = 0o600;

pub(super) fn load_runtime_state_file(
    path: &Path,
) -> io::Result<Option<LoadBalancerRuntimeStateSnapshot>> {
    if !path_exists_without_following_symlinks(path)? {
        return Ok(None);
    }
    let raw = read_regular_file_to_string_with_limit(path, MAX_RUNTIME_STATE_FILE_BYTES)?;
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub(super) fn write_runtime_state_file(
    path: &Path,
    snapshot: &LoadBalancerRuntimeStateSnapshot,
) -> io::Result<()> {
    let raw = serde_json::to_vec_pretty(snapshot)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if raw.len() as u64 > MAX_RUNTIME_STATE_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "load balancer runtime state file exceeds size limit",
        ));
    }
    write_atomically(path, &raw)
}

fn write_atomically(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "load balancer runtime state path has no parent",
        )
    })?;
    require_real_directory(parent)?;
    require_plain_write_destination(path)?;

    let mut temporary = tempfile::Builder::new()
        .prefix(".load-balancer-state.tmp-")
        .tempfile_in(parent)?;
    #[cfg(unix)]
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(RUNTIME_STATE_FILE_MODE))?;
    temporary.write_all(contents)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;

    let persisted = temporary.persist(path).map_err(|error| error.error)?;
    sync_after_persist(&persisted, parent)
}

fn read_regular_file_to_string_with_limit(path: &Path, max_bytes: u64) -> io::Result<String> {
    let file = open_regular_file(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "load balancer runtime state file exceeds size limit",
        ));
    }

    let mut contents = String::new();
    let mut limited = file.take(max_bytes.saturating_add(1));
    limited.read_to_string(&mut contents)?;
    if contents.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "load balancer runtime state file changed while reading and exceeded size limit",
        ));
    }
    Ok(contents)
}

fn open_regular_file(path: &Path) -> io::Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "load balancer runtime state path is not a regular file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "load balancer runtime state path is not a regular file",
        ));
    }
    Ok(file)
}

fn require_real_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "load balancer runtime state parent is not a real directory",
        ));
    }
    Ok(())
}

fn require_plain_write_destination(path: &Path) -> io::Result<()> {
    let Some(metadata) = optional_symlink_metadata(path)? else {
        return Ok(());
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "load balancer runtime state destination is not a regular file",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn sync_after_persist(_file: &File, parent: &Path) -> io::Result<()> {
    let directory = File::open(parent)?;
    directory.sync_all()
}

#[cfg(windows)]
fn sync_after_persist(file: &File, parent: &Path) -> io::Result<()> {
    file.sync_all()?;
    fluxheim_config::fs_trust::sync_directory(parent)
}

fn path_exists_without_following_symlinks(path: &Path) -> io::Result<bool> {
    optional_symlink_metadata(path).map(|metadata| metadata.is_some())
}

fn optional_symlink_metadata(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy;
    use fluxheim_common::test_support::{safe_child_path, unique_temp_path};

    #[test]
    fn runtime_state_file_round_trips_json_snapshot() {
        let dir = unique_temp_path("lb-runtime-state-file");
        std::fs::create_dir_all(&dir).unwrap();
        let path = safe_child_path(&dir, "state.json");
        let snapshot = LoadBalancerRuntimeStateSnapshot {
            version: 1,
            runtime_overrides: policy::RuntimeBackendPolicySnapshot {
                states: Vec::new(),
                weights: Vec::new(),
            },
            persistence: None,
        };

        write_runtime_state_file(&path, &snapshot).unwrap();
        assert_eq!(
            load_runtime_state_file(&path).unwrap().as_ref(),
            Some(&snapshot)
        );

        let replacement = LoadBalancerRuntimeStateSnapshot {
            version: 2,
            runtime_overrides: policy::RuntimeBackendPolicySnapshot {
                states: Vec::new(),
                weights: Vec::new(),
            },
            persistence: None,
        };
        write_runtime_state_file(&path, &replacement).unwrap();
        assert_eq!(
            load_runtime_state_file(&path).unwrap().as_ref(),
            Some(&replacement)
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_state_file_rejects_symlink_destination() {
        let dir = unique_temp_path("lb-runtime-state-symlink");
        std::fs::create_dir_all(&dir).unwrap();
        let outside = safe_child_path(&dir, "outside.json");
        std::fs::write(&outside, "{}").unwrap();
        let link = safe_child_path(&dir, "state.json");
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let snapshot = LoadBalancerRuntimeStateSnapshot {
            version: 1,
            runtime_overrides: policy::RuntimeBackendPolicySnapshot {
                states: Vec::new(),
                weights: Vec::new(),
            },
            persistence: None,
        };

        let error = write_runtime_state_file(&link, &snapshot).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(std::fs::read_to_string(outside).unwrap(), "{}");
    }

    #[cfg(unix)]
    #[test]
    fn runtime_state_file_rejects_symlink_parent() {
        let dir = unique_temp_path("lb-runtime-state-symlink-parent");
        std::fs::create_dir_all(&dir).unwrap();
        let outside = unique_temp_path("lb-runtime-state-outside-parent");
        std::fs::create_dir_all(&outside).unwrap();
        let link = unique_temp_path("lb-runtime-state-linked-parent");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let snapshot = LoadBalancerRuntimeStateSnapshot {
            version: 1,
            runtime_overrides: policy::RuntimeBackendPolicySnapshot {
                states: Vec::new(),
                weights: Vec::new(),
            },
            persistence: None,
        };

        let error = write_runtime_state_file(&link.join("state.json"), &snapshot).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(outside);
    }
}

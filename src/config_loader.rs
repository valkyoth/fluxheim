use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::config::ConfigLoadError;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit symlink-safe config file opening before building Fluxheim"
);

pub(crate) const MAX_CONFIG_DIRECTORY_FILES: usize = 256;
pub(crate) const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

pub(crate) fn canonical_config_source(path: &Path) -> Result<PathBuf, ConfigLoadError> {
    if existing_path_contains_symlink(path).map_err(ConfigLoadError::Read)? {
        return Err(ConfigLoadError::InvalidPath {
            path: path.to_path_buf(),
        });
    }

    let path = path.canonicalize().map_err(ConfigLoadError::Read)?;
    let metadata = fs::symlink_metadata(&path).map_err(ConfigLoadError::Read)?;
    if metadata.file_type().is_symlink() {
        return Err(ConfigLoadError::InvalidPath { path });
    }
    if path.is_dir() || regular_visible_toml_file(&path)? {
        return Ok(path);
    }

    Err(ConfigLoadError::InvalidPath { path })
}

pub(crate) fn toml_files(dir: &Path) -> Result<Vec<PathBuf>, ConfigLoadError> {
    let entries = fs::read_dir(dir).map_err(ConfigLoadError::Read)?;
    let mut files = Vec::new();

    for entry in entries {
        let entry = entry.map_err(ConfigLoadError::Read)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(ConfigLoadError::Read)?;
        if file_type.is_symlink() || !file_type.is_file() {
            continue;
        }
        if is_visible_toml_file(&path) {
            files.push(path);
            if files.len() > MAX_CONFIG_DIRECTORY_FILES {
                return Err(ConfigLoadError::Read(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "config directory {} contains more than {} TOML files",
                        dir.display(),
                        MAX_CONFIG_DIRECTORY_FILES
                    ),
                )));
            }
        }
    }

    Ok(files)
}

pub(crate) fn config_directory_files(dir: &Path) -> Result<Vec<PathBuf>, ConfigLoadError> {
    let mut files = toml_files(dir)?;
    files.sort();

    let conf_dir = dir.join("conf.d");
    if conf_dir.try_exists().map_err(ConfigLoadError::Read)? {
        let metadata = fs::symlink_metadata(&conf_dir).map_err(ConfigLoadError::Read)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ConfigLoadError::InvalidPath { path: conf_dir });
        }

        let mut conf_files = toml_files(&conf_dir)?;
        conf_files.sort();
        files.extend(conf_files);
        if files.len() > MAX_CONFIG_DIRECTORY_FILES {
            return Err(ConfigLoadError::Read(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "config directory {} and conf.d contain more than {} TOML files",
                    dir.display(),
                    MAX_CONFIG_DIRECTORY_FILES
                ),
            )));
        }
    }

    Ok(files)
}

pub(crate) fn regular_visible_toml_file(path: &Path) -> Result<bool, ConfigLoadError> {
    if !is_visible_toml_file(path) {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(path).map_err(ConfigLoadError::Read)?;
    Ok(!metadata.file_type().is_symlink() && metadata.is_file())
}

pub(crate) fn read_regular_config_file_to_string(path: &Path) -> Result<String, ConfigLoadError> {
    let metadata = fs::symlink_metadata(path).map_err(ConfigLoadError::Read)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ConfigLoadError::InvalidPath {
            path: path.to_path_buf(),
        });
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW);

    let file = options.open(path).map_err(ConfigLoadError::Read)?;
    let metadata = file.metadata().map_err(ConfigLoadError::Read)?;
    if !metadata.is_file() {
        return Err(ConfigLoadError::InvalidPath {
            path: path.to_path_buf(),
        });
    }
    if metadata.len() > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigLoadError::Read(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "config file {} exceeds {} bytes",
                path.display(),
                MAX_CONFIG_FILE_BYTES
            ),
        )));
    }

    let mut contents = String::new();
    let mut limited = file.take(MAX_CONFIG_FILE_BYTES.saturating_add(1));
    limited
        .read_to_string(&mut contents)
        .map_err(ConfigLoadError::Read)?;
    if contents.len() as u64 > MAX_CONFIG_FILE_BYTES {
        return Err(ConfigLoadError::Read(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "config file {} changed while reading and exceeded {} bytes",
                path.display(),
                MAX_CONFIG_FILE_BYTES
            ),
        )));
    }
    Ok(contents)
}

fn existing_path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

fn is_visible_toml_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|file_name| file_name.to_str()) else {
        return false;
    };

    !file_name.starts_with('.')
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("toml"))
}

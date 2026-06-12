#[cfg(feature = "load-balancer")]
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::config::ConfigError;
#[cfg(feature = "load-balancer")]
use crate::config_net::valid_authority;
#[cfg(feature = "load-balancer")]
use crate::config_proxy::MAX_PROXY_UPSTREAMS;

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

pub const MAX_CONFIG_DIRECTORY_FILES: usize = 256;
pub const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub enum ConfigLoadError {
    InvalidPath {
        path: PathBuf,
    },
    Read(std::io::Error),
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    Validate(ConfigError),
}

impl Display for ConfigLoadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath { path } => {
                write!(
                    formatter,
                    "config path must be a readable .toml file or directory, got {}",
                    path.display()
                )
            }
            Self::Read(error) => write!(formatter, "failed to read config: {error}"),
            Self::Parse { path, source } => {
                write!(
                    formatter,
                    "failed to parse config {}: {source}",
                    path.display()
                )?;
                if let Some(hint) = config_parse_hint(source) {
                    write!(formatter, "\n{hint}")?;
                }
                Ok(())
            }
            Self::Validate(error) => write!(formatter, "invalid config: {error}"),
        }
    }
}

impl Error for ConfigLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPath { .. } => None,
            Self::Read(error) => Some(error),
            Self::Parse { source, .. } => Some(source),
            Self::Validate(error) => Some(error),
        }
    }
}

pub fn canonical_config_source(path: &Path) -> Result<PathBuf, ConfigLoadError> {
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

pub fn toml_files(dir: &Path) -> Result<Vec<PathBuf>, ConfigLoadError> {
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

pub fn config_directory_files(dir: &Path) -> Result<Vec<PathBuf>, ConfigLoadError> {
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

pub fn regular_visible_toml_file(path: &Path) -> Result<bool, ConfigLoadError> {
    if !is_visible_toml_file(path) {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(path).map_err(ConfigLoadError::Read)?;
    Ok(!metadata.file_type().is_symlink() && metadata.is_file())
}

pub fn read_regular_config_file_to_string(path: &Path) -> Result<String, ConfigLoadError> {
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

#[cfg(feature = "load-balancer")]
pub fn read_proxy_upstreams_file(path: &Path) -> std::io::Result<Vec<String>> {
    const MAX_PROXY_UPSTREAMS_FILE_BYTES: u64 = 64 * 1024;

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "proxy upstreams file must be a regular file",
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW);

    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "proxy upstreams file must be a regular file",
        ));
    }
    if metadata.len() > MAX_PROXY_UPSTREAMS_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "proxy upstreams file is too large",
        ));
    }

    let mut contents = String::new();
    let mut limited = file.take(MAX_PROXY_UPSTREAMS_FILE_BYTES.saturating_add(1));
    limited.read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_PROXY_UPSTREAMS_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "proxy upstreams file changed while reading and became too large",
        ));
    }

    parse_proxy_upstreams_file_contents(&contents)
}

#[cfg(feature = "load-balancer")]
fn parse_proxy_upstreams_file_contents(contents: &str) -> std::io::Result<Vec<String>> {
    let mut upstreams = Vec::new();
    let mut seen = HashSet::new();
    for (line_index, line) in contents.lines().enumerate() {
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        if !valid_authority(value) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "proxy upstreams file line {} is not a host:port or ip:port authority",
                    line_index + 1
                ),
            ));
        }
        if !seen.insert(value.to_ascii_lowercase()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "proxy upstreams file line {} repeats an upstream",
                    line_index + 1
                ),
            ));
        }
        upstreams.push(value.to_owned());
        if upstreams.len() > MAX_PROXY_UPSTREAMS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "proxy upstreams file contains too many upstreams",
            ));
        }
    }

    Ok(upstreams)
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

fn config_parse_hint(error: &toml::de::Error) -> Option<&'static str> {
    let message = error.to_string();
    if message.contains("vhosts.proxy.error_pages.web") {
        return Some(
            "hint: proxy error pages are arrays; define [[vhosts.proxy.error_pages]] before [vhosts.proxy.error_pages.web]",
        );
    }
    if message.contains("vhosts.routes.proxy.error_pages.web") {
        return Some(
            "hint: route proxy error pages are arrays; define [[vhosts.routes.proxy.error_pages]] before [vhosts.routes.proxy.error_pages.web]",
        );
    }
    if message.contains("unknown field `vhost`") {
        return Some("hint: virtual hosts are configured with [[vhosts]], not [[vhost]]");
    }
    if message.contains("unknown field `action`") && message.contains("path_prefix") {
        return Some(
            "hint: routes select their action by defining one nested table: [vhosts.routes.proxy], [vhosts.routes.web], or [vhosts.routes.redirect]; do not set action = \"proxy\"",
        );
    }
    if message.contains("vhosts.routes.")
        && message.contains("invalid type: map, expected a sequence")
    {
        return Some(
            "hint: start each route with [[vhosts.routes]] before nested route tables such as [vhosts.routes.proxy] or [vhosts.routes.web]",
        );
    }
    if message.contains("invalid type: map, expected a sequence") {
        return Some(
            "hint: start each virtual host with [[vhosts]] before nested tables such as [vhosts.proxy]",
        );
    }
    if message.contains("[[vhosts.routes.") {
        return Some(
            "hint: route action/config tables use single-bracket tables such as [vhosts.routes.proxy], not arrays such as [[vhosts.routes.proxy]]",
        );
    }
    if message.contains("[[vhosts.proxy]]") {
        return Some(
            "hint: vhost proxy config uses [vhosts.proxy], not [[vhosts.proxy]]; proxy is a nested table inside one [[vhosts]] block",
        );
    }
    if message.contains("unknown field `certificates`") {
        return Some(
            "hint: vhost TLS uses [vhosts.tls.certificate] for one certificate pair; use global [[tls.certificates]] for additional listener certificates",
        );
    }
    None
}

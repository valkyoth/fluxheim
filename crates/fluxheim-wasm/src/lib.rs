#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
))]
const WASM_PLUGIN_O_NOFOLLOW: i32 = 0o400000;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const WASM_PLUGIN_O_NOFOLLOW: i32 = 0x0100;
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
))]
compile_error!(
    "O_NOFOLLOW is unknown on this Unix platform; audit symlink-safe Wasm plugin opening before building Fluxheim"
);

mod manifest;
#[cfg(feature = "runtime")]
mod runtime;
pub use manifest::{
    ValidatedWasmPluginManifest, WasmManifestError, WasmPluginAbi, WasmPluginFailMode,
    WasmPluginManifest, WasmPluginPhase, validate_plugin_manifest,
};
#[cfg(feature = "runtime")]
pub use runtime::{FluxWasmRuntime, WasmExecutionError, WasmExecutionOutcome};

pub const FLUXHEIM_WASM_ABI_VERSION: u32 = 1;
pub const DEFAULT_MAX_MODULE_BYTES: u64 = 1_048_576;
pub const DEFAULT_MAX_MEMORY_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_TABLE_ELEMENTS: usize = 10_000;
pub const DEFAULT_FUEL: u64 = 5_000_000;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(50);
pub const DEFAULT_COMPILE_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct WasmSandboxLimits {
    pub max_module_bytes: u64,
    pub max_memory_bytes: usize,
    pub max_table_elements: usize,
    pub fuel: u64,
    pub timeout: Duration,
    pub compile_timeout: Duration,
}

impl Default for WasmSandboxLimits {
    fn default() -> Self {
        Self {
            max_module_bytes: DEFAULT_MAX_MODULE_BYTES,
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            max_table_elements: DEFAULT_MAX_TABLE_ELEMENTS,
            fuel: DEFAULT_FUEL,
            timeout: DEFAULT_TIMEOUT,
            compile_timeout: DEFAULT_COMPILE_TIMEOUT,
        }
    }
}

impl WasmSandboxLimits {
    pub fn validate(self) -> Result<Self, WasmPluginError> {
        if self.max_module_bytes == 0 {
            return Err(WasmPluginError::InvalidLimit {
                field: "max_module_bytes",
                reason: "must be greater than zero",
            });
        }
        if self.max_memory_bytes == 0 {
            return Err(WasmPluginError::InvalidLimit {
                field: "max_memory_bytes",
                reason: "must be greater than zero",
            });
        }
        if self.max_table_elements == 0 {
            return Err(WasmPluginError::InvalidLimit {
                field: "max_table_elements",
                reason: "must be greater than zero",
            });
        }
        if self.fuel == 0 {
            return Err(WasmPluginError::InvalidLimit {
                field: "fuel",
                reason: "must be greater than zero",
            });
        }
        if self.timeout.is_zero() {
            return Err(WasmPluginError::InvalidLimit {
                field: "timeout",
                reason: "must be greater than zero",
            });
        }
        if self.compile_timeout.is_zero() {
            return Err(WasmPluginError::InvalidLimit {
                field: "compile_timeout",
                reason: "must be greater than zero",
            });
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WasmPluginFile {
    path: PathBuf,
    bytes: Vec<u8>,
    sha256_hex: String,
}

impl WasmPluginFile {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn sha256_hex(&self) -> &str {
        &self.sha256_hex
    }
}

#[derive(Debug, Error)]
pub enum WasmPluginError {
    #[error("wasm plugin path must be absolute: {path}")]
    RelativePath { path: PathBuf },
    #[error("wasm plugin path contains a non-normal component: {path}")]
    NonNormalComponent { path: PathBuf },
    #[error("wasm plugin path is outside approved plugin roots: {path}")]
    OutsideApprovedRoots { path: PathBuf },
    #[error("wasm plugin path is unsafe: {path}: {message}")]
    UnsafePath {
        path: PathBuf,
        message: &'static str,
    },
    #[error("wasm plugin file is too large: {path}: max {max_bytes} bytes")]
    Oversized { path: PathBuf, max_bytes: u64 },
    #[error("invalid wasm sandbox limit {field}: {reason}")]
    InvalidLimit {
        field: &'static str,
        reason: &'static str,
    },
    #[error("wasm plugin filesystem error: {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

pub fn load_plugin_file(
    path: &Path,
    approved_roots: &[PathBuf],
    limits: WasmSandboxLimits,
) -> Result<WasmPluginFile, WasmPluginError> {
    let limits = limits.validate()?;
    validate_plugin_path(path, approved_roots)?;

    let metadata = fs::symlink_metadata(path).map_err(|source| WasmPluginError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WasmPluginError::UnsafePath {
            path: path.to_path_buf(),
            message: "plugin must be a regular file",
        });
    }
    if metadata.len() > limits.max_module_bytes {
        return Err(WasmPluginError::Oversized {
            path: path.to_path_buf(),
            max_bytes: limits.max_module_bytes,
        });
    }

    let file = open_verified_plugin_file(path, &metadata)?;
    let mut bytes = Vec::new();
    file.take(limits.max_module_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| WasmPluginError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > limits.max_module_bytes {
        return Err(WasmPluginError::Oversized {
            path: path.to_path_buf(),
            max_bytes: limits.max_module_bytes,
        });
    }

    let sha256_hex = sha256_hex(&bytes);
    Ok(WasmPluginFile {
        path: path.to_path_buf(),
        bytes,
        sha256_hex,
    })
}

fn open_verified_plugin_file(
    path: &Path,
    expected_metadata: &fs::Metadata,
) -> Result<fs::File, WasmPluginError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(WASM_PLUGIN_O_NOFOLLOW);
    }

    let file = options.open(path).map_err(|source| WasmPluginError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let opened_metadata = file.metadata().map_err(|source| WasmPluginError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !opened_metadata.is_file() {
        return Err(WasmPluginError::UnsafePath {
            path: path.to_path_buf(),
            message: "plugin handle must be a regular file",
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened_metadata.dev() != expected_metadata.dev()
            || opened_metadata.ino() != expected_metadata.ino()
        {
            return Err(WasmPluginError::UnsafePath {
                path: path.to_path_buf(),
                message: "plugin file identity changed before read",
            });
        }
    }
    Ok(file)
}

pub fn validate_plugin_path(
    path: &Path,
    approved_roots: &[PathBuf],
) -> Result<(), WasmPluginError> {
    if !path.is_absolute() {
        return Err(WasmPluginError::RelativePath {
            path: path.to_path_buf(),
        });
    }
    reject_non_normal_components(path)?;
    reject_symlink_components(path)?;

    let plugin_canonical = path.canonicalize().map_err(|source| WasmPluginError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    for root in approved_roots {
        if !root.is_absolute() {
            continue;
        }
        reject_non_normal_components(root)?;
        reject_symlink_components(root)?;
        let root_metadata = fs::symlink_metadata(root).map_err(|source| WasmPluginError::Io {
            path: root.clone(),
            source,
        })?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(WasmPluginError::UnsafePath {
                path: root.clone(),
                message: "approved root must be a real directory",
            });
        }
        let root_canonical = root.canonicalize().map_err(|source| WasmPluginError::Io {
            path: root.clone(),
            source,
        })?;
        if plugin_canonical.starts_with(root_canonical) {
            return Ok(());
        }
    }

    Err(WasmPluginError::OutsideApprovedRoots {
        path: path.to_path_buf(),
    })
}

fn reject_non_normal_components(path: &Path) -> Result<(), WasmPluginError> {
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(WasmPluginError::NonNormalComponent {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), WasmPluginError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|source| WasmPluginError::Io {
            path: current.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(WasmPluginError::UnsafePath {
                path: current,
                message: "path contains a symlink",
            });
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn plugin_loader_accepts_regular_file_under_approved_root() {
        let directory = tempfile::tempdir().unwrap();
        let plugin = directory.path().join("plugin.wasm");
        fs::write(&plugin, b"\0asm\x01\0\0\0").unwrap();

        let loaded = load_plugin_file(
            &plugin,
            &[directory.path().to_path_buf()],
            WasmSandboxLimits::default(),
        )
        .unwrap();

        assert_eq!(loaded.path(), plugin.as_path());
        assert_eq!(loaded.bytes(), b"\0asm\x01\0\0\0");
        assert_eq!(
            loaded.sha256_hex(),
            "93a44bbb96c751218e4c00d479e4c14358122a389acca16205b1e4d0dc5f9476"
        );
    }

    #[test]
    fn plugin_loader_rejects_symlinked_plugin() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real.wasm");
        let link = directory.path().join("link.wasm");
        fs::write(&real, b"\0asm\x01\0\0\0").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&real, &link).unwrap();

        let error = load_plugin_file(
            &link,
            &[directory.path().to_path_buf()],
            WasmSandboxLimits::default(),
        )
        .unwrap_err();

        assert!(matches!(error, WasmPluginError::UnsafePath { .. }));
    }

    #[test]
    fn plugin_loader_rejects_symlinked_approved_root() {
        let directory = tempfile::tempdir().unwrap();
        let real_root = directory.path().join("plugins");
        let root_link = directory.path().join("plugins-link");
        fs::create_dir(&real_root).unwrap();
        let plugin = real_root.join("plugin.wasm");
        fs::write(&plugin, b"\0asm\x01\0\0\0").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_root, &root_link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&real_root, &root_link).unwrap();

        let error =
            load_plugin_file(&plugin, &[root_link], WasmSandboxLimits::default()).unwrap_err();

        assert!(matches!(error, WasmPluginError::UnsafePath { .. }));
    }

    #[test]
    fn plugin_loader_rejects_outside_approved_roots() {
        let approved = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let plugin = outside.path().join("plugin.wasm");
        fs::write(&plugin, b"\0asm\x01\0\0\0").unwrap();

        let error = load_plugin_file(
            &plugin,
            &[approved.path().to_path_buf()],
            WasmSandboxLimits::default(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            WasmPluginError::OutsideApprovedRoots { .. }
        ));
    }

    #[test]
    fn plugin_loader_rejects_oversized_file() {
        let directory = tempfile::tempdir().unwrap();
        let plugin = directory.path().join("plugin.wasm");
        fs::write(&plugin, b"\0asm\x01\0\0\0").unwrap();

        let error = load_plugin_file(
            &plugin,
            &[directory.path().to_path_buf()],
            WasmSandboxLimits {
                max_module_bytes: 4,
                ..WasmSandboxLimits::default()
            },
        )
        .unwrap_err();

        assert!(matches!(error, WasmPluginError::Oversized { .. }));
    }

    #[test]
    fn sandbox_limits_reject_zero_compile_timeout() {
        let error = WasmSandboxLimits {
            compile_timeout: Duration::ZERO,
            ..WasmSandboxLimits::default()
        }
        .validate()
        .unwrap_err();

        assert!(matches!(
            error,
            WasmPluginError::InvalidLimit {
                field: "compile_timeout",
                ..
            }
        ));
    }
}

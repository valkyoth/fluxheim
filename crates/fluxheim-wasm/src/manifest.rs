use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

use crate::{
    FLUXHEIM_WASM_ABI_VERSION, WasmPluginError, WasmPluginFile, WasmSandboxLimits, load_plugin_file,
};

pub const MAX_PLUGIN_NAME_BYTES: usize = 64;
pub const MAX_PLUGIN_PHASES: usize = 16;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WasmPluginAbi {
    FluxheimPolicyV1,
    ProxyWasmPreview,
    WasiPreview,
}

impl WasmPluginAbi {
    pub fn abi_version(self) -> u32 {
        match self {
            Self::FluxheimPolicyV1 => FLUXHEIM_WASM_ABI_VERSION,
            Self::ProxyWasmPreview | Self::WasiPreview => 0,
        }
    }

    pub fn is_preview(self) -> bool {
        !matches!(self, Self::FluxheimPolicyV1)
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum WasmPluginPhase {
    RequestHeaders,
    ResponseHeaders,
    AccessDecision,
    RouteDecision,
    CacheLookup,
    CacheStore,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WasmPluginFailMode {
    FailClosed,
    FailOpen,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WasmPluginManifest {
    pub name: String,
    pub path: PathBuf,
    pub abi: WasmPluginAbi,
    pub phases: Vec<WasmPluginPhase>,
    pub limits: WasmSandboxLimits,
    pub fail_mode: WasmPluginFailMode,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ValidatedWasmPluginManifest {
    name: String,
    path: PathBuf,
    abi: WasmPluginAbi,
    phases: Vec<WasmPluginPhase>,
    limits: WasmSandboxLimits,
    fail_mode: WasmPluginFailMode,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LoadedWasmPlugin {
    manifest: ValidatedWasmPluginManifest,
    file: WasmPluginFile,
}

impl LoadedWasmPlugin {
    pub fn manifest(&self) -> &ValidatedWasmPluginManifest {
        &self.manifest
    }

    pub fn file(&self) -> &WasmPluginFile {
        &self.file
    }
}

impl ValidatedWasmPluginManifest {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn abi(&self) -> WasmPluginAbi {
        self.abi
    }

    pub fn phases(&self) -> &[WasmPluginPhase] {
        &self.phases
    }

    pub fn limits(&self) -> WasmSandboxLimits {
        self.limits
    }

    pub fn fail_mode(&self) -> WasmPluginFailMode {
        self.fail_mode
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum WasmManifestError {
    #[error("wasm plugin name is empty")]
    EmptyName,
    #[error("wasm plugin name is too long: max {max_bytes} bytes")]
    NameTooLong { max_bytes: usize },
    #[error("wasm plugin name contains an invalid character")]
    InvalidName,
    #[error("wasm plugin path must be absolute: {path}")]
    RelativePath { path: PathBuf },
    #[error("wasm plugin path contains a non-normal component: {path}")]
    NonNormalPath { path: PathBuf },
    #[error("wasm plugin must declare at least one phase")]
    EmptyPhases,
    #[error("wasm plugin declares too many phases: max {max}")]
    TooManyPhases { max: usize },
    #[error("wasm plugin declares a duplicate phase: {phase:?}")]
    DuplicatePhase { phase: WasmPluginPhase },
    #[error("wasm plugin uses preview ABI {abi:?} without explicit preview allowance")]
    PreviewAbiDisabled { abi: WasmPluginAbi },
    #[error("wasm plugin fail_open is not allowed for security decision phases")]
    UnsafeFailOpen,
    #[error("invalid wasm sandbox limit {field}: {reason}")]
    InvalidLimit {
        field: &'static str,
        reason: &'static str,
    },
}

#[derive(Debug, Error)]
pub enum WasmPluginLoadError {
    #[error(transparent)]
    Manifest(#[from] WasmManifestError),
    #[error(transparent)]
    Plugin(#[from] WasmPluginError),
}

pub fn validate_plugin_manifest(
    manifest: WasmPluginManifest,
    allow_preview_abi: bool,
) -> Result<ValidatedWasmPluginManifest, WasmManifestError> {
    validate_plugin_name(&manifest.name)?;
    validate_manifest_path(&manifest.path)?;
    let limits = validate_manifest_limits(manifest.limits)?;
    if manifest.abi.is_preview() && !allow_preview_abi {
        return Err(WasmManifestError::PreviewAbiDisabled { abi: manifest.abi });
    }
    validate_phases(&manifest.phases)?;
    validate_fail_mode(manifest.fail_mode, &manifest.phases)?;

    Ok(ValidatedWasmPluginManifest {
        name: manifest.name,
        path: manifest.path,
        abi: manifest.abi,
        phases: manifest.phases,
        limits,
        fail_mode: manifest.fail_mode,
    })
}

pub fn load_plugin_from_manifest(
    manifest: WasmPluginManifest,
    approved_roots: &[PathBuf],
    allow_preview_abi: bool,
) -> Result<LoadedWasmPlugin, WasmPluginLoadError> {
    let manifest = validate_plugin_manifest(manifest, allow_preview_abi)?;
    let file = load_plugin_file(manifest.path(), approved_roots, manifest.limits())?;
    Ok(LoadedWasmPlugin { manifest, file })
}

fn validate_manifest_limits(
    limits: WasmSandboxLimits,
) -> Result<WasmSandboxLimits, WasmManifestError> {
    limits.validate().map_err(|error| match error {
        crate::WasmPluginError::InvalidLimit { field, reason } => {
            WasmManifestError::InvalidLimit { field, reason }
        }
        crate::WasmPluginError::RelativePath { .. }
        | crate::WasmPluginError::NonNormalComponent { .. }
        | crate::WasmPluginError::OutsideApprovedRoots { .. }
        | crate::WasmPluginError::UnsafePath { .. }
        | crate::WasmPluginError::Oversized { .. }
        | crate::WasmPluginError::Io { .. } => WasmManifestError::InvalidLimit {
            field: "limits",
            reason: "unexpected limit validation error",
        },
    })
}

fn validate_plugin_name(name: &str) -> Result<(), WasmManifestError> {
    if name.is_empty() {
        return Err(WasmManifestError::EmptyName);
    }
    if name.len() > MAX_PLUGIN_NAME_BYTES {
        return Err(WasmManifestError::NameTooLong {
            max_bytes: MAX_PLUGIN_NAME_BYTES,
        });
    }
    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(WasmManifestError::InvalidName);
    }
    Ok(())
}

fn validate_manifest_path(path: &Path) -> Result<(), WasmManifestError> {
    if !path.is_absolute() {
        return Err(WasmManifestError::RelativePath {
            path: path.to_path_buf(),
        });
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(WasmManifestError::NonNormalPath {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_phases(phases: &[WasmPluginPhase]) -> Result<(), WasmManifestError> {
    if phases.is_empty() {
        return Err(WasmManifestError::EmptyPhases);
    }
    if phases.len() > MAX_PLUGIN_PHASES {
        return Err(WasmManifestError::TooManyPhases {
            max: MAX_PLUGIN_PHASES,
        });
    }

    let mut seen = HashSet::with_capacity(phases.len());
    for phase in phases {
        if !seen.insert(*phase) {
            return Err(WasmManifestError::DuplicatePhase { phase: *phase });
        }
    }
    Ok(())
}

fn validate_fail_mode(
    fail_mode: WasmPluginFailMode,
    phases: &[WasmPluginPhase],
) -> Result<(), WasmManifestError> {
    if fail_mode == WasmPluginFailMode::FailOpen
        && phases.iter().any(|phase| {
            matches!(
                phase,
                WasmPluginPhase::AccessDecision
                    | WasmPluginPhase::RouteDecision
                    | WasmPluginPhase::CacheStore
            )
        })
    {
        return Err(WasmManifestError::UnsafeFailOpen);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    fn valid_manifest() -> WasmPluginManifest {
        WasmPluginManifest {
            name: "security-headers".to_owned(),
            path: PathBuf::from("/srv/fluxheim/plugins/security_headers.wasm"),
            abi: WasmPluginAbi::FluxheimPolicyV1,
            phases: vec![WasmPluginPhase::RequestHeaders],
            limits: WasmSandboxLimits::default(),
            fail_mode: WasmPluginFailMode::FailClosed,
        }
    }

    fn write_plugin(directory: &tempfile::TempDir) -> PathBuf {
        let path = directory.path().join("plugin.wasm");
        fs::write(&path, b"\0asm\x01\0\0\0").unwrap();
        path
    }

    #[test]
    fn validates_basic_manifest() {
        let validated = validate_plugin_manifest(valid_manifest(), false).unwrap();

        assert_eq!(validated.name(), "security-headers");
        assert_eq!(validated.abi().abi_version(), FLUXHEIM_WASM_ABI_VERSION);
        assert_eq!(validated.phases(), &[WasmPluginPhase::RequestHeaders]);
    }

    #[test]
    fn rejects_invalid_plugin_name() {
        let mut manifest = valid_manifest();
        manifest.name = "bad name".to_owned();

        let error = validate_plugin_manifest(manifest, false).unwrap_err();

        assert_eq!(error, WasmManifestError::InvalidName);
    }

    #[test]
    fn rejects_relative_plugin_path() {
        let mut manifest = valid_manifest();
        manifest.path = PathBuf::from("plugin.wasm");

        let error = validate_plugin_manifest(manifest, false).unwrap_err();

        assert!(matches!(error, WasmManifestError::RelativePath { .. }));
    }

    #[test]
    fn rejects_dot_segment_plugin_path() {
        let mut manifest = valid_manifest();
        manifest.path = PathBuf::from("/srv/fluxheim/plugins/../plugin.wasm");

        let error = validate_plugin_manifest(manifest, false).unwrap_err();

        assert!(matches!(error, WasmManifestError::NonNormalPath { .. }));
    }

    #[test]
    fn rejects_duplicate_phase() {
        let mut manifest = valid_manifest();
        manifest.phases = vec![
            WasmPluginPhase::RequestHeaders,
            WasmPluginPhase::RequestHeaders,
        ];

        let error = validate_plugin_manifest(manifest, false).unwrap_err();

        assert_eq!(
            error,
            WasmManifestError::DuplicatePhase {
                phase: WasmPluginPhase::RequestHeaders
            }
        );
    }

    #[test]
    fn rejects_preview_abi_when_not_allowed() {
        let mut manifest = valid_manifest();
        manifest.abi = WasmPluginAbi::ProxyWasmPreview;

        let error = validate_plugin_manifest(manifest, false).unwrap_err();

        assert_eq!(
            error,
            WasmManifestError::PreviewAbiDisabled {
                abi: WasmPluginAbi::ProxyWasmPreview
            }
        );
    }

    #[test]
    fn accepts_preview_abi_when_allowed() {
        let mut manifest = valid_manifest();
        manifest.abi = WasmPluginAbi::ProxyWasmPreview;

        let validated = validate_plugin_manifest(manifest, true).unwrap();

        assert_eq!(validated.abi(), WasmPluginAbi::ProxyWasmPreview);
    }

    #[test]
    fn rejects_fail_open_for_access_decisions() {
        let mut manifest = valid_manifest();
        manifest.phases = vec![WasmPluginPhase::AccessDecision];
        manifest.fail_mode = WasmPluginFailMode::FailOpen;

        let error = validate_plugin_manifest(manifest, false).unwrap_err();

        assert_eq!(error, WasmManifestError::UnsafeFailOpen);
    }

    #[test]
    fn rejects_zero_limit_values() {
        let mut manifest = valid_manifest();
        manifest.limits = WasmSandboxLimits {
            timeout: Duration::ZERO,
            ..WasmSandboxLimits::default()
        };

        let error = validate_plugin_manifest(manifest, false).unwrap_err();

        assert!(matches!(
            error,
            WasmManifestError::InvalidLimit {
                field: "timeout",
                ..
            }
        ));
    }

    #[test]
    fn loads_plugin_from_valid_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_plugin(&directory);
        let mut manifest = valid_manifest();
        manifest.path = plugin_path.clone();

        let loaded =
            load_plugin_from_manifest(manifest, &[directory.path().to_path_buf()], false).unwrap();

        assert_eq!(loaded.manifest().path(), plugin_path);
        assert_eq!(loaded.file().bytes(), b"\0asm\x01\0\0\0");
        assert_eq!(loaded.file().sha256_hex().len(), 64);
    }

    #[test]
    fn load_from_manifest_still_rejects_unapproved_root() {
        let approved = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let plugin_path = write_plugin(&outside);
        let mut manifest = valid_manifest();
        manifest.path = plugin_path;

        let error = load_plugin_from_manifest(manifest, &[approved.path().to_path_buf()], false)
            .unwrap_err();

        assert!(matches!(
            error,
            WasmPluginLoadError::Plugin(WasmPluginError::OutsideApprovedRoots { .. })
        ));
    }
}

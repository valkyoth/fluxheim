use std::path::PathBuf;

use fluxheim_config::{ByteSize, CacheDiskBackend};

use crate::DiskTierPlan;

pub const STORAGE_BIN_MANIFEST_FILENAME: &str = ".fluxheim-storage-bin-v1";
pub const STORAGE_BIN_DATA_DIR: &str = "bins";

const STORAGE_BIN_MANIFEST_MAGIC_V1: &str = "FLUXHEIM-STORAGE-BIN-v1";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageBinLayoutPlan {
    pub root: PathBuf,
    pub manifest_path: PathBuf,
    pub data_dir: PathBuf,
    pub bin_size_bytes: ByteSize,
    pub max_size_bytes: ByteSize,
    pub preallocate: bool,
    pub max_open_bins: usize,
}

impl StorageBinLayoutPlan {
    pub fn from_disk_plan(plan: &DiskTierPlan) -> Option<Self> {
        (plan.backend == CacheDiskBackend::StorageBin).then(|| {
            let root = plan.path.clone();
            Self {
                manifest_path: root.join(STORAGE_BIN_MANIFEST_FILENAME),
                data_dir: root.join(STORAGE_BIN_DATA_DIR),
                root,
                bin_size_bytes: plan.storage_bin.bin_size_bytes,
                max_size_bytes: plan.max_size_bytes,
                preallocate: plan.storage_bin.preallocate,
                max_open_bins: plan.storage_bin.max_open_bins,
            }
        })
    }

    pub fn max_bins(&self) -> u64 {
        let bin_size = self.bin_size_bytes.as_u64();
        if bin_size == 0 {
            return 0;
        }
        self.max_size_bytes.as_u64().div_ceil(bin_size)
    }

    pub fn bin_path(&self, bin_id: u64) -> PathBuf {
        self.data_dir.join(format!("{bin_id:016x}.fhbin"))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageBinManifest {
    pub bin_size_bytes: ByteSize,
    pub max_size_bytes: ByteSize,
    pub preallocate: bool,
    pub max_open_bins: usize,
}

impl StorageBinManifest {
    pub fn from_layout(plan: &StorageBinLayoutPlan) -> Self {
        Self {
            bin_size_bytes: plan.bin_size_bytes,
            max_size_bytes: plan.max_size_bytes,
            preallocate: plan.preallocate,
            max_open_bins: plan.max_open_bins,
        }
    }

    pub fn encode(&self) -> String {
        format!(
            "{STORAGE_BIN_MANIFEST_MAGIC_V1}\nbin_size_bytes={}\nmax_size_bytes={}\npreallocate={}\nmax_open_bins={}\n",
            self.bin_size_bytes.as_u64(),
            self.max_size_bytes.as_u64(),
            self.preallocate,
            self.max_open_bins
        )
    }

    pub fn decode(contents: &str) -> std::io::Result<Self> {
        let mut lines = contents.lines();
        match lines.next() {
            Some(STORAGE_BIN_MANIFEST_MAGIC_V1) => {}
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid storage-bin manifest magic",
                ));
            }
        }

        let bin_size_bytes = parse_storage_bin_manifest_u64(lines.next(), "bin_size_bytes")?;
        let max_size_bytes = parse_storage_bin_manifest_u64(lines.next(), "max_size_bytes")?;
        let preallocate = parse_storage_bin_manifest_bool(lines.next(), "preallocate")?;
        let max_open_bins = parse_storage_bin_manifest_usize(lines.next(), "max_open_bins")?;
        if lines.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "storage-bin manifest has trailing fields",
            ));
        }

        Ok(Self {
            bin_size_bytes: ByteSize::from_bytes(bin_size_bytes),
            max_size_bytes: ByteSize::from_bytes(max_size_bytes),
            preallocate,
            max_open_bins,
        })
    }

    pub fn ensure_matches_layout(&self, layout: &StorageBinLayoutPlan) -> std::io::Result<()> {
        let expected = Self::from_layout(layout);
        if self == &expected {
            return Ok(());
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "storage-bin manifest does not match configured cache disk layout",
        ))
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StorageBinObjectLocation {
    pub bin_id: u64,
    pub offset: u64,
    pub len: u64,
}

impl StorageBinObjectLocation {
    pub fn validate(self, bin_size_bytes: ByteSize) -> std::io::Result<Self> {
        let bin_size = bin_size_bytes.as_u64();
        let end = self.offset.checked_add(self.len).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "storage-bin object location overflows",
            )
        })?;
        if self.len == 0 || end > bin_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "storage-bin object location is outside its bin",
            ));
        }
        Ok(self)
    }
}

fn parse_storage_bin_manifest_u64(line: Option<&str>, key: &str) -> std::io::Result<u64> {
    parse_storage_bin_manifest_value(line, key)?
        .parse::<u64>()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid storage-bin manifest {key}: {error}"),
            )
        })
}

fn parse_storage_bin_manifest_usize(line: Option<&str>, key: &str) -> std::io::Result<usize> {
    parse_storage_bin_manifest_value(line, key)?
        .parse::<usize>()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid storage-bin manifest {key}: {error}"),
            )
        })
}

fn parse_storage_bin_manifest_bool(line: Option<&str>, key: &str) -> std::io::Result<bool> {
    parse_storage_bin_manifest_value(line, key)?
        .parse::<bool>()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid storage-bin manifest {key}: {error}"),
            )
        })
}

fn parse_storage_bin_manifest_value<'a>(
    line: Option<&'a str>,
    key: &str,
) -> std::io::Result<&'a str> {
    let Some(line) = line else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("missing storage-bin manifest {key}"),
        ));
    };
    let Some(value) = line.strip_prefix(&format!("{key}=")) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("missing storage-bin manifest {key}"),
        ));
    };
    Ok(value)
}

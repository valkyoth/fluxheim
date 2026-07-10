use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use fluxheim_cache::{
    CachePurgeIndex, DiskTierPlan, STORAGE_BIN_DATA_DIR, STORAGE_BIN_MANIFEST_FILENAME,
    StorageBinFileSet, StorageBinFreeMap, StorageBinLayoutPlan, StorageBinObjectLocation,
    prepare_storage_bin_layout,
};
use fluxheim_config::{CacheConfig, CacheDiskBackend};
use fs2::FileExt as _;

use super::native_http1_cache_disk_path::prepare_native_disk_cache_root;
use super::native_http1_cache_memory::NativeMemoryCacheVariant;

#[derive(Debug)]
pub(super) enum NativeDiskCacheBackend {
    Filesystem,
    StorageBin(Box<NativeStorageBinBackend>),
}

#[derive(Debug)]
pub(super) struct NativeStorageBinBackend {
    pub(super) layout: StorageBinLayoutPlan,
    pub(super) files: StorageBinFileSet,
    pub(super) free_map: Mutex<StorageBinFreeMap>,
    _lease: NativeStorageBinLease,
}

#[derive(Debug)]
struct NativeStorageBinLease {
    _file: std::fs::File,
}

#[derive(Debug, Default)]
pub(crate) struct NativeDiskCacheState {
    pub(super) objects: HashMap<String, NativeDiskCacheRecord>,
    pub(super) eviction_order: BTreeSet<(SystemTime, String)>,
    pub(super) variants: HashMap<String, Vec<NativeMemoryCacheVariant>>,
    pub(super) purge_index: CachePurgeIndex,
    pub(super) bytes: u64,
}

impl NativeDiskCacheState {
    pub(super) fn insert_object(&mut self, key: String, record: NativeDiskCacheRecord) {
        if let Some(previous) = self.objects.insert(key.clone(), record.clone()) {
            self.eviction_order
                .remove(&(previous.accessed_at, key.clone()));
        }
        self.eviction_order.insert((record.accessed_at, key));
    }

    pub(super) fn remove_object(&mut self, key: &str) -> Option<NativeDiskCacheRecord> {
        let record = self.objects.remove(key)?;
        self.eviction_order
            .remove(&(record.accessed_at, key.to_owned()));
        Some(record)
    }

    pub(super) fn touch_object(&mut self, key: &str, accessed_at: SystemTime) {
        let Some(record) = self.objects.get_mut(key) else {
            return;
        };
        self.eviction_order
            .remove(&(record.accessed_at, key.to_owned()));
        record.accessed_at = accessed_at;
        self.eviction_order.insert((accessed_at, key.to_owned()));
    }

    pub(super) fn oldest_key(&self) -> Option<String> {
        self.eviction_order.first().map(|(_, key)| key.to_owned())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NativeDiskCacheRecord {
    pub(super) location: NativeDiskCacheLocation,
    pub(super) weight: u64,
    pub(super) accessed_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum NativeDiskCacheLocation {
    Filesystem(PathBuf),
    StorageBin(StorageBinObjectLocation),
}

impl NativeDiskCacheLocation {
    pub(super) fn display(&self) -> String {
        match self {
            Self::Filesystem(path) => path.display().to_string(),
            Self::StorageBin(location) => format!(
                "storage-bin:{:016x}:{}+{}",
                location.bin_id, location.offset, location.len
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeDiskCacheStoreKey {
    pub(crate) combined: String,
    pub(crate) primary: String,
    pub(crate) user_tag: String,
    pub(crate) index_path: Option<String>,
    pub(crate) cache_tags: Vec<String>,
    pub(crate) vary_fields: Vec<String>,
}

impl NativeDiskCacheBackend {
    pub(super) fn from_config(config: &CacheConfig) -> std::io::Result<(PathBuf, Self)> {
        let path = config.disk.path.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "native disk cache requires cache.disk.path",
            )
        })?;
        match config.disk.backend {
            CacheDiskBackend::Filesystem => {
                let root = prepare_native_disk_cache_root(path)?;
                Ok((root, Self::Filesystem))
            }
            CacheDiskBackend::StorageBin => {
                let layout = prepare_native_storage_bin_layout(config)?;
                let root = layout.root.clone();
                let lease = acquire_native_storage_bin_lease(&root)?;
                let free_map = StorageBinFreeMap::new(&layout);
                let files = StorageBinFileSet::new(layout.clone());
                Ok((
                    root,
                    Self::StorageBin(Box::new(NativeStorageBinBackend {
                        layout,
                        files,
                        free_map: Mutex::new(free_map),
                        _lease: lease,
                    })),
                ))
            }
        }
    }
}

fn acquire_native_storage_bin_lease(
    root: &std::path::Path,
) -> std::io::Result<NativeStorageBinLease> {
    let file = open_native_storage_bin_lease_file(root)?;
    file.try_lock_exclusive().map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("storage-bin root is already owned: {}", root.display()),
            )
        } else {
            error
        }
    })?;
    Ok(NativeStorageBinLease { _file: file })
}

#[cfg(unix)]
fn open_native_storage_bin_lease_file(root: &std::path::Path) -> std::io::Result<std::fs::File> {
    let root_fd = rustix::fs::open(
        root,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(native_storage_bin_rustix_error)?;
    let fd = rustix::fs::openat(
        &root_fd,
        ".fluxheim-storage-bin.lock",
        rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(native_storage_bin_rustix_error)?;
    Ok(fd.into())
}

#[cfg(unix)]
fn native_storage_bin_rustix_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(not(unix))]
fn open_native_storage_bin_lease_file(root: &std::path::Path) -> std::io::Result<std::fs::File> {
    let path = root.join(".fluxheim-storage-bin.lock");
    if std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "storage-bin lease file must not be a symlink",
        ));
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
}

pub(crate) fn prepare_native_storage_bin_layout(
    config: &CacheConfig,
) -> std::io::Result<StorageBinLayoutPlan> {
    let path = config.disk.path.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "native storage-bin cache requires cache.disk.path",
        )
    })?;
    let plan = DiskTierPlan {
        backend: CacheDiskBackend::StorageBin,
        path: path.clone(),
        max_size_bytes: config.disk.max_size_bytes,
        max_object_bytes: config.max_object_bytes,
        cache_tag_headers: Vec::new(),
        storage_bin: config.disk.storage_bin.clone(),
        encryption: config.disk.encryption.clone(),
    };
    let mut layout = StorageBinLayoutPlan::from_disk_plan(&plan).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "native storage-bin cache requires a storage-bin disk plan",
        )
    })?;
    prepare_storage_bin_layout(&layout)?;
    let root = layout.root.canonicalize()?;
    layout = StorageBinLayoutPlan {
        root: root.clone(),
        manifest_path: root.join(STORAGE_BIN_MANIFEST_FILENAME),
        data_dir: root.join(STORAGE_BIN_DATA_DIR),
        ..layout
    };
    Ok(layout)
}

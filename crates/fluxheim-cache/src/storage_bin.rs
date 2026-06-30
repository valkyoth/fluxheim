use std::collections::BTreeMap;
use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use fluxheim_config::{ByteSize, CacheDiskBackend};

use crate::DiskTierPlan;

pub const STORAGE_BIN_MANIFEST_FILENAME: &str = ".fluxheim-storage-bin-v1";
pub const STORAGE_BIN_INDEX_FILENAME: &str = ".fluxheim-storage-bin-index-v1";
pub const STORAGE_BIN_DATA_DIR: &str = "bins";

const STORAGE_BIN_MANIFEST_MAGIC_V1: &str = "FLUXHEIM-STORAGE-BIN-v1";
const STORAGE_BIN_INDEX_MAGIC_V1: &str = "FLUXHEIM-STORAGE-BIN-INDEX-v1";

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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StorageBinFreeRange {
    pub offset: u64,
    pub len: u64,
}

#[derive(Debug, Clone)]
pub struct StorageBinFreeMap {
    bin_size_bytes: u64,
    max_size_bytes: u64,
    next_bin_id: u64,
    free: BTreeMap<u64, Vec<StorageBinFreeRange>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageBinIndexEntry {
    pub combined_key: String,
    pub location: StorageBinObjectLocation,
    pub accessed: SystemTime,
}

#[derive(Debug, Clone)]
pub struct StorageBinFileSet {
    layout: StorageBinLayoutPlan,
}

impl StorageBinFileSet {
    pub fn new(layout: StorageBinLayoutPlan) -> Self {
        Self { layout }
    }

    pub fn write_object(
        &self,
        location: StorageBinObjectLocation,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        if bytes.len() as u64 != location.len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin write length does not match object location",
            ));
        }
        let location = location.validate(self.layout.bin_size_bytes)?;
        let mut file = self.open_bin_for_write(location.bin_id)?;
        write_storage_bin_range(&mut file, location.offset, bytes)
    }

    pub fn read_object(&self, location: StorageBinObjectLocation) -> std::io::Result<Vec<u8>> {
        let location = location.validate(self.layout.bin_size_bytes)?;
        let mut file = self.open_bin_for_read(location.bin_id)?;
        read_storage_bin_range(&mut file, location.offset, location.len)
    }

    pub fn remove_bin(&self, bin_id: u64) -> std::io::Result<()> {
        let path = self.safe_bin_path(bin_id)?;
        let safe_path = StorageBinSafePath::from_path(path);
        match safe_path.remove_file() {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn open_bin_for_write(&self, bin_id: u64) -> std::io::Result<std::fs::File> {
        let path = self.safe_bin_path(bin_id)?;
        if let Some(parent) = path.parent() {
            prepare_storage_bin_data_dir(&self.layout.root, parent)?;
        }
        let safe_path = StorageBinSafePath::from_path(path);
        match safe_path.open_read_write_file() {
            Ok(file) => Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let file = safe_path.create_new_read_write_file()?;
                if self.layout.preallocate {
                    file.set_len(self.layout.bin_size_bytes.as_u64())?;
                    file.sync_all()?;
                }
                Ok(file)
            }
            Err(error) => Err(error),
        }
    }

    fn open_bin_for_read(&self, bin_id: u64) -> std::io::Result<std::fs::File> {
        let path = self.safe_bin_path(bin_id)?;
        StorageBinSafePath::from_path(path).open_existing_file()
    }

    fn safe_bin_path(&self, bin_id: u64) -> std::io::Result<PathBuf> {
        if bin_id >= self.layout.max_bins() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin id exceeds configured cache budget",
            ));
        }
        let path = self.layout.bin_path(bin_id);
        if !path.starts_with(&self.layout.root)
            || storage_bin_path_contains_symlink(&self.layout.root, &path)?
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("storage-bin path is unsafe: {}", path.display()),
            ));
        }
        Ok(path)
    }
}

impl StorageBinFreeMap {
    pub fn new(layout: &StorageBinLayoutPlan) -> Self {
        Self {
            bin_size_bytes: layout.bin_size_bytes.as_u64(),
            max_size_bytes: layout.max_size_bytes.as_u64(),
            next_bin_id: 0,
            free: BTreeMap::new(),
        }
    }

    pub fn from_occupied(
        layout: &StorageBinLayoutPlan,
        entries: &[StorageBinIndexEntry],
    ) -> std::io::Result<Self> {
        let mut map = Self::new(layout);
        let mut occupied = BTreeMap::<u64, Vec<StorageBinFreeRange>>::new();
        for entry in entries {
            let location = entry.location.validate(layout.bin_size_bytes)?;
            let Some(capacity) = map.bin_capacity(location.bin_id) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "storage-bin index references a bin outside the configured cache budget",
                ));
            };
            if location.offset.saturating_add(location.len) > capacity {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "storage-bin index object exceeds bin capacity",
                ));
            }
            occupied
                .entry(location.bin_id)
                .or_default()
                .push(StorageBinFreeRange {
                    offset: location.offset,
                    len: location.len,
                });
            map.next_bin_id = map.next_bin_id.max(location.bin_id.saturating_add(1));
        }

        for (bin_id, ranges) in occupied {
            let capacity = map.bin_capacity(bin_id).unwrap_or(0);
            let mut ranges = ranges;
            ranges.sort_by_key(|range| range.offset);
            let mut cursor = 0_u64;
            for range in ranges {
                if range.offset < cursor {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "storage-bin index contains overlapping object ranges",
                    ));
                }
                if range.offset > cursor {
                    map.insert_free_range(
                        bin_id,
                        StorageBinFreeRange {
                            offset: cursor,
                            len: range.offset - cursor,
                        },
                    )?;
                }
                cursor = range.offset.saturating_add(range.len);
            }
            if cursor < capacity {
                map.insert_free_range(
                    bin_id,
                    StorageBinFreeRange {
                        offset: cursor,
                        len: capacity - cursor,
                    },
                )?;
            }
        }
        Ok(map)
    }

    pub fn allocate(&mut self, len: u64) -> std::io::Result<Option<StorageBinObjectLocation>> {
        if len == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin allocation length must be greater than zero",
            ));
        }
        if len > self.bin_size_bytes {
            return Ok(None);
        }

        if let Some(location) = self.allocate_from_free_ranges(len)? {
            return Ok(Some(location));
        }

        let Some(capacity) = self.bin_capacity(self.next_bin_id) else {
            return Ok(None);
        };
        if len > capacity {
            return Ok(None);
        }

        let bin_id = self.next_bin_id;
        self.next_bin_id = self.next_bin_id.saturating_add(1);
        let remaining = capacity.saturating_sub(len);
        if remaining > 0 {
            self.insert_free_range(
                bin_id,
                StorageBinFreeRange {
                    offset: len,
                    len: remaining,
                },
            )?;
        }
        Ok(Some(StorageBinObjectLocation {
            bin_id,
            offset: 0,
            len,
        }))
    }

    pub fn release(&mut self, location: StorageBinObjectLocation) -> std::io::Result<()> {
        location.validate(ByteSize::from_bytes(self.bin_size_bytes))?;
        let Some(capacity) = self.bin_capacity(location.bin_id) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin release references a bin outside the configured cache budget",
            ));
        };
        let end = location.offset.saturating_add(location.len);
        if end > capacity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin release exceeds the bin capacity",
            ));
        }
        self.insert_free_range(
            location.bin_id,
            StorageBinFreeRange {
                offset: location.offset,
                len: location.len,
            },
        )
    }

    pub fn free_ranges(&self, bin_id: u64) -> &[StorageBinFreeRange] {
        self.free.get(&bin_id).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn allocated_size_bytes(&self) -> u64 {
        (0..self.next_bin_id)
            .filter_map(|bin_id| self.bin_capacity(bin_id))
            .fold(0_u64, u64::saturating_add)
    }

    pub fn free_size_bytes(&self) -> u64 {
        self.free
            .values()
            .flatten()
            .map(|range| range.len)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn free_range_count(&self) -> u64 {
        self.free
            .values()
            .map(|ranges| u64::try_from(ranges.len()).unwrap_or(u64::MAX))
            .fold(0_u64, u64::saturating_add)
    }

    pub fn largest_free_range_bytes(&self) -> u64 {
        self.free
            .values()
            .flatten()
            .map(|range| range.len)
            .max()
            .unwrap_or(0)
    }

    pub fn bin_files(&self) -> u64 {
        self.next_bin_id
    }

    pub fn reclaim_free_tail_bins(&mut self) -> Vec<u64> {
        let mut reclaimed = Vec::new();
        while self.next_bin_id > 0 {
            let bin_id = self.next_bin_id - 1;
            let Some(capacity) = self.bin_capacity(bin_id) else {
                break;
            };
            let Some(ranges) = self.free.get(&bin_id) else {
                break;
            };
            if ranges.len() != 1 || ranges[0].offset != 0 || ranges[0].len != capacity {
                break;
            }
            self.free.remove(&bin_id);
            self.next_bin_id -= 1;
            reclaimed.push(bin_id);
        }
        reclaimed
    }

    fn allocate_from_free_ranges(
        &mut self,
        len: u64,
    ) -> std::io::Result<Option<StorageBinObjectLocation>> {
        let mut selected = None;
        for (bin_id, ranges) in &self.free {
            if let Some(index) = ranges.iter().position(|range| range.len >= len) {
                selected = Some((*bin_id, index));
                break;
            }
        }

        let Some((bin_id, index)) = selected else {
            return Ok(None);
        };
        let ranges = self.free.get_mut(&bin_id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "storage-bin free range disappeared during allocation",
            )
        })?;
        let range = ranges[index];
        let location = StorageBinObjectLocation {
            bin_id,
            offset: range.offset,
            len,
        };
        if range.len == len {
            ranges.remove(index);
        } else {
            ranges[index] = StorageBinFreeRange {
                offset: range.offset.saturating_add(len),
                len: range.len.saturating_sub(len),
            };
        }
        if ranges.is_empty() {
            self.free.remove(&bin_id);
        }
        Ok(Some(location))
    }

    fn insert_free_range(
        &mut self,
        bin_id: u64,
        range: StorageBinFreeRange,
    ) -> std::io::Result<()> {
        if range.len == 0 {
            return Ok(());
        }
        let Some(capacity) = self.bin_capacity(bin_id) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin free range references a bin outside the configured cache budget",
            ));
        };
        let end = range.offset.checked_add(range.len).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin free range overflows",
            )
        })?;
        if end > capacity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "storage-bin free range exceeds the bin capacity",
            ));
        }

        let ranges = self.free.entry(bin_id).or_default();
        ranges.push(range);
        ranges.sort_by_key(|range| range.offset);
        let mut merged: Vec<StorageBinFreeRange> = Vec::with_capacity(ranges.len());
        for range in ranges.drain(..) {
            if let Some(last) = merged.last_mut() {
                let last_end = last.offset.saturating_add(last.len);
                if range.offset <= last_end {
                    let range_end = range.offset.saturating_add(range.len);
                    last.len = range_end.saturating_sub(last.offset).max(last.len);
                    continue;
                }
            }
            merged.push(range);
        }
        *ranges = merged;
        Ok(())
    }

    fn bin_capacity(&self, bin_id: u64) -> Option<u64> {
        let start = bin_id.checked_mul(self.bin_size_bytes)?;
        if start >= self.max_size_bytes {
            return None;
        }
        Some(self.bin_size_bytes.min(self.max_size_bytes - start))
    }
}

pub fn prepare_storage_bin_layout(
    layout: &StorageBinLayoutPlan,
) -> std::io::Result<StorageBinManifest> {
    let root = prepare_storage_bin_root(&layout.root)?;
    let canonical_layout = StorageBinLayoutPlan {
        root: root.clone(),
        manifest_path: root.join(STORAGE_BIN_MANIFEST_FILENAME),
        data_dir: root.join(STORAGE_BIN_DATA_DIR),
        bin_size_bytes: layout.bin_size_bytes,
        max_size_bytes: layout.max_size_bytes,
        preallocate: layout.preallocate,
        max_open_bins: layout.max_open_bins,
    };

    prepare_storage_bin_data_dir(&root, &canonical_layout.data_dir)?;
    match read_storage_bin_manifest(&root, &canonical_layout.manifest_path)? {
        Some(manifest) => {
            manifest.ensure_matches_layout(&canonical_layout)?;
            Ok(manifest)
        }
        None => {
            let manifest = StorageBinManifest::from_layout(&canonical_layout);
            write_storage_bin_manifest(&root, &canonical_layout.manifest_path, &manifest)?;
            Ok(manifest)
        }
    }
}

pub fn storage_bin_index_path(root: &Path) -> PathBuf {
    root.join(STORAGE_BIN_INDEX_FILENAME)
}

pub fn read_storage_bin_index(
    layout: &StorageBinLayoutPlan,
) -> std::io::Result<Vec<StorageBinIndexEntry>> {
    let path = storage_bin_index_path(&layout.root);
    if storage_bin_path_contains_symlink(&layout.root, &path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin index path contains symlink: {}",
                path.display()
            ),
        ));
    }
    let canonical = match path.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if !canonical.starts_with(&layout.root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin index escaped root: {}", canonical.display()),
        ));
    }

    let mut file = StorageBinSafePath::from_path(canonical).open_existing_file()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    parse_storage_bin_index(layout, &contents)
}

pub fn write_storage_bin_index(
    layout: &StorageBinLayoutPlan,
    entries: &[StorageBinIndexEntry],
) -> std::io::Result<()> {
    let path = storage_bin_index_path(&layout.root);
    if !path.starts_with(&layout.root) || storage_bin_path_contains_symlink(&layout.root, &path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin index path is unsafe: {}", path.display()),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin index path has no parent: {}", path.display()),
        )
    })?;
    let temp_path = storage_bin_temp_path(parent, "index")?;
    let path = StorageBinSafePath::from_path(path);
    let temp_path = StorageBinSafePath::from_path(temp_path);
    let write_result = (|| {
        let mut file = temp_path.create_new_file()?;
        writeln!(file, "{STORAGE_BIN_INDEX_MAGIC_V1}")?;
        let mut entries = entries.to_vec();
        entries.sort_by(|left, right| left.combined_key.cmp(&right.combined_key));
        for entry in entries {
            entry.location.validate(layout.bin_size_bytes)?;
            writeln!(
                file,
                "{}\t{}\t{}\t{}\t{}",
                storage_bin_hex_encode(entry.combined_key.as_bytes()),
                entry.location.bin_id,
                entry.location.offset,
                entry.location.len,
                storage_bin_system_time_unix_secs(entry.accessed).unwrap_or(0)
            )?;
        }
        file.sync_all()?;
        path.rename_from(&temp_path)
    })();
    if write_result.is_err() {
        let _ = temp_path.remove_file();
    }
    write_result
}

fn prepare_storage_bin_root(root: &Path) -> std::io::Result<PathBuf> {
    if storage_bin_configured_path_contains_symlink(root)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin root contains symlink: {}", root.display()),
        ));
    }
    match storage_bin_path_file_type_no_follow(root)? {
        Some(file_type) if file_type.is_symlink() || !file_type.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "storage-bin root is not a real directory: {}",
                    root.display()
                ),
            ));
        }
        Some(_) => {}
        None => {
            create_storage_bin_dir_all(root)?;
        }
    }
    if storage_bin_configured_path_contains_symlink(root)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin root contains symlink: {}", root.display()),
        ));
    }
    root.canonicalize()
}

fn read_storage_bin_manifest(
    root: &Path,
    path: &Path,
) -> std::io::Result<Option<StorageBinManifest>> {
    if storage_bin_path_contains_symlink(root, path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin manifest path contains symlink: {}",
                path.display()
            ),
        ));
    }
    let canonical = match path.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !canonical.starts_with(root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin manifest escaped root: {}", canonical.display()),
        ));
    }

    let mut file = StorageBinSafePath::from_path(canonical).open_existing_file()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    StorageBinManifest::decode(&contents).map(Some)
}

fn write_storage_bin_manifest(
    root: &Path,
    path: &Path,
    manifest: &StorageBinManifest,
) -> std::io::Result<()> {
    if !path.starts_with(root) || storage_bin_path_contains_symlink(root, path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("storage-bin manifest path is unsafe: {}", path.display()),
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin manifest path has no parent: {}",
                path.display()
            ),
        )
    })?;
    let temp_path = storage_bin_temp_path(parent, "manifest")?;
    let path = StorageBinSafePath::from_path(path.to_path_buf());
    let temp_path = StorageBinSafePath::from_path(temp_path);
    let write_result = (|| {
        let mut file = temp_path.create_new_file()?;
        file.write_all(manifest.encode().as_bytes())?;
        file.sync_all()?;
        path.rename_from(&temp_path)
    })();
    if write_result.is_err() {
        let _ = temp_path.remove_file();
    }
    write_result
}

fn parse_storage_bin_index(
    layout: &StorageBinLayoutPlan,
    contents: &str,
) -> std::io::Result<Vec<StorageBinIndexEntry>> {
    let mut lines = contents.lines();
    match lines.next() {
        Some(STORAGE_BIN_INDEX_MAGIC_V1) => {}
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid storage-bin index magic",
            ));
        }
    }
    let mut entries = Vec::new();
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid storage-bin index line",
            ));
        }
        let combined_key = storage_bin_hex_decode_string(fields[0])?;
        let location = StorageBinObjectLocation {
            bin_id: parse_storage_bin_index_u64(fields[1], "bin id")?,
            offset: parse_storage_bin_index_u64(fields[2], "offset")?,
            len: parse_storage_bin_index_u64(fields[3], "length")?,
        }
        .validate(layout.bin_size_bytes)?;
        entries.push(StorageBinIndexEntry {
            combined_key,
            location,
            accessed: storage_bin_unix_secs_system_time(parse_storage_bin_index_u64(
                fields[4], "accessed",
            )?),
        });
    }
    Ok(entries)
}

fn write_storage_bin_range(
    file: &mut std::fs::File,
    offset: u64,
    bytes: &[u8],
) -> std::io::Result<()> {
    file.seek(std::io::SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn read_storage_bin_range(
    file: &mut std::fs::File,
    offset: u64,
    len: u64,
) -> std::io::Result<Vec<u8>> {
    let capacity = usize::try_from(len).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "storage-bin object is too large for this platform",
        )
    })?;
    file.seek(std::io::SeekFrom::Start(offset))?;
    let mut bytes = vec![0; capacity];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn prepare_storage_bin_data_dir(root: &Path, data_dir: &Path) -> std::io::Result<PathBuf> {
    if storage_bin_path_contains_symlink(root, data_dir)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin data directory contains symlink: {}",
                data_dir.display()
            ),
        ));
    }
    match storage_bin_path_file_type_no_follow(data_dir)? {
        Some(file_type) if file_type.is_symlink() || !file_type.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "storage-bin data directory is not a real directory: {}",
                    data_dir.display()
                ),
            ));
        }
        Some(_) => {}
        None => {
            create_storage_bin_dir_all(data_dir)?;
        }
    }
    if storage_bin_path_contains_symlink(root, data_dir)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin data directory contains symlink: {}",
                data_dir.display()
            ),
        ));
    }
    let canonical = data_dir.canonicalize()?;
    if !canonical.starts_with(root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "storage-bin data directory escaped root: {}",
                canonical.display()
            ),
        ));
    }
    Ok(canonical)
}

fn create_storage_bin_dir_all(path: &Path) -> std::io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(
            component,
            std::path::Component::Prefix(_)
                | std::path::Component::RootDir
                | std::path::Component::CurDir
        ) {
            continue;
        }
        if matches!(component, std::path::Component::ParentDir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "storage-bin directory path must not contain parent traversal: {}",
                    path.display()
                ),
            ));
        }

        match storage_bin_path_file_type_no_follow(&current)? {
            Some(file_type) if file_type.is_symlink() || !file_type.is_dir() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "storage-bin directory path is not a real directory: {}",
                        current.display()
                    ),
                ));
            }
            Some(_) => {}
            None => {
                let mode = rustix::fs::Mode::RWXU | rustix::fs::Mode::RGRP | rustix::fs::Mode::XGRP;
                match rustix::fs::mkdir(&current, mode) {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(storage_bin_rustix_to_io_error(error)),
                }
            }
        }
    }
    Ok(())
}

fn storage_bin_path_file_type_no_follow(
    path: &Path,
) -> std::io::Result<Option<rustix::fs::FileType>> {
    match rustix::fs::statat(rustix::fs::CWD, path, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(rustix::fs::FileType::from_raw_mode(stat.st_mode))),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(None),
        Err(error) => Err(storage_bin_rustix_to_io_error(error)),
    }
}

fn storage_bin_configured_path_contains_symlink(path: &Path) -> std::io::Result<bool> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }

    Ok(false)
}

fn storage_bin_path_contains_symlink(root: &Path, path: &Path) -> std::io::Result<bool> {
    let Ok(relative) = path.strip_prefix(root) else {
        return Ok(true);
    };

    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Ok(true);
        }
    }

    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!("inspect storage-bin path {}: {error}", current.display()),
                ));
            }
        }
    }

    Ok(false)
}

fn storage_bin_temp_path(parent: &Path, label: &str) -> std::io::Result<PathBuf> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|error| {
        std::io::Error::other(format!("generate storage-bin {label} temp nonce: {error}"))
    })?;
    let mut encoded = String::with_capacity(nonce.len() * 2);
    for byte in nonce {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    Ok(parent.join(format!(
        ".fluxheim-storage-bin-{label}.{}.{}.tmp",
        std::process::id(),
        encoded
    )))
}

fn parse_storage_bin_index_u64(value: &str, field: &str) -> std::io::Result<u64> {
    value.parse::<u64>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid storage-bin index {field}: {error}"),
        )
    })
}

fn storage_bin_hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn storage_bin_hex_decode_string(value: &str) -> std::io::Result<String> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid storage-bin index hex key",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let high = storage_bin_hex_nibble(chunk[0]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid storage-bin index hex key",
            )
        })?;
        let low = storage_bin_hex_nibble(chunk[1]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid storage-bin index hex key",
            )
        })?;
        bytes.push((high << 4) | low);
    }
    String::from_utf8(bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("storage-bin index key is not utf-8: {error}"),
        )
    })
}

fn storage_bin_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn storage_bin_system_time_unix_secs(time: SystemTime) -> Option<u64> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn storage_bin_unix_secs_system_time(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(secs))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

#[derive(Debug, Clone)]
struct StorageBinSafePath {
    path: PathBuf,
}

impl StorageBinSafePath {
    fn from_path(path: PathBuf) -> Self {
        Self { path }
    }

    fn parent_and_name(&self) -> std::io::Result<(&Path, &std::ffi::OsStr)> {
        let parent = self.path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("storage-bin path has no parent: {}", self.path.display()),
            )
        })?;
        let name = self.path.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("storage-bin path has no file name: {}", self.path.display()),
            )
        })?;
        Ok((parent, name))
    }

    fn open_parent_dir(&self) -> std::io::Result<std::fs::File> {
        let (parent, _) = self.parent_and_name()?;
        let fd = rustix::fs::open(
            parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .map_err(storage_bin_rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn create_new_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(storage_bin_rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn create_new_read_write_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(storage_bin_rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn open_existing_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(storage_bin_rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn open_read_write_file(&self) -> std::io::Result<std::fs::File> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        let fd = rustix::fs::openat(
            &parent,
            name,
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(storage_bin_rustix_to_io_error)?;
        Ok(fd.into())
    }

    fn rename_from(&self, source: &StorageBinSafePath) -> std::io::Result<()> {
        let (_, source_name) = source.parent_and_name()?;
        let (_, destination_name) = self.parent_and_name()?;
        let source_parent = source.open_parent_dir()?;
        let destination_parent = self.open_parent_dir()?;
        rustix::fs::renameat(
            &source_parent,
            source_name,
            &destination_parent,
            destination_name,
        )
        .map_err(storage_bin_rustix_to_io_error)
    }

    fn remove_file(&self) -> std::io::Result<()> {
        let (_, name) = self.parent_and_name()?;
        let parent = self.open_parent_dir()?;
        rustix::fs::unlinkat(&parent, name, rustix::fs::AtFlags::empty())
            .map_err(storage_bin_rustix_to_io_error)
    }
}

fn storage_bin_rustix_to_io_error(error: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error.raw_os_error())
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

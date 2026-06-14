use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::SystemTime;

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

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use fluxheim_config::{
        ByteSize, CacheDiskBackend, CacheDiskEncryptionConfig, CacheDiskStorageBinConfig,
    };

    use super::{
        StorageBinFreeMap, StorageBinFreeRange, StorageBinIndexEntry, StorageBinLayoutPlan,
        StorageBinManifest, StorageBinObjectLocation,
    };
    use crate::DiskTierPlan;

    fn storage_bin_plan() -> DiskTierPlan {
        DiskTierPlan {
            path: std::path::PathBuf::from("/tmp/cache"),
            max_size_bytes: ByteSize::from_bytes(128),
            max_object_bytes: ByteSize::from_bytes(64),
            backend: CacheDiskBackend::StorageBin,
            storage_bin: CacheDiskStorageBinConfig {
                bin_size_bytes: ByteSize::from_bytes(32),
                preallocate: false,
                max_open_bins: 4,
            },
            encryption: CacheDiskEncryptionConfig::default(),
            cache_tag_headers: Vec::new(),
        }
    }

    #[test]
    fn storage_bin_manifest_round_trips() {
        let manifest = StorageBinManifest {
            bin_size_bytes: ByteSize::from_bytes(64),
            max_size_bytes: ByteSize::from_bytes(512),
            preallocate: true,
            max_open_bins: 8,
        };

        let decoded = StorageBinManifest::decode(&manifest.encode()).unwrap();

        assert_eq!(decoded, manifest);
    }

    #[test]
    fn storage_bin_free_map_allocates_and_reuses_ranges() {
        let layout = StorageBinLayoutPlan::from_disk_plan(&storage_bin_plan()).unwrap();
        let mut free_map = StorageBinFreeMap::new(&layout);

        let first = free_map.allocate(16).unwrap().unwrap();
        let second = free_map.allocate(8).unwrap().unwrap();

        assert_eq!(
            first,
            StorageBinObjectLocation {
                bin_id: 0,
                offset: 0,
                len: 16
            }
        );
        assert_eq!(
            second,
            StorageBinObjectLocation {
                bin_id: 0,
                offset: 16,
                len: 8
            }
        );
        assert_eq!(
            free_map.free_ranges(0),
            &[StorageBinFreeRange { offset: 24, len: 8 }]
        );

        free_map.release(first).unwrap();
        let reused = free_map.allocate(10).unwrap().unwrap();

        assert_eq!(reused.bin_id, 0);
        assert_eq!(reused.offset, 0);
        assert_eq!(reused.len, 10);
    }

    #[test]
    fn storage_bin_free_map_rebuilds_from_occupied_entries() {
        let layout = StorageBinLayoutPlan::from_disk_plan(&storage_bin_plan()).unwrap();
        let entries = vec![StorageBinIndexEntry {
            combined_key: "key".to_owned(),
            location: StorageBinObjectLocation {
                bin_id: 0,
                offset: 8,
                len: 8,
            },
            accessed: SystemTime::UNIX_EPOCH,
        }];

        let free_map = StorageBinFreeMap::from_occupied(&layout, &entries).unwrap();

        assert_eq!(
            free_map.free_ranges(0)[0],
            StorageBinFreeRange { offset: 0, len: 8 }
        );
        assert_eq!(
            free_map.free_ranges(0)[1],
            StorageBinFreeRange {
                offset: 16,
                len: 16
            }
        );
    }
}

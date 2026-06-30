use std::collections::BTreeMap;

use fluxheim_config::ByteSize;

use crate::storage_bin::{StorageBinIndexEntry, StorageBinLayoutPlan, StorageBinObjectLocation};

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

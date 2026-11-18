use super::{NativeDiskCache, NativeDiskCacheState};
use fluxheim_cache::StorageBinIndexBudget;

#[derive(Debug)]
pub(super) struct BinIndexAdmission {
    encrypted: bool,
    bytes: u64,
    pub(super) limit: u64,
    pending_rows: usize,
    pending_bytes: u64,
    pub(super) disabled: bool,
}

impl BinIndexAdmission {
    pub(super) fn new(encrypted: bool) -> Self {
        Self {
            encrypted,
            bytes: 0,
            limit: StorageBinIndexBudget::ROWS_BYTES,
            pending_rows: 0,
            pending_bytes: 0,
            disabled: false,
        }
    }

    fn weight(&self, key: &str) -> Option<u64> {
        StorageBinIndexBudget::maximum_row_bytes(if self.encrypted { 64 } else { key.len() })
    }

    fn available(&self, key: &str, rows: usize, replacing: bool) -> Option<u64> {
        let weight = self.weight(key)?;
        let base = if replacing {
            self.bytes.checked_sub(weight)?
        } else {
            self.bytes
        };
        (!self.disabled
            && rows
                .checked_sub(usize::from(replacing))?
                .checked_add(self.pending_rows)?
                < StorageBinIndexBudget::MAX_ROWS
            && base.checked_add(self.pending_bytes)?.checked_add(weight)? <= self.limit)
            .then_some(weight)
    }

    pub(super) fn insert(&mut self, key: &str) {
        self.bytes = self
            .bytes
            .saturating_add(self.weight(key).unwrap_or(self.limit.saturating_add(1)));
    }

    pub(super) fn remove(&mut self, key: &str) {
        self.bytes = self
            .bytes
            .saturating_sub(self.weight(key).unwrap_or(self.limit.saturating_add(1)));
    }
}

impl NativeDiskCacheState {
    pub(super) fn bin_index_admissible(&self, key: &str) -> bool {
        self.bin_index.as_ref().is_none_or(|i| {
            i.available(key, self.objects.len(), self.objects.contains_key(key))
                .is_some()
        })
    }
}

pub(super) struct BinIndexReservation<'a>(&'a NativeDiskCache, u64);

impl Drop for BinIndexReservation<'_> {
    fn drop(&mut self) {
        self.0.with_state_mut(|s| {
            if let Some(index) = &mut s.bin_index {
                index.pending_rows -= 1;
                index.pending_bytes -= self.1;
            }
        });
    }
}

impl NativeDiskCache {
    // The caller holds the key stripe. Reserve the whole replacement row so
    // another fill cannot consume its space between removing and inserting.
    pub(super) fn reserve_bin_index(&self, key: &str) -> Option<BinIndexReservation<'_>> {
        self.with_state_mut(|s| {
            let index = s.bin_index.as_mut()?;
            let weight = index.available(key, s.objects.len(), s.objects.contains_key(key))?;
            index.pending_rows += 1;
            index.pending_bytes += weight;
            Some(BinIndexReservation(self, weight))
        })
    }
}

pub(super) struct DiskAdmission<'a> {
    cache: &'a NativeDiskCache,
    objects: usize,
    bytes: u64,
}

impl Drop for DiskAdmission<'_> {
    fn drop(&mut self) {
        self.cache.with_state_mut(|state| {
            state.pending_objects = state.pending_objects.saturating_sub(self.objects);
            state.pending_bytes = state.pending_bytes.saturating_sub(self.bytes);
        });
    }
}

impl NativeDiskCacheState {
    pub(super) fn key_admissible(&self, key: &str, weight: u64, max_bytes: u64) -> bool {
        let existing = self.objects.get(key);
        !self.filesystem_writes_blocked
            && self.filesystem_object_limit.is_none_or(|limit| {
                self.objects
                    .len()
                    .saturating_sub(usize::from(existing.is_some()))
                    .saturating_add(self.pending_objects)
                    < limit
            })
            && self
                .bytes
                .saturating_sub(existing.map_or(0, |record| record.weight))
                .checked_add(self.pending_bytes)
                .and_then(|bytes| bytes.checked_add(weight))
                .is_some_and(|bytes| bytes <= max_bytes)
    }
}

impl NativeDiskCache {
    pub(super) fn reserve_admission(&self, key: &str, weight: u64) -> Option<DiskAdmission<'_>> {
        self.with_state_mut(|state| {
            if !state.key_admissible(key, weight, self.max_bytes) {
                return None;
            }
            // Reserve before releasing the state lock, so different key stripes
            // cannot all consume the final slot. No mutex is held across I/O.
            let (objects, bytes) = if state.filesystem_object_limit.is_some() {
                (1, weight)
            } else {
                (0, 0)
            };
            let pending_objects = state.pending_objects.checked_add(objects)?;
            let pending_bytes = state.pending_bytes.checked_add(bytes)?;
            state.pending_objects = pending_objects;
            state.pending_bytes = pending_bytes;
            Some(DiskAdmission {
                cache: self,
                objects,
                bytes,
            })
        })
    }
}

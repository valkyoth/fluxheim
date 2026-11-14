use super::{NativeDiskCache, NativeDiskCacheState};

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

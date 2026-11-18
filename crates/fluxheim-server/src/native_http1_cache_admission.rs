use super::native_http1_cache_state::native_disk_cache_mutation_lock_stripe as stripe;
use super::{NativeDiskCache, NativeDiskCacheState};
use fluxheim_cache::StorageBinIndexBudget;

pub(super) const BIN_INDEX_EVICTIONS_PER_FILL: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IndexRefusal {
    Full,
    Invalid,
    Disabled,
    Busy,
}

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

    fn available(&self, key: &str, rows: usize, replacing: bool) -> Result<u64, IndexRefusal> {
        if self.disabled {
            return Err(IndexRefusal::Disabled);
        }
        let weight = self
            .weight(key)
            .filter(|w| *w <= self.limit)
            .ok_or(IndexRefusal::Invalid)?;
        let base = if replacing {
            self.bytes
                .checked_sub(weight)
                .ok_or(IndexRefusal::Invalid)?
        } else {
            self.bytes
        };
        let rows = rows
            .checked_sub(usize::from(replacing))
            .and_then(|n| n.checked_add(self.pending_rows))
            .ok_or(IndexRefusal::Invalid)?;
        let bytes = base
            .checked_add(self.pending_bytes)
            .and_then(|n| n.checked_add(weight))
            .ok_or(IndexRefusal::Invalid)?;
        if rows < StorageBinIndexBudget::MAX_ROWS && bytes <= self.limit {
            Ok(weight)
        } else if self.pending_rows != 0 {
            Err(IndexRefusal::Busy)
        } else {
            Err(IndexRefusal::Full)
        }
    }

    fn reserve(&mut self, weight: u64) {
        self.pending_rows += 1;
        self.pending_bytes += weight;
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
                .is_ok()
        })
    }

    fn index_victim_count(&self, key: &str, limit: usize) -> Option<usize> {
        let index = self.bin_index.as_ref()?;
        if self.objects.contains_key(key)
            || index.available(key, self.objects.len(), false) != Err(IndexRefusal::Full)
        {
            return None;
        }
        let target = index.limit.checked_sub(index.weight(key)?)?;
        let mut bytes = index.bytes;
        for (n, (_, victim)) in self.eviction_order.iter().take(limit).enumerate() {
            bytes = bytes.checked_sub(index.weight(victim)?)?;
            if bytes <= target
                && self.objects.len().checked_sub(n + 1)? < StorageBinIndexBudget::MAX_ROWS
            {
                return Some(n + 1);
            }
        }
        None
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
    pub(super) fn reserve_bin_index(
        &self,
        key: &str,
    ) -> Result<BinIndexReservation<'_>, IndexRefusal> {
        self.with_state_mut(|s| {
            let index = s.bin_index.as_mut().ok_or(IndexRefusal::Disabled)?;
            let weight = index.available(key, s.objects.len(), s.objects.contains_key(key))?;
            index.reserve(weight);
            Ok(BinIndexReservation(self, weight))
        })
    }

    pub(super) fn reserve_bin_for_store(
        &self,
        key: &str,
        remaining: &mut usize,
    ) -> std::io::Result<Option<BinIndexReservation<'_>>> {
        match self.reserve_bin_index(key) {
            Ok(slot) => return Ok(Some(slot)),
            Err(IndexRefusal::Full) if *remaining > 0 => {}
            Err(_) => return Ok(None),
        }
        let Some(victims) = self.with_state(|s| {
            let count = s.index_victim_count(key, *remaining)?;
            Some(
                s.eviction_order
                    .iter()
                    .take(count)
                    .map(|(_, k)| k.clone())
                    .collect::<Vec<_>>(),
            )
        }) else {
            return Ok(None);
        };
        // The incoming stripe is already held. Never wait for a second stripe,
        // nor reclaim a partial set just because one of the victims is busy.
        let mut guards = Vec::new();
        let incoming_stripe = stripe(key);
        for victim in &victims {
            let id = stripe(victim);
            if id != incoming_stripe && !guards.iter().any(|(held, _)| *held == id) {
                match self.try_lock_key_mutation(victim) {
                    Ok(guard) => guards.push((id, guard)),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
                    Err(e) => return Err(e),
                }
            }
        }
        let slot = self.with_state_mut(|s| {
            // Recheck the LRU order and budget under the same lock as the
            // reservation. Other writers cannot steal the reclaimed space.
            if s.index_victim_count(key, *remaining) != Some(victims.len())
                || !s
                    .eviction_order
                    .iter()
                    .take(victims.len())
                    .map(|(_, k)| k)
                    .eq(&victims)
            {
                return None;
            }
            let index = s.bin_index.as_mut()?;
            let weight = index.weight(key)?;
            index.reserve(weight);
            Some(BinIndexReservation(self, weight))
        });
        let Some(slot) = slot else { return Ok(None) };
        *remaining -= victims.len();
        for victim in victims {
            if !self.remove_combined_locked(&victim) {
                return Ok(None);
            }
        }
        Ok(Some(slot))
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

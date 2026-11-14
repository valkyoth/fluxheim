use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError};

use super::native_http1_cache_disk_path::NativeSafeDiskCachePath;
use super::{
    NativeDiskCache, NativeDiskCacheBackend, NativeDiskCacheLocation, NativeDiskCacheRecord,
    NativeDiskCacheState,
};

const NATIVE_DISK_CACHE_MUTATION_LOCKS: usize = 128;

impl NativeDiskCache {
    pub(crate) fn remove_combined(&self, combined_key: &str) -> bool {
        let _mutation = self.lock_key_mutation(combined_key);
        self.remove_combined_locked(combined_key)
    }

    pub(crate) fn remove_combined_locked(&self, combined_key: &str) -> bool {
        let filesystem = self.with_state(|state| {
            state.objects.get(combined_key).and_then(|record| {
                matches!(record.location, NativeDiskCacheLocation::Filesystem(_))
                    .then(|| record.location.clone())
            })
        });
        if let Some(location) = &filesystem
            && self.remove_location(location).is_err()
        {
            self.pause_filesystem_writes();
            return false;
        }
        let removed = self.with_state_mut(|state| {
            let removed = state.remove_object(combined_key);
            if let Some(record) = &removed {
                state.bytes = state.bytes.saturating_sub(record.weight);
                state.purge_index.remove_combined(combined_key);
            }
            state.variants.retain(|_, variants| {
                variants.retain(|variant| variant.key != combined_key);
                !variants.is_empty()
            });
            removed
        });
        if let Some(record) = removed {
            if filesystem.is_none() {
                let _ = self.remove_location(&record.location);
            }
            self.persist_storage_bin_index();
            return true;
        }
        false
    }

    pub(crate) fn evict_oldest(&self) -> std::io::Result<bool> {
        let Some(key) = self.with_state(NativeDiskCacheState::oldest_key) else {
            return Ok(false);
        };
        Ok(self.remove_combined(&key))
    }

    pub(super) fn pause_filesystem_writes(&self) {
        let already_paused = self
            .with_state_mut(|state| std::mem::replace(&mut state.filesystem_writes_blocked, true));
        if !already_paused {
            log::error!(target: "fluxheim::native_http1",
                "filesystem cache write admission paused until restart after a filesystem mutation failure");
        }
    }

    pub(crate) fn with_state<R>(&self, f: impl FnOnce(&NativeDiskCacheState) -> R) -> R {
        match self.state.lock() {
            Ok(state) => f(&state),
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "native disk cache mutex poisoned: {error}"
                );
                fluxheim_common::fatal::abort(fluxheim_common::fatal::Reason::DiskCachePoisoned);
            }
        }
    }

    pub(crate) fn with_state_mut<R>(&self, f: impl FnOnce(&mut NativeDiskCacheState) -> R) -> R {
        match self.state.lock() {
            Ok(mut state) => f(&mut state),
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "native disk cache mutex poisoned: {error}"
                );
                fluxheim_common::fatal::abort(fluxheim_common::fatal::Reason::DiskCachePoisoned);
            }
        }
    }

    fn remove_location(&self, location: &NativeDiskCacheLocation) -> std::io::Result<()> {
        match (&self.backend, location) {
            (NativeDiskCacheBackend::Filesystem, NativeDiskCacheLocation::Filesystem(path)) => {
                match NativeSafeDiskCachePath::from_path(path.clone()).remove_file() {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error),
                }
            }
            (
                NativeDiskCacheBackend::StorageBin(_),
                NativeDiskCacheLocation::StorageBin(location),
            ) => self.release_storage_bin_location(*location),
            _ => Ok(()),
        }
    }

    pub(crate) fn lock_key_mutation(&self, combined_key: &str) -> RwLockWriteGuard<'_, ()> {
        let stripe = native_disk_cache_mutation_lock_stripe(combined_key);
        match self.mutation_locks[stripe].write() {
            Ok(guard) => guard,
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "native disk cache mutation lock poisoned: {error}"
                );
                fluxheim_common::fatal::abort(
                    fluxheim_common::fatal::Reason::DiskCacheMutationPoisoned,
                );
            }
        }
    }

    pub(super) fn try_lock_key_read(&self, key: &str) -> std::io::Result<RwLockReadGuard<'_, ()>> {
        self.mutation_locks[native_disk_cache_mutation_lock_stripe(key)]
            .try_read()
            .map_err(key_lock_error)
    }

    pub(super) fn remove_if_unchanged(
        &self,
        key: &str,
        expected: &NativeDiskCacheRecord,
    ) -> std::io::Result<bool> {
        // Do not upgrade a read lock or occupy a blocking worker waiting for a
        // writer. Identity is process-local and survives LRU timestamp updates.
        let _write = self.mutation_locks[native_disk_cache_mutation_lock_stripe(key)]
            .try_write()
            .map_err(key_lock_error)?;
        if !self.with_state(|state| {
            state
                .objects
                .get(key)
                .is_some_and(|record| Arc::ptr_eq(&record.identity, &expected.identity))
        }) {
            return Ok(false);
        }
        Ok(self.remove_combined_locked(key))
    }
}

fn key_lock_error<T>(error: TryLockError<T>) -> std::io::Error {
    match error {
        TryLockError::WouldBlock => {
            std::io::Error::new(std::io::ErrorKind::WouldBlock, "disk cache key is busy")
        }
        TryLockError::Poisoned(_) => {
            fluxheim_common::fatal::abort(fluxheim_common::fatal::Reason::DiskCacheMutationPoisoned)
        }
    }
}

pub(super) fn native_disk_cache_mutation_locks() -> Box<[RwLock<()>]> {
    (0..NATIVE_DISK_CACHE_MUTATION_LOCKS)
        .map(|_| RwLock::new(()))
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

pub(super) fn native_disk_cache_mutation_lock_stripe(combined_key: &str) -> usize {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in combined_key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash as usize) % NATIVE_DISK_CACHE_MUTATION_LOCKS
}

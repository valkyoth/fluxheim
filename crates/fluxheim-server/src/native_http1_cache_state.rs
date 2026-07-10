use std::sync::{Mutex, MutexGuard};

use super::native_http1_cache_disk_path::NativeSafeDiskCachePath;
use super::{
    NativeDiskCache, NativeDiskCacheBackend, NativeDiskCacheLocation, NativeDiskCacheState,
};

const NATIVE_DISK_CACHE_MUTATION_LOCKS: usize = 128;

impl NativeDiskCache {
    pub(crate) fn remove_combined(&self, combined_key: &str) -> bool {
        let _mutation = self.lock_key_mutation(combined_key);
        self.remove_combined_locked(combined_key)
    }

    pub(crate) fn remove_combined_locked(&self, combined_key: &str) -> bool {
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
            let _ = self.remove_location(&record.location);
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

    pub(crate) fn with_state<R>(&self, f: impl FnOnce(&NativeDiskCacheState) -> R) -> R {
        match self.state.lock() {
            Ok(state) => f(&state),
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "native disk cache mutex poisoned: {error}"
                );
                std::process::abort();
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
                std::process::abort();
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

    pub(crate) fn lock_key_mutation(&self, combined_key: &str) -> MutexGuard<'_, ()> {
        let stripe = native_disk_cache_mutation_lock_stripe(combined_key);
        match self.mutation_locks[stripe].lock() {
            Ok(guard) => guard,
            Err(error) => {
                log::error!(
                    target: "fluxheim::native_http1",
                    "native disk cache mutation lock poisoned: {error}"
                );
                std::process::abort();
            }
        }
    }
}

pub(super) fn native_disk_cache_mutation_locks() -> Box<[Mutex<()>]> {
    (0..NATIVE_DISK_CACHE_MUTATION_LOCKS)
        .map(|_| Mutex::new(()))
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn native_disk_cache_mutation_lock_stripe(combined_key: &str) -> usize {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in combined_key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash as usize) % NATIVE_DISK_CACHE_MUTATION_LOCKS
}

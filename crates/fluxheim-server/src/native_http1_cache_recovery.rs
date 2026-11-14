use std::fs::File;
use std::io::{self, Read as _};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use super::native_http1_cache_disk_path::{NativeSafeDiskCachePath, validate_single_link_file};

// All cache handles retain a shared lease after startup. Recovery may remove
// leftovers only while it has exclusive ownership, before exposing the cache.
#[derive(Debug)]
pub(super) struct FilesystemRecoveryLease {
    file: File,
    exclusive: bool,
}

impl Drop for FilesystemRecoveryLease {
    fn drop(&mut self) {
        // Explicitly release our lease: a concurrent fork may briefly retain a
        // CLOEXEC duplicate until exec, even after this process closes its fd.
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

impl FilesystemRecoveryLease {
    pub(super) fn acquire(root: &Path) -> io::Result<Self> {
        let file =
            NativeSafeDiskCachePath::from_path(root.join(".fluxheim-filesystem-recovery.lock"))
                .open_or_create_read_write_file()?;
        validate_single_link_file(&file)?;
        let exclusive = match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => true,
            Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
                fs2::FileExt::try_lock_shared(&file)?;
                false
            }
            Err(error) => return Err(error),
        };
        Ok(Self { file, exclusive })
    }

    pub(super) fn exclusive(&self) -> bool {
        self.exclusive
    }

    pub(super) fn finish_recovery(&mut self) -> io::Result<()> {
        if self.exclusive {
            // There is no portable atomic downgrade. A competing initializer
            // can win this gap; fail startup rather than wait or run unleased.
            fs2::FileExt::unlock(&self.file)?;
            fs2::FileExt::try_lock_shared(&self.file)?;
            self.exclusive = false;
        }
        Ok(())
    }
}

pub(super) const RECOVERY_ENTRY_LIMIT: usize = 65_536;
pub(super) const RECOVERY_READ_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
pub(super) const TEMP_MIN_AGE: Duration = Duration::from_secs(3600);

#[derive(Debug, Default)]
pub(super) struct RecoveryReport {
    pub(super) removed_files: u64,
    pub(super) removed_bytes: u64,
    pub(super) retained_files: u64,
    pub(super) retained_bytes: u64,
    pub(super) unknown_entries: u64,
    pub(super) failed_removals: u64,
}

impl RecoveryReport {
    pub(super) fn retain(&mut self, bytes: u64) {
        self.retained_files = self.retained_files.saturating_add(1);
        self.retained_bytes = self.retained_bytes.saturating_add(bytes);
    }

    pub(super) fn remove_or_retain(&mut self, path: &Path, bytes: u64, allowed: bool) {
        if allowed {
            match NativeSafeDiskCachePath::from_path(path.to_path_buf()).remove_file() {
                Ok(()) => {
                    self.removed_files = self.removed_files.saturating_add(1);
                    self.removed_bytes = self.removed_bytes.saturating_add(bytes);
                    return;
                }
                Err(_) => self.failed_removals = self.failed_removals.saturating_add(1),
            }
        }
        self.retain(bytes);
    }
}

pub(super) struct RecoveryBudget {
    remaining_entries: usize,
    remaining_bytes: u64,
    started: Instant,
}

impl RecoveryBudget {
    pub(super) fn new(entries: usize, bytes: u64) -> Self {
        Self {
            remaining_entries: entries,
            remaining_bytes: bytes,
            started: Instant::now(),
        }
    }

    pub(super) fn children(&mut self, path: &Path) -> io::Result<Vec<std::path::PathBuf>> {
        self.check_time()?;
        let paths = NativeSafeDiskCachePath::from_path(path.to_path_buf())
            .child_paths_bounded(self.remaining_entries)?;
        self.remaining_entries = self.remaining_entries.saturating_sub(paths.len());
        Ok(paths)
    }

    pub(super) fn charge_read(&mut self, bytes: u64) -> io::Result<()> {
        self.check_time()?;
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(bytes)
            .ok_or_else(|| io::Error::other("cache recovery read budget exceeded"))?;
        Ok(())
    }

    fn check_time(&self) -> io::Result<()> {
        if self.started.elapsed() > Duration::from_secs(30) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "cache recovery time budget exceeded",
            ));
        }
        Ok(())
    }
}

pub(super) fn lowercase_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn object_name(name: &str, shard: &str) -> bool {
    name.strip_suffix(".fhc")
        .is_some_and(|stem| lowercase_hex(stem, 64) && stem.starts_with(shard))
}

pub(super) fn temp_name(name: &str) -> bool {
    name.strip_prefix('.')
        .and_then(|s| s.strip_suffix(".tmp"))
        .is_some_and(|stem| lowercase_hex(stem, 24))
}

pub(super) fn old_temp(metadata: &std::fs::Metadata, now: SystemTime) -> bool {
    metadata
        .modified()
        .ok()
        .and_then(|time| now.duration_since(time).ok())
        .is_some_and(|age| age >= TEMP_MIN_AGE)
}

pub(super) fn recognizable_file(file: &mut File) -> io::Result<bool> {
    let mut prefix = [0_u8; 22];
    let mut read = 0;
    while read < prefix.len() {
        let count = file.read(&mut prefix[read..])?;
        if count == 0 {
            break;
        }
        read += count;
    }
    let bytes = &prefix[..read];
    Ok([
        fluxheim_cache::DISK_CACHE_MAGIC_V1,
        fluxheim_cache::DISK_CACHE_MAGIC_V2,
        fluxheim_cache::DISK_CACHE_MAGIC_V3,
        fluxheim_cache::DISK_CACHE_MAGIC_V4,
        fluxheim_cache::DISK_CACHE_MAGIC_V5,
        super::NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V1,
        super::NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V2,
    ]
    .iter()
    .any(|magic| bytes.starts_with(magic)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_budget_rejects_elapsed_time_and_excess_bytes() {
        let mut budget = RecoveryBudget::new(1, 10);
        budget.charge_read(10).unwrap();
        assert!(budget.charge_read(1).is_err());
        budget.started = Instant::now().checked_sub(Duration::from_secs(31)).unwrap();
        assert_eq!(
            budget.charge_read(0).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_lease_drop_releases_lock_despite_inherited_descriptor() {
        let directory = tempfile::tempdir().unwrap();
        let first = FilesystemRecoveryLease::acquire(directory.path()).unwrap();
        let duplicate = first.file.try_clone().unwrap();
        drop(first);
        let next = FilesystemRecoveryLease::acquire(directory.path()).unwrap();
        assert!(next.exclusive());
        drop(duplicate);
        assert!(FilesystemRecoveryLease::acquire(directory.path()).is_err());
    }
}

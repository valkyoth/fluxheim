//! Shared disk layout for a managed challenge and its publisher's OS lease.
use std::{fs::File, io, path::Path};

pub const ORDER_DIR: &str = ".fluxheim-order";
pub const ACTIVE_DIR: &str = "active";
pub const LEASE: &str = ".fluxheim-acme.lock";

/// Return a published file only while the owner of this generation is alive.
/// Readers never create directories or locks. A reader of an abandoned lease
/// takes a shared lock, so it cannot impersonate an exclusive publisher.
pub fn open_live_file(root: &Path, name: &str) -> io::Result<Option<File>> {
    if name != "fullchain.pem"
        && (name.is_empty()
            || name.len() > 256
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let active = root.join(ORDER_DIR).join(ACTIVE_DIR);
    let lock_path = active.join(LEASE);
    if let Err(e) = std::fs::symlink_metadata(&lock_path) {
        return absent(e);
    }
    let lease = match crate::fs_trust::open_regular_file(&lock_path) {
        Ok(file) => file,
        Err(e) => return absent(e),
    };
    let payload = match crate::fs_trust::open_regular_file(&active.join(name)) {
        Ok(file) => file,
        Err(e) => return absent(e),
    };
    match lease.try_lock_shared() {
        Ok(()) => Ok(None),
        Err(std::fs::TryLockError::WouldBlock) => Ok(Some(payload)),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

fn absent(e: io::Error) -> io::Result<Option<File>> {
    if e.kind() == io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(e)
    }
}

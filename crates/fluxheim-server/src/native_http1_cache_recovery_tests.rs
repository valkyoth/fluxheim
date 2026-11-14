use super::*;

#[test]
fn filesystem_recovery_preserves_ambiguous_leftovers() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = storage_bin_config(&directory.path().canonicalize().unwrap());
    config.disk.backend = CacheDiskBackend::Filesystem;
    let cache = NativeDiskCache::from_config(&config).unwrap();
    cache
        .store(disk_cache_store_key("valid"), &disk_cache_entry(b"body"))
        .unwrap();
    drop(cache);
    let shard = directory.path().join("aa");
    std::fs::create_dir_all(&shard).unwrap();
    let corrupt = shard.join(format!("{}.fhc", "0".repeat(64)));
    let leftover = shard.join(".aaaaaaaaaaaaaaaaaaaaaaaa.tmp");
    std::fs::write(&corrupt, b"invalid object").unwrap();
    std::fs::write(&leftover, b"incomplete object").unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&leftover)
        .unwrap();
    file.set_modified(SystemTime::UNIX_EPOCH).unwrap();
    drop(file);

    let recovered = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
    assert_eq!(recovered.stats().entries, 1);
    assert!(recovered.get("valid", |_| None).is_some());
    // Neither the name nor age alone proves that these arbitrary bytes are ours.
    assert!(corrupt.exists());
    assert!(leftover.exists());
    assert!(!directory.path().join(".fluxheim-disk-index-v1").exists());
}

fn filesystem_config(path: &std::path::Path) -> CacheConfig {
    let mut config = storage_bin_config(&path.canonicalize().unwrap());
    config.disk.backend = CacheDiskBackend::Filesystem;
    config
}

fn recovery_fixture(
    root: &std::path::Path,
    name: &str,
    bytes: &[u8],
    old: bool,
) -> std::path::PathBuf {
    let shard = root.join("aa");
    super::super::native_http1_cache_disk_path::create_native_cache_dir_all(&shard).unwrap();
    let path = shard.join(name);
    let mut file = super::super::native_http1_cache_disk_path::NativeSafeDiskCachePath::from_path(
        path.clone(),
    )
    .create_new_file()
    .unwrap();
    use std::io::Write as _;
    file.write_all(bytes).unwrap();
    if old {
        file.set_modified(SystemTime::UNIX_EPOCH).unwrap();
    }
    path
}

#[test]
fn filesystem_recovery_removes_only_recognizable_idle_leftovers() {
    let directory = tempfile::tempdir().unwrap();
    let config = filesystem_config(directory.path());
    let cache = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
    cache
        .store(
            disk_cache_store_key("valid"),
            &disk_cache_entry(b"retained body"),
        )
        .unwrap();
    let corrupt = recovery_fixture(
        directory.path(),
        &format!("{}.fhc", "a".repeat(64)),
        fluxheim_cache::DISK_CACHE_MAGIC_V5,
        true,
    );
    let old_temp = recovery_fixture(
        directory.path(),
        ".aaaaaaaaaaaaaaaaaaaaaaaa.tmp",
        fluxheim_cache::DISK_CACHE_MAGIC_V5,
        true,
    );
    let fresh_temp = recovery_fixture(
        directory.path(),
        ".bbbbbbbbbbbbbbbbbbbbbbbb.tmp",
        fluxheim_cache::DISK_CACHE_MAGIC_V5,
        false,
    );
    let unrelated = recovery_fixture(directory.path(), "notes.txt", b"operator data", true);
    let unrecognized = recovery_fixture(
        directory.path(),
        ".cccccccccccccccccccccccc.tmp",
        b"unknown data",
        true,
    );
    let mut oversized_bytes = fluxheim_cache::DISK_CACHE_MAGIC_V5.to_vec();
    oversized_bytes.resize(
        super::super::native_http1_cache_disk_path::native_disk_cache_read_limit(
            config.max_object_bytes,
        ) as usize
            + 1,
        0,
    );
    let oversized = recovery_fixture(
        directory.path(),
        &format!("aa{}.fhc", "b".repeat(62)),
        &oversized_bytes,
        true,
    );

    // Another cache/inspection handle cannot collect a live writer's files,
    // even if the writer has an old mtime or has paused for more than an hour.
    let observer = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
    assert!(corrupt.exists() && old_temp.exists() && oversized.exists());
    assert_eq!(
        &*observer.get("valid", |_| None).unwrap().body,
        b"retained body"
    );
    drop(cache);
    let pinned = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
    assert!(old_temp.exists());
    drop(observer);
    drop(pinned);

    for _ in 0..2 {
        let cache = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
        assert_eq!(
            &*cache.get("valid", |_| None).unwrap().body,
            b"retained body"
        );
        assert!(!corrupt.exists() && !old_temp.exists() && !oversized.exists());
        assert_eq!(
            std::fs::read(&fresh_temp).unwrap(),
            fluxheim_cache::DISK_CACHE_MAGIC_V5
        );
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"operator data");
        assert_eq!(std::fs::read(&unrecognized).unwrap(), b"unknown data");
    }
}

#[test]
fn filesystem_recovery_rejects_links_and_special_files() {
    let directory = tempfile::tempdir().unwrap();
    let config = filesystem_config(directory.path());
    let original = recovery_fixture(
        directory.path(),
        "outside",
        fluxheim_cache::DISK_CACHE_MAGIC_V5,
        true,
    );
    let hard = directory
        .path()
        .join("aa")
        .join(format!("{}.fhc", "a".repeat(64)));
    std::fs::hard_link(&original, &hard).unwrap();
    let child_dir = directory.path().join("aa/.bbbbbbbbbbbbbbbbbbbbbbbb.tmp");
    std::fs::create_dir(&child_dir).unwrap();
    #[cfg(unix)]
    {
        let link = directory.path().join("aa/.cccccccccccccccccccccccc.tmp");
        std::os::unix::fs::symlink(&original, link).unwrap();
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(directory.path().join("aa/.dddddddddddddddddddddddd.tmp"))
                .status()
                .unwrap()
                .success()
        );
    }
    let cache = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
    assert_eq!(cache.stats().entries, 0);
    assert!(hard.exists() && child_dir.is_dir());
    assert_eq!(
        std::fs::read(original).unwrap(),
        fluxheim_cache::DISK_CACHE_MAGIC_V5
    );
}

#[test]
fn filesystem_recovery_budget_and_accounting_are_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let config = filesystem_config(directory.path());
    let ambiguous = recovery_fixture(
        directory.path(),
        ".aaaaaaaaaaaaaaaaaaaaaaaa.tmp",
        b"unknown",
        true,
    );
    let recognized = recovery_fixture(
        directory.path(),
        &format!("{}.fhc", "a".repeat(64)),
        fluxheim_cache::DISK_CACHE_MAGIC_V5,
        true,
    );
    let cache = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
    assert!(!recognized.exists());
    let mut state = super::super::NativeDiskCacheState::default();
    let report = cache.recover_filesystem(&mut state, 10, 4096).unwrap();
    assert_eq!(report.retained_files, 1);
    assert_eq!(report.retained_bytes, 7);
    assert!(cache.recover_filesystem(&mut state, 1, 4096).is_err());
    assert!(cache.recover_filesystem(&mut state, 10, 0).is_err());
    assert_eq!(std::fs::read(ambiguous).unwrap(), b"unknown");
}

#[test]
fn filesystem_recovery_preserves_unknown_ciphertext_and_nonstandard_names() {
    let directory = tempfile::tempdir().unwrap();
    let config = filesystem_config(directory.path());
    let ciphertext = recovery_fixture(
        directory.path(),
        &format!("{}.fhc", "a".repeat(64)),
        super::super::NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V2,
        true,
    );
    let misplaced = recovery_fixture(
        directory.path(),
        &format!("{}.fhc", "b".repeat(64)),
        fluxheim_cache::DISK_CACHE_MAGIC_V5,
        true,
    );
    let old_name = recovery_fixture(
        directory.path(),
        "legacy.fhc",
        fluxheim_cache::DISK_CACHE_MAGIC_V5,
        true,
    );
    for _ in 0..2 {
        let cache = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
        assert_eq!(cache.stats().entries, 0);
        assert_eq!(
            std::fs::read(&ciphertext).unwrap(),
            super::super::NATIVE_DISK_CACHE_ENCRYPTED_MAGIC_V2
        );
        for path in [&misplaced, &old_name] {
            assert_eq!(
                std::fs::read(path).unwrap(),
                fluxheim_cache::DISK_CACHE_MAGIC_V5
            );
        }
    }
}

#[test]
fn filesystem_recovery_failed_removal_is_retained_and_counted() {
    let directory = tempfile::tempdir().unwrap();
    let child = directory.path().join("not-a-file");
    std::fs::create_dir(&child).unwrap();
    let mut report = super::super::native_http1_cache_recovery::RecoveryReport::default();
    report.remove_or_retain(&child, 123, true);
    assert_eq!(report.failed_removals, 1);
    assert_eq!(report.retained_bytes, 123);
    assert_eq!(report.removed_bytes, 0);
    assert!(child.is_dir());
}

#[cfg(unix)]
#[test]
fn filesystem_recovery_permission_denial_preserves_bytes() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::tempdir().unwrap();
    let path = recovery_fixture(
        directory.path(),
        ".aaaaaaaaaaaaaaaaaaaaaaaa.tmp",
        fluxheim_cache::DISK_CACHE_MAGIC_V5,
        true,
    );
    let parent = path.parent().unwrap();
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o500)).unwrap();
    let mut report = super::super::native_http1_cache_recovery::RecoveryReport::default();
    report.remove_or_retain(
        &path,
        fluxheim_cache::DISK_CACHE_MAGIC_V5.len() as u64,
        true,
    );
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    if rustix::process::geteuid().is_root() {
        return;
    }
    assert_eq!(report.failed_removals, 1);
    assert_eq!(report.retained_files, 1);
    assert_eq!(
        std::fs::read(path).unwrap(),
        fluxheim_cache::DISK_CACHE_MAGIC_V5
    );
}

#[test]
fn filesystem_recovery_lease_is_exclusive_only_while_initializing() {
    use super::super::native_http1_cache_recovery::FilesystemRecoveryLease;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut first = FilesystemRecoveryLease::acquire(&root).unwrap();
    assert!(first.exclusive());
    assert!(FilesystemRecoveryLease::acquire(&root).is_err());
    first.finish_recovery().unwrap();
    let second = FilesystemRecoveryLease::acquire(&root).unwrap();
    assert!(!second.exclusive());
    drop(first);
    let third = FilesystemRecoveryLease::acquire(&root).unwrap();
    assert!(!third.exclusive());
    drop(second);
    drop(third);
    assert!(FilesystemRecoveryLease::acquire(&root).unwrap().exclusive());
}

#[test]
fn filesystem_recovery_age_and_names_are_strict() {
    use super::super::native_http1_cache_recovery::{object_name, old_temp, temp_name};
    assert!(object_name(&format!("{}.fhc", "a".repeat(64)), "aa"));
    assert!(!object_name(&format!("{}.fhc", "a".repeat(64)), "bb"));
    assert!(!object_name(&format!("{}.fhc", "A".repeat(64)), "AA"));
    assert!(!temp_name(".old.tmp"));
    let directory = tempfile::tempdir().unwrap();
    let path = recovery_fixture(
        directory.path(),
        ".aaaaaaaaaaaaaaaaaaaaaaaa.tmp",
        b"",
        false,
    );
    let metadata = std::fs::metadata(path).unwrap();
    assert!(!old_temp(&metadata, SystemTime::UNIX_EPOCH));
}

#[cfg(unix)]
#[test]
fn filesystem_reader_retains_bytes_after_unlink() {
    use super::super::native_http1_cache_disk_path::{
        NativeSafeDiskCachePath, validate_single_link_file,
    };
    use std::io::Read as _;
    let directory = tempfile::tempdir().unwrap();
    let path = recovery_fixture(
        directory.path(),
        ".aaaaaaaaaaaaaaaaaaaaaaaa.tmp",
        b"pinned bytes",
        true,
    );
    let safe = NativeSafeDiskCachePath::from_path(path.clone());
    let mut reader = safe.open_existing_file().unwrap();
    safe.remove_file().unwrap();
    assert!(!path.exists());
    assert!(validate_single_link_file(&reader).is_err());
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"pinned bytes");
}

#[test]
fn documented_storage_bin_missing_index_is_cold_without_object_salvage() {
    let directory = tempfile::tempdir().unwrap();
    let config = storage_bin_config(&directory.path().canonicalize().unwrap());
    let cache = NativeDiskCache::from_config(&config).unwrap();
    cache
        .store(disk_cache_store_key("valid"), &disk_cache_entry(b"body"))
        .unwrap();
    drop(cache);
    let index = directory.path().join(".fluxheim-storage-bin-index-v1");
    assert!(index.exists());
    std::fs::remove_file(index).unwrap();
    let recovered = NativeDiskCache::try_from_config(&config).unwrap().unwrap();
    assert_eq!(recovered.stats().entries, 0);
    assert!(recovered.get("valid", |_| None).is_none());
    recovered
        .store(disk_cache_store_key("new"), &disk_cache_entry(b"new"))
        .unwrap();
    assert_eq!(&*recovered.get("new", |_| None).unwrap().body, b"new");
}

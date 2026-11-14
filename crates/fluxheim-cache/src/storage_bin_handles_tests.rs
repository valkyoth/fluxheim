use super::*;
use fluxheim_config::ByteSize;
use std::io::ErrorKind;

fn fixture(limit: usize) -> (tempfile::TempDir, StorageBinFileSet) {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();
    let layout = StorageBinLayoutPlan {
        manifest_path: root_path.join(STORAGE_BIN_MANIFEST_FILENAME),
        data_dir: root_path.join(STORAGE_BIN_DATA_DIR),
        root: root_path,
        bin_size_bytes: ByteSize::from_bytes(4096),
        max_size_bytes: ByteSize::from_bytes(4096 * 8),
        preallocate: true,
        max_open_bins: limit,
    };
    (root, StorageBinFileSet::new(layout))
}

fn location(bin_id: u64) -> StorageBinObjectLocation {
    StorageBinObjectLocation {
        bin_id,
        offset: 8,
        len: 4,
    }
}

#[test]
fn storage_bin_open_limit_one_is_shared_and_closes_before_reclaim() {
    let (_root, files) = fixture(1);
    files.write_object(location(0), b"zero").unwrap();
    files.write_object(location(1), b"one!").unwrap();
    let clone = files.clone();
    let mut held = files.open_bin_for_read(0).unwrap();
    assert_eq!(
        clone.read_object(location(1)).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    assert_eq!(
        clone.write_object(location(1), b"nope").unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    assert_eq!(
        clone.remove_bin(0).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    assert_eq!(
        clone.remove_bin(1).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    assert_eq!(
        read_storage_bin_range(&mut held.file, 8, 4).unwrap(),
        b"zero"
    );
    drop(files);
    drop(held);
    assert_eq!(clone.read_object(location(1)).unwrap(), b"one!");
    clone.remove_bin(0).unwrap();
    assert!(!clone.layout.bin_path(0).exists());
    clone.write_object(location(0), b"next").unwrap();
    assert_eq!(clone.read_object(location(0)).unwrap(), b"next");
}

#[test]
fn storage_bin_open_limit_counts_handles_not_unique_bins_and_is_seek_independent() {
    let (_root, files) = fixture(2);
    files.write_object(location(0), b"zero").unwrap();
    let mut first = files.open_bin_for_read(0).unwrap();
    let mut second = files.open_bin_for_read(0).unwrap();
    assert_eq!(
        files.open_bin_for_read(1).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    first.file.seek(std::io::SeekFrom::Start(8)).unwrap();
    second.file.seek(std::io::SeekFrom::Start(12)).unwrap();
    let mut bytes = [0; 4];
    first.file.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"zero");
    drop(second);
    // There is free global capacity, but deletion cannot race a reader.
    assert_eq!(
        files.remove_bin(0).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    drop(first);
    files.remove_bin(0).unwrap();
}

#[test]
fn storage_bin_open_limit_errors_and_unwinding_return_capacity() {
    let (_root, files) = fixture(1);
    for _ in 0..32 {
        assert!(files.read_object(location(0)).is_err());
        assert!(files.write_object(location(8), b"nope").is_err());
        assert!(files.write_object(location(0), b"bad length").is_err());
    }
    files.write_object(location(0), b"zero").unwrap();
    let unwind = std::panic::catch_unwind(|| {
        let _file = files.open_bin_for_read(0).unwrap();
        panic!("cancel test operation after opening its bin");
    });
    assert!(unwind.is_err());
    // Inject a short read after the actual handle is opened.
    std::fs::OpenOptions::new()
        .write(true)
        .open(files.layout.bin_path(0))
        .unwrap()
        .set_len(1)
        .unwrap();
    assert_eq!(
        files.read_object(location(0)).unwrap_err().kind(),
        ErrorKind::UnexpectedEof
    );
    files.write_object(location(0), b"next").unwrap();
    assert_eq!(files.read_object(location(0)).unwrap(), b"next");
    files.remove_bin(0).unwrap();
    files.remove_bin(0).unwrap();
}

#[test]
fn storage_bin_open_limit_zero_rejects_without_filesystem_mutation() {
    let (_root, files) = fixture(0);
    assert_eq!(
        files.write_object(location(0), b"nope").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        files.read_object(location(0)).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        files.remove_bin(0).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert!(!files.layout.data_dir.exists());
}

#[test]
fn storage_bin_open_limit_cancelled_future_drops_its_handle() {
    use std::future::Future as _;
    let (_root, files) = fixture(1);
    files.write_object(location(0), b"zero").unwrap();
    let mut pending = Box::pin(async {
        let held = files.open_bin_for_read(0).unwrap();
        std::future::pending::<()>().await;
        drop(held);
    });
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(pending.as_mut().poll(&mut context).is_pending());
    assert_eq!(
        files.read_object(location(0)).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    drop(pending);
    assert_eq!(files.read_object(location(0)).unwrap(), b"zero");
}

#[test]
fn storage_bin_open_limit_concurrent_actual_handles_are_bounded() {
    for limit in [1, 2] {
        concurrent_actual_handles(limit);
    }
}

fn concurrent_actual_handles(limit: usize) {
    let (_root, files) = fixture(limit);
    for id in 0..8 {
        files.write_object(location(id), b"data").unwrap();
    }
    let start = std::sync::Barrier::new(9);
    let opened = std::sync::Barrier::new(9);
    let release = std::sync::Barrier::new(9);
    let live = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for id in 0..8 {
            let (files, start, opened, release, live) = (&files, &start, &opened, &release, &live);
            scope.spawn(move || {
                start.wait();
                let held = files.open_bin_for_read(id);
                if held.is_ok() {
                    live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                opened.wait();
                release.wait();
                match held {
                    Ok(mut held) => assert_eq!(
                        read_storage_bin_range(&mut held.file, 8, 4).unwrap(),
                        b"data"
                    ),
                    Err(error) => assert_eq!(error.kind(), ErrorKind::WouldBlock),
                }
            });
        }
        start.wait();
        opened.wait();
        let count = live.load(std::sync::atomic::Ordering::SeqCst);
        release.wait();
        assert_eq!(count, limit, "actual live file count");
    });
    // Every bin remains readable after the simultaneous admitted operations end.
    for id in 0..8 {
        assert_eq!(files.read_object(location(id)).unwrap(), b"data");
    }
}

#[test]
fn storage_bin_open_limit_concurrent_creation_and_disjoint_writes_preserve_bytes() {
    let (_root, files) = fixture(2);
    for _ in 0..16 {
        let start = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            for (offset, body) in [(8, b"zero"), (12, b"one!")] {
                let (files, start) = (&files, &start);
                scope.spawn(move || {
                    start.wait();
                    files
                        .write_object(
                            StorageBinObjectLocation {
                                bin_id: 0,
                                offset,
                                len: 4,
                            },
                            body,
                        )
                        .unwrap();
                });
            }
        });
        assert_eq!(files.read_object(location(0)).unwrap(), b"zero");
        assert_eq!(
            files
                .read_object(StorageBinObjectLocation {
                    bin_id: 0,
                    offset: 12,
                    len: 4
                })
                .unwrap(),
            b"one!"
        );
        assert_eq!(
            std::fs::metadata(files.layout.bin_path(0)).unwrap().len(),
            4096
        );
        files.remove_bin(0).unwrap();
    }
}

#[test]
fn storage_bin_open_limit_exclusive_removal_and_unwind_cleanup() {
    let (_root, files) = fixture(2);
    files.write_object(location(0), b"zero").unwrap();
    let permit = files.admission.reserve(0, true).unwrap();
    assert_eq!(
        files.read_object(location(0)).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    assert_eq!(
        files.remove_bin(0).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    files.write_object(location(1), b"one!").unwrap();
    drop(permit);
    let _ = std::panic::catch_unwind(|| {
        let _guard = files.admission.reserve(0, false).unwrap();
        // A panic while holding a permit does not poison bookkeeping.
        panic!("unwind permit");
    });
    assert_eq!(files.read_object(location(0)).unwrap(), b"zero");
}

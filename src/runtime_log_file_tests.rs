use super::*;

fn fixture() -> tempfile::TempDir {
    tempfile::tempdir_in(fluxheim_common::test_support::test_root()).unwrap()
}

fn due(sink: &Sink) {
    sink.0.lock().unwrap().next_check = Instant::now();
}

#[test]
fn rename_delete_and_truncate_keep_whole_records_and_release_handles() {
    let directory = fixture();
    let path = directory.path().join("events.log");
    let rotated = directory.path().join("events.old");
    let mut first = Sink::new(&path, true, None).unwrap();
    let mut second = first.clone();
    let counters = first.counters().unwrap();
    first.write_all(b"before\n").unwrap();
    std::fs::rename(&path, &rotated).unwrap();
    due(&first);
    second.write_all(b"after\n").unwrap();
    first.write_all(b"same-handle\n").unwrap();
    assert_eq!(std::fs::read(&rotated).unwrap(), b"before\n");
    assert_eq!(std::fs::read(&path).unwrap(), b"after\nsame-handle\n");
    assert_eq!(counters.status().reopens, 1);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(0)
        .unwrap();
    first.write_all(b"truncated\n").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"truncated\n");
    std::fs::remove_file(&path).unwrap();
    due(&second);
    second.write_all(b"recreated\n").unwrap();
    #[cfg(unix)]
    {
        assert_eq!(std::fs::read(&path).unwrap(), b"recreated\n");
        assert_eq!(counters.status().reopens, 2);
    }
    #[cfg(windows)]
    {
        // Windows removal APIs may unlink immediately or defer deletion until
        // the last handle closes. A pending delete must keep the trusted handle.
        if counters.status().reopens == 2 {
            assert_eq!(std::fs::read(&path).unwrap(), b"recreated\n");
        } else {
            assert_eq!(counters.status().reopen_errors, 1);
            assert_eq!(counters.status().reopens, 1);
            assert_eq!(second.0.lock().unwrap().file.metadata().unwrap().len(), 20);
        }
    }
    drop((first, second));
    assert!(!counters.status().handle_open);
    let mut restarted = Sink::new(&path, false, None).unwrap();
    restarted.write_all(b"restart\n").unwrap();
    drop(restarted);
    assert_eq!(std::fs::read(&path).unwrap(), b"restart\n");
    directory.close().unwrap();
}

#[test]
fn failed_reopen_keeps_old_handle_and_is_rate_limited_then_recovers() {
    let directory = fixture();
    let path = directory.path().join("events.log");
    let rotated = directory.path().join("events.old");
    let mut sink = Sink::new(&path, false, None).unwrap();
    let counters = sink.counters().unwrap();
    std::fs::rename(&path, &rotated).unwrap();
    std::fs::create_dir(&path).unwrap();
    due(&sink);
    sink.write_all(b"old\n").unwrap();
    for _ in 0..10 {
        sink.write_all(b"old\n").unwrap();
    }
    assert_eq!(counters.status().reopen_errors, 1);
    assert_eq!(counters.status().checks, 1);
    assert_eq!(std::fs::read(&rotated).unwrap(), b"old\n".repeat(11));
    std::fs::remove_dir(&path).unwrap();
    // Non-append applies at startup only. An existing replacement is preserved.
    drop(open(&path, true).unwrap());
    std::fs::write(&path, b"replacement\n").unwrap();
    due(&sink);
    sink.write_all(b"new\n").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"replacement\nnew\n");
    assert_eq!(counters.status().reopens, 1);
}

#[test]
fn crash_alias_is_rejected_at_startup_and_reopen_without_truncation() {
    let directory = fixture();
    let crash_path = directory.path().join("fatal.log");
    let path = directory.path().join("events.log");
    let mut crash = super::super::crash::open(&crash_path).unwrap();
    crash.write_all(b"fatal-evidence\n").unwrap();
    std::fs::hard_link(&crash_path, &path).unwrap();
    assert!(Sink::new(&path, false, Some(&crash)).is_err());
    std::fs::remove_file(&path).unwrap();
    let mut sink = Sink::new(&path, true, Some(&crash)).unwrap();
    let old = directory.path().join("events.old");
    std::fs::rename(&path, &old).unwrap();
    std::fs::hard_link(&crash_path, &path).unwrap();
    due(&sink);
    sink.write_all(b"ordinary\n").unwrap();
    assert_eq!(std::fs::read(&old).unwrap(), b"ordinary\n");
    assert_eq!(std::fs::read(&crash_path).unwrap(), b"fatal-evidence\n");
    assert_eq!(sink.counters().unwrap().status().reopen_errors, 1);
}

#[test]
fn concurrent_lanes_do_not_interleave_records_and_drop_releases_sink() {
    let directory = fixture();
    let path = directory.path().join("events.log");
    let sink = Sink::new(&path, true, None).unwrap();
    let counters = sink.counters().unwrap();
    let start = Arc::new(std::sync::Barrier::new(5));
    let workers: Vec<_> = (0..4)
        .map(|n| {
            let mut writer = sink.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                let record = format!("{n}:{}\n", "x".repeat(4096));
                for _ in 0..50 {
                    writer.write_all(record.as_bytes()).unwrap();
                }
            })
        })
        .collect();
    start.wait();
    let mut archives = Vec::new();
    for n in 0..5 {
        let archive = directory.path().join(format!("events.{n}"));
        std::fs::rename(&path, &archive).unwrap();
        due(&sink);
        sink.clone().write_all(b"rotation-marker\n").unwrap();
        archives.push(archive);
    }
    drop(sink);
    for worker in workers {
        worker.join().unwrap();
    }
    archives.push(path);
    let content: String = archives
        .iter()
        .map(|path| std::fs::read_to_string(path).unwrap())
        .collect();
    assert_eq!(
        content
            .lines()
            .filter(|line| *line == "rotation-marker")
            .count(),
        5
    );
    let content = content.replace("rotation-marker\n", "");
    assert_eq!(content.lines().count(), 200);
    for line in content.lines() {
        assert_eq!(line.len(), 4098);
        assert!(line[2..].bytes().all(|byte| byte == b'x'));
    }
    assert!(!counters.status().handle_open);
}

#[test]
fn partial_write_and_storage_failure_latch_without_replay() {
    struct Failing {
        bytes: Vec<u8>,
        kind: io::ErrorKind,
    }
    impl Write for Failing {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.bytes.is_empty() {
                self.bytes.extend_from_slice(&bytes[..2]);
                Ok(2)
            } else {
                Err(io::Error::from(self.kind))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for kind in [
        io::ErrorKind::StorageFull,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::WriteZero,
    ] {
        let mut writer = Failing {
            bytes: Vec::new(),
            kind,
        };
        let counters = Counters::default();
        assert!(finish_write(writer.write_all(b"record\n"), &counters).is_err());
        assert_eq!(writer.bytes, b"re");
        assert_eq!(counters.status().write_errors, 1);
        assert!(counters.status().failed);
    }
}

#[cfg(unix)]
#[test]
fn hostile_replacement_and_permission_loss_fail_closed() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = fixture();
    let path = directory.path().join("events.log");
    let old = directory.path().join("events.old");
    let target = directory.path().join("private-data");
    std::fs::write(&target, b"unchanged").unwrap();
    let mut sink = Sink::new(&path, true, None).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    std::fs::rename(&path, &old).unwrap();
    symlink(&target, &path).unwrap();
    due(&sink);
    sink.write_all(b"trusted-old\n").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
    assert_eq!(sink.counters().unwrap().status().reopen_errors, 1);
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(sink.write_all(b"must-not-write\n").is_err());
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(sink.write_all(b"must-not-retry\n").is_err());
    assert_eq!(std::fs::read(&old).unwrap(), b"trusted-old\n");
    assert_eq!(sink.counters().unwrap().status().write_errors, 1);
}

#[test]
fn blocked_file_worker_does_not_block_shutdown_and_eventually_releases_handle() {
    let directory = fixture();
    let path = directory.path().join("events.log");
    let sink = Sink::new(&path, true, None).unwrap();
    let counters = sink.counters().unwrap();
    let state = sink.0.clone();
    let lock = state.lock().unwrap();
    let logger = super::super::dispatch::Logger::new(
        env_logger::Builder::new()
            .filter_level(log::LevelFilter::Info)
            .build(),
        crate::config::LoggingFormat::Json,
        Box::new(sink),
    )
    .unwrap();
    log::Log::log(
        &logger,
        &log::Record::builder()
            .level(log::Level::Info)
            .args(format_args!("bounded shutdown"))
            .build(),
    );
    let start = Instant::now();
    logger.shutdown(Duration::from_millis(10));
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(logger);
    drop(lock);
    drop(state);
    let deadline = Instant::now() + Duration::from_secs(5);
    while counters.status().handle_open {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        std::fs::read_to_string(path)
            .unwrap()
            .contains("bounded shutdown")
    );
}

#[cfg(unix)]
#[test]
fn fifo_and_untrusted_leaf_are_rejected_before_truncation() {
    use std::os::unix::fs::PermissionsExt;
    let directory = fixture();
    let path = directory.path().join("events.log");
    assert!(
        std::process::Command::new("/usr/bin/mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    assert!(open(&path, false).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"must-not-truncate").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(open(&path, false).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"must-not-truncate");
}

#[cfg(windows)]
#[test]
fn replacement_sharing_conflict_keeps_old_handle_then_recovers() {
    use std::os::windows::fs::OpenOptionsExt;
    let directory = fixture();
    let path = directory.path().join("events.log");
    let old = directory.path().join("events.old");
    let mut sink = Sink::new(&path, true, None).unwrap();
    std::fs::rename(&path, &old).unwrap();
    let exclusive = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    due(&sink);
    sink.write_all(b"old\n").unwrap();
    assert_eq!(sink.counters().unwrap().status().reopen_errors, 1);
    drop(exclusive);
    due(&sink);
    sink.write_all(b"new\n").unwrap();
    assert_eq!(std::fs::read(&old).unwrap(), b"old\n");
    assert_eq!(std::fs::read(&path).unwrap(), b"new\n");
}

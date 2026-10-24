use super::*;

#[cfg(unix)]
fn permissions(path: &Path, readers: Option<bool>) {
    use std::os::unix::fs::PermissionsExt;
    let mode = match readers {
        None => 0o600,
        Some(true) => 0o640,
        Some(false) => 0o644,
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(windows)]
fn permissions(path: &Path, readers: Option<bool>) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let current = windows_permissions::utilities::current_process_sid().unwrap();
    let extra = match readers {
        None => "",
        Some(true) => "(A;;FR;;;BG)",  // Built-in Guests group.
        Some(false) => "(A;;FR;;;WD)", // Everyone.
    };
    let descriptor: LocalBox<SecurityDescriptor> =
        format!("D:P(A;;FA;;;{current})(A;;FA;;;SY)(A;;FA;;;BA){extra}")
            .parse()
            .unwrap();
    windows_permissions::wrappers::SetNamedSecurityInfo(
        path,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        descriptor.dacl(),
        None,
    )
    .unwrap();
}

fn fixture() -> tempfile::TempDir {
    tempfile::tempdir_in(fluxheim_common::test_support::test_root()).unwrap()
}

#[test]
fn readable_existing_logs_are_rejected_without_truncation() {
    for group_only in [true, false] {
        let directory = fixture();
        let path = directory.path().join("events.log");
        std::fs::write(&path, b"existing-evidence\n").unwrap();
        permissions(&path, Some(group_only));
        for append in [true, false] {
            let error = match Sink::new(&path, append, None) {
                Ok(_) => panic!("readable existing log accepted"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                open(&path, append).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(std::fs::read(&path).unwrap(), b"existing-evidence\n");
        }
    }
}

#[test]
fn readable_replacement_keeps_private_handle_until_permissions_are_repaired() {
    for group_only in [true, false] {
        let directory = fixture();
        let path = directory.path().join("events.log");
        let old = directory.path().join("events.old");
        let mut sink = Sink::new(&path, true, None).unwrap();
        let mut other_lane = sink.clone();
        let counters = sink.counters().unwrap();
        sink.write_all(b"before\n").unwrap();
        std::fs::rename(&path, &old).unwrap();
        std::fs::write(&path, b"replacement-prefix\n").unwrap();
        permissions(&path, Some(group_only));
        sink.0.lock().unwrap().next_check = Instant::now();
        other_lane.write_all(b"retained\n").unwrap();
        assert_eq!(std::fs::read(&old).unwrap(), b"before\nretained\n");
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement-prefix\n");
        assert_eq!(counters.status().reopen_errors, 1);
        assert_eq!(counters.status().reopens, 0);
        assert_eq!(counters.status().write_errors, 0);
        assert!(!counters.status().failed);

        permissions(&path, None);
        sink.0.lock().unwrap().next_check = Instant::now();
        sink.write_all(b"recovered\n").unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"replacement-prefix\nrecovered\n"
        );
        assert_eq!(counters.status().reopens, 1);
    }
}

#[test]
fn active_log_read_access_latches_failure_before_any_further_record() {
    for group_only in [true, false] {
        for reopen_due in [true, false] {
            let directory = fixture();
            let path = directory.path().join("events.log");
            let mut sink = Sink::new(&path, true, None).unwrap();
            let mut other_lane = sink.clone();
            let counters = sink.counters().unwrap();
            sink.write_all(b"before\n").unwrap();
            permissions(&path, Some(group_only));
            sink.0.lock().unwrap().next_check = Instant::now()
                + if reopen_due {
                    Duration::ZERO
                } else {
                    Duration::from_secs(60)
                };
            let error = sink.write_all(b"must-not-write\n").unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(counters.status().failed);
            assert_eq!(counters.status().write_errors, 1);
            assert_eq!(std::fs::read(&path).unwrap(), b"before\n");
            permissions(&path, None);
            assert!(other_lane.write_all(b"must-not-retry\n").is_err());
            assert_eq!(counters.status().write_errors, 1);
            assert_eq!(std::fs::read(&path).unwrap(), b"before\n");
        }
    }
}

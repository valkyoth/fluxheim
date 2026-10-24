use super::*;

#[test]
fn poisoned_admin_throttle_reports_before_abort_with_logging_off() {
    const CHILD: &str = "FLUXHEIM_ADMIN_FATAL_CHILD";
    if std::env::var_os(CHILD).is_some() {
        #[cfg(unix)]
        rustix::process::setrlimit(
            rustix::process::Resource::Core,
            rustix::process::Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .unwrap();
        log::set_max_level(log::LevelFilter::Off);
        fluxheim_common::fatal::start_watchdog().unwrap();
        let throttle = AdminAuthThrottle::new(AdminAuthThrottleConfig::default());
        let state = throttle.state.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = state.lock().unwrap();
                panic!("fixture: poison admin state");
            })
            .join()
            .is_err()
        );
        drop(throttle.lock_state());
        panic!("poisoned admin state must not be recovered");
    }
    let output = fluxheim_common::test_process::self_command(fluxheim_common::test_process::TestBinary::Server).unwrap()
        .args(["--exact", "admin::security::fatal_tests::poisoned_admin_throttle_reports_before_abort_with_logging_off", "--nocapture"])
        .env(CHILD, "1").output().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(output.status.signal(), Some(6), "{output:?}");
    }
    #[cfg(windows)]
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("FATAL_SECURITY reason=AdminAuthThrottlePoisoned\n"),
        "{output:?}"
    );
}

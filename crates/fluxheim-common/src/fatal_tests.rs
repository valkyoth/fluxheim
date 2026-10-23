use super::*;
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::time::Instant;

const CHILD: &str = "FLUXHEIM_WATCHDOG_TEST";
const TEST: &str =
    "fatal::tests::termination_is_bounded_with_real_full_stderr_and_stalled_crash_sink";

#[cfg(target_os = "linux")]
#[test]
fn memory_dump_policy_is_effective_and_inherited_by_threads() {
    use rustix::process::{DumpableBehavior, dumpable_behavior};

    const CHILD: &str = "FLUXHEIM_DUMP_POLICY_TEST";
    if std::env::var_os(CHILD).is_some() {
        // Keep the test harness process unchanged; only this child is hardened.
        disable_memory_dumps().unwrap();
        disable_memory_dumps().unwrap();
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        thread::spawn(|| {
            assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        })
        .join()
        .unwrap();
        return;
    }
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "fatal::tests::memory_dump_policy_is_effective_and_inherited_by_threads",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .status()
        .unwrap();
    assert!(status.success());
}

fn block_real_stderr() {
    let (locked, received) = mpsc::channel();
    let finished = Arc::new(AtomicBool::new(false));
    let writer_finished = finished.clone();
    thread::spawn(move || {
        let mut stderr = io::stderr().lock();
        locked.send(()).unwrap();
        // The parent does not read this pipe until the child terminates. Keep
        // Rust's actual global stderr lock held during the blocking OS write.
        stderr.write_all(&vec![b'x'; 1024 * 1024]).unwrap();
        writer_finished.store(true, Ordering::Release);
    });
    received.recv_timeout(Duration::from_secs(5)).unwrap();
    thread::sleep(Duration::from_millis(100));
    assert!(
        !finished.load(Ordering::Acquire),
        "stderr pipe unexpectedly accepted 1 MiB"
    );
}

#[test]
fn termination_is_bounded_with_real_full_stderr_and_stalled_crash_sink() {
    if let Ok(mode) = std::env::var(CHILD) {
        disable_memory_dumps().unwrap();
        #[cfg(unix)]
        rustix::process::setrlimit(
            rustix::process::Resource::Core,
            rustix::process::Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .unwrap();
        if mode != "before-init" && mode != "before-init-full" {
            start_watchdog().unwrap();
            start_watchdog().unwrap(); // Idempotent, never resets a fatal deadline.
        }
        if mode == "fallback-full" {
            let file = tempfile::NamedTempFile::new().unwrap();
            install(File::open(file.path()).unwrap()).unwrap(); // Cannot write.
        }
        if mode.ends_with("full") {
            block_real_stderr();
        }
        if mode == "sink-lock" || mode == "concurrent" {
            install(tempfile::tempfile().unwrap()).unwrap();
            let _held = SINK.get().unwrap().lock().unwrap();
            if mode == "concurrent" {
                for _ in 0..4 {
                    thread::spawn(|| abort(Reason::AdminStatePoisoned));
                }
                loop {
                    thread::park();
                }
            }
            abort(Reason::AdminStatePoisoned);
        }
        if mode.starts_with("exit") {
            exit(Reason::MetricsListenerBindFailed);
        }
        abort(Reason::AdminStatePoisoned);
    }

    for mode in [
        "full",
        "fallback-full",
        "sink-lock",
        "concurrent",
        "before-init",
        "before-init-full",
        "exit",
        "exit-full",
    ] {
        let started = Instant::now();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, mode)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Includes process startup and a generous native-CI scheduling margin.
        // Never drain stderr while waiting: that would hide the original bug.
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() > Duration::from_secs(5) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("fatal path failed to terminate with {mode}");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        if mode == "exit" {
            assert_eq!(output.status.code(), Some(1));
            assert_eq!(output.stderr, Reason::MetricsListenerBindFailed.record());
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt as _;
                assert_eq!(output.status.signal(), Some(6), "{mode}: {output:?}");
            }
            #[cfg(windows)]
            assert!(!output.status.success(), "{mode}");
        }
        if mode.ends_with("full") {
            assert!(
                !output.stderr.is_empty(),
                "writer did not reach the OS pipe: {mode}"
            );
            assert!(
                output.stderr.len() < 1024 * 1024,
                "pipe was not full: {mode}"
            );
            assert!(
                output.stderr.contains(&b'x'),
                "pipe filler never wrote: {mode}"
            );
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains("FATAL_SECURITY"),
                "fatal write unexpectedly acquired the blocked stderr lock: {mode}"
            );
        }
        if mode == "before-init" {
            assert!(output.stderr.is_empty());
        }
    }
}

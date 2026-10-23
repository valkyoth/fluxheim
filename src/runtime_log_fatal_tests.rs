use super::*;
use std::process::{Command, Stdio};

const CHILD: &str = "FLUXHEIM_FATAL_CHILD";
const PATH: &str = "FLUXHEIM_FATAL_PATH";
const TEST: &str =
    "runtime::runtime_logging::dispatch::fatal_tests::fatal_reporting_survives_logging_failure";

struct Broken;
impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Blocked;
impl Write for Blocked {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        loop {
            std::thread::park();
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn fatal_reporting_survives_logging_failure() {
    if let Ok(mode) = std::env::var(CHILD) {
        #[cfg(unix)]
        rustix::process::setrlimit(
            rustix::process::Resource::Core,
            rustix::process::Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .unwrap();
        let path = std::path::PathBuf::from(std::env::var_os(PATH).unwrap());
        fluxheim_common::fatal::start_watchdog().unwrap();
        let config = crate::config::Config::default();
        if mode == "startup" {
            let mut config = config;
            config.logging.crash_file = Some(path);
            let _guard = super::super::init_logging(&config).unwrap();
            fluxheim_common::fatal::abort(
                fluxheim_common::fatal::Reason::AdminAuthThrottlePoisoned,
            );
        }
        if mode != "stderr" {
            let mut file = super::super::crash::open(&path).unwrap();
            if mode == "append" {
                file.write_all(b"previous crash\n").unwrap();
            }
            if mode == "sink-failed" {
                drop(file);
                file = std::fs::File::open(&path).unwrap();
            }
            fluxheim_common::fatal::install(file).unwrap();
            let second = super::super::crash::open(&path).unwrap();
            assert!(fluxheim_common::fatal::install(second).is_err());
        }
        if mode != "uninitialized" {
            let writer: Box<dyn Write + Send> = if mode == "failed" {
                Box::new(Broken)
            } else {
                Box::new(Blocked)
            };
            let logger = Arc::new(
                Logger::new(
                    env_logger::Builder::new().parse_filters("info").build(),
                    crate::config::LoggingFormat::Json,
                    writer,
                )
                .unwrap(),
            );
            log::set_boxed_logger(Box::new(logger.clone())).unwrap();
            log::set_max_level(log::LevelFilter::Info);
            for _ in 0..CAPACITY + 1 {
                log::info!("ordinary queue fixture");
            }
            if mode == "failed" {
                let deadline = Instant::now() + Duration::from_secs(5);
                while logger.status().worker_alive {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(1));
                }
            } else {
                assert_eq!(logger.status().pending, CAPACITY);
                assert_eq!(logger.status().queue_full, 1);
            }
            log::set_max_level(log::LevelFilter::Off);
            log::error!("must be filtered; secret-canary");
        }
        fluxheim_common::fatal::abort(fluxheim_common::fatal::Reason::AdminAuthThrottlePoisoned);
    }
    for mode in [
        "full",
        "failed",
        "uninitialized",
        "stderr",
        "startup",
        "append",
        "sink-failed",
    ] {
        if mode == "startup" && cfg!(feature = "privacy-mode") {
            continue; // The privacy build has a separate startup-rejection test.
        }
        let path = fluxheim_common::test_support::unique_temp_path("fatal-subprocess");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, mode)
            .env(PATH, &path)
            .env("RUST_LOG", "off")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("fatal reporting waited on the ordinary sink: {mode}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            assert_eq!(output.status.signal(), Some(6), "{mode}: {:?}", output);
        }
        #[cfg(windows)]
        assert!(!output.status.success(), "{mode}");
        let expected = fluxheim_common::fatal::Reason::AdminAuthThrottlePoisoned.record();
        if mode == "stderr" || mode == "sink-failed" {
            assert_eq!(
                output
                    .stderr
                    .windows(expected.len())
                    .filter(|part| *part == expected)
                    .count(),
                1
            );
            assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-canary"));
            if mode == "sink-failed" {
                assert_eq!(std::fs::read(&path).unwrap(), b"");
                std::fs::remove_file(path).unwrap();
            } else {
                assert!(!path.exists());
            }
        } else {
            let expected = if mode == "append" {
                [b"previous crash\n".as_slice(), expected].concat()
            } else {
                expected.to_vec()
            };
            assert_eq!(std::fs::read(&path).unwrap(), expected, "{mode}");
            assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-canary"));
            std::fs::remove_file(path).unwrap();
        }
    }
}

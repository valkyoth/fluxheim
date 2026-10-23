use super::*;
use crate::config::LoggingFormat;
use log::Log as _;
use std::fmt;
use std::sync::{Condvar, Mutex};

#[derive(Clone, Default)]
struct Output(Arc<Mutex<Vec<u8>>>);
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Clone, Default)]
struct Gate(Arc<(Mutex<bool>, Condvar)>);
impl Gate {
    fn wait(&self) {
        let (m, c) = &*self.0;
        drop(c.wait_while(m.lock().unwrap(), |open| !*open).unwrap());
    }
    fn release(&self) {
        let (m, c) = &*self.0;
        *m.lock().unwrap() = true;
        c.notify_all();
    }
}
struct Blocked(Gate);
impl Write for Blocked {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.wait();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn logger(filter: &str, writer: Box<dyn Write + Send>) -> Logger {
    Logger::new(
        env_logger::Builder::new().parse_filters(filter).build(),
        LoggingFormat::Json,
        writer,
    )
    .unwrap()
}
fn submit(logger: &Logger, message: impl fmt::Display) {
    logger.log(
        &log::Record::builder()
            .level(log::Level::Info)
            .target("test")
            .args(format_args!("{message}"))
            .build(),
    );
}
fn wait(mut condition: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn blocked_writer_bounds_many_producers_and_shutdown_without_formatting_drops() {
    struct Count<'a>(&'a AtomicU64);
    impl fmt::Display for Count<'_> {
        fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
            inc(self.0);
            out.write_str("bounded")
        }
    }
    let gate = Gate::default();
    let logger = logger("info", Box::new(Blocked(gate.clone())));
    let formatted = AtomicU64::new(0);
    std::thread::scope(|scope| {
        for _ in 0..32 {
            scope.spawn(|| {
                for _ in 0..1000 {
                    submit(&logger, Count(&formatted));
                }
            });
        }
    });
    let s = logger.status();
    assert_eq!(s.accepted, CAPACITY);
    assert_eq!(formatted.load(Ordering::Relaxed), CAPACITY);
    assert_eq!(s.queue_full + s.producer_busy + s.accepted, 32000);
    assert_eq!(s.pending, CAPACITY);
    assert_eq!(s.active_producers, 0);
    let start = Instant::now();
    logger.shutdown(Duration::from_millis(20));
    assert!(start.elapsed() < Duration::from_secs(1));
    submit(&logger, Count(&formatted));
    assert_eq!(logger.status().unavailable, 1);
    gate.release();
    wait(|| !logger.status().worker_alive);
    assert_eq!(logger.status().written, CAPACITY);
}

#[test]
fn blocked_formatters_cannot_exceed_global_producer_cap() {
    struct Slow(Gate);
    impl fmt::Display for Slow {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0.wait();
            f.write_str("ok")
        }
    }
    let gate = Gate::default();
    let logger = logger("info", Box::new(io::sink()));
    std::thread::scope(|scope| {
        for _ in 0..PRODUCERS {
            let gate = gate.clone();
            let logger = &logger;
            scope.spawn(move || submit(logger, Slow(gate)));
        }
        wait(|| logger.status().active_producers == PRODUCERS);
        submit(&logger, "must not format");
        assert_eq!(logger.status().producer_busy, 1);
        gate.release();
    });
    logger.shutdown(Duration::from_millis(500));
    assert_eq!(logger.status().written, PRODUCERS);
}

#[test]
fn formatting_recursion_and_unwind_release_both_credits() {
    struct Recursive<'a>(&'a Logger);
    impl fmt::Display for Recursive<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            submit(self.0, "nested");
            f.write_str("outer")
        }
    }
    struct Panics;
    impl fmt::Display for Panics {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("fixture formatter panic")
        }
    }
    let logger = logger("info", Box::new(io::sink()));
    submit(&logger, Recursive(&logger));
    assert_eq!(logger.status().recursive, 1);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| submit(&logger, Panics))).is_err()
    );
    submit(&logger, "after unwind");
    logger.shutdown(Duration::from_millis(500));
    assert_eq!(logger.status().written, 2);
    assert_eq!(logger.status().capture_panics, 1);
    assert_eq!(logger.status().active_producers, 0);
    assert_eq!(logger.counters.credits.load(Ordering::Acquire), 0);
}

#[test]
fn worker_recursion_is_suppressed_and_owner_drop_still_drains() {
    struct Reentrant(Arc<Mutex<std::sync::Weak<Logger>>>);
    impl Write for Reentrant {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(logger) = self.0.lock().unwrap().upgrade() {
                submit(&logger, "sink must not recursively log");
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let link = Arc::new(Mutex::new(std::sync::Weak::new()));
    let logger = Arc::new(logger("info", Box::new(Reentrant(link.clone()))));
    *link.lock().unwrap() = Arc::downgrade(&logger);
    submit(&logger, "outer");
    wait(|| logger.status().written == 1);
    assert_eq!(logger.status().recursive, 1);
    let counters = logger.counters.clone();
    for _ in 0..20 {
        submit(&logger, "drain after owner cancellation");
    }
    drop(logger);
    wait(|| !counters.alive.load(Ordering::Acquire));
    assert_eq!(counters.written.load(Ordering::Relaxed), 21);
    assert_eq!(counters.credits.load(Ordering::Acquire), 0);
}

#[test]
fn level_rejection_does_not_format_and_overflow_cannot_be_hidden_by_display() {
    struct MustNotFormat;
    impl fmt::Display for MustNotFormat {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("disabled formatter called")
        }
    }
    let off = logger("off", Box::new(io::sink()));
    submit(&off, MustNotFormat);
    assert_eq!(off.status().filtered, 1);
    struct IgnoreError;
    impl fmt::Display for IgnoreError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let _ = f.write_str(&"x".repeat(4097));
            f.write_str("partial")
        }
    }
    let on = logger("info", Box::new(io::sink()));
    submit(&on, IgnoreError);
    assert_eq!(on.status().oversized, 1);
    assert_eq!(on.status().accepted, 0);
}

proptest::proptest! {
    #[test]
    fn arbitrary_unicode_records_stay_bounded_and_json_roundtrips(message in ".{0,5000}", target in ".{0,1100}") {
        let captured = Record::capture(&log::Record::builder().target(&target).args(format_args!("{message}")).build());
        if let Ok(record) = captured {
            for format in [LoggingFormat::Json, LoggingFormat::Text] {
                if let Ok(encoded) = record.encode(format) {
                    proptest::prop_assert!(encoded.as_str().len() <= 8192);
                    proptest::prop_assert_eq!(encoded.as_str().matches('\n').count(), 1);
                    if matches!(format, LoggingFormat::Json) {
                        let value: serde_json::Value = serde_json::from_str(encoded.as_str()).unwrap();
                        proptest::prop_assert_eq!(value["message"].as_str().unwrap(), message.as_str());
                        proptest::prop_assert_eq!(value["target"].as_str().unwrap(), target.as_str());
                    }
                }
            }
        }
    }
}

#[test]
fn repeated_initialization_does_not_replace_or_stop_the_owner() {
    const CHILD: &str = "FLUXHEIM_LOG_OWNER_TEST";
    if std::env::var_os(CHILD).is_some() {
        let config = crate::config::Config::default();
        let guard = super::super::init_logging(&config).unwrap();
        let result = super::super::init_logging(&config);
        assert!(matches!(result, Err(error) if error.to_string().contains("already initialized")));
        assert!(super::super::status().unwrap().worker_alive);
        assert!(
            fluxheim_observability::operational::status()
                .unwrap()
                .audit
                .worker_alive
        );
        drop(guard);
        assert!(!super::super::status().unwrap().worker_alive);
        assert!(
            !fluxheim_observability::operational::status()
                .unwrap()
                .audit
                .worker_alive
        );
        return;
    }
    assert!(std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "runtime::runtime_logging::dispatch::tests::repeated_initialization_does_not_replace_or_stop_the_owner"])
        .env(CHILD, "1").status().unwrap().success());
}

#[test]
fn failed_write_flush_and_panicking_writer_close_lane_and_count_losses() {
    struct Failed(u8, Gate);
    impl Write for Failed {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.1.wait();
            match self.0 {
                0 => Err(io::ErrorKind::BrokenPipe.into()),
                1 => Ok(bytes.len()),
                _ => panic!("fixture writer panic"),
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::Other.into())
        }
    }
    for mode in 0..3 {
        let gate = Gate::default();
        let logger = logger("info", Box::new(Failed(mode, gate.clone())));
        for _ in 0..10 {
            submit(&logger, "queued");
        }
        gate.release();
        wait(|| logger.status().discarded == 10);
        submit(&logger, "after failure");
        let s = logger.status();
        assert_eq!(s.unavailable, 1);
        assert_eq!(s.written, 0);
        assert_eq!(s.pending, 0);
        assert_eq!(s.sink_errors + s.worker_panics, 1);
        assert_eq!(logger.counters.credits.load(Ordering::Acquire), 0);
    }
}

#[test]
fn filters_use_bounded_message_and_oversize_records_do_not_poison_sink() {
    let output = Output::default();
    let logger = logger("info/allowed", Box::new(output.clone()));
    submit(&logger, "excluded");
    submit(&logger, "a".repeat(4097));
    submit(&logger, format!("allowed{}", "\u{0001}".repeat(4000)));
    submit(&logger, "allowed\n\"quoted\"");
    logger.shutdown(Duration::from_millis(500));
    let s = logger.status();
    assert_eq!(s.filtered, 1);
    assert_eq!(s.oversized, 2);
    assert_eq!(s.discarded, 1);
    assert_eq!(s.written, 1);
    assert_eq!(s.sink_errors, 0);
    let bytes = output.0.lock().unwrap();
    let decoded: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded["message"], "allowed\n\"quoted\"");
    assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 1);
}

#[test]
fn record_schema_preserves_baseline_and_text_has_one_line() {
    let mut record = Record::capture(
        &log::Record::builder()
            .level(log::Level::Warn)
            .target("fluxheim::security")
            .args(format_args!("denied\n\"quoted\"\t\\path"))
            .build(),
    )
    .unwrap();
    record.timestamp = "2026-10-23T00:00:00.000Z"
        .parse::<jiff::Timestamp>()
        .unwrap()
        .into();
    let encoded = record.encode(LoggingFormat::Json).unwrap();
    let actual: serde_json::Value = serde_json::from_str(encoded.as_str()).unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../tests/fixtures/observability/runtime-log.json"
    ))
    .unwrap();
    assert_eq!(actual, expected);
    let text = record.encode(LoggingFormat::Text).unwrap();
    assert_eq!(text.as_str().matches('\n').count(), 1);
    assert!(
        text.as_str()
            .starts_with("2026-10-23T00:00:00.000Z WARN fluxheim::security: ")
    );
}

#[test]
fn preinstalled_logger_fails_initialization_and_stops_workers() {
    const CHILD: &str = "FLUXHEIM_LOG_INIT_TEST";
    if std::env::var_os(CHILD).is_some() {
        struct Null;
        impl log::Log for Null {
            fn enabled(&self, _: &log::Metadata<'_>) -> bool {
                false
            }
            fn log(&self, _: &log::Record<'_>) {}
            fn flush(&self) {}
        }
        static NULL: Null = Null;
        log::set_logger(&NULL).unwrap();
        assert!(super::super::init_logging(&crate::config::Config::default()).is_err());
        assert!(!super::super::status().unwrap().worker_alive);
        assert!(
            !fluxheim_observability::operational::status()
                .unwrap()
                .audit
                .worker_alive
        );
        return;
    }
    assert!(std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "runtime::runtime_logging::dispatch::tests::preinstalled_logger_fails_initialization_and_stops_workers"])
        .env(CHILD, "1").status().unwrap().success());
}

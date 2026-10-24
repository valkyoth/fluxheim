//! One file handle shared by all four bounded logging workers.
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CHECK_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Default)]
pub(super) struct Counters {
    checks: AtomicU64,
    reopens: AtomicU64,
    reopen_errors: AtomicU64,
    write_errors: AtomicU64,
    failed: AtomicBool,
    open: AtomicBool,
}

#[derive(serde::Serialize)]
pub(crate) struct Status {
    check_interval_ms: u64,
    checks: u64,
    reopens: u64,
    reopen_errors: u64,
    write_errors: u64,
    failed: bool,
    handle_open: bool,
}

impl Counters {
    pub(super) fn status(&self) -> Status {
        Status {
            check_interval_ms: 1000,
            checks: self.checks.load(Ordering::Relaxed),
            reopens: self.reopens.load(Ordering::Relaxed),
            reopen_errors: self.reopen_errors.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Acquire),
            handle_open: self.open.load(Ordering::Acquire),
        }
    }
}

fn increment(counter: &AtomicU64) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}

struct State {
    path: PathBuf,
    file: File,
    crash: Option<File>,
    next_check: Instant,
    counters: Arc<Counters>,
}

impl Drop for State {
    fn drop(&mut self) {
        self.counters.open.store(false, Ordering::Release);
    }
}

#[derive(Clone)]
pub(super) struct Sink(Arc<Mutex<State>>);

impl Sink {
    pub(super) fn new(path: &Path, append: bool, crash: Option<&File>) -> io::Result<Self> {
        let path = std::path::absolute(path)?;
        let file = open(&path, true)?;
        if let Some(crash) = crash {
            super::crash::require_distinct(crash, &file)?;
        }
        if !append {
            file.set_len(0)?;
        }
        let counters = Arc::new(Counters::default());
        counters.open.store(true, Ordering::Release);
        Ok(Self(Arc::new(Mutex::new(State {
            path,
            file,
            crash: crash.map(File::try_clone).transpose()?,
            next_check: Instant::now() + CHECK_INTERVAL,
            counters,
        }))))
    }

    pub(super) fn counters(&self) -> io::Result<Arc<Counters>> {
        self.0
            .lock()
            .map(|state| state.counters.clone())
            .map_err(|_| io::Error::other("log file state poisoned"))
    }
}

impl State {
    fn reopen_if_due(&mut self, now: Instant) {
        if now < self.next_check {
            return;
        }
        // One attempt per interval across all lanes, including failures. No
        // retry loop or additional thread is created on a request or log path.
        self.next_check = now + CHECK_INTERVAL;
        increment(&self.counters.checks);
        let candidate = (|| {
            let file = open(&self.path, true)?;
            if let Some(crash) = &self.crash {
                super::crash::require_distinct(crash, &file)?;
            }
            let changed = !super::crash::same(&self.file, &file)?;
            Ok::<_, io::Error>((file, changed))
        })();
        match candidate {
            Ok((file, true)) => {
                self.file = file;
                increment(&self.counters.reopens);
            }
            Ok((_, false)) => {}
            Err(_) => increment(&self.counters.reopen_errors),
        }
    }
}

impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("log file state poisoned"))?;
        if state.counters.failed.load(Ordering::Acquire) {
            return Err(io::Error::other(
                "log file requires restart after write failure",
            ));
        }
        state.reopen_if_due(Instant::now());
        // Serialize the entire record, including short OS writes, with the
        // handle swap. Producers and status readers never acquire this mutex.
        let result = (|| {
            if fluxheim_config::fs_trust::opened_file_has_insecure_owner_or_write_permissions(
                &state.file,
            )? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "log handle no longer trusted",
                ));
            }
            #[cfg(windows)]
            {
                use std::io::{Seek, SeekFrom};
                state.file.seek(SeekFrom::End(0))?;
            }
            state.file.write_all(bytes)
        })();
        finish_write(result, &state.counters)?;
        Ok(bytes.len())
    }

    // File has no userspace buffering. This is not a durable sync guarantee.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn finish_write(result: io::Result<()>, counters: &Counters) -> io::Result<()> {
    if result.is_err() {
        increment(&counters.write_errors);
        counters.failed.store(true, Ordering::Release);
    }
    result
}

pub(super) fn open(path: &Path, append: bool) -> io::Result<File> {
    fluxheim_config::config_path::validate_required_process_path("logging.file.path", path)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "unsafe log file path"))?;
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags};
        File::from(rustix::fs::open(
            path,
            OFlags::CREATE
                | OFlags::WRONLY
                | OFlags::APPEND
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )?)
    };
    #[cfg(windows)]
    let file = match fluxheim_config::fs_trust::create_confidential_file(path) {
        Ok(file) => {
            drop(file);
            fluxheim_config::fs_trust::open_regular_file_for_update(path)?
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            fluxheim_config::fs_trust::open_regular_file_for_update(path)?
        }
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file()
        || fluxheim_config::fs_trust::opened_file_has_insecure_owner_or_write_permissions(&file)?
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted log file",
        ));
    }
    if !append {
        file.set_len(0)?;
    }
    Ok(file)
}

#[cfg(test)]
#[path = "runtime_log_file_tests.rs"]
mod tests;

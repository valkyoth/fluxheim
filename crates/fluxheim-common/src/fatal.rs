//! Last-chance diagnostics, independent of asynchronous loggers and their filters.
//!
//! Diagnostics are best effort and guarded by a prestarted termination watchdog,
//! not a durable audit journal. An external supervisor is still needed if the OS
//! cannot schedule the watchdog or the process itself is compromised.

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread::{self, Thread};
use std::time::Duration;

static SINK: OnceLock<Mutex<File>> = OnceLock::new();
static WATCHDOG: OnceLock<io::Result<Thread>> = OnceLock::new();
static TERMINATING: AtomicBool = AtomicBool::new(false);
const DIAGNOSTIC_GRACE: Duration = Duration::from_millis(250);

/// Start once before serving, including when no crash file is configured.
/// Failure must reject startup. The watchdog is parked while healthy, never
/// touches logging locks, and cannot be disarmed once termination is requested.
pub fn start_watchdog() -> io::Result<()> {
    match WATCHDOG.get_or_init(|| {
        thread::Builder::new()
            .name("fluxheim-fatal-watchdog".into())
            .spawn(|| {
                while !TERMINATING.load(Ordering::Acquire) {
                    thread::park();
                }
                thread::sleep(DIAGNOSTIC_GRACE);
                std::process::abort();
            })
            .map(|handle| handle.thread().clone())
    }) {
        Ok(_) => Ok(()),
        Err(error) => Err(io::Error::new(
            error.kind(),
            "fatal watchdog could not start",
        )),
    }
}

macro_rules! reasons {
    ($($name:ident),+ $(,)?) => {
        /// Closed reason vocabulary: no request fields, secrets, or raw errors.
        #[derive(Clone, Copy, Debug)]
        pub enum Reason { $($name),+ }
        impl Reason {
            pub fn record(self) -> &'static [u8] {
                match self {
                    $(Self::$name => concat!("FATAL_SECURITY reason=", stringify!($name), "\n").as_bytes()),+
                }
            }
        }
    };
}

reasons! {
    AdminAuthThrottlePoisoned, AdminTokenEntropyFailed, AdminHmacFailed,
    AdminDeadlinePoisoned, AdminStatePoisoned, AdminClockInvalid,
    RequestAdmissionDuplicated, RateLimitPoisoned, RateLimitBucketMissing,
    RateLimitEntropyFailed, ForwardedIdentityPoisoned, ProxyConfigPoisoned,
    UdpSessionsPoisoned, UdpResponseRatePoisoned,
    DiskCachePoisoned, DiskCacheMutationPoisoned, CachePurgeRegistryPoisoned,
    MemoryCachePoisoned, CacheStatsRegistryPoisoned, CacheFillRegistryPoisoned,
    StorageBinFreeMapPoisoned, StorageBinRegistryPoisoned, StorageBinFlushPoisoned,
    StorageBinStatePoisoned, SliceBoundaryEntropyFailed, PeerFillEntropyFailed,
    MirrorInflightPoisoned, MirrorSampleEntropyFailed, MirrorMarkerEntropyFailed,
    WasmCompilePoolPoisoned, WasmCacheKeyPoisoned, WasmCacheStorePoisoned,
    TlsGenerationWakerPoisoned, TlsConnectionIdExhausted, TlsLeaseAttachmentFailed,
    BackendHealthPoisoned, BackendDiscoveryPoisoned, BackendSelectionEntropyFailed,
    BackendRoutingEntropyFailed, CookieKeyEntropyFailed, CookieHmacEntropyFailed,
    CookieNameOverflow,
    StreamListenerBindFailed, UdpListenerBindFailed, MetricsListenerBindFailed,
    MetricsListenerFailed, HttpProxyListenerFailed,
}

/// Install a dedicated, securely opened private regular file before serving.
/// The caller owns path/ACL validation. The handle is retained until process exit
/// and must not alias an ordinary log sink. A second installation is rejected.
pub fn install(file: File) -> io::Result<()> {
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "crash sink must be a regular file",
        ));
    }
    start_watchdog()?;
    SINK.set(Mutex::new(file))
        .map_err(|_| io::Error::new(io::ErrorKind::AlreadyExists, "crash sink already installed"))
}

fn write_file(file: &mut File, reason: Reason) -> io::Result<()> {
    // Windows trusted-file helpers return an update handle. Serialize seek/write
    // on this private handle; Unix startup also opens it with O_APPEND.
    file.seek(SeekFrom::End(0))?;
    file.write_all(reason.record())?;
    file.sync_data()
}

fn report(reason: Reason) {
    // get() does not wait for an in-progress initialization. Without a ready
    // watchdog, skip potentially blocking diagnostics and terminate immediately.
    let Some(Ok(watchdog)) = WATCHDOG.get() else {
        return;
    };
    TERMINATING.store(true, Ordering::Release);
    watchdog.unpark();
    let written = SINK.get().is_some_and(|sink| {
        let mut file = sink.lock().unwrap_or_else(|poison| poison.into_inner());
        write_file(&mut file, reason).is_ok()
    });
    if !written {
        let mut stderr = io::stderr().lock();
        let _ = stderr.write_all(reason.record());
        let _ = stderr.flush();
    }
}

/// Report with watchdog protection, then abort without unwinding. Before
/// watchdog initialization, abort immediately without attempting sink I/O.
pub fn abort(reason: Reason) -> ! {
    report(reason);
    std::process::abort()
}

/// Critical service failure: preserve exit status 1 if reporting completes.
/// If reporting or exit stalls, the watchdog aborts instead. No queue drain is
/// implied; only this finite reason is attempted independently of the queues.
pub fn exit(reason: Reason) -> ! {
    report(reason);
    std::process::exit(1)
}

#[cfg(test)]
#[path = "fatal_tests.rs"]
mod tests;

//! Last-chance diagnostics, independent of asynchronous loggers and their filters.
//!
//! This is a synchronous write attempt, not a durable audit journal. A stalled
//! kernel/device can stall termination; no in-process facility survives every
//! storage failure, external kill, or process compromise.

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::sync::{Mutex, OnceLock};

static SINK: OnceLock<Mutex<File>> = OnceLock::new();

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

/// Attempt the finite diagnostic synchronously, then abort without unwinding.
/// With no crash file (including early startup), or on a file error, stderr is
/// the fallback. This bypasses RUST_LOG, privacy filters and ordinary log queues.
pub fn abort(reason: Reason) -> ! {
    let written = SINK.get().is_some_and(|sink| {
        let mut file = sink.lock().unwrap_or_else(|poison| poison.into_inner());
        write_file(&mut file, reason).is_ok()
    });
    if !written {
        let mut stderr = io::stderr().lock();
        let _ = stderr.write_all(reason.record());
        let _ = stderr.flush();
    }
    std::process::abort()
}

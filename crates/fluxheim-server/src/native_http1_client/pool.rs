use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use tokio::sync::{Mutex, Semaphore};

use super::NativeHttp1Stream;
use crate::NativeHttp1Error;
use crate::native_http2_client::NativeHttp2ConnectionDriver;

#[derive(Debug, Default)]
pub(super) struct NativeHttp1Pool {
    pub(super) max_idle: usize,
    pub(super) idle_timeout: Option<Duration>,
    pub(super) idle: Mutex<Vec<IdleNativeHttp1Connection>>,
}

impl NativeHttp1Pool {
    pub(super) fn new(max_idle: usize, idle_timeout: Option<Duration>) -> Self {
        Self {
            max_idle,
            idle_timeout,
            idle: Mutex::new(Vec::new()),
        }
    }
}

#[derive(Debug)]
pub(super) struct NativeHttp2Pool {
    pub(super) stream_slots: Arc<Semaphore>,
    pub(super) connection: Mutex<Option<Arc<NativeHttp2PooledConnection>>>,
    pub(super) setup: Mutex<()>,
}

impl NativeHttp2Pool {
    pub(super) fn new(max_concurrent_streams: u32) -> Self {
        debug_assert!(
            (max_concurrent_streams as usize) <= Semaphore::MAX_PERMITS,
            "max_concurrent_streams exceeds Semaphore::MAX_PERMITS"
        );
        Self {
            stream_slots: Arc::new(Semaphore::new(max_concurrent_streams as usize)),
            connection: Mutex::new(None),
            setup: Mutex::new(()),
        }
    }
}

pub(super) struct NativeHttp2PooledConnection {
    pub(super) client: SendRequest<Bytes>,
    pub(super) driver: NativeHttp2ConnectionDriver,
}

impl std::fmt::Debug for NativeHttp2PooledConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeHttp2PooledConnection")
            .finish_non_exhaustive()
    }
}

impl Drop for NativeHttp2PooledConnection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

pub(super) struct IdleNativeHttp1Connection {
    pub(super) stream: NativeHttp1Stream,
    pub(super) inserted_at: Instant,
}

impl std::fmt::Debug for IdleNativeHttp1Connection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdleNativeHttp1Connection")
            .field("inserted_at", &self.inserted_at)
            .finish_non_exhaustive()
    }
}

pub(super) fn pooled_connection_error_can_retry(error: &NativeHttp1Error) -> bool {
    matches!(
        error,
        NativeHttp1Error::Io(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof
            )
    )
}

pub(super) fn native_http1_retry_method_allowed(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

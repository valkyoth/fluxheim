use std::sync::Arc;
use std::time::{Duration, Instant};

use fluxheim_protocol::{Http1ParseError, http_token_valid};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::NativeHttp1Error;
use crate::native_http1_response_metadata::{NativeCacheStatus, NativeProxyStatusError};
use crate::response_retention::NativeResponseRetention;

const WRITE_CHUNK_BYTES: usize = 8192;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1Response {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    content_length: Option<u64>,
    body: Vec<u8>,
    body_sha256: Option<Arc<[u8; 32]>>,
    close: bool,
    cache_status: Option<NativeCacheStatus>,
    proxy_status_error: Option<NativeProxyStatusError>,
    cache_status_metadata_emitted: bool,
    proxy_status_metadata_emitted: bool,
    write_policy: NativeHttp1ResponseWritePolicy,
    retention: Option<NativeResponseRetention>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHttp1ResponseWritePolicy {
    write_timeout: Option<Duration>,
    total_response_timeout: Option<Duration>,
    min_send_rate_bytes_per_sec: Option<usize>,
}

impl Default for NativeHttp1ResponseWritePolicy {
    fn default() -> Self {
        Self {
            write_timeout: Some(Duration::from_secs(30)),
            total_response_timeout: Some(Duration::from_secs(300)),
            min_send_rate_bytes_per_sec: Some(8 * 1024),
        }
    }
}

impl NativeHttp1Response {
    pub fn new(status: u16, reason: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            reason: reason.into(),
            headers: Vec::new(),
            content_length: None,
            body: body.into(),
            body_sha256: None,
            close: false,
            cache_status: None,
            proxy_status_error: None,
            cache_status_metadata_emitted: false,
            proxy_status_metadata_emitted: false,
            write_policy: NativeHttp1ResponseWritePolicy::default(),
            retention: None,
        }
    }

    pub const fn with_content_length(mut self, content_length: u64) -> Self {
        self.content_length = Some(content_length);
        self
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_retry_after_secs(self, retry_after_secs: u64) -> Self {
        self.with_header("retry-after", retry_after_secs.to_string())
    }

    pub const fn close_connection(mut self) -> Self {
        self.close = true;
        self
    }

    pub const fn with_write_policy(mut self, policy: NativeHttp1ResponseWritePolicy) -> Self {
        self.write_policy = policy;
        self
    }

    pub(crate) fn with_retention(mut self, retention: NativeResponseRetention) -> Self {
        self.retention = Some(retention);
        self
    }

    pub(crate) fn retention(&self) -> Option<NativeResponseRetention> {
        self.retention.clone()
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub(crate) fn remove_header(&mut self, name: &str) {
        self.headers
            .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
    }

    pub(crate) fn push_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.push((name.into(), value.into()));
    }

    pub(crate) fn set_cache_status(&mut self, cache_status: NativeCacheStatus) {
        self.cache_status = Some(cache_status);
    }

    pub(crate) fn cache_status(&self) -> Option<&NativeCacheStatus> {
        self.cache_status.as_ref()
    }

    pub(crate) const fn cache_status_metadata_emitted(&self) -> bool {
        self.cache_status_metadata_emitted
    }

    pub(crate) const fn mark_cache_status_metadata_emitted(&mut self) {
        self.cache_status_metadata_emitted = true;
    }

    pub(crate) const fn with_proxy_status_error(mut self, error: NativeProxyStatusError) -> Self {
        self.proxy_status_error = Some(error);
        self
    }

    pub(crate) const fn proxy_status_error(&self) -> Option<NativeProxyStatusError> {
        self.proxy_status_error
    }

    pub(crate) const fn proxy_status_metadata_emitted(&self) -> bool {
        self.proxy_status_metadata_emitted
    }

    pub(crate) const fn mark_proxy_status_metadata_emitted(&mut self) {
        self.proxy_status_metadata_emitted = true;
    }

    pub const fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    pub(crate) const fn close_requested(&self) -> bool {
        self.close
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn with_body_sha256(mut self, digest: Arc<[u8; 32]>) -> Self {
        self.body_sha256 = Some(digest);
        self
    }

    pub(crate) fn body_sha256(&self) -> Option<&[u8; 32]> {
        self.body_sha256.as_deref()
    }

    pub(crate) fn set_body_sha256(&mut self, digest: [u8; 32]) {
        self.body_sha256 = Some(Arc::new(digest));
    }

    #[cfg(any(
        feature = "compression-brotli",
        feature = "compression-gzip",
        feature = "compression-zstd"
    ))]
    pub(crate) fn replace_body(&mut self, body: impl Into<Vec<u8>>) {
        self.body = body.into();
        self.body_sha256 = None;
        self.content_length = None;
    }
}

impl NativeHttp1ResponseWritePolicy {
    pub const fn new(
        write_timeout: Option<Duration>,
        total_response_timeout: Option<Duration>,
        min_send_rate_bytes_per_sec: Option<usize>,
    ) -> Self {
        Self {
            write_timeout,
            total_response_timeout,
            min_send_rate_bytes_per_sec,
        }
    }

    pub const fn write_timeout(self) -> Option<Duration> {
        self.write_timeout
    }

    pub const fn total_response_timeout(self) -> Option<Duration> {
        self.total_response_timeout
    }

    pub const fn min_send_rate_bytes_per_sec(self) -> Option<usize> {
        self.min_send_rate_bytes_per_sec
    }
}

pub(super) async fn write_response<S>(
    stream: &mut S,
    response: NativeHttp1Response,
    close: bool,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    let policy = response.write_policy;
    let write = write_response_inner(stream, response, close, policy);
    if let Some(total_response_timeout) = policy.total_response_timeout {
        timeout(total_response_timeout, write)
            .await
            .map_err(|_| timeout_error("response total timeout"))?
    } else {
        write.await
    }
}

async fn write_response_inner<S>(
    stream: &mut S,
    response: NativeHttp1Response,
    close: bool,
    policy: NativeHttp1ResponseWritePolicy,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    let reason = sanitize_reason_phrase(&response.reason).collect::<String>();
    write_all_with_policy(
        stream,
        format!("HTTP/1.1 {} {reason}\r\n", response.status).as_bytes(),
        policy,
    )
    .await?;
    write_all_with_policy(
        stream,
        format!(
            "Date: {}\r\n",
            httpdate::fmt_http_date(std::time::SystemTime::now())
        )
        .as_bytes(),
        policy,
    )
    .await?;
    write_all_with_policy(
        stream,
        format!(
            "Content-Length: {}\r\n",
            response
                .content_length
                .unwrap_or(response.body.len() as u64)
        )
        .as_bytes(),
        policy,
    )
    .await?;
    write_all_with_policy(
        stream,
        if close {
            b"Connection: close\r\n"
        } else {
            b"Connection: keep-alive\r\n"
        },
        policy,
    )
    .await?;
    for (name, value) in response.headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("date")
        {
            continue;
        }
        if !valid_response_header(&name, &value) {
            return Err(Http1ParseError::InvalidHeaderValue.into());
        }
        write_all_with_policy(stream, format!("{name}: {value}\r\n").as_bytes(), policy).await?;
    }
    write_all_with_policy(stream, b"\r\n", policy).await?;
    write_body_with_policy(stream, &response.body, policy).await?;
    flush_with_policy(stream, policy).await?;
    Ok(())
}

async fn write_all_with_policy<S>(
    stream: &mut S,
    bytes: &[u8],
    policy: NativeHttp1ResponseWritePolicy,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    if let Some(write_timeout) = policy.write_timeout {
        timeout(write_timeout, stream.write_all(bytes))
            .await
            .map_err(|_| timeout_error("response write timeout"))??;
    } else {
        stream.write_all(bytes).await?;
    }
    Ok(())
}

async fn flush_with_policy<S>(
    stream: &mut S,
    policy: NativeHttp1ResponseWritePolicy,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    if let Some(write_timeout) = policy.write_timeout {
        timeout(write_timeout, stream.flush())
            .await
            .map_err(|_| timeout_error("response write timeout"))??;
    } else {
        stream.flush().await?;
    }
    Ok(())
}

async fn write_body_with_policy<S>(
    stream: &mut S,
    body: &[u8],
    policy: NativeHttp1ResponseWritePolicy,
) -> Result<(), NativeHttp1Error>
where
    S: AsyncWrite + Unpin,
{
    let Some(min_send_rate) = policy.min_send_rate_bytes_per_sec else {
        return write_all_with_policy(stream, body, policy).await;
    };
    if body.is_empty() {
        return Ok(());
    }

    let started_at = Instant::now();
    let mut written = 0usize;
    for chunk in body.chunks(WRITE_CHUNK_BYTES) {
        write_all_with_policy(stream, chunk, policy).await?;
        written = written.saturating_add(chunk.len());
        let elapsed = started_at.elapsed();
        if elapsed >= Duration::from_secs(1)
            && (written as f64 / elapsed.as_secs_f64()) < min_send_rate as f64
        {
            return Err(timeout_error("response min send rate not met"));
        }
    }
    Ok(())
}

fn timeout_error(message: &'static str) -> NativeHttp1Error {
    NativeHttp1Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
}

fn valid_response_header(name: &str, value: &str) -> bool {
    http_token_valid(name)
        && !value
            .bytes()
            .any(|byte| matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f..=0xff))
}

fn sanitize_reason_phrase(reason: &str) -> impl Iterator<Item = char> + '_ {
    reason
        .bytes()
        .filter(|byte| matches!(byte, 0x09 | 0x20..=0x7e))
        .map(char::from)
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::AsyncWrite;

    use super::*;

    struct StalledWriter;

    impl AsyncWrite for StalledWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn default_response_policy_is_bounded() {
        let policy = NativeHttp1ResponseWritePolicy::default();
        assert_eq!(policy.write_timeout(), Some(Duration::from_secs(30)));
        assert_eq!(
            policy.total_response_timeout(),
            Some(Duration::from_secs(300))
        );
        assert_eq!(policy.min_send_rate_bytes_per_sec(), Some(8 * 1024));
    }

    #[tokio::test]
    async fn stalled_response_writer_is_terminated_by_policy() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let retention =
            crate::response_retention::acquire_static_response_retention_from(slots.clone(), 1)
                .await
                .unwrap();
        let mut writer = StalledWriter;
        let response = NativeHttp1Response::new(200, "OK", vec![0_u8; 1024])
            .with_write_policy(NativeHttp1ResponseWritePolicy::new(
                Some(Duration::from_millis(5)),
                Some(Duration::from_millis(20)),
                Some(1),
            ))
            .with_retention(retention);

        let error = write_response(&mut writer, response, true)
            .await
            .unwrap_err();
        assert!(
            matches!(error, NativeHttp1Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut)
        );
        assert!(
            crate::response_retention::acquire_static_response_retention_from(slots, 1)
                .await
                .is_ok()
        );
    }
}

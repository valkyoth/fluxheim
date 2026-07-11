use std::io;
use std::time::Duration;

use fluxheim_common::{FluxError, FluxResult};
use sanitization::sanitize_bytes;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::watch;

const STREAM_COPY_BUFFER_BYTES: usize = 16 * 1024;

struct StreamCopyBuffer([u8; STREAM_COPY_BUFFER_BYTES]);

impl StreamCopyBuffer {
    fn new() -> Self {
        Self([0; STREAM_COPY_BUFFER_BYTES])
    }

    fn clear_forwarded(&mut self, bytes: usize) {
        sanitize_bytes(&mut self.0[..bytes]);
    }
}

impl Drop for StreamCopyBuffer {
    fn drop(&mut self) {
        sanitize_bytes(&mut self.0);
    }
}

pub fn checked_stream_byte_count(
    current: u64,
    additional: u64,
    max_connection_bytes: Option<u64>,
) -> FluxResult<u64> {
    let next = current.checked_add(additional).ok_or_else(|| {
        FluxError::io(
            "count stream bytes",
            io::Error::new(
                io::ErrorKind::InvalidData,
                "stream copied byte counter overflowed",
            ),
        )
    })?;
    if max_connection_bytes.is_some_and(|limit| next > limit) {
        return Err(FluxError::io(
            "enforce stream byte limit",
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "stream max connection bytes exceeded",
            ),
        ));
    }
    Ok(next)
}

pub async fn copy_bidirectional_with_limits(
    downstream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    upstream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    idle_timeout: Duration,
    max_connection_bytes: Option<u64>,
) -> FluxResult<(u64, u64)> {
    let (downstream_reader, downstream_writer) = tokio::io::split(downstream);
    let (upstream_reader, upstream_writer) = tokio::io::split(upstream);
    let (activity_tx, mut activity_rx) = watch::channel(tokio::time::Instant::now());
    let downstream_copy = copy_direction(
        downstream_reader,
        upstream_writer,
        max_connection_bytes,
        activity_tx.clone(),
    );
    let upstream_copy = copy_direction(
        upstream_reader,
        downstream_writer,
        max_connection_bytes,
        activity_tx,
    );
    tokio::pin!(downstream_copy);
    tokio::pin!(upstream_copy);

    let idle_timer = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_timer);
    let mut downstream_total = None;
    let mut upstream_total = None;
    let mut activity_open = true;

    loop {
        tokio::select! {
            biased;
            result = &mut downstream_copy, if downstream_total.is_none() => {
                downstream_total = Some(result?);
            }
            result = &mut upstream_copy, if upstream_total.is_none() => {
                upstream_total = Some(result?);
            }
            activity = activity_rx.changed(), if activity_open => {
                if activity.is_ok() {
                    let last_activity = *activity_rx.borrow_and_update();
                    idle_timer.as_mut().reset(last_activity + idle_timeout);
                } else {
                    activity_open = false;
                }
            }
            _ = &mut idle_timer => {
                return Err(FluxError::timeout(
                    "stream idle timeout",
                    "stream idle timeout elapsed",
                ));
            }
        }
        if let (Some(downstream_total), Some(upstream_total)) = (downstream_total, upstream_total) {
            return Ok((downstream_total, upstream_total));
        }
    }
}

async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    max_connection_bytes: Option<u64>,
    activity: watch::Sender<tokio::time::Instant>,
) -> FluxResult<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = StreamCopyBuffer::new();
    let mut total = 0u64;
    loop {
        let bytes = reader
            .read(&mut buffer.0)
            .await
            .map_err(|error| FluxError::io("read stream", error))?;
        if bytes == 0 {
            writer
                .shutdown()
                .await
                .map_err(|error| FluxError::io("shutdown stream", error))?;
            return Ok(total);
        }
        total = checked_stream_byte_count(total, bytes as u64, max_connection_bytes)?;
        writer
            .write_all(&buffer.0[..bytes])
            .await
            .map_err(|error| FluxError::io("write stream", error))?;
        buffer.clear_forwarded(bytes);
        activity.send_replace(tokio::time::Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_copy_buffer_clears_forwarded_prefix() {
        let mut buffer = StreamCopyBuffer([7; STREAM_COPY_BUFFER_BYTES]);
        buffer.clear_forwarded(3);
        assert_eq!(&buffer.0[..3], &[0, 0, 0]);
        assert_eq!(buffer.0[3], 7);
    }
}

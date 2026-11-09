use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::*;

struct FaultIo {
    write_fails: bool,
}
impl AsyncRead for FaultIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("read-canary")))
    }
}
impl AsyncWrite for FaultIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(if self.write_fails {
            Err(io::Error::other("write-canary"))
        } else {
            Ok(data.len())
        })
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn actual_http1_write_and_read_boundaries_attach_phase() {
    for write_fails in [false, true] {
        let upstream = crate::NativeHttp1Upstream::new("127.0.0.1:1");
        let error = upstream
            .send_on_stream(
                FaultIo { write_fails },
                &crate::native_http1_client_tests::request(),
            )
            .await
            .unwrap_err();
        let NativeHttp1Error::Io(error) = error else {
            panic!("wrong error")
        };
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            upstream_phase(&error),
            Some(if write_fails {
                UpstreamPhase::Write
            } else {
                UpstreamPhase::Read
            })
        );
    }
}

#[tokio::test]
async fn actual_failed_tcp_connect_attaches_phase() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let error = crate::NativeHttp1Upstream::new(address.to_string())
        .send(&mut crate::native_http1_client_tests::request())
        .await
        .unwrap_err();
    let NativeHttp1Error::Io(error) = error else {
        panic!("wrong error")
    };
    assert_eq!(upstream_phase(&error), Some(UpstreamPhase::Connect));
}

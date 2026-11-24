use std::io::ErrorKind;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixListener;

#[test]
fn reload_requires_a_complete_bounded_ack_not_eof() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("reload.sock");
        let listener = UnixListener::bind(&path).unwrap();
        for (reply, keep_open, expected) in [
            (b"ok\n".as_slice(), true, None),
            (b"ok", false, Some(ErrorKind::InvalidData)),
            (b"", true, Some(ErrorKind::TimedOut)),
            (b"error: test\n", false, Some(ErrorKind::Other)),
            (&[b'x'; 4096], true, Some(ErrorKind::InvalidData)),
        ] {
            let peer = async {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut command = [0; 20];
                stream.read_exact(&mut command).await.unwrap();
                assert_eq!(&command, b"reload-certificates\n");
                stream.write_all(reply).await.unwrap();
                if keep_open {
                    // The client must finish while this descriptor is still open.
                    assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
                }
            };
            let client = super::reload_exchange(&path, Duration::from_millis(500));
            let (result, ()) =
                tokio::time::timeout(Duration::from_secs(5), futures::future::join(client, peer))
                    .await
                    .unwrap();
            assert_eq!(result.err().map(|e| e.kind()), expected);
        }
    });
}

#[test]
fn trickling_reply_does_not_extend_the_overall_deadline() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("reload.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            while stream.write_all(b"x").await.is_ok() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            super::reload_exchange(&path, Duration::from_millis(300)),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), ErrorKind::TimedOut);
        peer.abort();
        let _ = peer.await;
    });
}

#[test]
fn absent_refused_and_full_sockets_never_confirm_activation() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("reload.sock");
        let limit = Duration::from_millis(200);
        assert!(super::reload_exchange(&path, limit).await.is_err());
        let socket = tokio::net::UnixSocket::new_stream().unwrap();
        socket.bind(&path).unwrap();
        let listener = socket.listen(1).unwrap();
        let mut clients = Vec::new();
        for _ in 0..8 {
            match tokio::time::timeout(limit, tokio::net::UnixStream::connect(&path)).await {
                Ok(Ok(client)) => clients.push(client),
                _ => break,
            }
        }
        assert!(!clients.is_empty());
        assert!(
            tokio::time::timeout(Duration::from_secs(3), super::reload_exchange(&path, limit))
                .await
                .unwrap()
                .is_err()
        );
        drop(listener);
        assert!(super::reload_exchange(&path, limit).await.is_err());
    });
}
